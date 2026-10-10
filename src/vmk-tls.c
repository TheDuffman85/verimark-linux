/*
 * Client side of the Synaptics "niseTlsLib" TLS 1.2 dialect.
 *
 * The protocol looks like TLS 1.2 but deviates in several places. Every
 * deviation below is copied from synaWudfBioUsb132.dll and annotated with the
 * function it was taken from:
 *
 *  - handshake flights sent by the host are prefixed with 44 00 00 00
 *    (ssiTlsEstablish @0x18006f670, FUN_1800712d0, FUN_180075900)
 *  - ClientHello: 7 byte session id, 6 suites, *empty* compression list,
 *    extensions without the outer length (ECC only)        FUN_180072530
 *  - Certificate message: u24 len, u24 len, 2 zero bytes, cert FUN_1800729b0
 *  - ClientKeyExchange: raw point / raw PSK identity, no length prefix
 *                                                          FUN_180073120
 *  - CertificateVerify: raw DER signature, no TLS signature-algorithm or
 *    signature-length prefix                               FUN_180072d40
 *  - key expansion seed is client_random || server_random  FUN_180071a30
 *  - the handshake hash (SHA-256) excludes Finished messages, so both
 *    Finished messages are computed over the same hash    FUN_1800739e0
 *  - CBC records MAC the sequence number only if the ServerHello minor
 *    version has bit 7 set                                 FUN_1800750f0/FUN_180071420
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "vmk-private.h"

#include <stdlib.h>
#include <string.h>

static const vmk_cipher_spec cipher_specs[] = {
  /* table @0x18011db30, offered in this order */
  { 0xc005, 0x20, 0x20, 0x00, 0x04 }, /* ECDH_ECDSA_WITH_AES_256_CBC_SHA (HMAC-SHA256) */
  { 0xc02e, 0x00, 0x20, 0x04, 0x25 }, /* ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
  { 0x003d, 0x20, 0x20, 0x00, 0x08 }, /* RSA_WITH_AES_256_CBC_SHA256 */
  { 0x008d, 0x20, 0x20, 0x00, 0x10 }, /* PSK_WITH_AES_256_CBC_SHA (HMAC-SHA256) */
  { 0x00a8, 0x00, 0x10, 0x04, 0x13 }, /* PSK_WITH_AES_128_GCM_SHA256 */
  { 0x00a9, 0x00, 0x20, 0x04, 0x31 }, /* PSK_WITH_AES_256_GCM_SHA384 */
};
#define N_SPECS (sizeof cipher_specs / sizeof cipher_specs[0])

#define REC_CCS        0x14
#define REC_ALERT      0x15
#define REC_HANDSHAKE  0x16
#define REC_APPDATA    0x17

#define HS_CLIENT_HELLO        0x01
#define HS_SERVER_HELLO        0x02
#define HS_CERTIFICATE         0x0b
#define HS_CERTIFICATE_REQUEST 0x0d
#define HS_SERVER_HELLO_DONE   0x0e
#define HS_CERTIFICATE_VERIFY  0x0f
#define HS_CLIENT_KEY_EXCHANGE 0x10
#define HS_FINISHED            0x14

#define STATE_ESTABLISHED      0xff

#define HANDSHAKE_REPLY_SIZE   0x100  /* ssiTlsEstablish: *param_3 = 0x100 */
#define CLOSE_REPLY_SIZE       0x964  /* ssiTlsAlertNotify */

typedef struct
{
  uint8_t *data;
  size_t   len, cap;
} buf_t;

static int
buf_append (buf_t *b, const void *data, size_t len)
{
  if (b->len + len > b->cap)
    {
      size_t cap = b->cap ? b->cap * 2 : 256;
      uint8_t *n;
      while (cap < b->len + len)
        cap *= 2;
      if (!(n = realloc (b->data, cap)))
        return VMK_E_NOMEM;
      b->data = n;
      b->cap = cap;
    }
  if (len)
    memcpy (b->data + b->len, data, len);
  b->len += len;
  return VMK_OK;
}

static void
buf_free (buf_t *b)
{
  if (b->data)
    vmk_secure_zero (b->data, b->cap);
  free (b->data);
  memset (b, 0, sizeof *b);
}

struct vmk_tls
{
  vmk_pairing pair;
  int         state;           /* expected handshake message */

  uint8_t     randoms[64];     /* client_random || server_random */
  uint8_t     master[48];
  uint8_t     key_block[128];
  const vmk_cipher_spec *cs;
  buf_t       transcript;

  uint64_t    wseq, rseq;
  bool        wenc, renc;
  bool        mac_seq;         /* ServerHello minor & 0x80 */
  bool        resumed;
};

vmk_tls *
vmk_tls_new (const vmk_pairing *pairing)
{
  vmk_tls *tls = calloc (1, sizeof *tls);

  if (!tls)
    return NULL;
  tls->pair = *pairing;
  return tls;
}

void
vmk_tls_free (vmk_tls *tls)
{
  if (!tls)
    return;
  buf_free (&tls->transcript);
  vmk_secure_zero (tls, sizeof *tls);
  free (tls);
}

bool
vmk_tls_established (vmk_tls *tls)
{
  return tls && tls->state == STATE_ESTABLISHED;
}

size_t
vmk_tls_overhead (vmk_tls *tls)
{
  (void) tls;
  return 0x45; /* ssiTlsWrap: *param_3 += 0x45 */
}

static bool
cs_sha384 (const vmk_tls *tls)
{
  return tls->cs && (tls->cs->flags & VMK_CS_SHA384);
}

/* key block: c_mac | s_mac | c_key | s_key | c_iv | s_iv */
#define KB_CMAC(t)  ((t)->key_block)
#define KB_SMAC(t)  ((t)->key_block + (t)->cs->mac_key_len)
#define KB_CKEY(t)  ((t)->key_block + 2 * (t)->cs->mac_key_len)
#define KB_SKEY(t)  ((t)->key_block + 2 * (t)->cs->mac_key_len + (t)->cs->enc_key_len)
#define KB_CIV(t)   ((t)->key_block + 2 * (t)->cs->mac_key_len + 2 * (t)->cs->enc_key_len)
#define KB_SIV(t)   (KB_CIV (t) + 4)

static void
seq_bytes (uint64_t seq, uint8_t out[8])
{
  for (int i = 7; i >= 0; i--, seq >>= 8)
    out[i] = seq & 0xff;
}

/* ---- record layer ------------------------------------------------------- */

static int
record_encrypt (vmk_tls *tls, uint8_t type, const uint8_t *plain, size_t len, buf_t *out)
{
  uint8_t hdr[5] = { type, 0x03, 0x03 };
  int r;

  if (len > 0x4000)
    return VMK_E_INVAL;

  if (!tls->wenc)
    {
      put_be16 (hdr + 3, (uint16_t) len);
      if ((r = buf_append (out, hdr, 5)))
        return r;
      return buf_append (out, plain, len);
    }

  if (tls->cs->flags & VMK_CS_AEAD)
    {
      uint8_t nonce[12], aad[13], tag[16];
      uint8_t *ct = malloc (len ? len : 1);

      if (!ct)
        return VMK_E_NOMEM;
      memcpy (nonce, KB_CIV (tls), 4);
      if ((r = vmk_random (nonce + 4, 8)))
        goto gcm_out;
      seq_bytes (tls->wseq, aad);
      put_be16 (hdr + 3, (uint16_t) len);
      memcpy (aad + 8, hdr, 5);
      if ((r = vmk_aes_gcm_encrypt (KB_CKEY (tls), tls->cs->enc_key_len, nonce, aad, 13,
                                    plain, len, ct, tag)))
        goto gcm_out;
      put_be16 (hdr + 3, (uint16_t) (len + 8 + 16));
      if (!(r = buf_append (out, hdr, 5)) &&
          !(r = buf_append (out, nonce + 4, 8)) &&
          !(r = buf_append (out, ct, len)))
        r = buf_append (out, tag, 16);
gcm_out:
      free (ct);
      if (!r)
        tls->wseq++;
      return r;
    }
  else
    {
      uint8_t seq[8], mac[32], iv[16];
      size_t total = len + 32, pad = 16 - (total % 16);
      uint8_t *pt = malloc (total + pad), *ct = malloc (total + pad);

      if (!pt || !ct)
        {
          free (pt);
          free (ct);
          return VMK_E_NOMEM;
        }
      seq_bytes (tls->wseq, seq);
      put_be16 (hdr + 3, (uint16_t) len);
      {
        const uint8_t *p[] = { seq, hdr, plain };
        const size_t l[] = { tls->mac_seq ? 8 : 0, 5, len };
        r = vmk_hmac (false, KB_CMAC (tls), tls->cs->mac_key_len, p, l, 3, mac);
      }
      if (r)
        goto cbc_out;
      memcpy (pt, plain, len);
      memcpy (pt + len, mac, 32);
      memset (pt + total, (int) (pad - 1), pad);
      if ((r = vmk_random (iv, 16)) ||
          (r = vmk_aes_cbc (true, KB_CKEY (tls), tls->cs->enc_key_len, iv, pt, total + pad, ct)))
        goto cbc_out;
      put_be16 (hdr + 3, (uint16_t) (16 + total + pad));
      if (!(r = buf_append (out, hdr, 5)) && !(r = buf_append (out, iv, 16)))
        r = buf_append (out, ct, total + pad);
cbc_out:
      vmk_secure_zero (pt, total + pad);
      free (pt);
      free (ct);
      if (!r)
        tls->wseq++;
      return r;
    }
}

/* decrypts one record body in place; returns plaintext location/length */
static int
record_decrypt (vmk_tls *tls, const uint8_t hdr_in[5], uint8_t *body, size_t len,
                uint8_t **plain, size_t *plain_len)
{
  uint8_t hdr[5];
  int r;

  memcpy (hdr, hdr_in, 5);
  if (tls->cs->flags & VMK_CS_AEAD)
    {
      uint8_t nonce[12], aad[13];
      size_t pl;

      if (len < 24)
        return VMK_E_PROTO;
      pl = len - 24;
      memcpy (nonce, KB_SIV (tls), 4);
      memcpy (nonce + 4, body, 8);
      seq_bytes (tls->rseq, aad);
      put_be16 (hdr + 3, (uint16_t) pl);
      memcpy (aad + 8, hdr, 5);
      r = vmk_aes_gcm_decrypt (KB_SKEY (tls), tls->cs->enc_key_len, nonce, aad, 13,
                               body + 8, pl, body + 8, body + 8 + pl);
      tls->rseq++;
      if (r)
        return VMK_E_CRYPTO;
      *plain = body + 8;
      *plain_len = pl;
      return VMK_OK;
    }
  else
    {
      uint8_t seq[8], mac[32], pad;
      size_t ctlen, pl;

      if (len < 0x20 || (len - 16) % 16)
        return VMK_E_PROTO;
      ctlen = len - 16;
      if ((r = vmk_aes_cbc (false, KB_SKEY (tls), tls->cs->enc_key_len, body, body + 16, ctlen,
                            body + 16)))
        return r;
      pad = body[16 + ctlen - 1];
      if (pad >= 0x10 || ctlen < (size_t) pad + 1 + 32)
        return VMK_E_PROTO;
      for (unsigned i = 0; i < pad; i++)
        if (body[16 + ctlen - 1 - i] != pad)
          return VMK_E_PROTO;
      pl = ctlen - pad - 1 - 32;
      seq_bytes (tls->rseq, seq);
      put_be16 (hdr + 3, (uint16_t) pl);
      {
        const uint8_t *p[] = { seq, hdr, body + 16 };
        const size_t l[] = { tls->mac_seq ? 8 : 0, 5, pl };
        if ((r = vmk_hmac (false, KB_SMAC (tls), tls->cs->mac_key_len, p, l, 3, mac)))
          return r;
      }
      tls->rseq++;
      if (!vmk_ct_equal (mac, body + 16 + pl, 32))
        return VMK_E_CRYPTO;
      *plain = body + 16;
      *plain_len = pl;
      return VMK_OK;
    }
}

/* ---- key schedule --------------------------------------------------------- */

static int
derive_keys (vmk_tls *tls, const uint8_t *premaster, size_t premaster_len)
{
  int r;

  /* FUN_1800716a0 */
  if ((r = vmk_prf (cs_sha384 (tls), premaster, premaster_len, "master secret",
                    tls->randoms, 64, tls->master, 48)))
    return r;
  /* FUN_180071a30: length = 2 * enc_key_len + 0x40, seed client||server */
  return vmk_prf (cs_sha384 (tls), tls->master, 48, "key expansion", tls->randoms, 64,
                  tls->key_block, 2 * tls->cs->enc_key_len + 0x40);
}

static int
finished_verify_data (vmk_tls *tls, bool client, uint8_t out[12])
{
  uint8_t hash[32];

  vmk_sha256 (tls->transcript.data, tls->transcript.len, hash);
  return vmk_prf (cs_sha384 (tls), tls->master, 48,
                  client ? "client finished" : "server finished", hash, 32, out, 12);
}

/* ---- handshake message builders ------------------------------------------ */

static int
hs_append (vmk_tls *tls, buf_t *msgs, uint8_t type, const uint8_t *body, size_t len, bool hash)
{
  uint8_t h[4] = { type };
  int r;

  put_be24 (h + 1, (uint32_t) len);
  if ((r = buf_append (msgs, h, 4)) || (r = buf_append (msgs, body, len)))
    return r;
  if (hash && ((r = buf_append (&tls->transcript, h, 4)) ||
               (r = buf_append (&tls->transcript, body, len))))
    return r;
  return VMK_OK;
}

static int
build_client_hello (vmk_tls *tls, buf_t *msgs)
{
  uint8_t b[0x3d - 4 + 14];
  size_t n = 0;
  int r;

  if ((r = vmk_random (tls->randoms, 32)))
    return r;
  b[n++] = 0x03;
  b[n++] = 0x03;
  memcpy (b + n, tls->randoms, 32);
  n += 32;
  b[n++] = 7;                     /* session id length, 7 zero bytes (no resumption) */
  memset (b + n, 0, 7);
  n += 7;
  put_be16 (b + n, 2 * N_SPECS);
  n += 2;
  for (size_t i = 0; i < N_SPECS; i++, n += 2)
    put_be16 (b + n, cipher_specs[i].id);
  b[n++] = 0;                     /* compression methods: none listed */
  if (tls->pair.type == VMK_PAIR_ECC)
    {
      /* supported_groups { secp256r1 }, ec_point_formats { uncompressed } */
      static const uint8_t ext[14] = { 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17,
                                       0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 };
      memcpy (b + n, ext, sizeof ext);
      n += sizeof ext;
    }
  return hs_append (tls, msgs, HS_CLIENT_HELLO, b, n, true);
}

static int
build_client_flight (vmk_tls *tls, buf_t *out)
{
  buf_t hs = { 0 }, rec = { 0 };
  uint8_t premaster[0x84];
  size_t premaster_len;
  int r;

  if (tls->pair.type == VMK_PAIR_PSK)
    {
      /* ClientKeyExchange = raw PSK identity */
      if ((r = hs_append (tls, &hs, HS_CLIENT_KEY_EXCHANGE, tls->pair.psk_id,
                          sizeof tls->pair.psk_id, true)))
        goto out;
      /* RFC 4279 premaster with fixed 0x40 lengths */
      put_be16 (premaster, 0x40);
      memset (premaster + 2, 0, 0x40);
      put_be16 (premaster + 0x42, 0x40);
      memcpy (premaster + 0x44, tls->pair.psk, 0x40);
      premaster_len = 0x84;
    }
  else
    {
      uint8_t cert[VMK_CERT_SIZE + 8], point[65], eph[32], sx[32], sy[32];
      uint8_t hash[32], sig[80];
      size_t sig_len = sizeof sig;

      /* Certificate */
      memset (cert, 0, sizeof cert);
      put_be24 (cert, VMK_CERT_SIZE);
      put_be24 (cert + 3, VMK_CERT_SIZE);
      memcpy (cert + 8, tls->pair.host_cert, VMK_CERT_SIZE);
      if ((r = hs_append (tls, &hs, HS_CERTIFICATE, cert, sizeof cert, true)))
        goto out;

      /* ClientKeyExchange = ephemeral point 04||X||Y, ECDH with sensor cert key */
      point[0] = 0x04;
      if ((r = vmk_ec_generate (eph, point + 1, point + 33)))
        goto out;
      vmk_cert_get_pub (tls->pair.sensor_cert, sx, sy);
      r = vmk_ecdh (eph, sx, sy, premaster);
      vmk_secure_zero (eph, sizeof eph);
      if (r)
        goto out;
      premaster_len = 32;
      if ((r = hs_append (tls, &hs, HS_CLIENT_KEY_EXCHANGE, point, sizeof point, true)))
        goto out;

      /* CertificateVerify */
      vmk_sha256 (tls->transcript.data, tls->transcript.len, hash);
      if ((r = vmk_ecdsa_sign (tls->pair.host_priv, hash, sig, &sig_len)))
        goto out;
      /* FUN_180072d40 @0x1800730bb loads the callback's updated length,
       * then adds the four-byte handshake header. 0x100 is its initial
       * output capacity, not the wire length (the decompiler loses this). */
      if ((r = hs_append (tls, &hs, HS_CERTIFICATE_VERIFY, sig, sig_len, true)))
        goto out;
    }

  if ((r = derive_keys (tls, premaster, premaster_len)))
    goto out;

  /* handshake record, ChangeCipherSpec, then encrypted Finished */
  {
    static const uint8_t ccs = 0x01;
    uint8_t fin[12];

    if ((r = record_encrypt (tls, REC_HANDSHAKE, hs.data, hs.len, &rec)) ||
        (r = record_encrypt (tls, REC_CCS, &ccs, 1, &rec)))
      goto out;
    tls->wenc = true;
    tls->wseq = 0;
    if ((r = finished_verify_data (tls, true, fin)))
      goto out;
    hs.len = 0;
    if ((r = hs_append (tls, &hs, HS_FINISHED, fin, 12, false)) ||
        (r = record_encrypt (tls, REC_HANDSHAKE, hs.data, hs.len, &rec)))
      goto out;
  }
  {
    static const uint8_t prefix[4] = { 0x44, 0, 0, 0 };
    if (!(r = buf_append (out, prefix, 4)))
      r = buf_append (out, rec.data, rec.len);
  }
out:
  vmk_secure_zero (premaster, sizeof premaster);
  buf_free (&hs);
  buf_free (&rec);
  return r;
}

/* ---- incoming handshake ---------------------------------------------------- */

static int
handle_server_hello (vmk_tls *tls, const uint8_t *p, size_t len)
{
  size_t off;
  uint16_t suite;

  if (len < 0x23)
    return VMK_E_PROTO;
  if (p[0] != 0x03 || (p[1] & 3) != 3)
    return VMK_E_PROTO;
  tls->mac_seq = (p[1] & 0x80) != 0;
  memcpy (tls->randoms + 32, p + 2, 32);
  off = 0x23;
  if (p[0x22])
    {
      if (p[0x22] > 0x20 || off + p[0x22] > len)
        return VMK_E_PROTO;
      /* we always offer a zero session id; a matching one means resumption */
      if (p[0x22] == 7)
        {
          static const uint8_t zero[7];
          if (memcmp (p + off, zero, 7) == 0)
            {
              VMK_WARN ("tls: sensor wants to resume a session we do not have");
              return VMK_E_PROTO;
            }
        }
      off += p[0x22];
    }
  if (off + 3 > len)
    return VMK_E_PROTO;
  suite = get_be16 (p + off);
  tls->cs = NULL;
  for (size_t i = 0; i < N_SPECS; i++)
    if (cipher_specs[i].id == suite)
      tls->cs = &cipher_specs[i];
  if (!tls->cs || p[off + 2] != 0)
    {
      VMK_ERR ("tls: unsupported cipher suite 0x%04x", suite);
      return VMK_E_PROTO;
    }
  /* niseTls leaves the sequence number out of the CBC MAC unless the
   * ServerHello minor version has bit 7 set; such records can be replayed
   * and reordered. GCM always authenticates it. */
  if (!(tls->cs->flags & VMK_CS_AEAD) && !tls->mac_seq)
    {
      VMK_ERR ("tls: refusing CBC suite 0x%04x without sequence numbers in the MAC", suite);
      return VMK_E_PROTO;
    }
  VMK_DBG ("tls: cipher suite 0x%04x, seq-in-mac %d", suite, tls->mac_seq);
  tls->state = tls->pair.type == VMK_PAIR_PSK ? HS_SERVER_HELLO_DONE : HS_CERTIFICATE_REQUEST;
  return VMK_OK;
}

static int
process_handshake (vmk_tls *tls, const uint8_t *p, size_t len)
{
  while (len)
    {
      uint8_t type;
      size_t mlen;
      int r;

      if (len < 4)
        return VMK_E_PROTO;
      type = p[0];
      mlen = get_be24 (p + 1);
      if (mlen > len - 4)
        return VMK_E_PROTO;
      if (type != tls->state)
        {
          VMK_ERR ("tls: unexpected handshake message %u (expected %d)", type, tls->state);
          return VMK_E_PROTO;
        }
      if (type != HS_FINISHED &&
          (r = buf_append (&tls->transcript, p, 4 + mlen)))
        return r;

      switch (type)
        {
        case HS_SERVER_HELLO:
          if ((r = handle_server_hello (tls, p + 4, mlen)))
            return r;
          break;

        case HS_CERTIFICATE_REQUEST:
          /* FUN_180074cb0: [n_types=1][0x40 ecdsa_sign][...] */
          if (mlen < 2 || p[4 + 1] != 0x40)
            return VMK_E_PROTO;
          tls->state = HS_SERVER_HELLO_DONE;
          break;

        case HS_SERVER_HELLO_DONE:
          tls->state = HS_FINISHED;
          break;

        case HS_FINISHED:
          {
            uint8_t expect[12];
            if (mlen != 12)
              return VMK_E_PROTO;
            if ((r = finished_verify_data (tls, false, expect)))
              return r;
            if (!vmk_ct_equal (expect, p + 4, 12))
              {
                VMK_ERR ("tls: server Finished mismatch");
                return VMK_E_CRYPTO;
              }
            tls->state = STATE_ESTABLISHED;
          }
          break;

        default:
          return VMK_E_PROTO;
        }
      p += 4 + mlen;
      len -= 4 + mlen;
    }
  return VMK_OK;
}

/* Parses a buffer of records received from the sensor.  Application data
 * (when established) is appended to @app. */
static int
process_records (vmk_tls *tls, uint8_t *data, size_t len, buf_t *app)
{
  while (len)
    {
      uint8_t *hdr = data, *body, *plain;
      size_t blen, plen;
      bool authenticated = false;
      int r;

      if (len < 5)
        return VMK_E_PROTO;
      if (hdr[1] != 0x03 || hdr[2] != 0x03)
        {
          VMK_ERR ("tls: bad record version %02x %02x", hdr[1], hdr[2]);
          return VMK_E_PROTO;
        }
      blen = get_be16 (hdr + 3);
      if (blen == 0 || blen > len - 5)
        return VMK_E_PROTO;
      body = data + 5;
      plain = body;
      plen = blen;

      /* the sensor sends alerts in the clear when it has lost the session */
      if (tls->renc && (hdr[0] != REC_ALERT || blen > 15))
        {
          if ((r = record_decrypt (tls, hdr, body, blen, &plain, &plen)))
            {
              /* fatal, as in TLS: no second guess against the same keys */
              VMK_ERR ("tls: record decryption failed, session ended");
              tls->state = 0;
              return r;
            }
          authenticated = true;
        }

      switch (hdr[0])
        {
        case REC_CCS:
          if (tls->state != HS_FINISHED || plen < 1 || plain[0] != 1)
            return VMK_E_PROTO;
          tls->renc = true;
          tls->rseq = 0;
          break;

        case REC_ALERT:
          if (plen < 2)
            return VMK_E_PROTO;
          VMK_DBG ("tls: alert level %u description %u%s", plain[0], plain[1],
                   authenticated ? "" : " (not authenticated)");
          if (tls->renc && !authenticated)
            {
              /* The sensor dropped the session, or the alert was injected
               * on the bus. Either way the session is over; it must not be
               * taken as a verdict on the pairing. */
              VMK_ERR ("tls: clear alert %u/%u in an encrypted session, session ended",
                       plain[0], plain[1]);
              tls->state = 0;
              return VMK_E_PROTO;
            }
          if (plain[1] == 0)
            {
              VMK_DBG ("tls: close_notify from sensor");
              tls->state = 0;
              break;
            }
          /* niseTls takes warning 50 as "session resumed". We never offer
           * resumption, and accepting it would skip the server Finished. */
          if (plain[1] == 42 && tls->state != STATE_ESTABLISHED)
            {
              VMK_ERR ("tls: sensor reports bad certificate - pairing data rejected");
              return VMK_E_BAD_PAIRING;
            }
          VMK_ERR ("tls: fatal alert %u/%u", plain[0], plain[1]);
          tls->state = 0;
          return VMK_E_PROTO;

        case REC_HANDSHAKE:
          if ((r = process_handshake (tls, plain, plen)))
            return r;
          break;

        case REC_APPDATA:
          if (tls->state != STATE_ESTABLISHED || !tls->renc)
            return VMK_E_PROTO;
          if (app && (r = buf_append (app, plain, plen)))
            return r;
          break;

        default:
          VMK_ERR ("tls: unknown record type 0x%02x", hdr[0]);
          return VMK_E_PROTO;
        }
      data += 5 + blen;
      len -= 5 + blen;
    }
  return VMK_OK;
}

/* ---- public API ------------------------------------------------------------ */

int
vmk_tls_handshake (vmk_dev *dev, vmk_tls *tls)
{
  static const uint8_t prefix[4] = { 0x44, 0, 0, 0 };
  buf_t out = { 0 }, msgs = { 0 }, rec = { 0 };
  uint8_t reply[HANDSHAKE_REPLY_SIZE];
  size_t rlen;
  int r;

  tls->state = HS_SERVER_HELLO;
  tls->transcript.len = 0;
  tls->wenc = tls->renc = false;
  tls->wseq = tls->rseq = 0;
  tls->cs = NULL;

  /* flight 1: ClientHello */
  if ((r = build_client_hello (tls, &msgs)) ||
      (r = record_encrypt (tls, REC_HANDSHAKE, msgs.data, msgs.len, &rec)) ||
      (r = buf_append (&out, prefix, 4)) ||
      (r = buf_append (&out, rec.data, rec.len)))
    goto out;
  VMK_DBG ("tls: sending ClientHello (%s)", tls->pair.type == VMK_PAIR_PSK ? "PSK" : "ECC");
  if ((r = vmk_raw_exchange (dev, out.data, out.len, reply, sizeof reply, &rlen,
                             VMK_DEFAULT_TIMEOUT)))
    goto out;
  if ((r = process_records (tls, reply, rlen, NULL)))
    goto out;
  if (tls->state != HS_FINISHED)
    {
      VMK_ERR ("tls: server flight incomplete (state %d)", tls->state);
      r = VMK_E_PROTO;
      goto out;
    }

  /* flight 2: [Certificate] ClientKeyExchange [CertificateVerify] CCS Finished */
  out.len = 0;
  if ((r = build_client_flight (tls, &out)))
    goto out;
  VMK_DBG ("tls: sending client key exchange + Finished");
  if ((r = vmk_raw_exchange (dev, out.data, out.len, reply, sizeof reply, &rlen,
                             VMK_DEFAULT_TIMEOUT)))
    goto out;
  if ((r = process_records (tls, reply, rlen, NULL)))
    goto out;
  if (tls->state != STATE_ESTABLISHED)
    {
      VMK_ERR ("tls: no server Finished received");
      r = VMK_E_PROTO;
      goto out;
    }
  VMK_INFO ("tls: session established (suite 0x%04x)", tls->cs->id);
out:
  buf_free (&out);
  buf_free (&msgs);
  buf_free (&rec);
  return r;
}

int
vmk_tls_wrap (vmk_tls *tls, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
  buf_t b = { 0 };
  int r;

  if (!vmk_tls_established (tls))
    return VMK_E_PROTO;
  if ((r = record_encrypt (tls, REC_APPDATA, in, in_len, &b)))
    {
      buf_free (&b);
      return r;
    }
  *out = b.data;
  *out_len = b.len;
  return VMK_OK;
}

int
vmk_tls_unwrap (vmk_tls *tls, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
  buf_t app = { 0 };
  uint8_t *copy;
  int r;

  if (!vmk_tls_established (tls))
    return VMK_E_PROTO;
  if (!(copy = malloc (in_len ? in_len : 1)))
    return VMK_E_NOMEM;
  memcpy (copy, in, in_len);
  r = process_records (tls, copy, in_len, &app);
  free (copy);
  if (r)
    {
      buf_free (&app);
      return r;
    }
  *out = app.data;
  *out_len = app.len;
  return VMK_OK;
}

int
vmk_tls_close_notify (vmk_tls *tls, uint8_t **out, size_t *out_len)
{
  static const uint8_t alert[2] = { 1, 0 }; /* warning, close_notify */
  buf_t b = { 0 };
  int r;

  if ((r = record_encrypt (tls, REC_ALERT, alert, 2, &b)))
    {
      buf_free (&b);
      return r;
    }
  tls->state = 0;
  *out = b.data;
  *out_len = b.len;
  return VMK_OK;
}

size_t vmk_tls_close_reply_size (void);
size_t
vmk_tls_close_reply_size (void)
{
  return CLOSE_REPLY_SIZE;
}
