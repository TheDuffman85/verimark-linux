/* Offline ECC handshake against a small simulated sensor. No USB or pairing
 * files are used. SPDX-License-Identifier: LGPL-2.1-or-later */
#include "vmk-private.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>

typedef struct
{
  vmk_pairing pair;
  uint8_t sensor_priv[32], host_x[32], host_y[32];
  uint8_t randoms[64], transcript[1024], server_flight[66];
  size_t transcript_len;
  unsigned exchanges;
  const uint8_t *reply2;  /* canned answer to flight 2 instead of CCS + Finished */
  size_t reply2_len;
} peer_t;

/* Link only the TLS and crypto modules; replace transport and logging. */
void vmk_log (int level, const char *fmt, ...) { (void) level; (void) fmt; }

static void
append_transcript (peer_t *p, const uint8_t *data, size_t len)
{
  assert (len <= sizeof p->transcript - p->transcript_len);
  memcpy (p->transcript + p->transcript_len, data, len);
  p->transcript_len += len;
}

int
vmk_raw_exchange (vmk_dev *dev, const uint8_t *out, size_t out_len,
                  uint8_t *in, size_t in_size, size_t *in_len, unsigned timeout_ms)
{
  peer_t *p = dev->t.user;
  (void) timeout_ms;
  assert (out_len >= 9 && memcmp (out, "\x44\0\0\0\x16\x03\x03", 7) == 0);
  size_t record_len = get_be16 (out + 7);
  assert (record_len <= out_len - 9);
  if (p->exchanges++ == 0)
    {
      assert (out_len == 84 && record_len == 75 && out[9] == 1);
      memcpy (p->randoms, out + 15, 32);
      append_transcript (p, out + 9, record_len);
      append_transcript (p, p->server_flight + 5, 61);
      assert (in_size >= sizeof p->server_flight);
      memcpy (in, p->server_flight, sizeof p->server_flight);
      *in_len = sizeof p->server_flight;
      return VMK_OK;
    }

  assert (p->exchanges == 2);
  if (p->reply2)
    {
      memcpy (in, p->reply2, p->reply2_len);
      *in_len = p->reply2_len;
      return VMK_OK;
    }
  const uint8_t *hs = out + 9;
  assert (record_len >= 412 + 69 + 4);
  assert (hs[0] == 11 && get_be24 (hs + 1) == 408);
  assert (get_be24 (hs + 4) == 400 && get_be24 (hs + 7) == 400);
  assert (hs[10] == 0 && hs[11] == 0);
  assert (memcmp (hs + 12, p->pair.host_cert, 400) == 0);
  const uint8_t *cke = hs + 412;
  assert (cke[0] == 16 && get_be24 (cke + 1) == 65 && cke[4] == 4);
  append_transcript (p, hs, 481);

  const uint8_t *cv = hs + 481;
  size_t sig_len = get_be24 (cv + 1);
  assert (cv[0] == 15 && sig_len <= record_len - 485);
  /* The DER decoder independently determines the signature's size. This
   * fails with the old 256-byte padded CertificateVerify, even if its
   * prefix is a valid signature. */
  const unsigned char *der_end = cv + 4;
  ECDSA_SIG *sig = d2i_ECDSA_SIG (NULL, &der_end, (long) sig_len);
  assert (sig != NULL && der_end == cv + 4 + sig_len);
  ECDSA_SIG_free (sig);
  assert (record_len == 485 + sig_len);
  uint8_t hash[32];
  vmk_sha256 (p->transcript, p->transcript_len, hash);
  assert (vmk_ecdsa_verify (p->host_x, p->host_y, hash, cv + 4, sig_len) == VMK_OK);
  append_transcript (p, cv, 4 + sig_len);

  uint8_t z[32], master[48], keys[128], nonce[12], aad[13] = { 0 };
  uint8_t finished[16], expected[12];
  assert (vmk_ecdh (p->sensor_priv, cke + 5, cke + 37, z) == VMK_OK);
  assert (vmk_prf (true, z, sizeof z, "master secret", p->randoms, 64,
                   master, sizeof master) == VMK_OK);
  assert (vmk_prf (true, master, 48, "key expansion", p->randoms, 64,
                   keys, sizeof keys) == VMK_OK);
  const uint8_t *ccs = out + 9 + record_len;
  assert (out_len == 9 + record_len + 6 + 45);
  assert (memcmp (ccs, "\x14\x03\x03\0\x01\x01\x16\x03\x03\0\x28", 11) == 0);
  memcpy (nonce, keys + 64, 4);
  memcpy (nonce + 4, ccs + 11, 8);
  memcpy (aad + 8, "\x16\x03\x03\0\x10", 5);
  assert (vmk_aes_gcm_decrypt (keys, 32, nonce, aad, sizeof aad,
                              ccs + 19, 16, finished, ccs + 35) == VMK_OK);
  assert (memcmp (finished, "\x14\0\0\x0c", 4) == 0);
  vmk_sha256 (p->transcript, p->transcript_len, hash);
  assert (vmk_prf (true, master, 48, "client finished", hash, 32, expected, 12) == VMK_OK);
  assert (memcmp (finished + 4, expected, 12) == 0);

  /* Return the peer's CCS and authenticated Finished, including its own
   * write key and fixed IV, so the client's verification must succeed. */
  assert (in_size >= 51);
  memcpy (in, ccs, 11);
  memset (in + 11, 0xa5, 8);
  memcpy (nonce, keys + 68, 4);
  memcpy (nonce + 4, in + 11, 8);
  assert (vmk_prf (true, master, 48, "server finished", hash, 32, finished + 4, 12) == VMK_OK);
  assert (vmk_aes_gcm_encrypt (keys + 32, 32, nonce, aad, sizeof aad,
                              finished, 16, in + 19, in + 35) == VMK_OK);
  *in_len = 51;
  vmk_secure_zero (z, sizeof z);
  vmk_secure_zero (master, sizeof master);
  vmk_secure_zero (keys, sizeof keys);
  return VMK_OK;
}

/* ServerHello flight with the given minor version and suite */
static vmk_tls *
peer_setup (peer_t *p, uint8_t minor, uint16_t suite)
{
  uint8_t sx[32], sy[32], *s = p->server_flight;

  memset (p, 0, sizeof *p);
  p->pair.type = VMK_PAIR_ECC;
  assert (vmk_ec_generate (p->pair.host_priv, p->host_x, p->host_y) == VMK_OK);
  assert (vmk_cert_build_host (p->host_x, p->host_y, p->pair.host_cert) == VMK_OK);
  assert (vmk_ec_generate (p->sensor_priv, sx, sy) == VMK_OK);
  put_le16 (p->pair.sensor_cert, VMK_CERT_MAGIC);
  vmk_reverse (p->pair.sensor_cert + 4, sx, 32);
  vmk_reverse (p->pair.sensor_cert + 0x48, sy, 32);

  memcpy (s, "\x16\x03\x03\0\x3d\x02\0\0\x2d\x03\x83", 11);
  s[10] = minor;
  assert (vmk_random (p->randoms + 32, 32) == VMK_OK);
  memcpy (s + 11, p->randoms + 32, 32);
  memcpy (s + 43, "\x07TLSpeer\xc0\x2e\0\x0d\0\0\x04\x01\x40\0\0\x0e\0\0\0", 23);
  put_be16 (s + 51, suite);
  return vmk_tls_new (&p->pair);
}

int
main (void)
{
  static const uint8_t clear_close[] = { 0x15, 0x03, 0x03, 0, 2, 1, 0 };
  static const uint8_t resumed[] = { 0x15, 0x03, 0x03, 0, 2, 1, 50 };
  static const uint8_t ccs_alert_42[] = { 0x14, 0x03, 0x03, 0, 1, 1,
                                          0x15, 0x03, 0x03, 0, 2, 2, 42 };
  uint8_t forged[5 + 40] = { 0x17, 0x03, 0x03, 0, 40 }, *out;
  size_t out_len;
  peer_t p;
  vmk_dev dev = { .t = { .user = &p } };
  vmk_tls *tls;

  /* Multiple random signatures exercise the variable DER integer sizes. */
  for (unsigned trial = 0; trial < 64; trial++)
    {
      assert ((tls = peer_setup (&p, 0x83, 0xc02e)) != NULL);
      assert (vmk_tls_handshake (&dev, tls) == VMK_OK);
      assert (p.exchanges == 2 && vmk_tls_established (tls));

      /* a clear alert inside the session is an error and ends it */
      if (trial == 0)
        {
          assert (vmk_tls_unwrap (tls, clear_close, sizeof clear_close,
                                  &out, &out_len) == VMK_E_PROTO);
          assert (!vmk_tls_established (tls));
        }
      /* a record that does not authenticate ends the session */
      if (trial == 1)
        {
          assert (vmk_tls_unwrap (tls, forged, sizeof forged, &out, &out_len) == VMK_E_CRYPTO);
          assert (!vmk_tls_established (tls));
        }
      vmk_tls_free (tls);
      vmk_secure_zero (&p, sizeof p);
    }
  puts ("64 ECC/GCM handshakes passed (DER signature length, transcript, Finished)");

  /* "session resumed" alert must not replace the server Finished */
  assert ((tls = peer_setup (&p, 0x83, 0xc02e)) != NULL);
  p.reply2 = resumed;
  p.reply2_len = sizeof resumed;
  assert (vmk_tls_handshake (&dev, tls) != VMK_OK && !vmk_tls_established (tls));
  vmk_tls_free (tls);

  /* after the sensor's CCS, a clear alert 42 is unauthenticated: an error,
   * not "pairing rejected" (which makes the driver pair again) */
  assert ((tls = peer_setup (&p, 0x83, 0xc02e)) != NULL);
  p.reply2 = ccs_alert_42;
  p.reply2_len = sizeof ccs_alert_42;
  assert (vmk_tls_handshake (&dev, tls) == VMK_E_PROTO);
  vmk_tls_free (tls);

  /* CBC without the sequence number in the MAC is refused after ServerHello */
  assert ((tls = peer_setup (&p, 0x03, 0xc005)) != NULL);
  assert (vmk_tls_handshake (&dev, tls) == VMK_E_PROTO && p.exchanges == 1);
  vmk_tls_free (tls);
  vmk_secure_zero (&p, sizeof p);
  puts ("resume alert, clear alerts, forged record and replayable CBC refused");
  return 0;
}
