/*
 * libvmk crypto primitives on top of OpenSSL.
 *
 * The Windows driver uses BCrypt/CNG. Equivalences established while
 * reverse engineering (addresses in synaWudfBioUsb132.dll):
 *  - prfTLS12 @0x180053e60       : TLS 1.2 P_hash (SHA-256 or SHA-384)
 *  - palPRF mode 2 @0x18004e780  : BCryptDeriveKey(KDF_HASH, SHA256) = SHA256(Z)
 *  - palCryptoEcdh @0x1800a76b0  : ECDH P-256, coordinates passed little endian
 *  - FUN_1800a7f80               : ECDSA sign, r/s re-encoded with
 *                                  CryptEncodeObject(X509_ECC_SIGNATURE) = DER
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "vmk-private.h"
#include "vmk-tables.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

void
vmk_reverse (uint8_t *dst, const uint8_t *src, size_t len)
{
  for (size_t i = 0; i < len / 2; i++)
    {
      uint8_t a = src[i], b = src[len - 1 - i];
      dst[i] = b;
      dst[len - 1 - i] = a;
    }
  if (len & 1)
    dst[len / 2] = src[len / 2];
}

void
vmk_secure_zero (void *p, size_t len)
{
  OPENSSL_cleanse (p, len);
}

bool
vmk_ct_equal (const void *a, const void *b, size_t len)
{
  return CRYPTO_memcmp (a, b, len) == 0;
}

int
vmk_random (uint8_t *buf, size_t len)
{
  return RAND_bytes (buf, (int) len) == 1 ? VMK_OK : VMK_E_CRYPTO;
}

void
vmk_sha256 (const uint8_t *data, size_t len, uint8_t out[32])
{
  unsigned int olen = 32;
  EVP_Digest (data, len, out, &olen, EVP_sha256 (), NULL);
}

int
vmk_hmac (bool sha384, const uint8_t *key, size_t key_len,
          const uint8_t *const *parts, const size_t *part_lens, size_t n_parts,
          uint8_t *out)
{
  int ret = VMK_E_CRYPTO;
  unsigned int olen = 0;
  HMAC_CTX *ctx = HMAC_CTX_new ();

  if (!ctx)
    return VMK_E_NOMEM;
  if (!HMAC_Init_ex (ctx, key, (int) key_len, sha384 ? EVP_sha384 () : EVP_sha256 (), NULL))
    goto out;
  for (size_t i = 0; i < n_parts; i++)
    if (part_lens[i] && !HMAC_Update (ctx, parts[i], part_lens[i]))
      goto out;
  if (!HMAC_Final (ctx, out, &olen))
    goto out;
  ret = VMK_OK;
out:
  HMAC_CTX_free (ctx);
  return ret;
}

int
vmk_prf (bool sha384, const uint8_t *secret, size_t secret_len, const char *label,
         const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len)
{
  const size_t hlen = sha384 ? 48 : 32;
  const size_t label_len = strlen (label);
  uint8_t a[48], block[48];
  int r;

  /* A(1) = HMAC(secret, label || seed) */
  {
    const uint8_t *p[] = { (const uint8_t *) label, seed };
    const size_t l[] = { label_len, seed_len };
    if ((r = vmk_hmac (sha384, secret, secret_len, p, l, 2, a)))
      return r;
  }
  while (out_len)
    {
      const uint8_t *p[] = { a, (const uint8_t *) label, seed };
      const size_t l[] = { hlen, label_len, seed_len };
      size_t n;

      if ((r = vmk_hmac (sha384, secret, secret_len, p, l, 3, block)))
        return r;
      n = out_len < hlen ? out_len : hlen;
      memcpy (out, block, n);
      out += n;
      out_len -= n;
      if (out_len)
        {
          const uint8_t *pa[] = { a };
          const size_t la[] = { hlen };
          if ((r = vmk_hmac (sha384, secret, secret_len, pa, la, 1, a)))
            return r;
        }
    }
  vmk_secure_zero (a, sizeof a);
  vmk_secure_zero (block, sizeof block);
  return VMK_OK;
}

static const EVP_CIPHER *
aes_cipher (bool gcm, size_t key_len)
{
  if (gcm)
    return key_len == 16 ? EVP_aes_128_gcm () : EVP_aes_256_gcm ();
  return key_len == 16 ? EVP_aes_128_cbc () : EVP_aes_256_cbc ();
}

int
vmk_aes_cbc (bool encrypt, const uint8_t *key, size_t key_len, const uint8_t iv[16],
             const uint8_t *in, size_t len, uint8_t *out)
{
  EVP_CIPHER_CTX *ctx;
  int outl = 0, ret = VMK_E_CRYPTO;

  if (len % 16)
    return VMK_E_INVAL;
  if (!(ctx = EVP_CIPHER_CTX_new ()))
    return VMK_E_NOMEM;
  if (!EVP_CipherInit_ex (ctx, aes_cipher (false, key_len), NULL, key, iv, encrypt ? 1 : 0))
    goto out;
  EVP_CIPHER_CTX_set_padding (ctx, 0);
  if (!EVP_CipherUpdate (ctx, out, &outl, in, (int) len) || (size_t) outl != len)
    goto out;
  ret = VMK_OK;
out:
  EVP_CIPHER_CTX_free (ctx);
  return ret;
}

int
vmk_aes_gcm_encrypt (const uint8_t *key, size_t key_len, const uint8_t iv[12],
                     const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                     uint8_t *out, uint8_t tag[16])
{
  EVP_CIPHER_CTX *ctx;
  int outl = 0, ret = VMK_E_CRYPTO;

  if (!(ctx = EVP_CIPHER_CTX_new ()))
    return VMK_E_NOMEM;
  if (!EVP_EncryptInit_ex (ctx, aes_cipher (true, key_len), NULL, NULL, NULL) ||
      !EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) ||
      !EVP_EncryptInit_ex (ctx, NULL, NULL, key, iv))
    goto out;
  if (aad_len && !EVP_EncryptUpdate (ctx, NULL, &outl, aad, (int) aad_len))
    goto out;
  if (len && !EVP_EncryptUpdate (ctx, out, &outl, in, (int) len))
    goto out;
  if (!EVP_EncryptFinal_ex (ctx, out + outl, &outl) ||
      !EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    goto out;
  ret = VMK_OK;
out:
  EVP_CIPHER_CTX_free (ctx);
  return ret;
}

int
vmk_aes_gcm_decrypt (const uint8_t *key, size_t key_len, const uint8_t iv[12],
                     const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                     uint8_t *out, const uint8_t tag[16])
{
  EVP_CIPHER_CTX *ctx;
  int outl = 0, ret = VMK_E_CRYPTO;

  if (!(ctx = EVP_CIPHER_CTX_new ()))
    return VMK_E_NOMEM;
  if (!EVP_DecryptInit_ex (ctx, aes_cipher (true, key_len), NULL, NULL, NULL) ||
      !EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) ||
      !EVP_DecryptInit_ex (ctx, NULL, NULL, key, iv))
    goto out;
  if (aad_len && !EVP_DecryptUpdate (ctx, NULL, &outl, aad, (int) aad_len))
    goto out;
  if (len && !EVP_DecryptUpdate (ctx, out, &outl, in, (int) len))
    goto out;
  if (!EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *) tag) ||
      EVP_DecryptFinal_ex (ctx, out + outl, &outl) <= 0)
    goto out;
  ret = VMK_OK;
out:
  EVP_CIPHER_CTX_free (ctx);
  return ret;
}

/* ---- P-256 --------------------------------------------------------------- */

static EC_KEY *
ec_key_from_priv (const uint8_t priv[32])
{
  EC_KEY *key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *d = BN_bin2bn (priv, 32, NULL);
  EC_POINT *pub = NULL;
  const EC_GROUP *grp;

  if (!key || !d)
    goto fail;
  grp = EC_KEY_get0_group (key);
  if (!(pub = EC_POINT_new (grp)) ||
      !EC_POINT_mul (grp, pub, d, NULL, NULL, NULL) ||
      !EC_KEY_set_private_key (key, d) ||
      !EC_KEY_set_public_key (key, pub))
    goto fail;
  EC_POINT_free (pub);
  BN_clear_free (d);
  return key;
fail:
  EC_POINT_free (pub);
  BN_clear_free (d);
  EC_KEY_free (key);
  return NULL;
}

static EC_KEY *
ec_key_from_pub (const uint8_t x[32], const uint8_t y[32])
{
  EC_KEY *key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *bx = BN_bin2bn (x, 32, NULL), *by = BN_bin2bn (y, 32, NULL);

  if (!key || !bx || !by || !EC_KEY_set_public_key_affine_coordinates (key, bx, by))
    {
      EC_KEY_free (key);
      key = NULL;
    }
  BN_free (bx);
  BN_free (by);
  return key;
}

static int
ec_key_get_pub (EC_KEY *key, uint8_t x[32], uint8_t y[32])
{
  BIGNUM *bx = BN_new (), *by = BN_new ();
  int ret = VMK_E_CRYPTO;

  if (bx && by &&
      EC_POINT_get_affine_coordinates (EC_KEY_get0_group (key), EC_KEY_get0_public_key (key),
                                       bx, by, NULL) &&
      BN_bn2binpad (bx, x, 32) == 32 && BN_bn2binpad (by, y, 32) == 32)
    ret = VMK_OK;
  BN_free (bx);
  BN_free (by);
  return ret;
}

int
vmk_ec_generate (uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32])
{
  EC_KEY *key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  int ret = VMK_E_CRYPTO;

  if (key && EC_KEY_generate_key (key) &&
      BN_bn2binpad (EC_KEY_get0_private_key (key), priv, 32) == 32)
    ret = ec_key_get_pub (key, pub_x, pub_y);
  EC_KEY_free (key);
  return ret;
}

int
vmk_ec_pub_from_priv (const uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32])
{
  EC_KEY *key = ec_key_from_priv (priv);
  int ret = key ? ec_key_get_pub (key, pub_x, pub_y) : VMK_E_CRYPTO;

  EC_KEY_free (key);
  return ret;
}

int
vmk_ecdh (const uint8_t priv[32], const uint8_t peer_x[32], const uint8_t peer_y[32],
          uint8_t z[32])
{
  EC_KEY *mine = ec_key_from_priv (priv);
  EC_KEY *peer = ec_key_from_pub (peer_x, peer_y);
  int ret = VMK_E_CRYPTO;

  if (mine && peer &&
      ECDH_compute_key (z, 32, EC_KEY_get0_public_key (peer), mine, NULL) == 32)
    ret = VMK_OK;
  EC_KEY_free (mine);
  EC_KEY_free (peer);
  return ret;
}

int
vmk_ecdsa_sign (const uint8_t priv[32], const uint8_t digest[32], uint8_t *der, size_t *der_len)
{
  EC_KEY *key = ec_key_from_priv (priv);
  unsigned int len = (unsigned int) *der_len;
  int ret = VMK_E_CRYPTO;

  if (key && (size_t) ECDSA_size (key) <= *der_len &&
      ECDSA_sign (0, digest, 32, der, &len, key) == 1)
    {
      *der_len = len;
      ret = VMK_OK;
    }
  EC_KEY_free (key);
  return ret;
}

int
vmk_ecdsa_verify (const uint8_t pub_x[32], const uint8_t pub_y[32], const uint8_t digest[32],
                  const uint8_t *der, size_t der_len)
{
  EC_KEY *key = ec_key_from_pub (pub_x, pub_y);
  int ret = VMK_E_CRYPTO;

  if (key && ECDSA_verify (0, digest, 32, der, (int) der_len, key) == 1)
    ret = VMK_OK;
  EC_KEY_free (key);
  return ret;
}

/* ---- vendor certificate format ------------------------------------------
 *  0x00 u16  magic 0x5f3f
 *  0x02 u16  curve id (0x17 = secp256r1)
 *  0x04 X    0x44 bytes, little endian, zero padded
 *  0x48 Y    0x44 bytes, little endian, zero padded
 *  0x8c      2 zero bytes
 *  0x8e u16  signature length
 *  0x90      DER ECDSA signature over SHA-256(cert[0..0x8e))
 */
void
vmk_cert_get_pub (const uint8_t *cert, uint8_t x[32], uint8_t y[32])
{
  vmk_reverse (x, cert + 0x04, 32);
  vmk_reverse (y, cert + 0x48, 32);
}

int
vmk_cert_verify (const uint8_t *cert, const uint8_t x[32], const uint8_t y[32])
{
  uint8_t digest[32];
  uint16_t sig_len = get_le16 (cert + 0x8e);

  if (get_le16 (cert) != VMK_CERT_MAGIC || sig_len == 0 || 0x90 + sig_len > VMK_CERT_SIZE)
    return VMK_E_PROTO;
  vmk_sha256 (cert, VMK_CERT_SIGNED_LEN, digest);
  return vmk_ecdsa_verify (x, y, digest, cert + 0x90, sig_len);
}

/* Host signing key, palGenHSPrivKey @0x1800a5a70:
 *   key  = SynaKm[0..16]
 *   seed = SynaKm[16..32] || aa aa                (FUN_1800a64e0)
 *   d    = PRF_SHA256(key, "HS_KEY_PAIR_GEN", seed, 32), little endian
 * SynaKm is assembled by palSynaKmGet @0x1800a5850 from four constants. */
void
vmk_hs_private_key (uint8_t priv[32])
{
  static const uint8_t synakm[32] = {
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
    0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38,
    0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
  };
  uint8_t seed[18], le[32];

  memcpy (seed, synakm + 16, 16);
  seed[16] = seed[17] = 0xaa;
  vmk_prf (false, synakm, 16, "HS_KEY_PAIR_GEN", seed, sizeof seed, le, 32);
  vmk_reverse (priv, le, 32);
  vmk_secure_zero (le, sizeof le);
}

/* _tudorSecurityPreparePairingParams @0x18006a4c0 + FUN_18006a090 */
int
vmk_cert_build_host (const uint8_t pub_x[32], const uint8_t pub_y[32], uint8_t cert[VMK_CERT_SIZE])
{
  uint8_t hs[32], digest[32], sig[80];
  size_t sig_len = sizeof sig;
  int r;

  memset (cert, 0, VMK_CERT_SIZE);
  put_le16 (cert, VMK_CERT_MAGIC);
  put_le16 (cert + 2, 0x17);
  vmk_reverse (cert + 0x04, pub_x, 32);
  vmk_reverse (cert + 0x48, pub_y, 32);
  vmk_sha256 (cert, VMK_CERT_SIGNED_LEN, digest);
  vmk_hs_private_key (hs);
  r = vmk_ecdsa_sign (hs, digest, sig, &sig_len);
  vmk_secure_zero (hs, sizeof hs);
  if (r)
    return r;
  put_le16 (cert + 0x8e, (uint16_t) sig_len);
  memcpy (cert + 0x90, sig, sig_len);
  return VMK_OK;
}

const struct vmk_ss_key *
vmk_find_ss_key (const vmk_version *v)
{
  for (size_t i = 0; i < sizeof vmk_ss_keys / sizeof vmk_ss_keys[0]; i++)
    if (vmk_ss_keys[i].major == v->fw_major && vmk_ss_keys[i].minor == v->fw_minor &&
        vmk_ss_keys[i].flag == (v->ss_key_flag ? 1 : 0))
      return &vmk_ss_keys[i];
  return NULL;
}
