/*
 * libvmk internals
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#pragma once

#include "vmk.h"
#include <stdarg.h>

/* ---- VCSFW command ids (name table at 0x1800640b0) ---------------------- */
#define VCSFW_CMD_GET_VERSION          0x01
#define VCSFW_CMD_RESET                0x05
#define VCSFW_CMD_PEEK                 0x07
#define VCSFW_CMD_POKE                 0x08
#define VCSFW_CMD_PROVISION            0x0e
#define VCSFW_CMD_RESET_OWNERSHIP      0x10
#define VCSFW_CMD_GET_STARTINFO        0x19
#define VCSFW_CMD_LED_EX2              0x39
#define VCSFW_CMD_STORAGE_INFO_GET     0x3e
#define VCSFW_CMD_STORAGE_PART_FORMAT  0x3f
#define VCSFW_CMD_STORAGE_PART_READ    0x40
#define VCSFW_CMD_STORAGE_PART_WRITE   0x41
#define VCSFW_CMD_DB_OBJECT_CREATE     0x47
#define VCSFW_CMD_TAKE_OWNERSHIP_EX2   0x4f
#define VCSFW_CMD_GET_CERTIFICATE_EX   0x50
#define VCSFW_CMD_TIDLE_SET            0x57
#define VCSFW_CMD_BOOTLDR_PATCH        0x7d
#define VCSFW_CMD_FRAME_READ           0x7f
#define VCSFW_CMD_FRAME_ACQ            0x80
#define VCSFW_CMD_FRAME_FINISH         0x81
#define VCSFW_CMD_FRAME_STATE_GET      0x82
#define VCSFW_CMD_EVENT_CONFIG         0x86
#define VCSFW_CMD_EVENT_READ           0x87
#define VCSFW_CMD_FRAME_STREAM         0x8b
#define VCSFW_CMD_IOTA_FIND            0x8e
#define VCSFW_CMD_PAIR                 0x93   /* _tudorCmdDoPair / _tudorCmdDoPairBasic */
#define VCSFW_CMD_ENROLL               0x96   /* MIS enroll, sub-commands below */
#define VCSFW_CMD_IDENTIFY_MATCH       0x99   /* MIS identify */
#define VCSFW_CMD_DB2_GET_DB_INFO      0x9e
#define VCSFW_CMD_DB2_GET_OBJECT_LIST  0x9f
#define VCSFW_CMD_DB2_GET_OBJECT_INFO  0xa0
#define VCSFW_CMD_DB2_GET_OBJECT_DATA  0xa1
#define VCSFW_CMD_DB2_WRITE_OBJECT     0xa2
#define VCSFW_CMD_DB2_DELETE_OBJECT    0xa3
#define VCSFW_CMD_DB2_CLEANUP          0xa4
#define VCSFW_CMD_DB2_FORMAT           0xa5
#define VCSFW_CMD_SSO                  0xac
#define VCSFW_CMD_OPINFO_GET           0xae

#define ENROLL_SUB_START   1
#define ENROLL_SUB_UPDATE  2
#define ENROLL_SUB_COMMIT  3
#define ENROLL_SUB_FINISH  4

#define DB2_TYPE_USER      1
#define DB2_TYPE_TEMPLATE  2
#define DB2_TYPE_PAYLOAD   3

/* event ids (FUN_18005aed0 / FUN_18005b0e0) */
#define VMK_EVENT_FINGER_PRESENT 1  /* finger state, used by CheckForFingerPresence */
#define VMK_EVENT_FINGER_REMOVED 2
#define VMK_EVENT_FINGER_DOWN  3
#define VMK_EVENT_FINGER_UP    4
#define VMK_EVENT_FRAME_READY  0x18

/* status words treated as success by FUN_180065270 */
#define VMK_STATUS_OK          0x0000
#define VMK_STATUS_OK_412      0x0412
#define VMK_STATUS_OK_5CC      0x05cc
/* others that matter */
#define VMK_STATUS_RETRY_401   0x0401   /* -> 0xd1, LED cmd retries once */
#define VMK_STATUS_NEED_FINISH 0x05cb   /* -> 0xdd, FRAME_ACQ: send FRAME_FINISH first */
#define VMK_STATUS_BUSY_6EA    0x06ea   /* -> 0xdf, FRAME_ACQ: retry after 100 ms */
#define VMK_STATUS_NO_MATCH    0x0509   /* -> 0x12e, IDENTIFY_MATCH: no template matched */

/* USB vendor requests (palUsbDriverIoControl / tudorUsbProtoIoControl) */
#define VMK_REQ_GET_TLS_STATE  0x14   /* IN, 2 bytes, byte0 != 0 -> sensor in TLS session */
#define VMK_REQ_SET_DATA       0x15   /* OUT */
#define VMK_REQ_19             0x19   /* OUT wValue = bool */
#define VMK_REQ_1A             0x1a   /* IN 1 byte */
#define VMK_REQ_1B             0x1b   /* OUT */

#define VMK_DEFAULT_TIMEOUT    2000
#define VMK_LONG_TIMEOUT       30000

/* ---- TLS ---------------------------------------------------------------- */
typedef struct
{
  uint16_t id;
  uint8_t  mac_key_len;   /* spec[4] */
  uint8_t  enc_key_len;   /* spec[5] */
  uint8_t  fixed_iv_len;  /* spec[6] */
  uint8_t  flags;         /* spec[7]: bit0 AEAD(GCM), bit5 SHA384 PRF */
} vmk_cipher_spec;

#define VMK_CS_AEAD   0x01
#define VMK_CS_SHA384 0x20

typedef struct vmk_tls vmk_tls;

vmk_tls *vmk_tls_new (const vmk_pairing *pairing);
void     vmk_tls_free (vmk_tls *tls);
/* runs the complete handshake over the device transport */
int      vmk_tls_handshake (vmk_dev *dev, vmk_tls *tls);
bool     vmk_tls_established (vmk_tls *tls);
/* encrypt one application data record */
int      vmk_tls_wrap (vmk_tls *tls, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
/* decrypt reply records; returns concatenated application data */
int      vmk_tls_unwrap (vmk_tls *tls, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
/* builds an encrypted close_notify alert */
int      vmk_tls_close_notify (vmk_tls *tls, uint8_t **out, size_t *out_len);
size_t   vmk_tls_overhead (vmk_tls *tls);

/* ---- device ------------------------------------------------------------- */
struct vmk_dev
{
  vmk_transport t;
  vmk_version   version;
  bool          have_version;
  vmk_tls      *tls;
  bool          allow_clear;    /* see vmk_allow_clear_session() */
  uint16_t      event_seq;      /* EVENT_CONFIG reply @0x40, used by EVENT_READ */
  bool          legacy_event_read;
  bool          capture_armed;
  uint8_t       last_intr[7];
  bool          enrolling;
};

/* raw exchange, no TLS: bulk out + bulk in */
int  vmk_raw_exchange (vmk_dev *dev, const uint8_t *out, size_t out_len,
                       uint8_t *in, size_t in_size, size_t *in_len, unsigned timeout_ms);
bool vmk_cancelled (vmk_dev *dev);

/* ---- logging ------------------------------------------------------------ */
void vmk_log (int level, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
bool vmk_log_enabled (int level);
#define VMK_ERR(...)   vmk_log (VMK_LOG_ERROR, __VA_ARGS__)
#define VMK_WARN(...)  vmk_log (VMK_LOG_WARN, __VA_ARGS__)
#define VMK_INFO(...)  vmk_log (VMK_LOG_INFO, __VA_ARGS__)
#define VMK_DBG(...)   vmk_log (VMK_LOG_DEBUG, __VA_ARGS__)
#define VMK_TRACE(...) vmk_log (VMK_LOG_TRACE, __VA_ARGS__)

/* ---- byte helpers --------------------------------------------------------- */
static inline void put_le16 (uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static inline void put_le32 (uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static inline void put_be16 (uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static inline void put_be24 (uint8_t *p, uint32_t v) { p[0] = v >> 16; p[1] = v >> 8; p[2] = v; }
static inline uint16_t get_le16 (const uint8_t *p) { return p[0] | (p[1] << 8); }
static inline uint32_t get_le32 (const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t) p[3] << 24); }
static inline uint16_t get_be16 (const uint8_t *p) { return (p[0] << 8) | p[1]; }
static inline uint32_t get_be24 (const uint8_t *p) { return (p[0] << 16) | (p[1] << 8) | p[2]; }

void vmk_reverse (uint8_t *dst, const uint8_t *src, size_t len);
void vmk_secure_zero (void *p, size_t len);
/* constant time comparison for MACs and Finished data */
bool vmk_ct_equal (const void *a, const void *b, size_t len);

/* ---- crypto (vmk-crypto.c, OpenSSL) -------------------------------------- */
int  vmk_random (uint8_t *buf, size_t len);
void vmk_sha256 (const uint8_t *data, size_t len, uint8_t out[32]);
int  vmk_hmac (bool sha384, const uint8_t *key, size_t key_len,
               const uint8_t *const *parts, const size_t *part_lens, size_t n_parts,
               uint8_t *out);
/* TLS 1.2 P_hash PRF (prfTLS12 @0x180053e60) */
int  vmk_prf (bool sha384, const uint8_t *secret, size_t secret_len, const char *label,
              const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len);
int  vmk_aes_cbc (bool encrypt, const uint8_t *key, size_t key_len, const uint8_t iv[16],
                  const uint8_t *in, size_t len, uint8_t *out);
int  vmk_aes_gcm_encrypt (const uint8_t *key, size_t key_len, const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                          uint8_t *out, uint8_t tag[16]);
int  vmk_aes_gcm_decrypt (const uint8_t *key, size_t key_len, const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                          uint8_t *out, const uint8_t tag[16]);

/* P-256 helpers. Scalars and coordinates are 32 byte big endian. */
int  vmk_ec_generate (uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32]);
int  vmk_ec_pub_from_priv (const uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32]);
int  vmk_ecdh (const uint8_t priv[32], const uint8_t peer_x[32], const uint8_t peer_y[32],
               uint8_t z[32]);
int  vmk_ecdsa_sign (const uint8_t priv[32], const uint8_t digest[32], uint8_t *der, size_t *der_len);
int  vmk_ecdsa_verify (const uint8_t pub_x[32], const uint8_t pub_y[32], const uint8_t digest[32],
                       const uint8_t *der, size_t der_len);

/* Sensor certificate (400 bytes, magic 0x5f3f) */
#define VMK_CERT_SIZE        400
#define VMK_CERT_MAGIC       0x5f3f
#define VMK_CERT_SIGNED_LEN  0x8e
void vmk_cert_get_pub (const uint8_t *cert, uint8_t x[32], uint8_t y[32]);
int  vmk_cert_verify (const uint8_t *cert, const uint8_t x[32], const uint8_t y[32]);
int  vmk_cert_build_host (const uint8_t pub_x[32], const uint8_t pub_y[32], uint8_t cert[VMK_CERT_SIZE]);
void vmk_hs_private_key (uint8_t priv[32]);
const struct vmk_ss_key *vmk_find_ss_key (const vmk_version *v);
