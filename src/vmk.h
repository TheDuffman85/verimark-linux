/*
 * libvmk - protocol core for the Kensington VeriMark Desktop (K62330WW)
 * fingerprint key (Synaptics FS7600 "Tudor" match-in-sensor, USB 047d:00f2 /
 * 06cb:00de, interface 1).
 *
 * Everything in here was reconstructed from the Windows driver
 * synaWudfBioUsb132.dll v6.0.9.1132; the comments name the function address
 * each structure was taken from.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- error codes ------------------------------------------------------- */
enum {
  VMK_OK = 0,
  VMK_E_IO = -1,            /* USB transfer failed */
  VMK_E_TIMEOUT = -2,       /* USB transfer timed out */
  VMK_E_PROTO = -3,         /* malformed / unexpected data from the sensor */
  VMK_E_STATUS = -4,        /* sensor returned a non-success status word */
  VMK_E_CRYPTO = -5,        /* crypto failure (bad MAC, bad signature...) */
  VMK_E_NOMEM = -6,
  VMK_E_CANCELLED = -7,
  VMK_E_NOT_PAIRED = -8,    /* TLS needed but no pairing data on the host */
  VMK_E_UNSUPPORTED = -9,   /* firmware / mode we do not handle */
  VMK_E_INVAL = -10,
  VMK_E_NOT_FOUND = -11,
  VMK_E_FULL = -12,
  VMK_E_BAD_PAIRING = -13,  /* sensor rejected our pairing data (alert 42) */
  VMK_E_INSECURE = -14,     /* would need a session without TLS (not allowed) */
};

const char *vmk_strerror (int err);

/* ---- logging ------------------------------------------------------------ */
enum { VMK_LOG_ERROR, VMK_LOG_WARN, VMK_LOG_INFO, VMK_LOG_DEBUG, VMK_LOG_TRACE };
typedef void (*vmk_log_func) (int level, const char *msg, void *user);
void vmk_set_log_handler (vmk_log_func func, void *user, int max_level);

/* ---- transport ---------------------------------------------------------- */
/* All callbacks are synchronous. Return 0 on success or a VMK_E_* code.
 * bulk_out/bulk_in are optional: the VeriMark Desktop has no bulk endpoints
 * and carries commands over EP0 vendor requests 0x16/0x17 instead
 * (palWinUsbBulkWriteEp0InEp0Out / palWinUsbBulkReadEP0). */
typedef struct
{
  void *user;
  int (*bulk_out) (void *user, const uint8_t *data, size_t len, unsigned timeout_ms);
  int (*bulk_in) (void *user, uint8_t *data, size_t len, size_t *actual, unsigned timeout_ms);
  int (*intr_in) (void *user, uint8_t *data, size_t len, size_t *actual, unsigned timeout_ms);
  int (*control) (void *user, uint8_t request_type, uint8_t request, uint16_t value,
                  uint16_t index, uint8_t *data, uint16_t len, size_t *actual,
                  unsigned timeout_ms);
  /* optional: USB port reset; device must be usable again afterwards */
  int (*reset) (void *user);
  /* optional: returns true when the running operation should abort */
  bool (*is_cancelled) (void *user);
} vmk_transport;

/* ---- sensor information ------------------------------------------------- */
typedef struct
{
  uint32_t build_time;
  uint32_t build_num;
  uint8_t  fw_major, fw_minor;
  uint8_t  target;
  char     product;          /* 'A' application, 'B'/'C' boot loader */
  uint8_t  silicon_rev, formal_release, platform, patch;
  uint8_t  serial[6];
  uint8_t  security[2];      /* reply[0x18], reply[0x19] */
  uint16_t iface;
  uint8_t  provision_raw;    /* reply[0x25] */

  /* decoded flags (_tudorInitDevice/@0x180055de0) */
  bool     ss_key_flag;      /* reply[0x19] & 0x20 */
  bool     advanced_security;/* reply[0x18] & 0x01 -> ECC pairing, else PSK */
  uint8_t  provision_state;  /* reply[0x25] & 0x0f; 0/1/4 = not provisioned (no TLS) */
} vmk_version;

/* ---- pairing data (host side secret, persisted by the caller) ------------ */
enum { VMK_PAIR_NONE = 0, VMK_PAIR_ECC = 1, VMK_PAIR_PSK = 2 };

typedef struct
{
  int     type;                 /* VMK_PAIR_ECC or VMK_PAIR_PSK */
  uint8_t serial[6];            /* sensor serial the data belongs to */
  /* ECC (advanced security) */
  uint8_t host_priv[32];        /* big endian scalar */
  uint8_t host_cert[400];       /* tag 1 */
  uint8_t sensor_cert[400];     /* tag 3 */
  /* PSK (basic security) */
  uint8_t psk[64];              /* tag 5 */
  uint8_t psk_id[32];           /* tag 6 */
} vmk_pairing;

int  vmk_pairing_save (const vmk_pairing *p, const char *path);
int  vmk_pairing_load (vmk_pairing *p, const char *path);

/* ---- device handle ------------------------------------------------------ */
typedef struct vmk_dev vmk_dev;

vmk_dev *vmk_dev_new (const vmk_transport *transport);
void     vmk_dev_free (vmk_dev *dev);

/* Sessions are TLS protected unless allowed otherwise. By default vmk_open()
 * refuses a sensor that reports itself as unprovisioned (VMK_E_INSECURE):
 * a device spoofing the sensor could otherwise answer every command in the
 * clear, including "match" for any template. Without TLS only GET_VERSION,
 * GET_STARTINFO and PAIR are sent (PAIR verifies the sensor certificate), and
 * once a session was set up nothing falls back to the clear. Diagnostic tools
 * may allow clear sessions; an authentication path must not. */
void     vmk_allow_clear_session (vmk_dev *dev, bool allow);

/* Low level: GET_VERSION. Works before any session. */
int vmk_get_version (vmk_dev *dev, vmk_version *out);

/* Full bring-up as the Windows driver does it (_tudorInitDevice):
 * GET_VERSION, GET_STARTINFO and, when the sensor is provisioned, a TLS
 * session using @pairing. If the sensor requires pairing and @pairing is
 * NULL, returns VMK_E_NOT_PAIRED (call vmk_pair first). */
int vmk_open (vmk_dev *dev, const vmk_pairing *pairing);
/* Sends a TLS close_notify (if needed). Safe to call multiple times. */
void vmk_close (vmk_dev *dev);

const vmk_version *vmk_dev_version (vmk_dev *dev);
bool vmk_needs_tls (const vmk_version *v);
bool vmk_tls_active (vmk_dev *dev);

/* Pair the host with the sensor (VCSFW_CMD 0x93). The device must have been
 * opened with vmk_open(dev, NULL) which will have returned VMK_E_NOT_PAIRED. */
int vmk_pair (vmk_dev *dev, vmk_pairing *out);

/* Generic command (TLS wrapped when a session is active). *reply receives a
 * malloc()ed buffer with the full plaintext reply (status word included). */
int vmk_cmd (vmk_dev *dev, const uint8_t *cmd, size_t cmd_len,
             uint8_t **reply, size_t *reply_len, size_t expected_len,
             uint16_t *status, unsigned timeout_ms);

/* ---- fingerprint operations --------------------------------------------- */
typedef uint8_t vmk_tuid[16];

typedef struct
{
  uint8_t  progress;       /* 0..100 */
  bool     rejected;
  bool     redundant;
  bool     fixed_pattern;
  bool     failed;         /* only meaningful when progress == 100 */
  uint16_t quality;
  uint32_t template_count;
  vmk_tuid tuid;           /* valid when progress == 100 */
} vmk_enroll_status;

typedef struct
{
  bool     matched;
  uint32_t score;
  vmk_tuid tuid;
  uint8_t *payload;        /* payload stored at enroll time (malloc()ed) */
  size_t   payload_len;
} vmk_match;

enum {
  VMK_LED_OFF = 0,
  VMK_LED_WAIT_FINGER = 1,
  VMK_LED_SCAN_OK = 2,
  VMK_LED_SCAN_BAD = 3,
  VMK_LED_MATCH = 4,
  VMK_LED_NO_MATCH = 5,
};
int vmk_led (vmk_dev *dev, int event);

/* Arms the sensor and blocks until a finger has been imaged (or cancelled /
 * @timeout_ms expired, 0 = forever). The image stays inside the sensor. */
int vmk_capture (vmk_dev *dev, unsigned timeout_ms);

/* Returns once no finger rests on the sensor (immediately when none does).
 * *was_present (optional) tells whether it had to wait. */
int vmk_wait_finger_removed (vmk_dev *dev, unsigned timeout_ms, bool *was_present);
/* Diagnostics: logs (VMK_LOG_INFO) every finger event for @duration_ms */
int vmk_watch_events (vmk_dev *dev, unsigned duration_ms);

int vmk_enroll_start (vmk_dev *dev);
/* Call after each successful vmk_capture */
int vmk_enroll_add_image (vmk_dev *dev, vmk_enroll_status *st);
/* Stores the template with @payload attached (opaque, <= ~200 bytes). */
int vmk_enroll_commit (vmk_dev *dev, const uint8_t *payload, size_t payload_len);
/* Ends the enroll session; discards it unless committed. */
int vmk_enroll_finish (vmk_dev *dev);

/* Match the last captured image against @n templates (n = 0: all) */
int  vmk_identify (vmk_dev *dev, const vmk_tuid *tuids, size_t n, vmk_match *out);
void vmk_match_clear (vmk_match *m);

/* On-chip database */
typedef struct
{
  vmk_tuid tuid;
  uint8_t *payload;
  size_t   payload_len;
} vmk_record;

int  vmk_db_list (vmk_dev *dev, vmk_record **records, size_t *n);
void vmk_db_records_free (vmk_record *records, size_t n);
/* Deletes the enrollment owning @tuid (its user object, template and payload) */
int  vmk_db_delete (vmk_dev *dev, const vmk_tuid tuid);
/* *exists = false when the sensor has no template @tuid */
int  vmk_db_template_exists (vmk_dev *dev, const vmk_tuid tuid, bool *exists);
int  vmk_db_erase (vmk_dev *dev);
/* Reclaims the slots of deleted objects (done by vmk_enroll_start when full) */
int  vmk_db_cleanup (vmk_dev *dev);

typedef struct
{
  uint16_t version_major, version_minor;
  uint32_t pversion;
  uint16_t template_slot_size, payload_slot_size;
  uint16_t users, deleted_users, free_user_slots;
  uint16_t templates, deleted_templates, free_template_slots;
  uint16_t payloads, deleted_payloads, free_payload_slots;
} vmk_db_info;
int vmk_db_get_info (vmk_dev *dev, vmk_db_info *info);

/* Payload helpers (tag/length/value container compatible with the Windows
 * driver's palTagVal format, so Windows can parse/skip it). */
int  vmk_payload_build (const char *user_id, uint8_t **out, size_t *out_len);
/* returns a newly allocated NUL terminated user id or NULL */
char *vmk_payload_get_user_id (const uint8_t *payload, size_t len);

void vmk_hexdump (int level, const char *prefix, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
