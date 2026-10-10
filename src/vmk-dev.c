/*
 * libvmk device layer: command transport, bring-up, TLS session, pairing.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "vmk-private.h"
#include "vmk-tables.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

size_t vmk_tls_close_reply_size (void);

/* ---- logging ---------------------------------------------------------------- */

static vmk_log_func log_func;
static void *log_user;
static int log_max = VMK_LOG_WARN;

void
vmk_set_log_handler (vmk_log_func func, void *user, int max_level)
{
  log_func = func;
  log_user = user;
  log_max = max_level;
}

bool
vmk_log_enabled (int level)
{
  return level <= log_max;
}

void
vmk_log (int level, const char *fmt, ...)
{
  char msg[1024];
  va_list ap;

  if (level > log_max)
    return;
  va_start (ap, fmt);
  vsnprintf (msg, sizeof msg, fmt, ap);
  va_end (ap);
  if (log_func)
    log_func (level, msg, log_user);
  else
    fprintf (stderr, "vmk: %s\n", msg);
}

void
vmk_hexdump (int level, const char *prefix, const uint8_t *data, size_t len)
{
  char line[16 * 3 + 1];

  if (!vmk_log_enabled (level))
    return;
  vmk_log (level, "%s (%zu bytes)", prefix, len);
  for (size_t off = 0; off < len; off += 16)
    {
      size_t n = len - off < 16 ? len - off : 16, p = 0;
      for (size_t i = 0; i < n; i++)
        p += snprintf (line + p, sizeof line - p, "%02x ", data[off + i]);
      vmk_log (level, "  %04zx: %s", off, line);
    }
}

const char *
vmk_strerror (int err)
{
  switch (err)
    {
    case VMK_OK: return "success";
    case VMK_E_IO: return "USB I/O error";
    case VMK_E_TIMEOUT: return "timeout";
    case VMK_E_PROTO: return "protocol error";
    case VMK_E_STATUS: return "sensor returned an error status";
    case VMK_E_CRYPTO: return "cryptographic failure";
    case VMK_E_NOMEM: return "out of memory";
    case VMK_E_CANCELLED: return "cancelled";
    case VMK_E_NOT_PAIRED: return "sensor is not paired with this host";
    case VMK_E_UNSUPPORTED: return "unsupported sensor firmware or mode";
    case VMK_E_INVAL: return "invalid argument";
    case VMK_E_NOT_FOUND: return "not found";
    case VMK_E_FULL: return "storage full";
    case VMK_E_BAD_PAIRING: return "sensor rejected the stored pairing data";
    case VMK_E_INSECURE: return "refusing a session without TLS";
    default: return "unknown error";
    }
}

/* ---- device ------------------------------------------------------------------ */

vmk_dev *
vmk_dev_new (const vmk_transport *transport)
{
  vmk_dev *dev = calloc (1, sizeof *dev);

  if (dev)
    dev->t = *transport;
  return dev;
}

void
vmk_dev_free (vmk_dev *dev)
{
  if (!dev)
    return;
  vmk_tls_free (dev->tls);
  free (dev);
}

void
vmk_allow_clear_session (vmk_dev *dev, bool allow)
{
  dev->allow_clear = allow;
}

const vmk_version *
vmk_dev_version (vmk_dev *dev)
{
  return dev->have_version ? &dev->version : NULL;
}

bool
vmk_cancelled (vmk_dev *dev)
{
  return dev->t.is_cancelled && dev->t.is_cancelled (dev->t.user);
}

bool
vmk_tls_active (vmk_dev *dev)
{
  return vmk_tls_established (dev->tls);
}

#define EP0_REQ_WRITE   0x16
#define EP0_REQ_READ    0x17
#define EP0_CHUNK       0x1000
#define EP0_FLAG_CONT   0x4000   /* not the first chunk */
#define EP0_FLAG_MORE   0x8000   /* more chunks follow */

/* palWinUsbBulkWriteEp0InEp0Out @0x1800478e0: data zero padded to a multiple
 * of 8, last chunk carries (len & 7) in the low bits of wValue. */
static int
ep0_write (vmk_dev *dev, const uint8_t *data, size_t len, unsigned timeout_ms)
{
  size_t off = 0;
  bool first = true;

  if (!len)
    return VMK_E_INVAL;
  while (off < len)
    {
      size_t rest = len - off, n, wire;
      uint16_t value = first ? 0 : EP0_FLAG_CONT;
      uint8_t buf[EP0_CHUNK];
      size_t actual = 0;
      int r;

      if (rest > EP0_CHUNK)
        {
          n = wire = EP0_CHUNK;
          value |= EP0_FLAG_MORE;
        }
      else
        {
          n = rest;
          wire = (n + 7) & ~(size_t) 7;
          value |= len & 7;
        }
      memset (buf, 0, wire);
      memcpy (buf, data + off, n);
      r = dev->t.control (dev->t.user, 0x40, EP0_REQ_WRITE, value, 0, buf, (uint16_t) wire,
                          &actual, timeout_ms);
      if (r)
        return r;
      if (actual < wire)
        return VMK_E_IO;
      off += n;
      first = false;
    }
  return VMK_OK;
}

/* palWinUsbBulkReadEP0 @0x180047130 */
static int
ep0_read (vmk_dev *dev, uint8_t *data, size_t size, size_t *got, unsigned timeout_ms)
{
  bool first = true;
  int retries = 0;

  *got = 0;
  while (*got < size)
    {
      size_t rest = size - *got, n = rest > EP0_CHUNK ? EP0_CHUNK : rest, actual = 0;
      uint16_t value = (first ? 0 : EP0_FLAG_CONT) | (rest > EP0_CHUNK ? EP0_FLAG_MORE : 0);
      int r;

      first = false;
      r = dev->t.control (dev->t.user, 0xc0, EP0_REQ_READ, value, 0, data + *got, (uint16_t) n,
                          &actual, timeout_ms);
      if (r == VMK_E_TIMEOUT && retries++ < 3 && !vmk_cancelled (dev))
        continue; /* Windows retries ERROR_SEM_TIMEOUT with the continuation flag */
      if (r)
        return r;
      *got += actual;
      if (actual < n)
        break;
    }
  return VMK_OK;
}

/* tudorUsbProtoIoControl 0x67 -> FUN_18005ef80: write request, then read reply */
int
vmk_raw_exchange (vmk_dev *dev, const uint8_t *out, size_t out_len,
                  uint8_t *in, size_t in_size, size_t *in_len, unsigned timeout_ms)
{
  bool ep0 = !dev->t.bulk_out || !dev->t.bulk_in;
  int r;

  vmk_hexdump (VMK_LOG_TRACE, "usb out", out, out_len);
  r = ep0 ? ep0_write (dev, out, out_len, timeout_ms)
          : dev->t.bulk_out (dev->t.user, out, out_len, timeout_ms);
  if (r)
    {
      VMK_ERR ("request write failed: %s", vmk_strerror (r));
      return r;
    }
  r = ep0 ? ep0_read (dev, in, in_size, in_len, timeout_ms)
          : dev->t.bulk_in (dev->t.user, in, in_size, in_len, timeout_ms);
  if (r)
    {
      VMK_ERR ("reply read failed: %s", vmk_strerror (r));
      return r;
    }
  vmk_hexdump (VMK_LOG_TRACE, "usb in", in, *in_len);
  return VMK_OK;
}

static bool
status_ok (uint16_t s)
{
  return s == VMK_STATUS_OK || s == VMK_STATUS_OK_412 || s == VMK_STATUS_OK_5CC;
}

/* Commands that may go out without TLS. A session that was set up and then
 * died (dev->tls kept, not established) never falls back to the clear. */
static bool
clear_cmd_allowed (vmk_dev *dev, uint8_t cmd)
{
  if (dev->tls)
    return false;
  return dev->allow_clear || cmd == VCSFW_CMD_GET_VERSION || cmd == VCSFW_CMD_GET_STARTINFO ||
         cmd == VCSFW_CMD_PAIR;
}

/* FUN_180063bb0 */
int
vmk_cmd (vmk_dev *dev, const uint8_t *cmd, size_t cmd_len,
         uint8_t **reply, size_t *reply_len, size_t expected_len,
         uint16_t *status, unsigned timeout_ms)
{
  uint8_t *wire = NULL, *in = NULL, *plain = NULL;
  size_t wire_len, in_size, in_len = 0, plain_len = 0;
  bool tls = vmk_tls_established (dev->tls);
  uint16_t st;
  int r;

  if (status)
    *status = 0xffff;
  if (reply)
    *reply = NULL;
  if (reply_len)
    *reply_len = 0;
  if (!timeout_ms)
    timeout_ms = VMK_DEFAULT_TIMEOUT;
  if (expected_len < 2)
    expected_len = 2;
  if (!cmd_len)
    return VMK_E_INVAL;
  if (!tls && !clear_cmd_allowed (dev, cmd[0]))
    {
      VMK_ERR ("refusing to send command 0x%02x outside a TLS session", cmd[0]);
      return VMK_E_INSECURE;
    }

  vmk_hexdump (VMK_LOG_DEBUG, "cmd", cmd, cmd_len);
  if (tls)
    {
      if ((r = vmk_tls_wrap (dev->tls, cmd, cmd_len, &wire, &wire_len)))
        return r;
    }
  else
    {
      wire = (uint8_t *) cmd;
      wire_len = cmd_len;
    }

  in_size = expected_len + (tls ? vmk_tls_overhead (dev->tls) : 0);
  if (!(in = malloc (in_size)))
    {
      r = VMK_E_NOMEM;
      goto out;
    }
  if ((r = vmk_raw_exchange (dev, wire, wire_len, in, in_size, &in_len, timeout_ms)))
    goto out;

  if (tls)
    {
      if ((r = vmk_tls_unwrap (dev->tls, in, in_len, &plain, &plain_len)))
        goto out;
    }
  else
    {
      plain = in;
      plain_len = in_len;
      in = NULL;
    }
  vmk_hexdump (VMK_LOG_DEBUG, "reply", plain, plain_len);

  if (plain_len < 2)
    {
      VMK_ERR ("reply to command 0x%02x too short (%zu)", cmd[0], plain_len);
      r = VMK_E_PROTO;
      goto out;
    }
  st = get_le16 (plain);
  if (status)
    *status = st;
  if (!status_ok (st))
    {
      VMK_DBG ("command 0x%02x returned status 0x%04x", cmd[0], st);
      r = VMK_E_STATUS;
    }
  if (reply)
    {
      *reply = plain;
      plain = NULL;
    }
  if (reply_len)
    *reply_len = plain_len;
out:
  if (tls)
    free (wire);
  free (in);
  free (plain);
  return r;
}

/* ---- GET_VERSION (FUN_18005f0e0, decoded in FUN_180055de0) ------------------ */

static int
sensor_tls_state (vmk_dev *dev, bool *in_session)
{
  uint8_t buf[2] = { 0 };
  size_t actual = 0;
  int r;

  r = dev->t.control (dev->t.user, 0xc0, VMK_REQ_GET_TLS_STATE, 0, 0, buf, 2, &actual,
                      VMK_DEFAULT_TIMEOUT);
  if (r)
    return r;
  *in_session = buf[0] != 0;
  return VMK_OK;
}

/* A host that went away without close_notify (crash, kill) leaves the sensor
 * in TLS mode. Windows ("Sensor is in secure session but host is not") has a
 * helper service reset the device. A USB port reset does not end the session,
 * but the sensor drops it when it answers a plaintext command with a fatal
 * alert, so one throwaway GET_VERSION is enough. */
static int
leave_stale_session (vmk_dev *dev)
{
  const uint8_t cmd = VCSFW_CMD_GET_VERSION;
  uint8_t rep[64];
  size_t len = 0;
  bool in_session = false;

  if (vmk_tls_established (dev->tls) || sensor_tls_state (dev, &in_session) != VMK_OK ||
      !in_session)
    return VMK_OK;
  VMK_WARN ("sensor still holds a TLS session from a previous host session, ending it");
  if (vmk_raw_exchange (dev, &cmd, 1, rep, sizeof rep, &len, VMK_DEFAULT_TIMEOUT) == VMK_OK &&
      len >= 2 && rep[0] == 0x15)
    VMK_DBG ("sensor answered with a TLS alert record");
  if (sensor_tls_state (dev, &in_session) == VMK_OK && !in_session)
    return VMK_OK;
  if (dev->t.reset && dev->t.reset (dev->t.user) == VMK_OK &&
      sensor_tls_state (dev, &in_session) == VMK_OK && !in_session)
    return VMK_OK;
  VMK_ERR ("cannot end the sensor's stale TLS session; unplug and replug the key");
  return VMK_E_IO;
}

int
vmk_get_version (vmk_dev *dev, vmk_version *v)
{
  const uint8_t cmd = VCSFW_CMD_GET_VERSION;
  uint8_t *rep;
  size_t len;
  int r;

  if ((r = leave_stale_session (dev)))
    return r;
  if ((r = vmk_cmd (dev, &cmd, 1, &rep, &len, 0x26, NULL, 0)))
    {
      free (rep);
      return r;
    }
  if (len < 0x26)
    {
      free (rep);
      return VMK_E_PROTO;
    }
  memset (v, 0, sizeof *v);
  v->build_time = get_le32 (rep + 2);
  v->build_num = get_le32 (rep + 6);
  v->fw_major = rep[10];
  v->fw_minor = rep[11];
  v->target = rep[12];
  v->product = (char) rep[13];
  v->silicon_rev = rep[14];
  v->formal_release = rep[15];
  v->platform = rep[16];
  v->patch = rep[17];
  memcpy (v->serial, rep + 0x12, 6);
  v->security[0] = rep[0x18];
  v->security[1] = rep[0x19];
  v->iface = get_le16 (rep + 0x22);
  v->provision_raw = rep[0x25];
  v->ss_key_flag = (rep[0x19] & 0x20) != 0;
  v->advanced_security = (rep[0x18] & 0x01) != 0;
  v->provision_state = rep[0x25] & 0x0f;
  free (rep);
  dev->version = *v;
  dev->have_version = true;
  VMK_INFO ("sensor fw %u.%u build %u, product '%c', provision state %u, %s security",
            v->fw_major, v->fw_minor, v->build_num, v->product ? v->product : '?',
            v->provision_state, v->advanced_security ? "advanced (ECC)" : "basic (PSK)");
  return VMK_OK;
}

bool
vmk_needs_tls (const vmk_version *v)
{
  /* tudorTlsEstablishSession: states 0, 1, 4 -> "Sensor is not provisioned" */
  return !(v->provision_state == 0 || v->provision_state == 1 || v->provision_state == 4);
}

static int
get_startinfo (vmk_dev *dev)
{
  const uint8_t cmd = VCSFW_CMD_GET_STARTINFO;
  uint8_t *rep = NULL;
  size_t len;
  int r = vmk_cmd (dev, &cmd, 1, &rep, &len, 0x44, NULL, 0);

  if (!r && len >= 4)
    VMK_DBG ("start info: start type %u, reset type %u", rep[2], rep[3]);
  free (rep);
  return r;
}

static int
tls_start (vmk_dev *dev, const vmk_pairing *pairing)
{
  bool sensor_in_session = false;
  int r;

  /* no session object until the handshake starts: GET_VERSION below must
   * still be allowed in the clear */
  vmk_tls_free (dev->tls);
  dev->tls = NULL;

  if (sensor_tls_state (dev, &sensor_in_session) == VMK_OK && sensor_in_session)
    {
      /* Windows reports this as "Sensor is in secure session but host is not"
       * and has the device reset. We do the same: a USB reset tears down the
       * sensor side session. */
      VMK_WARN ("sensor still holds a TLS session from a previous host session");
      if (dev->t.reset && dev->t.reset (dev->t.user) == VMK_OK)
        {
          vmk_version v;
          if ((r = vmk_get_version (dev, &v)))
            return r;
          if (sensor_tls_state (dev, &sensor_in_session) == VMK_OK && sensor_in_session)
            VMK_WARN ("sensor still reports a TLS session after reset, trying anyway");
        }
    }

  if (!(dev->tls = vmk_tls_new (pairing)))
    return VMK_E_NOMEM;
  r = vmk_tls_handshake (dev, dev->tls);
  if (r)
    {
      vmk_tls_free (dev->tls);
      dev->tls = NULL;
    }
  return r;
}

int
vmk_open (vmk_dev *dev, const vmk_pairing *pairing)
{
  vmk_version v;
  int r;

  vmk_close (dev);
  if ((r = vmk_get_version (dev, &v)))
    return r;
  if (v.product == 'B' || v.product == 'C')
    {
      VMK_ERR ("sensor is in boot loader mode; update its firmware under Windows first");
      return VMK_E_UNSUPPORTED;
    }
  if (v.product != 'A')
    {
      VMK_ERR ("unexpected product id 0x%02x", (uint8_t) v.product);
      return VMK_E_UNSUPPORTED;
    }
  if ((r = get_startinfo (dev)))
    VMK_WARN ("GET_STARTINFO failed: %s", vmk_strerror (r));

  if (!vmk_needs_tls (&v))
    {
      /* GET_VERSION is not authenticated: a spoofed device can claim this */
      if (!dev->allow_clear)
        {
          VMK_ERR ("sensor reports provision state %u (no TLS); refusing an "
                   "unauthenticated session", v.provision_state);
          return VMK_E_INSECURE;
        }
      VMK_INFO ("sensor is not provisioned, using a clear session");
      return VMK_OK;
    }
  if (!pairing || pairing->type == VMK_PAIR_NONE)
    return VMK_E_NOT_PAIRED;
  if (memcmp (pairing->serial, v.serial, 6) != 0)
    {
      VMK_WARN ("pairing data belongs to a different sensor");
      return VMK_E_NOT_PAIRED;
    }
  r = tls_start (dev, pairing);
  if (r == VMK_E_PROTO)
    {
      /* an interrupted handshake leaves the sensor expecting the rest of a
       * flight; it answers the next ClientHello with alert 47 and resets */
      VMK_WARN ("TLS handshake failed, retrying once");
      r = tls_start (dev, pairing);
    }
  return r;
}

void
vmk_close (vmk_dev *dev)
{
  uint8_t *rec = NULL, *in;
  size_t rec_len, in_len, in_size = vmk_tls_close_reply_size ();

  if (dev->enrolling)
    vmk_enroll_finish (dev);
  if (!vmk_tls_established (dev->tls))
    {
      /* a session that failed or was ended by the sensor */
      vmk_tls_free (dev->tls);
      dev->tls = NULL;
      return;
    }
  /* tudorTlsSuspendSession(.., 1) / ssiTlsAlertNotify */
  if (vmk_tls_close_notify (dev->tls, &rec, &rec_len) == VMK_OK && (in = malloc (in_size)))
    {
      if (vmk_raw_exchange (dev, rec, rec_len, in, in_size, &in_len, VMK_DEFAULT_TIMEOUT))
        VMK_DBG ("no reply to close_notify");
      free (in);
    }
  free (rec);
  vmk_tls_free (dev->tls);
  dev->tls = NULL;
}

/* ---- pairing ----------------------------------------------------------------- */

static int
check_ss_cert (const vmk_version *v, const uint8_t *cert)
{
  const struct vmk_ss_key *k = vmk_find_ss_key (v);
  uint8_t x[32], y[32];

  if (!k)
    {
      VMK_ERR ("no sensor root key for firmware %u.%u (flag %d)", v->fw_major, v->fw_minor,
               v->ss_key_flag);
      return VMK_E_UNSUPPORTED;
    }
  vmk_reverse (x, k->x, 32);
  vmk_reverse (y, k->y, 32);
  return vmk_cert_verify (cert, x, y);
}

/* _tudorUnwrapPsk @0x18006cb00 + _tudorDecVerifyWithAES_GCM @0x18006c790 */
static int
unwrap_psk (const uint8_t host_priv[32], const uint8_t *sensor_cert,
            const uint8_t *blob, size_t blob_len, uint8_t psk[64])
{
  uint8_t sx[32], sy[32], z[32], k1[32], k[64];
  size_t ct_len;
  int r;

  if (blob_len < 0x24 + 64)
    return VMK_E_PROTO;
  ct_len = blob_len - 0x24;
  if (get_le32 (blob + blob_len - 4) != ct_len || ct_len != 64)
    {
      VMK_ERR ("unexpected wrapped PSK layout (len %zu, inner %u)", blob_len,
               get_le32 (blob + blob_len - 4));
      return VMK_E_PROTO;
    }
  vmk_cert_get_pub (sensor_cert, sx, sy);
  if ((r = vmk_ecdh (host_priv, sx, sy, z)))
    return r;
  vmk_sha256 (z, 32, k1);                         /* BCrypt KDF_HASH(SHA256) */
  {
    static const uint8_t seed[4] = { 0 };
    r = vmk_prf (false, k1, 32, "WRKP", seed, 4, k, 64);  /* palSymKeyGen */
  }
  if (!r)
    r = vmk_aes_gcm_decrypt (k + 32, 32, blob + ct_len, NULL, 0, blob, ct_len, psk,
                             blob + ct_len + 12);
  vmk_secure_zero (z, sizeof z);
  vmk_secure_zero (k1, sizeof k1);
  vmk_secure_zero (k, sizeof k);
  if (r)
    VMK_ERR ("PSK unwrap failed");
  return r;
}

static int
pair_basic (vmk_dev *dev, const uint8_t host_priv[32], const uint8_t px[32],
            const uint8_t py[32], vmk_pairing *out)
{
  uint8_t cmd[1 + 0xb4], *rep = NULL, *R;
  size_t len;
  uint32_t wrapped_len;
  int r;

  /* _tudorSecurityBasicPairing @0x18006b8c0 */
  memset (cmd, 0, sizeof cmd);
  cmd[0] = VCSFW_CMD_PAIR;
  if ((r = vmk_random (cmd + 1, 32)))          /* Rh */
    return r;
  put_le32 (cmd + 1 + 0x20, 0x17);              /* curve id */
  put_le32 (cmd + 1 + 0x24, 32);                /* key size in bytes */
  cmd[1 + 0x28] = 0;
  vmk_reverse (cmd + 1 + 0x2c, px, 32);         /* X, 0x44 bytes LE */
  vmk_reverse (cmd + 1 + 0x70, py, 32);         /* Y, 0x44 bytes LE */

  if ((r = vmk_cmd (dev, cmd, sizeof cmd, &rep, &len, 0x100 + 0x346, NULL, VMK_LONG_TIMEOUT)))
    goto out;
  if (len < 2 + 0x344)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  R = rep + 2;
  wrapped_len = get_le32 (R + 0x340);
  if (2 + 0x344 + (size_t) wrapped_len > len)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  /* certificate chain: cert1 signed by the root key, cert2 signed by cert1 */
  if ((r = check_ss_cert (&dev->version, R)))
    {
      VMK_ERR ("sensor certificate 1 does not verify against the root key");
      goto out;
    }
  {
    uint8_t x[32], y[32];
    vmk_cert_get_pub (R, x, y);
    if ((r = vmk_cert_verify (R + VMK_CERT_SIZE, x, y)))
      {
        VMK_ERR ("sensor certificate 2 does not verify");
        goto out;
      }
  }
  if ((r = unwrap_psk (host_priv, R + VMK_CERT_SIZE, R + 0x344, wrapped_len, out->psk)))
    goto out;
  memcpy (out->psk_id, R + 0x320, 32);
  memcpy (out->sensor_cert, R + VMK_CERT_SIZE, VMK_CERT_SIZE);
  out->type = VMK_PAIR_PSK;
out:
  free (rep);
  return r;
}

static int
pair_advanced (vmk_dev *dev, const uint8_t *host_cert, vmk_pairing *out)
{
  uint8_t cmd[1 + VMK_CERT_SIZE], *rep = NULL;
  size_t len;
  int r;

  /* _tudorSecurityAdvancedPairing @0x18006b710 / _tudorCmdDoPair */
  cmd[0] = VCSFW_CMD_PAIR;
  memcpy (cmd + 1, host_cert, VMK_CERT_SIZE);
  if ((r = vmk_cmd (dev, cmd, sizeof cmd, &rep, &len, 0x322, NULL, VMK_LONG_TIMEOUT)))
    goto out;
  if (len < 2 + 2 * VMK_CERT_SIZE)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  if ((r = check_ss_cert (&dev->version, rep + 2 + VMK_CERT_SIZE)))
    {
      VMK_ERR ("sensor certificate does not verify against the root key");
      goto out;
    }
  memcpy (out->host_cert, rep + 2, VMK_CERT_SIZE);
  memcpy (out->sensor_cert, rep + 2 + VMK_CERT_SIZE, VMK_CERT_SIZE);
  out->type = VMK_PAIR_ECC;
out:
  free (rep);
  return r;
}

int
vmk_pair (vmk_dev *dev, vmk_pairing *out)
{
  uint8_t px[32], py[32], host_cert[VMK_CERT_SIZE];
  int r;

  vmk_close (dev);
  if (!dev->have_version)
    {
      vmk_version v;
      if ((r = vmk_get_version (dev, &v)))
        return r;
    }
  if (dev->version.provision_state != 3)
    {
      /* tudorSecurityDoPair: "Skipping pairing: sensors is not secure" */
      VMK_WARN ("sensor provision state %u does not allow pairing", dev->version.provision_state);
      return VMK_E_UNSUPPORTED;
    }

  memset (out, 0, sizeof *out);
  memcpy (out->serial, dev->version.serial, 6);
  if ((r = vmk_ec_generate (out->host_priv, px, py)) ||
      (r = vmk_cert_build_host (px, py, host_cert)))
    return r;

  if (dev->version.advanced_security)
    {
      VMK_INFO ("pairing in advanced security mode (ECC)");
      r = pair_advanced (dev, host_cert, out);
    }
  else
    {
      VMK_INFO ("pairing in basic security mode (PSK)");
      memcpy (out->host_cert, host_cert, VMK_CERT_SIZE);
      r = pair_basic (dev, out->host_priv, px, py, out);
    }
  if (r)
    vmk_secure_zero (out, sizeof *out);
  return r;
}

/* ---- pairing file -------------------------------------------------------------- */

#define PAIR_MAGIC "VMKPAIR1"

int
vmk_pairing_save (const vmk_pairing *p, const char *path)
{
  char tmp[4096];
  int fd;
  ssize_t w;

  if (snprintf (tmp, sizeof tmp, "%s.tmp", path) >= (int) sizeof tmp)
    return VMK_E_INVAL;
  fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0)
    {
      VMK_ERR ("cannot write %s: %s", tmp, strerror (errno));
      return VMK_E_IO;
    }
  w = write (fd, PAIR_MAGIC, 8);
  if (w == 8)
    w = write (fd, p, sizeof *p);
  if (w != (ssize_t) sizeof *p || fsync (fd) != 0)
    {
      close (fd);
      unlink (tmp);
      return VMK_E_IO;
    }
  close (fd);
  if (rename (tmp, path) != 0)
    {
      unlink (tmp);
      return VMK_E_IO;
    }
  return VMK_OK;
}

int
vmk_pairing_load (vmk_pairing *p, const char *path)
{
  char magic[8];
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  ssize_t r1, r2;

  if (fd < 0)
    return errno == ENOENT ? VMK_E_NOT_FOUND : VMK_E_IO;
  r1 = read (fd, magic, 8);
  r2 = read (fd, p, sizeof *p);
  close (fd);
  if (r1 != 8 || memcmp (magic, PAIR_MAGIC, 8) != 0 || r2 != (ssize_t) sizeof *p ||
      (p->type != VMK_PAIR_ECC && p->type != VMK_PAIR_PSK))
    {
      memset (p, 0, sizeof *p);
      return VMK_E_PROTO;
    }
  return VMK_OK;
}
