/*
 * libvmk fingerprint operations: LED, capture, match-in-sensor enroll and
 * identify, and the on-chip template database (DB2).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "vmk-private.h"
#include "vmk-tables.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static void
sleep_ms (unsigned ms)
{
  struct timespec ts = { ms / 1000, (long) (ms % 1000) * 1000000L };
  nanosleep (&ts, NULL);
}

static uint64_t
now_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/* simple command without interesting reply data */
static int
cmd_simple (vmk_dev *dev, const uint8_t *cmd, size_t len, uint16_t *status, unsigned timeout)
{
  return vmk_cmd (dev, cmd, len, NULL, NULL, 2, status, timeout);
}

/* ---- LED (FUN_1800624c0, table vmk_led_table) --------------------------------- */

int
vmk_led (vmk_dev *dev, int event)
{
  uint8_t cmd[1 + VMK_LED_ENTRY_SIZE];
  uint16_t st;
  int r;

  if (event < 0 || event > 5)
    return VMK_E_INVAL;
  cmd[0] = VCSFW_CMD_LED_EX2;
  memcpy (cmd + 1, vmk_led_table[event], VMK_LED_ENTRY_SIZE);
  r = cmd_simple (dev, cmd, sizeof cmd, &st, 0);
  if (r == VMK_E_STATUS && st == VMK_STATUS_RETRY_401)
    r = cmd_simple (dev, cmd, sizeof cmd, &st, 0);
  if (r)
    VMK_DBG ("LED event %d failed: %s (0x%04x)", event, vmk_strerror (r), st);
  return r;
}

/* ---- events ------------------------------------------------------------------- */

/* EVENT_CONFIG (FUN_180060c60). @events: list of event ids, n = 0 disables. */
static int
event_config (vmk_dev *dev, const uint8_t *events, size_t n)
{
  uint8_t cmd[0x25] = { VCSFW_CMD_EVENT_CONFIG }, *rep = NULL;
  uint32_t mask = 0;
  size_t len;
  int r;

  for (size_t i = 0; i < n; i++)
    mask |= 1u << (events[i] & 0x1f);
  if (n)
    {
      put_le32 (cmd + 1, mask);
      put_le32 (cmd + 17, mask);
    }
  else
    put_le32 (cmd + 33, 4);
  r = vmk_cmd (dev, cmd, sizeof cmd, &rep, &len, 0x42, NULL, 0);
  if (!r && len >= 0x42)
    {
      dev->event_seq = get_le16 (rep + 0x40);
      VMK_TRACE ("event config: seq %u", dev->event_seq);
    }
  free (rep);
  return r;
}

/* EVENT_READ (FUN_180061070). ORs (1 << type) of every event read into
 * *seen; *last_state receives the last finger state event (1 or 2), if any. */
static int
event_read (vmk_dev *dev, uint32_t *seen, int *last_state)
{
  enum { MAX_EVENTS = 0x20 };
  uint8_t cmd[9] = { VCSFW_CMD_EVENT_READ }, *rep = NULL;
  size_t len;
  uint16_t st, count;
  int r;

  for (;;)
    {
      put_le16 (cmd + 1, dev->event_seq);
      put_le16 (cmd + 3, MAX_EVENTS);
      put_le32 (cmd + 5, 1);
      r = vmk_cmd (dev, cmd, dev->legacy_event_read ? 5 : 9, &rep, &len, MAX_EVENTS * 12 + 6,
                   &st, 0);
      if (r == VMK_E_STATUS && !dev->legacy_event_read && (st == 0x0405 || st == 0x0406))
        {
          VMK_DBG ("falling back to legacy event read");
          dev->legacy_event_read = true;
          free (rep);
          rep = NULL;
          continue;
        }
      break;
    }
  if (r)
    goto out;
  if (len < 6)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  count = get_le16 (rep + 2);
  for (uint16_t i = 0; i < count && 6 + (size_t) i * 12 + 12 <= len; i++)
    {
      const uint8_t *e = rep + 6 + i * 12;
      VMK_DBG ("event: type 0x%02x data %08x %08x", e[0], get_le32 (e + 4), get_le32 (e + 8));
      if (e[0] < 32)
        *seen |= 1u << e[0];
      if (last_state && (e[0] == VMK_EVENT_FINGER_PRESENT || e[0] == VMK_EVENT_FINGER_REMOVED))
        *last_state = e[0];
    }
  dev->event_seq += count;
out:
  free (rep);
  return r;
}

/* Diagnostics: log every finger event for @duration_ms */
int
vmk_watch_events (vmk_dev *dev, unsigned duration_ms)
{
  /* the sensor rejects state and edge events together (status 0x064b) */
  static const uint8_t state_ev[] = { VMK_EVENT_FINGER_PRESENT, VMK_EVENT_FINGER_REMOVED };
  static const uint8_t edge_ev[] = { VMK_EVENT_FINGER_DOWN, VMK_EVENT_FINGER_UP };
  const char *which = getenv ("VMK_WATCH_EDGES");
  uint64_t start = now_ms ();
  int r;

  if ((r = which && *which == '1' ? event_config (dev, edge_ev, 2) : event_config (dev, state_ev, 2)))
    return r;
  while (!r && now_ms () - start < duration_ms && !vmk_cancelled (dev))
    {
      uint8_t pkt[16];
      size_t got = 0;
      uint32_t seen = 0;

      r = dev->t.intr_in (dev->t.user, pkt, sizeof pkt, &got, 250);
      if (r != VMK_OK && r != VMK_E_TIMEOUT)
        break;
      r = event_read (dev, &seen, NULL);
      for (int i = 1; i < 32 && !r; i++)
        if (seen & (1u << i))
          VMK_INFO ("%6u ms: event %d", (unsigned) (now_ms () - start), i);
    }
  event_config (dev, NULL, 0);
  return r;
}

/* CCaptureImage::CheckForFingerPresence @0x18000d5a0 arms the finger state
 * events (mask 0x180 -> ids 1 and 2); when the sensor reports a finger
 * present it waits for "removed" before the next capture. Without this, a
 * finger left on the sensor is imaged again right away. */
int
vmk_wait_finger_removed (vmk_dev *dev, unsigned timeout_ms, bool *was_present)
{
  static const uint8_t ev[] = { VMK_EVENT_FINGER_PRESENT, VMK_EVENT_FINGER_REMOVED };
  uint64_t start = now_ms (), last_poll = 0;
  bool waiting = false;
  int state = 0, r;

  if (was_present)
    *was_present = false;
  if ((r = event_config (dev, ev, 2)))
    return r;
  for (;;)
    {
      uint8_t pkt[16];
      size_t got = 0;
      uint32_t seen = 0;

      if (now_ms () - last_poll >= 200)
        {
          last_poll = now_ms ();
          if ((r = event_read (dev, &seen, &state)))
            break;
          if (state == VMK_EVENT_FINGER_PRESENT && !waiting)
            {
              VMK_DBG ("finger still on the sensor, waiting for it to be lifted");
              waiting = true;
              if (was_present)
                *was_present = true;
            }
        }
      if (state == VMK_EVENT_FINGER_REMOVED)
        break;
      /* the sensor only reports a state change; silence means no finger */
      if (state == 0 && now_ms () - start >= 500)
        break;
      if (vmk_cancelled (dev))
        {
          r = VMK_E_CANCELLED;
          break;
        }
      if (timeout_ms && now_ms () - start > timeout_ms)
        {
          r = VMK_E_TIMEOUT;
          break;
        }
      r = dev->t.intr_in (dev->t.user, pkt, sizeof pkt, &got, 100);
      if (r == VMK_OK && got)
        last_poll = 0;
      else if (r != VMK_E_TIMEOUT && r != VMK_OK)
        break;
      r = VMK_OK;
    }
  event_config (dev, NULL, 0);
  return r;
}

/* ---- capture (tudorCaptureStart / Process / Finish) ---------------------------- */

static int
frame_finish (vmk_dev *dev)
{
  const uint8_t cmd = VCSFW_CMD_FRAME_FINISH;
  return cmd_simple (dev, &cmd, 1, NULL, 0);
}

/* FRAME_ACQ as issued for capture flags 7 (enroll and verify/identify):
 *   flags 0x14, count 1, then u16 1, 0x00, 0x08, mode 2 -> (1, 1, 1), 0 */
static int
frame_acq (vmk_dev *dev)
{
  uint8_t cmd[17] = { VCSFW_CMD_FRAME_ACQ };
  uint16_t st;
  int r;

  put_le32 (cmd + 1, 0x14);
  put_le32 (cmd + 5, 1);
  put_le16 (cmd + 9, 1);
  cmd[11] = 0;
  cmd[12] = 8;
  cmd[13] = 1;
  cmd[14] = 1;
  cmd[15] = 1;
  cmd[16] = 0;

  for (int attempt = 0, finished = 0;; attempt++)
    {
      r = cmd_simple (dev, cmd, sizeof cmd, &st, 0);
      if (r != VMK_E_STATUS)
        return r;
      if (st == VMK_STATUS_BUSY_6EA && attempt < 3)
        {
          sleep_ms (100);
          continue;
        }
      if (st == VMK_STATUS_NEED_FINISH && !finished)
        {
          finished = 1;
          if (frame_finish (dev) == VMK_OK)
            continue;
        }
      VMK_ERR ("FRAME_ACQ failed with status 0x%04x", st);
      return r;
    }
}

int
vmk_capture (vmk_dev *dev, unsigned timeout_ms)
{
  static const uint8_t ev[] = { VMK_EVENT_FRAME_READY };
  uint64_t start = now_ms (), last_poll = 0;
  uint32_t seen = 0;
  int r;

  if ((r = vmk_wait_finger_removed (dev, timeout_ms, NULL)))
    return r;
  if ((r = event_config (dev, ev, 1)))
    return r;
  if ((r = frame_acq (dev)))
    {
      event_config (dev, NULL, 0);
      return r;
    }
  dev->capture_armed = true;
  vmk_led (dev, VMK_LED_WAIT_FINGER);
  VMK_DBG ("capture armed, waiting for finger");

  while (!(seen & (1u << VMK_EVENT_FRAME_READY)))
    {
      uint8_t pkt[16];
      size_t got = 0;

      if (vmk_cancelled (dev))
        {
          r = VMK_E_CANCELLED;
          break;
        }
      if (timeout_ms && now_ms () - start > timeout_ms)
        {
          r = VMK_E_TIMEOUT;
          break;
        }
      /* The sensor signals pending events on the interrupt endpoint
       * (palWinUsb interrupt thread, 7 byte packets). */
      r = dev->t.intr_in (dev->t.user, pkt, sizeof pkt, &got, 200);
      if (r == VMK_OK && got)
        {
          vmk_hexdump (VMK_LOG_DEBUG, "interrupt", pkt, got);
          memcpy (dev->last_intr, pkt, got < 7 ? got : 7);
        }
      else if (r != VMK_E_TIMEOUT && r != VMK_OK)
        break;
      /* poll the event queue on every interrupt and at least once a second */
      if ((r == VMK_OK && got) || now_ms () - last_poll >= 1000)
        {
          last_poll = now_ms ();
          if ((r = event_read (dev, &seen, NULL)))
            break;
        }
      r = VMK_OK;
    }

  /* tudorCaptureFinish: disable events, FRAME_FINISH */
  event_config (dev, NULL, 0);
  {
    int r2 = frame_finish (dev);
    if (!r && r2)
      r = r2;
  }
  dev->capture_armed = false;
  vmk_led (dev, VMK_LED_OFF);
  if (!r)
    VMK_DBG ("finger imaged");
  return r;
}

/* ---- enroll (FUN_18007c2a0 / FUN_18007c780 / FUN_180087130 / FUN_18007cd70) ---- */

int
vmk_enroll_start (vmk_dev *dev)
{
  uint8_t cmd[13] = { VCSFW_CMD_ENROLL };
  int r;

  vmk_db_info info;

  /* each enrollment takes a user, a template and a payload slot */
  if ((r = vmk_db_get_info (dev, &info)))
    return r;
  if (!info.free_user_slots || !info.free_template_slots || !info.free_payload_slots)
    {
      VMK_INFO ("database has no free slot, reclaiming deleted ones");
      if ((r = vmk_db_cleanup (dev)) || (r = vmk_db_get_info (dev, &info)))
        return r;
      if (!info.free_user_slots || !info.free_template_slots || !info.free_payload_slots)
        return VMK_E_FULL;
    }

  put_le32 (cmd + 1, ENROLL_SUB_START);
  /* [5..8] = 1 and [9..12] = nonce size only when a nonce is requested */
  r = vmk_cmd (dev, cmd, sizeof cmd, NULL, NULL, 6, NULL, 0);
  if (!r)
    dev->enrolling = true;
  return r;
}

int
vmk_enroll_add_image (vmk_dev *dev, vmk_enroll_status *st)
{
  uint8_t cmd[5] = { VCSFW_CMD_ENROLL }, *rep = NULL;
  const uint8_t *s;
  size_t len;
  int r;

  memset (st, 0, sizeof *st);
  put_le32 (cmd + 1, ENROLL_SUB_UPDATE);
  if ((r = vmk_cmd (dev, cmd, sizeof cmd, &rep, &len, 0x52, NULL, 10000)))
    goto out;
  if (len < 0x16 + 0x3c || get_le32 (rep + 0x12) != 0x3c)
    {
      VMK_ERR ("unexpected enroll status layout (len %zu, size %u)", len,
               len >= 0x16 ? get_le32 (rep + 0x12) : 0);
      r = VMK_E_PROTO;
      goto out;
    }
  s = rep + 0x16;
  st->progress = s[2];
  st->redundant = get_le32 (s + 0x18) != 0;
  st->rejected = get_le32 (s + 0x1c) != 0;
  st->template_count = get_le32 (s + 0x24);
  st->quality = get_le16 (s + 0x28);
  st->failed = get_le32 (s + 0x30) != 0;
  st->fixed_pattern = get_le32 (s + 0x38) != 0;
  if (st->progress == 100)
    memcpy (st->tuid, rep + 2, 16);
  VMK_INFO ("enroll: progress %u%%, templates %u, quality %u%s%s%s",
            st->progress, st->template_count, st->quality,
            st->rejected ? ", rejected" : "", st->redundant ? " (redundant)" : "",
            st->fixed_pattern ? " (fixed pattern)" : "");
  vmk_led (dev, st->rejected ? VMK_LED_SCAN_BAD : VMK_LED_SCAN_OK);
out:
  free (rep);
  return r;
}

int
vmk_enroll_commit (vmk_dev *dev, const uint8_t *payload, size_t payload_len)
{
  uint8_t *cmd;
  int r;

  if (payload_len > 0x400)
    return VMK_E_INVAL;
  if (!(cmd = calloc (1, payload_len + 0xd)))
    return VMK_E_NOMEM;
  cmd[0] = VCSFW_CMD_ENROLL;
  put_le32 (cmd + 1, ENROLL_SUB_COMMIT);
  put_le32 (cmd + 9, (uint32_t) payload_len);
  if (payload_len)
    memcpy (cmd + 0xd, payload, payload_len);
  r = cmd_simple (dev, cmd, payload_len + 0xd, NULL, 10000);
  free (cmd);
  return r;
}

int
vmk_enroll_finish (vmk_dev *dev)
{
  uint8_t cmd[5] = { VCSFW_CMD_ENROLL };
  int r;

  put_le32 (cmd + 1, ENROLL_SUB_FINISH);
  r = cmd_simple (dev, cmd, sizeof cmd, NULL, 10000);
  dev->enrolling = false;
  return r;
}

/* ---- identify (FUN_18007d0a0 / misAuthImageToTemplates) ------------------------- */

void
vmk_match_clear (vmk_match *m)
{
  free (m->payload);
  memset (m, 0, sizeof *m);
}

int
vmk_identify (vmk_dev *dev, const vmk_tuid *tuids, size_t n, vmk_match *out)
{
  size_t cmd_len = 0xd + n * 16, len;
  uint8_t *cmd = calloc (1, cmd_len), *rep = NULL;
  uint32_t qm, len_a, len_b;
  uint16_t st = 0;
  int r;

  memset (out, 0, sizeof *out);
  if (!cmd)
    return VMK_E_NOMEM;
  cmd[0] = VCSFW_CMD_IDENTIFY_MATCH;
  put_le32 (cmd + 1, 1);
  if (n)
    {
      put_le32 (cmd + 5, (uint32_t) (n * 16));
      memcpy (cmd + 0xd, tuids, n * 16);
    }
  r = vmk_cmd (dev, cmd, cmd_len, &rep, &len, 0x642, &st, 10000);
  free (cmd);
  /* FUN_180065270 maps 0x0509 to 0x12e, which the WinBio layer reports as
   * "no match" (0x6b -> 0x8009801f) */
  if (r == VMK_E_STATUS && st == VMK_STATUS_NO_MATCH)
    {
      r = VMK_OK;
      VMK_INFO ("identify: no match");
      vmk_led (dev, VMK_LED_NO_MATCH);
      goto out;
    }
  if (r)
    goto out;
  if (len < 0x1e)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  qm = get_le32 (rep + 0x12);
  len_a = get_le32 (rep + 0x16);
  len_b = get_le32 (rep + 0x1a);
  if (qm != 0x24 || 0x1e + (size_t) qm + len_a + len_b > len)
    {
      VMK_ERR ("unexpected identify reply layout (qm %u, a %u, b %u, len %zu)", qm, len_a,
               len_b, len);
      r = VMK_E_PROTO;
      goto out;
    }
  out->score = get_le32 (rep + 0x1e);
  out->matched = (int32_t) out->score > 0;
  if (out->matched)
    {
      memcpy (out->tuid, rep + 2, 16);
      if (len_b && (out->payload = malloc (len_b)))
        {
          memcpy (out->payload, rep + 0x1e + qm + len_a, len_b);
          out->payload_len = len_b;
        }
    }
  VMK_INFO ("identify: %s (score 0x%x)", out->matched ? "match" : "no match", out->score);
  vmk_led (dev, out->matched ? VMK_LED_MATCH : VMK_LED_NO_MATCH);
out:
  free (rep);
  return r;
}

/* ---- DB2 object store ------------------------------------------------------------ */

static int
db2_obj_cmd (vmk_dev *dev, uint8_t op, uint8_t type, const uint8_t id[16],
             uint8_t **rep, size_t *len, size_t expected, unsigned timeout)
{
  uint8_t cmd[21] = { op, type };

  if (id)
    memcpy (cmd + 5, id, 16);
  return vmk_cmd (dev, cmd, sizeof cmd, rep, len, expected, NULL, timeout);
}

int
vmk_db_get_info (vmk_dev *dev, vmk_db_info *info)
{
  const uint8_t cmd[2] = { VCSFW_CMD_DB2_GET_DB_INFO, 1 };
  uint8_t *rep = NULL;
  const uint8_t *d;
  size_t len;
  int r;

  if ((r = vmk_cmd (dev, cmd, sizeof cmd, &rep, &len, 0x28, NULL, 0)))
    goto out;
  if (len < 0x28)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  d = rep + 2;
  info->version_major = get_le16 (d + 0x02);
  info->version_minor = get_le16 (d + 0x04);
  info->pversion = get_le32 (d + 0x06);
  info->template_slot_size = get_le16 (d + 0x10);
  info->payload_slot_size = get_le16 (d + 0x12);
  info->users = get_le16 (d + 0x14);
  info->deleted_users = get_le16 (d + 0x16);
  info->free_user_slots = get_le16 (d + 0x18);
  info->templates = get_le16 (d + 0x1a);
  info->deleted_templates = get_le16 (d + 0x1c);
  info->free_template_slots = get_le16 (d + 0x1e);
  info->payloads = get_le16 (d + 0x20);
  info->deleted_payloads = get_le16 (d + 0x22);
  info->free_payload_slots = get_le16 (d + 0x24);
out:
  free (rep);
  return r;
}

/* GET_OBJECT_LIST: reply = status, u16 count, count * 16 byte ids */
static int
db2_list (vmk_dev *dev, uint8_t type, const uint8_t parent[16], uint16_t max,
          uint8_t **ids, uint16_t *count)
{
  uint8_t *rep = NULL;
  size_t len;
  int r;

  *ids = NULL;
  *count = 0;
  if (!max)
    return VMK_OK;
  if ((r = db2_obj_cmd (dev, VCSFW_CMD_DB2_GET_OBJECT_LIST, type, parent, &rep, &len,
                        (size_t) max * 16 + 4, 0)))
    goto out;
  if (len < 4)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  *count = get_le16 (rep + 2);
  if (4 + (size_t) *count * 16 > len)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  if (*count && (*ids = malloc ((size_t) *count * 16)))
    memcpy (*ids, rep + 4, (size_t) *count * 16);
  else if (*count)
    r = VMK_E_NOMEM;
out:
  free (rep);
  return r;
}

static int
db2_get_data (vmk_dev *dev, uint8_t type, const uint8_t id[16], uint8_t **data, size_t *data_len)
{
  uint8_t *rep = NULL;
  size_t len;
  uint32_t size;
  int r;

  *data = NULL;
  *data_len = 0;
  /* GET_OBJECT_INFO: 0x34 bytes for templates/payloads, data size @ +0x30 */
  if ((r = db2_obj_cmd (dev, VCSFW_CMD_DB2_GET_OBJECT_INFO, type, id, &rep, &len,
                        type == DB2_TYPE_USER ? 0xc : 0x34, 0)))
    goto out;
  if (type == DB2_TYPE_USER || len < 0x34)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  size = get_le32 (rep + 0x30);
  free (rep);
  rep = NULL;
  if (size > 0x10000)
    return VMK_E_PROTO;
  if ((r = db2_obj_cmd (dev, VCSFW_CMD_DB2_GET_OBJECT_DATA, type, id, &rep, &len,
                        (size_t) size + 8, 0)))
    goto out;
  if (len < 8 || 8 + (size_t) get_le32 (rep + 4) > len)
    {
      r = VMK_E_PROTO;
      goto out;
    }
  *data_len = get_le32 (rep + 4);
  if (!(*data = malloc (*data_len ? *data_len : 1)))
    r = VMK_E_NOMEM;
  else
    memcpy (*data, rep + 8, *data_len);
out:
  free (rep);
  return r;
}

int
vmk_db_template_exists (vmk_dev *dev, const vmk_tuid tuid, bool *exists)
{
  uint8_t *rep = NULL;
  size_t len;
  int r = db2_obj_cmd (dev, VCSFW_CMD_DB2_GET_OBJECT_INFO, DB2_TYPE_TEMPLATE, tuid, &rep, &len,
                       0x34, 0);

  free (rep);
  *exists = r == VMK_OK;
  return r == VMK_E_STATUS ? VMK_OK : r;
}

static int
db2_delete (vmk_dev *dev, uint8_t type, const uint8_t id[16])
{
  return db2_obj_cmd (dev, VCSFW_CMD_DB2_DELETE_OBJECT, type, id, NULL, NULL, 4,
                      VMK_LONG_TIMEOUT);
}

void
vmk_db_records_free (vmk_record *records, size_t n)
{
  for (size_t i = 0; i < n; i++)
    free (records[i].payload);
  free (records);
}

/* FUN_180082d20: templates under parent ff..ff, payloads under each template */
int
vmk_db_list (vmk_dev *dev, vmk_record **records, size_t *n)
{
  static const uint8_t all[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  vmk_db_info info;
  uint8_t *tids = NULL;
  uint16_t nt = 0;
  vmk_record *out = NULL;
  int r;

  *records = NULL;
  *n = 0;
  if ((r = vmk_db_get_info (dev, &info)) ||
      (r = db2_list (dev, DB2_TYPE_TEMPLATE, all, info.templates, &tids, &nt)))
    goto fail;
  if (nt && !(out = calloc (nt, sizeof *out)))
    {
      r = VMK_E_NOMEM;
      goto fail;
    }
  for (uint16_t i = 0; i < nt; i++)
    {
      uint8_t *pids = NULL;
      uint16_t np = 0;

      memcpy (out[i].tuid, tids + i * 16, 16);
      if ((r = db2_list (dev, DB2_TYPE_PAYLOAD, out[i].tuid,
                         info.payloads ? info.payloads : 1, &pids, &np)))
        goto fail;
      if (np)
        r = db2_get_data (dev, DB2_TYPE_PAYLOAD, pids, &out[i].payload, &out[i].payload_len);
      free (pids);
      if (r)
        goto fail;
    }
  free (tids);
  *records = out;
  *n = nt;
  return VMK_OK;
fail:
  free (tids);
  vmk_db_records_free (out, nt);
  return r;
}

/* The sensor creates one user object per enrollment at commit; the template
 * is its child and the payload the template's child. FUN_180083e20 deletes an
 * enrollment by deleting that user object (GET_OBJECT_INFO: user id at +0x12
 * of the info data), which removes the template and payload with it. */
int
vmk_db_delete (vmk_dev *dev, const vmk_tuid tuid)
{
  vmk_db_info info;
  uint8_t *pids = NULL, *rep = NULL;
  uint16_t np = 0;
  uint16_t st;
  size_t len;
  int r;

  r = db2_obj_cmd (dev, VCSFW_CMD_DB2_GET_OBJECT_INFO, DB2_TYPE_TEMPLATE, tuid, &rep, &len,
                   0x34, 0);
  if (r == VMK_E_STATUS)
    {
      free (rep);
      return VMK_E_NOT_FOUND;
    }
  if (r == VMK_OK && len >= 0x24)
    {
      static const uint8_t none[16];
      if (memcmp (rep + 0x14, none, 16) != 0)
        r = db2_delete (dev, DB2_TYPE_USER, rep + 0x14);
      else
        r = VMK_E_PROTO;
      free (rep);
      if (r == VMK_OK)
        return VMK_OK;
      VMK_WARN ("deleting the enrollment's user object failed: %s", vmk_strerror (r));
    }
  else
    free (rep);

  /* fallback: drop attached payloads first, then the template itself */
  if (vmk_db_get_info (dev, &info) == VMK_OK &&
      db2_list (dev, DB2_TYPE_PAYLOAD, tuid, info.payloads ? info.payloads : 1, &pids, &np) == VMK_OK)
    for (uint16_t i = 0; i < np; i++)
      db2_delete (dev, DB2_TYPE_PAYLOAD, pids + i * 16);
  free (pids);

  {
    uint8_t cmd[21] = { VCSFW_CMD_DB2_DELETE_OBJECT, DB2_TYPE_TEMPLATE };
    memcpy (cmd + 5, tuid, 16);
    r = vmk_cmd (dev, cmd, sizeof cmd, NULL, NULL, 4, &st, VMK_LONG_TIMEOUT);
  }
  if (r == VMK_E_STATUS)
    {
      VMK_WARN ("delete of template failed with status 0x%04x", st);
      r = VMK_E_NOT_FOUND;
    }
  return r;
}

/* FUN_180086f10: DB2_CLEANUP reclaims the slots of deleted objects in one
 * partition (1 users, 2 templates, 3 payloads). Until then a deleted object
 * keeps its slot; FUN_180087690 cleans all three after an erase. */
int
vmk_db_cleanup (vmk_dev *dev)
{
  int r = VMK_OK;

  for (uint8_t part = 1; part <= 3; part++)
    {
      const uint8_t cmd[2] = { VCSFW_CMD_DB2_CLEANUP, part };
      uint8_t *rep = NULL;
      size_t len;
      int r2 = vmk_cmd (dev, cmd, sizeof cmd, &rep, &len, 8, NULL, VMK_LONG_TIMEOUT);

      if (!r2 && len >= 8)
        VMK_DBG ("DB2 cleanup partition %u: reply %02x %02x %02x %02x %02x %02x", part, rep[2],
                 rep[3], rep[4], rep[5], rep[6], rep[7]);
      free (rep);
      if (r2 && !r)
        r = r2;
    }
  return r;
}

/* stiTudorDatabaseErase / FUN_180087690: delete every user object (which owns
 * templates and payloads), then any template left over. */
int
vmk_db_erase (vmk_dev *dev)
{
  static const uint8_t zero[16], all[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  vmk_db_info info;
  uint8_t *ids = NULL;
  uint16_t n = 0;
  int r;

  if ((r = vmk_db_get_info (dev, &info)))
    return r;
  if (info.users && (r = db2_list (dev, DB2_TYPE_USER, zero, info.users, &ids, &n)) == VMK_OK)
    for (uint16_t i = 0; i < n; i++)
      if ((r = db2_delete (dev, DB2_TYPE_USER, ids + i * 16)))
        VMK_WARN ("deleting user object failed: %s", vmk_strerror (r));
  free (ids);
  ids = NULL;

  if ((r = vmk_db_get_info (dev, &info)))
    return r;
  if (info.templates &&
      (r = db2_list (dev, DB2_TYPE_TEMPLATE, all, info.templates, &ids, &n)) == VMK_OK)
    for (uint16_t i = 0; i < n; i++)
      vmk_db_delete (dev, ids + i * 16);
  free (ids);
  if (r)
    return r;
  if (vmk_db_cleanup (dev))
    VMK_DBG ("DB2 cleanup failed (ignored)");
  return vmk_db_get_info (dev, &info);
}

/* ---- payload container ------------------------------------------------------------
 * palTagVal blob format (FUN_180042580): repeated [u16 tag][u32 length][data].
 * The Windows driver uses tags 0..3 for WinBio data. We use private tags so
 * Windows skips our records instead of treating them as WinBio identities. */
#define PAYLOAD_TAG_MAGIC   0x4c46 /* 'FL' */
#define PAYLOAD_TAG_USER_ID 0x4c47
static const char payload_magic[] = "libfprint-verimark-1";

int
vmk_payload_build (const char *user_id, uint8_t **out, size_t *out_len)
{
  size_t ml = sizeof payload_magic - 1, ul = user_id ? strlen (user_id) : 0;
  size_t len = 6 + ml + 6 + ul;
  uint8_t *p = malloc (len);

  if (!p)
    return VMK_E_NOMEM;
  put_le16 (p, PAYLOAD_TAG_MAGIC);
  put_le32 (p + 2, (uint32_t) ml);
  memcpy (p + 6, payload_magic, ml);
  put_le16 (p + 6 + ml, PAYLOAD_TAG_USER_ID);
  put_le32 (p + 8 + ml, (uint32_t) ul);
  if (ul)
    memcpy (p + 12 + ml, user_id, ul);
  *out = p;
  *out_len = len;
  return VMK_OK;
}

char *
vmk_payload_get_user_id (const uint8_t *p, size_t len)
{
  bool magic = false;
  char *uid = NULL;

  for (size_t off = 0; off + 6 <= len;)
    {
      uint16_t tag = get_le16 (p + off);
      uint32_t l = get_le32 (p + off + 2);

      if (off + 6 + l > len)
        break;
      if (tag == PAYLOAD_TAG_MAGIC && l == sizeof payload_magic - 1 &&
          memcmp (p + off + 6, payload_magic, l) == 0)
        magic = true;
      else if (tag == PAYLOAD_TAG_USER_ID && !uid && (uid = malloc (l + 1)))
        {
          memcpy (uid, p + off + 6, l);
          uid[l] = 0;
        }
      off += 6 + l;
    }
  if (!magic)
    {
      free (uid);
      return NULL;
    }
  return uid;
}
