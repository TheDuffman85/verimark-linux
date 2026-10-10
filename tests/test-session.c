/* Session policy against a spoofed sensor. The fake device answers on EP0
 * like the VeriMark but claims to be unprovisioned, so it could answer every
 * command in the clear (including "match" for any template). libvmk must
 * refuse such a session unless the caller allowed clear sessions.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "vmk-private.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
  uint8_t  cmd[256];
  size_t   cmd_len;
  uint8_t  reply[0x80];
  size_t   reply_len;
  unsigned identify_seen;
} fake_t;

/* Answers like a spoofing device would: unprovisioned, and IDENTIFY echoes
 * the first requested template with a positive score. */
static void
fake_answer (fake_t *f)
{
  memset (f->reply, 0, sizeof f->reply);
  f->reply_len = 2;
  switch (f->cmd[0])
    {
    case VCSFW_CMD_GET_VERSION:
      f->reply[10] = 10;                 /* fw 10.1 */
      f->reply[11] = 1;
      f->reply[13] = 'A';                /* application firmware */
      f->reply[0x25] = 0;                /* provision state 0: "no TLS" */
      f->reply_len = 0x26;
      break;
    case VCSFW_CMD_GET_STARTINFO:
      f->reply_len = 0x44;
      break;
    case VCSFW_CMD_IDENTIFY_MATCH:
      f->identify_seen++;
      assert (f->cmd_len >= 0xd + 16);
      memcpy (f->reply + 2, f->cmd + 0xd, 16);
      put_le32 (f->reply + 0x12, 0x24);
      put_le32 (f->reply + 0x1e, 1);
      f->reply_len = 0x42;
      break;
    }
}

static int
fake_control (void *user, uint8_t rt, uint8_t req, uint16_t value, uint16_t index,
              uint8_t *data, uint16_t len, size_t *actual, unsigned timeout_ms)
{
  fake_t *f = user;
  (void) index;
  (void) timeout_ms;

  if (rt == 0x40 && req == 0x16)
    {
      /* single chunk: wire length padded to 8, low bits = len & 7 */
      assert (!(value & 0xc000) && len <= sizeof f->cmd);
      f->cmd_len = len - ((value & 7) ? 8 - (value & 7) : 0);
      memcpy (f->cmd, data, len);
      fake_answer (f);
      *actual = len;
      return VMK_OK;
    }
  if (rt == 0xc0 && req == 0x17)
    {
      size_t n = f->reply_len < len ? f->reply_len : len;
      memcpy (data, f->reply, n);
      *actual = n;
      return VMK_OK;
    }
  if (rt == 0xc0 && req == VMK_REQ_GET_TLS_STATE)
    {
      memset (data, 0, len);
      *actual = len;
      return VMK_OK;
    }
  return VMK_E_IO;
}

static vmk_dev *
fake_dev (fake_t *f)
{
  const vmk_transport t = { .user = f, .control = fake_control };
  memset (f, 0, sizeof *f);
  return vmk_dev_new (&t);
}

int
main (void)
{
  static const vmk_tuid tuid = { 0x11, 0x22, 0x33, 0x44 };
  vmk_pairing pairing = { .type = VMK_PAIR_ECC };
  vmk_match m;
  fake_t f;
  vmk_dev *dev;

  vmk_set_log_handler (NULL, NULL, VMK_LOG_ERROR - 1);

  /* default policy: no clear session, with or without pairing data */
  dev = fake_dev (&f);
  assert (vmk_open (dev, NULL) == VMK_E_INSECURE);
  assert (vmk_open (dev, &pairing) == VMK_E_INSECURE);
  assert (!vmk_tls_active (dev));
  /* nothing that carries a result may go out in the clear */
  assert (vmk_identify (dev, &tuid, 1, &m) != VMK_OK && !m.matched);
  assert (f.identify_seen == 0);
  vmk_dev_free (dev);

  /* opt-in (diagnostic CLI): this is what the spoof could do otherwise */
  dev = fake_dev (&f);
  vmk_allow_clear_session (dev, true);
  assert (vmk_open (dev, NULL) == VMK_OK && !vmk_tls_active (dev));
  assert (vmk_identify (dev, &tuid, 1, &m) == VMK_OK && m.matched);
  assert (memcmp (m.tuid, tuid, 16) == 0 && f.identify_seen == 1);
  vmk_match_clear (&m);
  vmk_dev_free (dev);

  puts ("spoofed unprovisioned sensor refused; clear session only when allowed");
  return 0;
}
