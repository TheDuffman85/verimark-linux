/*
 * Where pairing secrets live. fprintd runs with StateDirectory=fprint, so
 * /var/lib/fprint is writable for it even with ProtectSystem=strict; the CLI
 * (run as root) uses the same location so both share one pairing.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifndef VMK_PAIRING_DIR
#define VMK_PAIRING_DIR "/var/lib/fprint/verimark"
#endif

static inline const char *
vmk_pairing_dir (void)
{
  const char *env = getenv ("VMK_PAIRING_DIR");
  return env && *env ? env : VMK_PAIRING_DIR;
}

static inline void
vmk_pairing_path (const uint8_t serial[6], char *buf, size_t size)
{
  snprintf (buf, size, "%s/%02x%02x%02x%02x%02x%02x.pair", vmk_pairing_dir (),
            serial[0], serial[1], serial[2], serial[3], serial[4], serial[5]);
}

static inline void
vmk_ensure_pairing_dir (void)
{
  mkdir (vmk_pairing_dir (), 0700);
}
