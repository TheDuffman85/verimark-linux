/*
 * verimark-cli - talk to a Kensington VeriMark Desktop without fprintd.
 *
 * Useful for pairing, diagnostics and protocol tracing:
 *   sudo verimark-cli -vv info
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "vmk.h"
#include "vmk-paths.h"

#include <errno.h>
#include <getopt.h>
#include <libusb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const struct { uint16_t vid, pid; } known_ids[] = {
  { 0x047d, 0x00f2 }, /* Kensington VeriMark Desktop K62330WW */
  { 0x06cb, 0x00de }, /* Synaptics reference id from the same INF */
};

typedef struct
{
  libusb_context *ctx;
  libusb_device_handle *h;
  int iface;
  uint8_t ep_out, ep_in, ep_intr;
} usb_t;

static volatile sig_atomic_t interrupted;

static void
on_sigint (int sig)
{
  (void) sig;
  interrupted = 1;
}

static int
map_usb_err (int r)
{
  if (r == LIBUSB_ERROR_TIMEOUT)
    return VMK_E_TIMEOUT;
  if (r == LIBUSB_ERROR_NO_MEM)
    return VMK_E_NOMEM;
  return VMK_E_IO;
}

static int
t_bulk_out (void *u, const uint8_t *data, size_t len, unsigned timeout)
{
  usb_t *usb = u;
  int done = 0, r;

  r = libusb_bulk_transfer (usb->h, usb->ep_out, (uint8_t *) data, (int) len, &done, timeout);
  if (r)
    return map_usb_err (r);
  return (size_t) done == len ? VMK_OK : VMK_E_IO;
}

static int
t_bulk_in (void *u, uint8_t *data, size_t len, size_t *actual, unsigned timeout)
{
  usb_t *usb = u;
  int done = 0, r;

  r = libusb_bulk_transfer (usb->h, usb->ep_in, data, (int) len, &done, timeout);
  *actual = (size_t) done;
  return r ? map_usb_err (r) : VMK_OK;
}

static int
t_intr_in (void *u, uint8_t *data, size_t len, size_t *actual, unsigned timeout)
{
  usb_t *usb = u;
  int done = 0, r;

  *actual = 0;
  if (!usb->ep_intr)
    return VMK_E_TIMEOUT;
  r = libusb_interrupt_transfer (usb->h, usb->ep_intr, data, (int) len, &done, timeout);
  *actual = (size_t) done;
  return r ? map_usb_err (r) : VMK_OK;
}

static int
t_control (void *u, uint8_t rt, uint8_t req, uint16_t value, uint16_t index, uint8_t *data,
           uint16_t len, size_t *actual, unsigned timeout)
{
  usb_t *usb = u;
  int r = libusb_control_transfer (usb->h, rt, req, value, index, data, len, timeout);

  if (r < 0)
    return map_usb_err (r);
  if (actual)
    *actual = (size_t) r;
  return VMK_OK;
}

static int
t_reset (void *u)
{
  usb_t *usb = u;
  int r;

  libusb_release_interface (usb->h, usb->iface);
  r = libusb_reset_device (usb->h);
  if (r)
    return VMK_E_IO;
  return libusb_claim_interface (usb->h, usb->iface) ? VMK_E_IO : VMK_OK;
}

static bool
t_cancelled (void *u)
{
  (void) u;
  return interrupted != 0;
}

static int
usb_open (usb_t *usb)
{
  libusb_device **list;
  ssize_t n;
  int r = -1;

  memset (usb, 0, sizeof *usb);
  if (libusb_init (&usb->ctx))
    return -1;
  n = libusb_get_device_list (usb->ctx, &list);
  for (ssize_t i = 0; i < n && !usb->h; i++)
    {
      struct libusb_device_descriptor dd;
      struct libusb_config_descriptor *cfg;

      if (libusb_get_device_descriptor (list[i], &dd))
        continue;
      bool known = false;
      for (size_t k = 0; k < sizeof known_ids / sizeof known_ids[0]; k++)
        known |= dd.idVendor == known_ids[k].vid && dd.idProduct == known_ids[k].pid;
      if (!known || libusb_get_active_config_descriptor (list[i], &cfg))
        continue;

      /* The INF binds MI_01: the vendor interface with bulk in/out + interrupt in */
      for (int f = 0; f < cfg->bNumInterfaces && !usb->h; f++)
        {
          const struct libusb_interface_descriptor *id = &cfg->interface[f].altsetting[0];
          uint8_t out = 0, in = 0, intr = 0;

          for (int e = 0; e < id->bNumEndpoints; e++)
            {
              const struct libusb_endpoint_descriptor *ep = &id->endpoint[e];
              int type = ep->bmAttributes & 3;
              if (type == LIBUSB_TRANSFER_TYPE_BULK && !(ep->bEndpointAddress & 0x80) && !out)
                out = ep->bEndpointAddress;
              else if (type == LIBUSB_TRANSFER_TYPE_BULK && (ep->bEndpointAddress & 0x80) && !in)
                in = ep->bEndpointAddress;
              else if (type == LIBUSB_TRANSFER_TYPE_INTERRUPT && (ep->bEndpointAddress & 0x80) && !intr)
                intr = ep->bEndpointAddress;
            }
          /* vendor interface: bulk pair (Synaptics reference) or interrupt only
           * (VeriMark Desktop, commands then go over EP0) */
          if (id->bInterfaceClass != LIBUSB_CLASS_VENDOR_SPEC || (!(out && in) && !intr))
            continue;
          if (libusb_open (list[i], &usb->h))
            {
              fprintf (stderr, "cannot open %04x:%04x (try sudo or install the udev rule)\n",
                       dd.idVendor, dd.idProduct);
              break;
            }
          usb->iface = id->bInterfaceNumber;
          usb->ep_out = out;
          usb->ep_in = in;
          usb->ep_intr = intr;
          libusb_set_auto_detach_kernel_driver (usb->h, 1);
          if (libusb_claim_interface (usb->h, usb->iface))
            {
              fprintf (stderr, "cannot claim interface %d (is fprintd running?)\n", usb->iface);
              libusb_close (usb->h);
              usb->h = NULL;
              break;
            }
          fprintf (stderr, "using %04x:%04x interface %d (out 0x%02x, in 0x%02x, intr 0x%02x)\n",
                   dd.idVendor, dd.idProduct, usb->iface, out, in, intr);
          r = 0;
        }
      libusb_free_config_descriptor (cfg);
    }
  if (n >= 0)
    libusb_free_device_list (list, 1);
  if (r)
    {
      if (!usb->h)
        fprintf (stderr, "no VeriMark device found\n");
      libusb_exit (usb->ctx);
    }
  return r;
}

static void
usb_close (usb_t *usb)
{
  libusb_release_interface (usb->h, usb->iface);
  libusb_close (usb->h);
  libusb_exit (usb->ctx);
}

static void
print_hex (const uint8_t *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
    printf ("%02x", p[i]);
}

static int
parse_hex (const char *s, uint8_t *out, size_t n)
{
  if (strlen (s) != n * 2)
    return -1;
  for (size_t i = 0; i < n; i++)
    if (sscanf (s + 2 * i, "%2hhx", &out[i]) != 1)
      return -1;
  return 0;
}

/* ---- dump: read-only walk of the DB2 object tree ---------------------------- */

static const uint8_t id_zero[16];
static const uint8_t id_all[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const char *const obj_names[] = { "?", "user", "template", "payload" };

static int
obj_cmd (vmk_dev *dev, uint8_t op, uint8_t type, const uint8_t id[16], uint8_t **rep,
         size_t *len, size_t expected)
{
  uint8_t cmd[21] = { op, type };
  uint16_t st = 0;
  int r;

  memcpy (cmd + 5, id, 16);
  r = vmk_cmd (dev, cmd, sizeof cmd, rep, len, expected, &st, 0);
  if (r == VMK_E_STATUS)
    printf ("    (status 0x%04x)\n", st);
  return r;
}

static void
dump_children (vmk_dev *dev, int depth, uint8_t type, const uint8_t parent[16])
{
  uint8_t *rep = NULL;
  size_t len;

  if (depth > 3 || obj_cmd (dev, 0x9f, type, parent, &rep, &len, 64 * 16 + 4) || len < 4)
    {
      free (rep);
      return;
    }
  for (unsigned i = 0, n = rep[2] | rep[3] << 8; i < n && 4 + (i + 1) * 16 <= len; i++)
    {
      const uint8_t *id = rep + 4 + i * 16;
      uint8_t *info = NULL, *data = NULL;
      size_t ilen = 0, dlen = 0;

      printf ("%*s%s ", depth * 2, "", obj_names[type]);
      print_hex (id, 16);
      if (!obj_cmd (dev, 0xa0, type, id, &info, &ilen, type == 1 ? 0xc : 0x34))
        {
          printf ("\n%*s  info:", depth * 2, "");
          for (size_t k = 2; k < ilen; k++)
            printf (" %02x", info[k]);
        }
      if (type != 1 && ilen >= 0x34 &&
          !obj_cmd (dev, 0xa1, type, id, &data, &dlen, (size_t) (info[0x30] | info[0x31] << 8) + 8)
          && dlen >= 8)
        {
          char *uid = vmk_payload_get_user_id (data + 8, dlen - 8);
          printf ("\n%*s  data (%zu bytes)%s%s", depth * 2, "", dlen - 8, uid ? ": " : "",
                  uid ? uid : "");
          if (!uid)
            for (size_t k = 8; k < dlen && k < 8 + 64; k++)
              printf (" %02x", data[k]);
          free (uid);
        }
      printf ("\n");
      free (info);
      free (data);
      for (uint8_t t = 1; t <= 3; t++)
        dump_children (dev, depth + 1, t, id);
    }
  free (rep);
}

static void
dump_db (vmk_dev *dev)
{
  printf ("== children of 00..00\n");
  for (uint8_t t = 1; t <= 3; t++)
    dump_children (dev, 1, t, id_zero);
  printf ("== children of ff..ff (no recursion)\n");
  for (uint8_t t = 1; t <= 3; t++)
    dump_children (dev, 3, t, id_all);
}

static void
log_cb (int level, const char *msg, void *user)
{
  static const char *names[] = { "E", "W", "I", "D", "T" };
  (void) user;
  fprintf (stderr, "[%s] %s\n", names[level], msg);
}

static void
usage (void)
{
  fprintf (stderr,
           "usage: verimark-cli [-v...] [-p pairing-file] <command>\n"
           "commands:\n"
           "  info              sensor version, security state and database info\n"
           "  pair              pair this host with the sensor (stores the pairing file)\n"
           "  enroll [label]    enroll a finger (stored on the sensor)\n"
           "  identify          scan a finger and match it against all stored templates\n"
           "  verify <tuid>     scan a finger and match it against one template\n"
           "  list              list templates stored on the sensor\n"
           "  dump              print the raw on-chip object tree (read only)\n"
           "  delete <tuid>     delete one template (32 hex digits)\n"
           "  erase             delete all templates on the sensor (Windows ones too)\n"
           "  cleanup           reclaim the storage of deleted templates\n"
           "  led <0-5>         show an LED pattern\n"
           "  lift              wait until no finger rests on the sensor\n"
           "  events            log finger events for 40 s (use -v;\n"
           "                    VMK_WATCH_EDGES=1 for down/up edges)\n");
}

int
main (int argc, char **argv)
{
  const char *pair_path = NULL;
  char path_buf[512];
  int verbose = 0, opt, r, rc = 1;
  vmk_transport t;
  vmk_pairing pairing, *pp = NULL;
  vmk_dev *dev;
  usb_t usb;

  while ((opt = getopt (argc, argv, "vp:h")) != -1)
    switch (opt)
      {
      case 'v': verbose++; break;
      case 'p': pair_path = optarg; break;
      default: usage (); return 2;
      }
  if (optind >= argc)
    {
      usage ();
      return 2;
    }
  const char *cmd = argv[optind];

  vmk_set_log_handler (log_cb, NULL, VMK_LOG_WARN + verbose);
  signal (SIGINT, on_sigint);

  if (usb_open (&usb))
    return 1;
  t = (vmk_transport) {
    .user = &usb, .bulk_out = t_bulk_out, .bulk_in = t_bulk_in, .intr_in = t_intr_in,
    .control = t_control, .reset = t_reset, .is_cancelled = t_cancelled,
  };
  if (!usb.ep_out || !usb.ep_in)
    t.bulk_out = NULL, t.bulk_in = NULL; /* EP0 command transport */
  dev = vmk_dev_new (&t);
  /* diagnostics also cover unprovisioned sensors; the TOD driver, which
   * authenticates users, never allows a clear session */
  vmk_allow_clear_session (dev, true);

  {
    vmk_version v;
    if ((r = vmk_get_version (dev, &v)))
      {
        fprintf (stderr, "GET_VERSION failed: %s\n", vmk_strerror (r));
        goto out;
      }
    if (!pair_path)
      {
        vmk_pairing_path (v.serial, path_buf, sizeof path_buf);
        pair_path = path_buf;
      }
    if (vmk_pairing_load (&pairing, pair_path) == VMK_OK)
      pp = &pairing;

    if (!strcmp (cmd, "info"))
      {
        printf ("firmware:          %u.%u (build %u, time %u)\n", v.fw_major, v.fw_minor,
                v.build_num, v.build_time);
        printf ("product:           '%c' (target %u, platform %u, silicon rev %u, patch %u)\n",
                v.product ? v.product : '?', v.target, v.platform, v.silicon_rev, v.patch);
        printf ("serial:            ");
        print_hex (v.serial, 6);
        printf ("\nsecurity bytes:    %02x %02x, provision byte %02x\n", v.security[0],
                v.security[1], v.provision_raw);
        printf ("provision state:   %u (%s)\n", v.provision_state,
                vmk_needs_tls (&v) ? "TLS required" : "clear session");
        printf ("pairing mode:      %s\n", v.advanced_security ? "advanced (ECC)" : "basic (PSK)");
        printf ("pairing file:      %s (%s)\n", pair_path, pp ? "present" : "missing");
      }
  }

  if (!strcmp (cmd, "pair"))
    {
      r = vmk_open (dev, NULL);
      if (r == VMK_OK && !vmk_tls_active (dev))
        {
          printf ("sensor does not use TLS, no pairing needed\n");
          rc = 0;
          goto out;
        }
      if (r != VMK_E_NOT_PAIRED && r != VMK_OK)
        {
          fprintf (stderr, "open failed: %s\n", vmk_strerror (r));
          goto out;
        }
      if ((r = vmk_pair (dev, &pairing)))
        {
          fprintf (stderr, "pairing failed: %s\n", vmk_strerror (r));
          goto out;
        }
      vmk_ensure_pairing_dir ();
      if ((r = vmk_pairing_save (&pairing, pair_path)))
        {
          fprintf (stderr, "cannot save pairing data to %s: %s\n", pair_path, vmk_strerror (r));
          goto out;
        }
      printf ("paired (%s), pairing data saved to %s\n",
              pairing.type == VMK_PAIR_PSK ? "PSK" : "ECC", pair_path);
      pp = &pairing;
      if ((r = vmk_open (dev, pp)))
        {
          fprintf (stderr, "TLS session with new pairing failed: %s\n", vmk_strerror (r));
          goto out;
        }
      printf ("TLS session established successfully\n");
      rc = 0;
      goto out;
    }

  if ((r = vmk_open (dev, pp)))
    {
      fprintf (stderr, "open failed: %s%s\n", vmk_strerror (r),
               r == VMK_E_NOT_PAIRED ? " - run 'verimark-cli pair' first" : "");
      goto out;
    }

  if (!strcmp (cmd, "info"))
    {
      vmk_db_info di;
      printf ("session:           %s\n", vmk_tls_active (dev) ? "TLS" : "clear");
      if ((r = vmk_db_get_info (dev, &di)) == VMK_OK)
        {
          printf ("database:          v%u.%u, %u templates (%u free slots), %u payloads, %u users\n",
                  di.version_major, di.version_minor, di.templates, di.free_template_slots,
                  di.payloads, di.users);
          printf ("slot sizes:        template %u, payload %u\n", di.template_slot_size,
                  di.payload_slot_size);
        }
      else
        fprintf (stderr, "DB info failed: %s\n", vmk_strerror (r));
      rc = 0;
    }
  else if (!strcmp (cmd, "led") && optind + 1 < argc)
    {
      rc = vmk_led (dev, atoi (argv[optind + 1])) != VMK_OK;
    }
  else if (!strcmp (cmd, "enroll"))
    {
      const char *label = optind + 1 < argc ? argv[optind + 1] : "verimark-cli";
      vmk_enroll_status st = { 0 };
      uint8_t *payload;
      size_t plen;

      if ((r = vmk_enroll_start (dev)))
        {
          fprintf (stderr, "enroll start failed: %s\n", vmk_strerror (r));
          goto out;
        }
      while (st.progress < 100)
        {
          printf ("touch the sensor...\n");
          fflush (stdout);
          if ((r = vmk_capture (dev, 0)))
            break;
          if ((r = vmk_enroll_add_image (dev, &st)))
            break;
          if (st.rejected)
            printf ("  scan rejected%s, try again\n", st.redundant ? " (same area as before)" : "");
          else
            printf ("  progress %u%%\n", st.progress);
          if (st.progress == 100 && st.failed)
            {
              r = VMK_E_STATUS;
              break;
            }
        }
      if (!r)
        {
          vmk_payload_build (label, &payload, &plen);
          r = vmk_enroll_commit (dev, payload, plen);
          free (payload);
        }
      vmk_enroll_finish (dev);
      if (r)
        fprintf (stderr, "enroll failed: %s\n", vmk_strerror (r));
      else
        {
          printf ("enrolled template ");
          print_hex (st.tuid, 16);
          printf ("\n");
          rc = 0;
        }
    }
  else if (!strcmp (cmd, "identify") || (!strcmp (cmd, "verify") && optind + 1 < argc))
    {
      vmk_tuid tuid;
      size_t n = 0;
      vmk_match m;

      if (!strcmp (cmd, "verify"))
        {
          if (parse_hex (argv[optind + 1], tuid, 16))
            {
              fprintf (stderr, "template id must be 32 hex digits\n");
              goto out;
            }
          n = 1;
        }
      printf ("touch the sensor...\n");
      fflush (stdout);
      if ((r = vmk_capture (dev, 0)) || (r = vmk_identify (dev, n ? &tuid : NULL, n, &m)))
        fprintf (stderr, "identify failed: %s\n", vmk_strerror (r));
      else
        {
          if (m.matched)
            {
              char *uid = vmk_payload_get_user_id (m.payload, m.payload_len);
              printf ("MATCH template ");
              print_hex (m.tuid, 16);
              printf (" (%s)\n", uid ? uid : "foreign payload");
              free (uid);
            }
          else
            printf ("NO MATCH\n");
          rc = m.matched ? 0 : 3;
          vmk_match_clear (&m);
        }
    }
  else if (!strcmp (cmd, "list"))
    {
      vmk_record *recs;
      size_t n;
      if ((r = vmk_db_list (dev, &recs, &n)))
        fprintf (stderr, "list failed: %s\n", vmk_strerror (r));
      else
        {
          for (size_t i = 0; i < n; i++)
            {
              char *uid = vmk_payload_get_user_id (recs[i].payload, recs[i].payload_len);
              print_hex (recs[i].tuid, 16);
              printf ("  %s\n", uid ? uid : recs[i].payload_len ? "(Windows / foreign record)" : "(no payload)");
              free (uid);
            }
          printf ("%zu template(s)\n", n);
          vmk_db_records_free (recs, n);
          rc = 0;
        }
    }
  else if (!strcmp (cmd, "events"))
    {
      if ((r = vmk_watch_events (dev, 40000)))
        fprintf (stderr, "event watch failed: %s\n", vmk_strerror (r));
      rc = r != VMK_OK;
    }
  else if (!strcmp (cmd, "lift"))
    {
      bool present;
      if ((r = vmk_wait_finger_removed (dev, 30000, &present)))
        fprintf (stderr, "waiting for finger removal failed: %s\n", vmk_strerror (r));
      else
        {
          printf ("no finger on the sensor%s\n", present ? " (waited for it to be lifted)" : "");
          rc = 0;
        }
    }
  else if (!strcmp (cmd, "dump"))
    {
      dump_db (dev);
      rc = 0;
    }
  else if (!strcmp (cmd, "delete") && optind + 1 < argc)
    {
      vmk_tuid tuid;
      if (parse_hex (argv[optind + 1], tuid, 16))
        fprintf (stderr, "template id must be 32 hex digits\n");
      else if ((r = vmk_db_delete (dev, tuid)))
        fprintf (stderr, "delete failed: %s\n", vmk_strerror (r));
      else
        rc = 0;
    }
  else if (!strcmp (cmd, "cleanup"))
    {
      if ((r = vmk_db_cleanup (dev)))
        fprintf (stderr, "cleanup failed: %s\n", vmk_strerror (r));
      else
        rc = 0;
    }
  else if (!strcmp (cmd, "erase"))
    {
      if ((r = vmk_db_erase (dev)))
        fprintf (stderr, "erase failed: %s\n", vmk_strerror (r));
      else
        rc = 0;
    }
  else if (strcmp (cmd, "info"))
    usage ();

out:
  vmk_close (dev);
  vmk_dev_free (dev);
  usb_close (&usb);
  return rc;
}
