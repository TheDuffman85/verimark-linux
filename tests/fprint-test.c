/*
 * fprint-test - drive the VeriMark TOD module through the public libfprint
 * API, the same way fprintd does, without installing anything:
 *
 *   FP_TOD_DRIVERS_DIR=<dir with the module> fprint-test list
 *   fprint-test enroll right-index.print
 *   fprint-test verify right-index.print
 *   fprint-test identify a.print b.print ...
 *   fprint-test delete right-index.print
 *   fprint-test suspend   (identify against the device's prints, with a
 *                          suspend/resume cycle while waiting for the finger)
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <fprint.h>
#include <stdio.h>
#include <string.h>

static void describe (FpPrint *p);

static FpPrint *
load_print (const char *path, GError **error)
{
  g_autofree guchar *data = NULL;
  gsize len;

  if (!g_file_get_contents (path, (gchar **) &data, &len, error))
    return NULL;
  return fp_print_deserialize (data, len, error);
}

static void
enroll_progress (FpDevice *dev, gint stage, FpPrint *print, gpointer user, GError *error)
{
  if (error)
    printf ("  stage %d: retry (%s)\n", stage, error->message);
  else
    printf ("  stage %d/%d\n", stage, fp_device_get_nr_enroll_stages (dev));
  fflush (stdout);
}

/* ---- suspend: what fprintd does on PrepareForSleep during a verify ---- */

typedef struct
{
  GMainLoop *loop;
  gboolean   identify_done;
  FpPrint   *match;
  GError    *error;
} SuspendTest;

static void
st_identify_done (GObject *src, GAsyncResult *res, gpointer user)
{
  SuspendTest *t = user;

  printf ("identify finished\n");
  t->identify_done = TRUE;
  fp_device_identify_finish (FP_DEVICE (src), res, &t->match, NULL, &t->error);
  g_main_loop_quit (t->loop);
}

static void
st_async_done (GObject *src, GAsyncResult *res, gpointer user)
{
  GAsyncResult **out = user;

  *out = g_object_ref (res);
}

/* Runs the main context for up to @ms, or until *@res is set. */
static gboolean
st_wait (GAsyncResult **res, guint ms)
{
  gint64 end = g_get_monotonic_time () + ms * 1000;

  while ((!res || !*res) && g_get_monotonic_time () < end)
    if (!g_main_context_iteration (NULL, FALSE))
      g_usleep (10000);
  return res && *res;
}

static void
st_pump (guint ms)
{
  st_wait (NULL, ms);
}

static int
suspend_test (FpDevice *dev, GError **error)
{
  g_autoptr(GPtrArray) gallery = fp_device_list_prints_sync (dev, NULL, error);
  g_autoptr(GMainLoop) loop = g_main_loop_new (NULL, FALSE);
  g_autoptr(GAsyncResult) sres = NULL;
  g_autoptr(GAsyncResult) rres = NULL;
  g_autoptr(GError) serr = NULL;
  g_autoptr(GError) rerr = NULL;
  SuspendTest t = { .loop = loop };

  if (!gallery)
    return 1;
  if (gallery->len == 0)
    {
      fprintf (stderr, "no libfprint prints on the device\n");
      return 1;
    }
  printf ("identifying against %u print(s); do NOT touch the sensor yet\n", gallery->len);
  fflush (stdout);
  fp_device_identify (dev, gallery, NULL, NULL, NULL, NULL, st_identify_done, &t);
  st_pump (2000);

  printf ("suspending...\n");
  fflush (stdout);
  fp_device_suspend (dev, NULL, st_async_done, &sres);
  if (!st_wait (&sres, 5000))
    {
      fprintf (stderr, "FAIL: suspend did not complete within 5 s\n");
      return 1;
    }
  fp_device_suspend_finish (dev, sres, &serr);
  printf ("suspend: %s; identify %s\n", serr ? serr->message : "ok",
          t.identify_done ? "already finished (bad)" : "still running (good)");
  printf ("close while suspended (fprintd's release) would %s\n",
          t.identify_done ? "fail with BUSY" : "not happen");
  printf ("simulated sleep for 3 s, touching the sensor now must have no effect\n");
  fflush (stdout);
  st_pump (3000);

  fp_device_resume (dev, NULL, st_async_done, &rres);
  if (!st_wait (&rres, 5000))
    {
      fprintf (stderr, "FAIL: resume did not complete within 5 s\n");
      return 1;
    }
  fp_device_resume_finish (dev, rres, &rerr);
  printf ("resume: %s\n", rerr ? rerr->message : "ok");
  if (!t.identify_done)
    {
      printf ("now touch the sensor with the enrolled finger...\n");
      fflush (stdout);
      g_main_loop_run (loop);
    }
  if (t.error)
    {
      g_propagate_error (error, t.error);
      return 1;
    }
  printf ("%s\n", t.match ? "MATCH" : "NO MATCH");
  if (!t.match)
    return 3;
  describe (t.match);
  g_object_unref (t.match);
  return 0;
}

static void
describe (FpPrint *p)
{
  const GDate *date = fp_print_get_enroll_date (p);
  char buf[32] = "";

  if (date && g_date_valid (date))
    g_date_strftime (buf, sizeof buf, "%Y-%m-%d", date);
  printf ("  finger %d, user '%s', enrolled %s, driver %s, device stored %d\n",
          fp_print_get_finger (p), fp_print_get_username (p) ?: "", buf,
          fp_print_get_driver (p), fp_print_get_device_stored (p));
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) ctx = fp_context_new ();
  g_autoptr(GError) error = NULL;
  GPtrArray *devices;
  FpDevice *dev = NULL;
  const char *cmd;
  int rc = 1;

  if (argc < 2)
    {
      fprintf (stderr, "usage: fprint-test list|enroll FILE|verify FILE|identify FILE...|delete FILE|clear|suspend\n");
      return 2;
    }
  cmd = argv[1];

  devices = fp_context_get_devices (ctx);
  for (guint i = 0; i < devices->len && !dev; i++)
    if (g_strcmp0 (fp_device_get_driver (g_ptr_array_index (devices, i)), "verimark") == 0)
      dev = g_ptr_array_index (devices, i);
  if (!dev)
    {
      fprintf (stderr, "no device handled by the verimark driver (%u devices found)\n",
               devices->len);
      return 1;
    }
  printf ("device: %s (%s), features 0x%x, %d enroll stages\n", fp_device_get_name (dev),
          fp_device_get_device_id (dev), fp_device_get_features (dev),
          fp_device_get_nr_enroll_stages (dev));
  if (!fp_device_open_sync (dev, NULL, &error))
    {
      fprintf (stderr, "open failed: %s\n", error->message);
      return 1;
    }

  if (!strcmp (cmd, "list"))
    {
      g_autoptr(GPtrArray) prints = fp_device_list_prints_sync (dev, NULL, &error);
      if (prints)
        {
          printf ("%u print(s) on the device\n", prints->len);
          for (guint i = 0; i < prints->len; i++)
            describe (g_ptr_array_index (prints, i));
          rc = 0;
        }
    }
  else if (!strcmp (cmd, "enroll") && argc > 2)
    {
      FpPrint *tmpl = fp_print_new (dev);
      g_autoptr(FpPrint) print = NULL;
      g_autofree guchar *data = NULL;
      gsize len;

      fp_print_set_finger (tmpl, FP_FINGER_RIGHT_INDEX);
      fp_print_set_username (tmpl, g_get_user_name ());
      printf ("enrolling, touch the sensor repeatedly...\n");
      fflush (stdout);
      print = fp_device_enroll_sync (dev, tmpl, NULL, enroll_progress, NULL, &error);
      if (print && fp_print_serialize (print, &data, &len, &error) &&
          g_file_set_contents (argv[2], (gchar *) data, len, &error))
        {
          printf ("enrolled, print saved to %s\n", argv[2]);
          describe (print);
          rc = 0;
        }
    }
  else if (!strcmp (cmd, "verify") && argc > 2)
    {
      g_autoptr(FpPrint) print = load_print (argv[2], &error);
      gboolean match = FALSE;

      if (print)
        {
          printf ("verifying, touch the sensor...\n");
          fflush (stdout);
          if (fp_device_verify_sync (dev, print, NULL, NULL, NULL, &match, NULL, &error))
            {
              printf ("%s\n", match ? "MATCH" : "NO MATCH");
              rc = match ? 0 : 3;
            }
        }
    }
  else if (!strcmp (cmd, "identify") && argc > 2)
    {
      g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
      g_autoptr(FpPrint) match = NULL;

      for (int i = 2; i < argc && !error; i++)
        {
          FpPrint *p = load_print (argv[i], &error);
          if (p)
            g_ptr_array_add (gallery, p);
        }
      if (!error)
        {
          printf ("identifying against %u print(s), touch the sensor...\n", gallery->len);
          fflush (stdout);
          if (fp_device_identify_sync (dev, gallery, NULL, NULL, NULL, &match, NULL, &error))
            {
              for (guint i = 0; match && i < gallery->len; i++)
                if (g_ptr_array_index (gallery, i) == match)
                  printf ("MATCH %s\n", argv[i + 2]);
              if (!match)
                printf ("NO MATCH\n");
              rc = match ? 0 : 3;
            }
        }
    }
  else if (!strcmp (cmd, "delete") && argc > 2)
    {
      g_autoptr(FpPrint) print = load_print (argv[2], &error);
      if (print && fp_device_delete_print_sync (dev, print, NULL, &error))
        {
          printf ("deleted\n");
          rc = 0;
        }
    }
  else if (!strcmp (cmd, "suspend"))
    rc = suspend_test (dev, &error);
  else if (!strcmp (cmd, "clear"))
    {
      if (fp_device_clear_storage_sync (dev, NULL, &error))
        {
          printf ("cleared\n");
          rc = 0;
        }
    }
  else
    fprintf (stderr, "unknown command or missing argument\n");

  if (error)
    fprintf (stderr, "%s failed: %s\n", cmd, error->message);
  g_clear_error (&error);
  if (!fp_device_close_sync (dev, NULL, &error))
    fprintf (stderr, "close failed: %s\n", error->message);
  return rc;
}
