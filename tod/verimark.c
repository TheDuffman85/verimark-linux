/*
 * libfprint TOD driver for the Kensington VeriMark Desktop (K62330WW,
 * USB 047d:00f2), a Synaptics match-in-sensor device.
 *
 * Templates never leave the sensor. A print stores the sensor's template id
 * (TUID) in its fpi-data; the libvmk payload stored next to the template
 * carries the libfprint user id so prints can be listed again.
 *
 * libvmk is synchronous, so every action runs in a GTask worker thread.
 * Progress reports are posted to the device's main context in order; the
 * GTask completion is queued behind them on the same context.
 *
 * System suspend: the capture loop is stopped and the worker parks until
 * resume, then arms the capture again, so a running verify/enroll survives
 * the suspend (see park_for_suspend()).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define G_LOG_DOMAIN "libfprint-verimark"

#include <drivers_api.h>

#include "vmk.h"
#include "vmk-paths.h"

#include <string.h>
#include <time.h>

#define VERIMARK_ENROLL_STAGES 7   /* sensor reports progress in steps of 100/7 */
#define VERIMARK_IFACE         1   /* interface 0 is the FIDO HID */
#define VERIMARK_INTR_EP       0x83

G_DECLARE_FINAL_TYPE (FpiDeviceVerimark, fpi_device_verimark, FPI, DEVICE_VERIMARK, FpDevice)

struct _FpiDeviceVerimark
{
  FpDevice      parent;

  GUsbDevice   *usb;
  guint8        intr_ep;
  vmk_dev      *vmk;
  GCancellable *cancellable;   /* of the running action, polled by the worker */
  GMainContext *context;       /* where reports are delivered */

  GMutex        suspend_lock;
  GCond         suspend_cond;
  gint          suspend_requested;  /* between dev_suspend() and dev_resume() */
  gboolean      suspend_reported;   /* fpi_device_suspend_complete() was called */
  GAsyncResult *deferred;           /* action that ended during suspend */
};

G_DEFINE_TYPE (FpiDeviceVerimark, fpi_device_verimark, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = 0x047d, .pid = 0x00f2 },
  { .vid = 0, .pid = 0 },
};

/* ---- libvmk glue ------------------------------------------------------------ */

static void
vmk_log_cb (int level, const char *msg, void *user)
{
  (void) user;
  if (level <= VMK_LOG_WARN)
    g_warning ("%s", msg);
  else
    g_debug ("%s", msg);
}

static int
map_usb_error (GError *error)
{
  if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
    return VMK_E_TIMEOUT;
  if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED))
    return VMK_E_CANCELLED;
  g_debug ("USB transfer failed: %s", error->message);
  return VMK_E_IO;
}

/* Transfers are not cancellable: aborting one mid-command would desync the
 * TLS sequence numbers. Cancellation is checked between commands instead. */
static int
t_control (void *user, uint8_t rt, uint8_t req, uint16_t value, uint16_t index, uint8_t *data,
           uint16_t len, size_t *actual, unsigned timeout_ms)
{
  FpiDeviceVerimark *self = user;
  g_autoptr(GError) error = NULL;
  gsize done = 0;

  if (!g_usb_device_control_transfer (self->usb,
                                      (rt & 0x80) ? G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST
                                                  : G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                      (GUsbDeviceRequestType) ((rt >> 5) & 3),
                                      (GUsbDeviceRecipient) (rt & 0x1f),
                                      req, value, index, data, len, &done, timeout_ms, NULL,
                                      &error))
    return map_usb_error (error);
  if (actual)
    *actual = done;
  return VMK_OK;
}

static int
t_intr_in (void *user, uint8_t *data, size_t len, size_t *actual, unsigned timeout_ms)
{
  FpiDeviceVerimark *self = user;
  g_autoptr(GError) error = NULL;
  gsize done = 0;

  *actual = 0;
  if (!g_usb_device_interrupt_transfer (self->usb, self->intr_ep, data, len, &done, timeout_ms,
                                        NULL, &error))
    return map_usb_error (error);
  *actual = done;
  return VMK_OK;
}

static int
t_reset (void *user)
{
  FpiDeviceVerimark *self = user;
  g_autoptr(GError) error = NULL;

  g_usb_device_release_interface (self->usb, VERIMARK_IFACE, 0, NULL);
  if (!g_usb_device_reset (self->usb, &error) ||
      !g_usb_device_claim_interface (self->usb, VERIMARK_IFACE, 0, &error))
    {
      g_warning ("USB reset failed: %s", error->message);
      return VMK_E_IO;
    }
  return VMK_OK;
}

static bool
t_is_cancelled (void *user)
{
  FpiDeviceVerimark *self = user;

  /* a suspend request stops the capture loops like a cancellation */
  return g_atomic_int_get (&self->suspend_requested) ||
         (self->cancellable && g_cancellable_is_cancelled (self->cancellable));
}

static GError *
vmk_error (int r)
{
  switch (r)
    {
    case VMK_E_CANCELLED:
      return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation was cancelled");
    case VMK_E_NOT_FOUND:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND);
    case VMK_E_FULL:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL);
    case VMK_E_PROTO:
    case VMK_E_STATUS:
    case VMK_E_CRYPTO:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", vmk_strerror (r));
    case VMK_E_UNSUPPORTED:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED, "%s", vmk_strerror (r));
    default:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "%s", vmk_strerror (r));
    }
}

/* ---- print data --------------------------------------------------------------- */

static void
print_set_tuid (FpPrint *print, const vmk_tuid tuid)
{
  GVariant *data = g_variant_new ("(@ay)",
                                  g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, tuid, 16, 1));

  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", data, NULL);
}

static gboolean
print_get_tuid (FpPrint *print, vmk_tuid tuid)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) bytes = NULL;
  const guint8 *p;
  gsize n = 0;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_check_format_string (data, "(@ay)", FALSE))
    return FALSE;
  g_variant_get (data, "(@ay)", &bytes);
  p = g_variant_get_fixed_array (bytes, &n, 1);
  if (n != 16)
    return FALSE;
  memcpy (tuid, p, 16);
  return TRUE;
}

/* A print for an enrollment made by this driver, filled from the libfprint
 * user id in its payload; NULL for other enrollments (Windows). */
static FpPrint *
print_from_record (FpDevice *device, const vmk_record *rec)
{
  g_autofree char *uid = vmk_payload_get_user_id (rec->payload, rec->payload_len);
  FpPrint *print;

  if (!uid)
    return NULL;
  print = fp_print_new (device);
  print_set_tuid (print, rec->tuid);
  if (!fpi_print_fill_from_user_id (print, uid))
    fp_print_set_description (print, uid);
  return print;
}

static const vmk_record *
find_record (const vmk_record *recs, size_t n, const vmk_tuid tuid)
{
  for (size_t i = 0; i < n; i++)
    if (memcmp (recs[i].tuid, tuid, 16) == 0)
      return &recs[i];
  return NULL;
}

/* ---- reports from the worker ---------------------------------------------------- */

typedef enum {
  REPORT_FINGER_NEEDED,
  REPORT_FINGER_DONE,
  REPORT_ENROLL_STAGE,
  REPORT_ENROLL_RETRY,
  REPORT_VERIFY,
  REPORT_IDENTIFY,
} ReportKind;

typedef struct
{
  FpDevice  *device;
  ReportKind kind;
  int        value;
  FpPrint   *print;   /* identify match (gallery print, borrowed by the device) */
  FpPrint   *scan;    /* identify: the enrollment the scan matched on the sensor */
  char      *msg;
} Report;

static void
report_free (gpointer data)
{
  Report *r = data;

  g_clear_object (&r->device);
  g_clear_object (&r->print);
  g_clear_object (&r->scan);
  g_free (r->msg);
  g_free (r);
}

static gboolean
report_dispatch (gpointer data)
{
  Report *r = data;

  switch (r->kind)
    {
    case REPORT_FINGER_NEEDED:
      fpi_device_report_finger_status (r->device, FP_FINGER_STATUS_NEEDED);
      break;
    case REPORT_FINGER_DONE:
      fpi_device_report_finger_status (r->device, FP_FINGER_STATUS_NONE);
      break;
    case REPORT_ENROLL_STAGE:
      fpi_device_enroll_progress (r->device, r->value, NULL, NULL);
      break;
    case REPORT_ENROLL_RETRY:
      fpi_device_enroll_progress (r->device, r->value, NULL,
                                  fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL, "%s",
                                                            r->msg));
      break;
    case REPORT_VERIFY:
      fpi_device_verify_report (r->device, r->value ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, NULL,
                                NULL);
      break;
    case REPORT_IDENTIFY:
      fpi_device_identify_report (r->device, r->print, r->scan, NULL);
      break;
    }
  return G_SOURCE_REMOVE;
}

/* Always queues: g_main_context_invoke() would run @func right in the worker
 * thread whenever no thread owns the context at that moment. */
static void
queue_on_context (FpiDeviceVerimark *self, GSourceFunc func, gpointer data, GDestroyNotify destroy)
{
  g_autoptr(GSource) source = g_idle_source_new ();

  g_source_set_priority (source, G_PRIORITY_DEFAULT);
  g_source_set_callback (source, func, data, destroy);
  g_source_attach (source, self->context);
}

static Report *
report_new (FpiDeviceVerimark *self, ReportKind kind, int value, FpPrint *print, const char *msg)
{
  Report *r = g_new0 (Report, 1);

  r->device = g_object_ref (FP_DEVICE (self));
  r->kind = kind;
  r->value = value;
  r->print = print ? g_object_ref (print) : NULL;
  r->msg = g_strdup (msg);
  return r;
}

static void
post_report (FpiDeviceVerimark *self, ReportKind kind, int value, FpPrint *print, const char *msg)
{
  queue_on_context (self, report_dispatch, report_new (self, kind, value, print, msg), report_free);
}

static void
post_identify (FpiDeviceVerimark *self, FpPrint *match, FpPrint *scan)
{
  Report *r = report_new (self, REPORT_IDENTIFY, 0, match, NULL);

  r->scan = scan ? g_object_ref (scan) : NULL;
  queue_on_context (self, report_dispatch, r, report_free);
}

/* ---- action plumbing -------------------------------------------------------------- */

static void
finish_action (FpDevice *device, GAsyncResult *res)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (device);
  GError *error = NULL;
  gpointer result = g_task_propagate_pointer (G_TASK (res), &error);

  g_clear_object (&self->cancellable);
  switch (fpi_device_get_current_action (device))
    {
    case FPI_DEVICE_ACTION_OPEN:
      fpi_device_open_complete (device, error);
      break;
    case FPI_DEVICE_ACTION_CLOSE:
      fpi_device_close_complete (device, error);
      break;
    case FPI_DEVICE_ACTION_ENROLL:
      fpi_device_enroll_complete (device, result, error);
      break;
    case FPI_DEVICE_ACTION_VERIFY:
      fpi_device_verify_complete (device, error);
      break;
    case FPI_DEVICE_ACTION_IDENTIFY:
      fpi_device_identify_complete (device, error);
      break;
    case FPI_DEVICE_ACTION_LIST:
      fpi_device_list_complete (device, result, error);
      break;
    case FPI_DEVICE_ACTION_DELETE:
      fpi_device_delete_complete (device, error);
      break;
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
      fpi_device_clear_storage_complete (device, error);
      break;
    default:
      g_assert_not_reached ();
    }
}

/* Reports the suspend once; returns FALSE if it was already reported. */
static gboolean
mark_suspend_reported (FpiDeviceVerimark *self)
{
  gboolean first;

  g_mutex_lock (&self->suspend_lock);
  first = self->suspend_requested && !self->suspend_reported;
  if (first)
    self->suspend_reported = TRUE;
  g_mutex_unlock (&self->suspend_lock);
  return first;
}

static void
action_done (GObject *object, GAsyncResult *res, gpointer user_data)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (object);
  FpDevice *device = FP_DEVICE (object);

  /* An action that ends while a suspend is pending is completed after resume:
   * fprintd clients answer a result by releasing the device, and libfprint
   * refuses to close a suspended device. fprintd then drops the claim while
   * the device stays open, and every later claim fails until fprintd exits. */
  if (g_atomic_int_get (&self->suspend_requested))
    {
      g_debug ("action ended during suspend, completing it after resume");
      g_set_object (&self->deferred, res);
      if (mark_suspend_reported (self))
        fpi_device_suspend_complete (device, NULL);
      return;
    }
  finish_action (device, res);
}

static void
run_action (FpDevice *device, GTaskThreadFunc func, gpointer data, GDestroyNotify destroy)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (device);
  g_autoptr(GTask) task = g_task_new (device, NULL, action_done, NULL);

  self->context = g_main_context_get_thread_default ();
  if (!self->context)
    self->context = g_main_context_default ();
  g_set_object (&self->cancellable, fpi_device_get_cancellable (device));
  g_task_set_task_data (task, data, destroy);
  g_task_run_in_thread (task, func);
}

#define RETURN_VMK_ERROR(task, r) \
  do { g_task_return_error (task, vmk_error (r)); return; } while (0)

/* ---- suspend / resume ---------------------------------------------------------------- */

static gboolean
report_suspended (gpointer data)
{
  FpiDeviceVerimark *self = data;

  if (mark_suspend_reported (self))
    fpi_device_suspend_complete (FP_DEVICE (self), NULL);
  return G_SOURCE_REMOVE;
}

/* Called by the worker when vmk_capture() returned VMK_E_CANCELLED. On a
 * suspend request the capture has already been ended cleanly (events off,
 * FRAME_FINISH, LED off); the worker reports the device as suspended and
 * waits without touching USB. Returns TRUE after resume (capture again),
 * FALSE for a real cancellation. */
static gboolean
park_for_suspend (FpiDeviceVerimark *self)
{
  gboolean resumed;

  g_mutex_lock (&self->suspend_lock);
  if (!self->suspend_requested)
    {
      g_mutex_unlock (&self->suspend_lock);
      return FALSE;
    }
  g_debug ("capture stopped for system suspend");
  queue_on_context (self, report_suspended, g_object_ref (self), g_object_unref);
  while (self->suspend_requested && !g_cancellable_is_cancelled (self->cancellable))
    g_cond_wait_until (&self->suspend_cond, &self->suspend_lock,
                       g_get_monotonic_time () + 100 * G_TIME_SPAN_MILLISECOND);
  resumed = !self->suspend_requested;
  g_mutex_unlock (&self->suspend_lock);
  if (resumed)
    g_debug ("resumed, arming the capture again");
  return resumed;
}

/* vmk_capture() wrapped in finger status reports, restarted after a suspend.
 * If the sensor lost its session while suspended, the next command fails and
 * the action ends with an error after resume; the following open recovers. */
static int
capture (FpiDeviceVerimark *self)
{
  int r;

  do
    {
      post_report (self, REPORT_FINGER_NEEDED, 0, NULL, NULL);
      r = vmk_capture (self->vmk, 0);
      post_report (self, REPORT_FINGER_DONE, 0, NULL, NULL);
    }
  while (r == VMK_E_CANCELLED && park_for_suspend (self));
  return r;
}

/* Only called while enroll, verify or identify runs; libfprint waits for the
 * other actions to finish. The worker answers from park_for_suspend(), or
 * from action_done() if the action ends first. */
static void
dev_suspend (FpDevice *device)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (device);

  g_mutex_lock (&self->suspend_lock);
  self->suspend_reported = FALSE;
  g_atomic_int_set (&self->suspend_requested, TRUE);
  g_mutex_unlock (&self->suspend_lock);
}

static void
dev_resume (FpDevice *device)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (device);
  g_autoptr(GAsyncResult) deferred = g_steal_pointer (&self->deferred);

  g_mutex_lock (&self->suspend_lock);
  g_atomic_int_set (&self->suspend_requested, FALSE);
  self->suspend_reported = FALSE;
  g_cond_broadcast (&self->suspend_cond);
  g_mutex_unlock (&self->suspend_lock);

  fpi_device_resume_complete (device, NULL);
  if (deferred)
    finish_action (device, deferred);
}

/* ---- open / close ------------------------------------------------------------------ */

static int
pair_and_save (FpiDeviceVerimark *self, const char *path, vmk_pairing *pairing)
{
  int r;

  g_message ("pairing with the VeriMark sensor (pairing data: %s)", path);
  if ((r = vmk_pair (self->vmk, pairing)))
    return r;
  vmk_ensure_pairing_dir ();
  if ((r = vmk_pairing_save (pairing, path)))
    g_warning ("cannot store pairing data in %s: %s", path, vmk_strerror (r));
  return r;
}

static void
open_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceVerimark *self = source;
  const vmk_transport t = {
    .user = self, .intr_in = t_intr_in, .control = t_control, .reset = t_reset,
    .is_cancelled = t_is_cancelled,
  };
  g_autoptr(GError) error = NULL;
  vmk_pairing pairing;
  vmk_version v;
  char path[512];
  int r;

  if (!g_usb_device_claim_interface (self->usb, VERIMARK_IFACE, 0, &error))
    {
      g_task_return_error (task, g_steal_pointer (&error));
      return;
    }
  self->vmk = vmk_dev_new (&t);
  if ((r = vmk_get_version (self->vmk, &v)))
    goto fail;
  vmk_pairing_path (v.serial, path, sizeof path);

  r = vmk_pairing_load (&pairing, path);
  if (r != VMK_OK && r != VMK_E_NOT_FOUND)
    g_warning ("ignoring unreadable pairing data %s: %s", path, vmk_strerror (r));
  r = vmk_open (self->vmk, r == VMK_OK ? &pairing : NULL);
  /* Alert 42 arrives before the handshake is encrypted, so it is not
   * authenticated; it is also what the sensor sends after the key was paired
   * under Windows. Builds with -Dauto_repair=false leave re-pairing to
   * 'verimark-cli pair'. */
  if (r == VMK_E_BAD_PAIRING && !VMK_AUTO_REPAIR)
    g_warning ("the sensor rejected the stored pairing data in %s; run "
               "'sudo verimark-cli pair' to pair again", path);
  else if (r == VMK_E_NOT_PAIRED || r == VMK_E_BAD_PAIRING)
    {
      if (r == VMK_E_BAD_PAIRING)
        g_warning ("the sensor rejected the stored pairing data, pairing again");
      if ((r = pair_and_save (self, path, &pairing)) == VMK_OK)
        r = vmk_open (self->vmk, &pairing);
    }
  explicit_bzero (&pairing, sizeof pairing);
  /* libvmk refuses clear sessions by default; never authenticate over one */
  if (!r && !vmk_tls_active (self->vmk))
    r = VMK_E_INSECURE;
  if (r)
    goto fail;
  g_task_return_pointer (task, NULL, NULL);
  return;

fail:
  vmk_dev_free (self->vmk);
  self->vmk = NULL;
  g_usb_device_release_interface (self->usb, VERIMARK_IFACE, 0, NULL);
  RETURN_VMK_ERROR (task, r);
}

static void
dev_open (FpDevice *device)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (device);

  self->usb = fpi_device_get_usb_device (device);
  self->intr_ep = VERIMARK_INTR_EP;
  run_action (device, open_thread, NULL, NULL);
}

static void
close_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceVerimark *self = source;
  g_autoptr(GError) error = NULL;

  vmk_close (self->vmk);
  vmk_dev_free (self->vmk);
  self->vmk = NULL;
  if (!g_usb_device_release_interface (self->usb, VERIMARK_IFACE, 0, &error))
    g_debug ("releasing the interface failed: %s", error->message);
  g_task_return_pointer (task, NULL, NULL);
}

static void
dev_close (FpDevice *device)
{
  run_action (device, close_thread, NULL, NULL);
}

/* ---- enroll -------------------------------------------------------------------------- */

static void
enroll_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceVerimark *self = source;
  FpPrint *print = data;
  vmk_enroll_status st = { 0 };
  g_autofree char *user_id = NULL;
  int stage = 0, r;

  if ((r = vmk_enroll_start (self->vmk)))
    RETURN_VMK_ERROR (task, r);

  while (st.progress < 100)
    {
      r = capture (self);
      if (r || (r = vmk_enroll_add_image (self->vmk, &st)))
        break;
      if (st.rejected)
        {
          post_report (self, REPORT_ENROLL_RETRY, stage, NULL,
                       st.redundant ? "Scan covered the same area as before, move your finger a little"
                                    : "Scan was not usable, try again");
          continue;
        }
      if (st.progress == 100 && st.failed)
        {
          r = VMK_E_STATUS;
          break;
        }
      stage = MIN ((st.progress * VERIMARK_ENROLL_STAGES + 50) / 100, VERIMARK_ENROLL_STAGES);
      if (st.progress < 100)
        post_report (self, REPORT_ENROLL_STAGE, stage, NULL, NULL);
    }

  if (!r)
    {
      uint8_t *payload;
      size_t len;

      user_id = fpi_print_generate_user_id (print);
      if (!(r = vmk_payload_build (user_id, &payload, &len)))
        {
          r = vmk_enroll_commit (self->vmk, payload, len);
          free (payload);
        }
    }
  vmk_enroll_finish (self->vmk);
  if (r)
    RETURN_VMK_ERROR (task, r);

  /* the last stage is reported together with the finished print */
  post_report (self, REPORT_ENROLL_STAGE, VERIMARK_ENROLL_STAGES, NULL, NULL);
  print_set_tuid (print, st.tuid);
  g_task_return_pointer (task, g_object_ref (print), g_object_unref);
}

static void
dev_enroll (FpDevice *device)
{
  FpPrint *print = NULL;

  fpi_device_get_enroll_data (device, &print);
  /* the date becomes part of the user id stored on the sensor */
  if (!fp_print_get_enroll_date (print))
    {
      g_autoptr(GDate) today = g_date_new ();

      g_date_set_time_t (today, time (NULL));
      fp_print_set_enroll_date (print, today);
    }
  run_action (device, enroll_thread, g_object_ref (print), g_object_unref);
}

/* ---- verify / identify ------------------------------------------------------------------ */

typedef struct
{
  GPtrArray *prints;   /* FpPrint, gallery order */
  bool       verify;
} MatchData;

static void
match_data_free (gpointer data)
{
  MatchData *m = data;

  g_ptr_array_unref (m->prints);
  g_free (m);
}

static void
match_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceVerimark *self = source;
  MatchData *m = data;
  vmk_record *recs = NULL;
  size_t nrecs = 0, n = 0;
  g_autofree vmk_tuid *tuids = NULL;
  g_autofree FpPrint **owners = NULL;
  g_autofree const vmk_record **sources = NULL;
  g_autoptr(FpPrint) scanned = NULL;
  FpPrint *matched = NULL;
  vmk_match res;
  int r = VMK_OK;

  /* Only ask for templates the sensor still has: identifying against an
   * empty list would match every template on the sensor, including ones
   * enrolled under Windows. Identify also includes this driver's
   * enrollments that are missing from the gallery (left behind when the
   * host lost its print store): a match on one is reported as the scanned
   * print without a gallery match, and fprintd's duplicate check before an
   * enroll deletes it. Windows enrollments are never included. */
  if (!m->verify && (r = vmk_db_list (self->vmk, &recs, &nrecs)))
    RETURN_VMK_ERROR (task, r);
  tuids = g_new0 (vmk_tuid, m->prints->len + nrecs + 1);
  owners = g_new0 (FpPrint *, m->prints->len + nrecs + 1);
  sources = g_new0 (const vmk_record *, m->prints->len + nrecs + 1);

  for (guint i = 0; i < m->prints->len; i++)
    {
      FpPrint *p = g_ptr_array_index (m->prints, i);
      bool exists = false;

      if (!print_get_tuid (p, tuids[n]))
        continue;
      if (m->verify && (r = vmk_db_template_exists (self->vmk, tuids[n], &exists)))
        goto out;
      if (!m->verify)
        exists = (sources[n] = find_record (recs, nrecs, tuids[n])) != NULL;
      if (exists)
        owners[n++] = p;
    }
  for (size_t i = 0; i < nrecs; i++)
    {
      g_autofree char *uid = NULL;
      bool listed = false;

      for (size_t j = 0; j < n && !listed; j++)
        listed = sources[j] == &recs[i];
      if (listed || !(uid = vmk_payload_get_user_id (recs[i].payload, recs[i].payload_len)))
        continue;
      g_debug ("including an enrollment unknown to the host (%s)", uid);
      memcpy (tuids[n], recs[i].tuid, 16);
      sources[n++] = &recs[i];
    }
  if (m->verify && n == 0)
    {
      r = VMK_E_NOT_FOUND;
      goto out;
    }

  if ((r = capture (self)))
    goto out;

  memset (&res, 0, sizeof res);
  if (n && (r = vmk_identify (self->vmk, (const vmk_tuid *) tuids, n, &res)))
    goto out;
  if (!n)
    vmk_led (self->vmk, VMK_LED_NO_MATCH);
  for (size_t i = 0; res.matched && i < n; i++)
    if (memcmp (tuids[i], res.tuid, 16) == 0)
      {
        matched = owners[i];
        if (sources[i] && (scanned = print_from_record (FP_DEVICE (self), sources[i])))
          g_object_ref_sink (scanned);
        break;
      }
  vmk_match_clear (&res);

  if (m->verify)
    post_report (self, REPORT_VERIFY, matched != NULL, NULL, NULL);
  else
    post_identify (self, matched, scanned);

out:
  vmk_db_records_free (recs, nrecs);
  if (r)
    RETURN_VMK_ERROR (task, r);
  g_task_return_pointer (task, NULL, NULL);
}

static void
dev_verify (FpDevice *device)
{
  MatchData *m = g_new0 (MatchData, 1);
  FpPrint *print = NULL;

  fpi_device_get_verify_data (device, &print);
  m->prints = g_ptr_array_new_with_free_func (g_object_unref);
  g_ptr_array_add (m->prints, g_object_ref (print));
  m->verify = true;
  run_action (device, match_thread, m, match_data_free);
}

static void
dev_identify (FpDevice *device)
{
  MatchData *m = g_new0 (MatchData, 1);
  GPtrArray *gallery = NULL;

  fpi_device_get_identify_data (device, &gallery);
  m->prints = g_ptr_array_new_with_free_func (g_object_unref);
  for (guint i = 0; i < gallery->len; i++)
    g_ptr_array_add (m->prints, g_object_ref (g_ptr_array_index (gallery, i)));
  run_action (device, match_thread, m, match_data_free);
}

/* ---- storage ----------------------------------------------------------------------------- */

/* Only templates carrying a libfprint payload are reported, so fprintd never
 * sees (or garbage collects) enrollments made by the Windows driver. */
static void
list_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceVerimark *self = source;
  FpDevice *device = FP_DEVICE (self);
  g_autoptr(GPtrArray) prints = g_ptr_array_new_with_free_func (g_object_unref);
  vmk_record *recs;
  size_t n;
  int r;

  if ((r = vmk_db_list (self->vmk, &recs, &n)))
    RETURN_VMK_ERROR (task, r);
  for (size_t i = 0; i < n; i++)
    {
      FpPrint *print = print_from_record (device, &recs[i]);

      if (print)
        g_ptr_array_add (prints, print);
    }
  vmk_db_records_free (recs, n);
  g_task_return_pointer (task, g_steal_pointer (&prints), (GDestroyNotify) g_ptr_array_unref);
}

static void
dev_list (FpDevice *device)
{
  run_action (device, list_thread, NULL, NULL);
}

static void
delete_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceVerimark *self = source;
  vmk_tuid tuid;
  int r;

  if (!print_get_tuid (data, tuid))
    {
      g_task_return_error (task, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }
  if ((r = vmk_db_delete (self->vmk, tuid)))
    RETURN_VMK_ERROR (task, r);
  g_task_return_pointer (task, NULL, NULL);
}

static void
dev_delete (FpDevice *device)
{
  FpPrint *print = NULL;

  fpi_device_get_delete_data (device, &print);
  run_action (device, delete_thread, g_object_ref (print), g_object_unref);
}

/* Deletes every libfprint enrollment; Windows enrollments stay. */
static void
clear_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceVerimark *self = source;
  vmk_record *recs;
  size_t n;
  int r;

  if ((r = vmk_db_list (self->vmk, &recs, &n)))
    RETURN_VMK_ERROR (task, r);
  for (size_t i = 0; i < n && !r; i++)
    {
      g_autofree char *uid = vmk_payload_get_user_id (recs[i].payload, recs[i].payload_len);

      if (uid)
        r = vmk_db_delete (self->vmk, recs[i].tuid);
    }
  vmk_db_records_free (recs, n);
  if (r)
    RETURN_VMK_ERROR (task, r);
  g_task_return_pointer (task, NULL, NULL);
}

static void
dev_clear_storage (FpDevice *device)
{
  run_action (device, clear_thread, NULL, NULL);
}

/* ---- GObject -------------------------------------------------------------------------------- */

static void
fpi_device_verimark_finalize (GObject *object)
{
  FpiDeviceVerimark *self = FPI_DEVICE_VERIMARK (object);

  g_clear_object (&self->cancellable);
  g_clear_object (&self->deferred);
  if (self->vmk)
    vmk_dev_free (self->vmk);
  g_mutex_clear (&self->suspend_lock);
  g_cond_clear (&self->suspend_cond);
  G_OBJECT_CLASS (fpi_device_verimark_parent_class)->finalize (object);
}

static void
fpi_device_verimark_init (FpiDeviceVerimark *self)
{
  g_mutex_init (&self->suspend_lock);
  g_cond_init (&self->suspend_cond);
}

static void
fpi_device_verimark_class_init (FpiDeviceVerimarkClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  const char *debug = g_getenv ("VMK_DEBUG");

  G_OBJECT_CLASS (klass)->finalize = fpi_device_verimark_finalize;

  dev_class->id = "verimark";
  dev_class->full_name = "Kensington VeriMark Desktop";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = VERIMARK_ENROLL_STAGES;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->temp_hot_seconds = -1;
  dev_class->temp_cold_seconds = -1;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;
  dev_class->list = dev_list;
  dev_class->delete = dev_delete;
  dev_class->clear_storage = dev_clear_storage;
  dev_class->suspend = dev_suspend;
  dev_class->resume = dev_resume;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_STORAGE;

  /* VMK_DEBUG=1..3 adds libvmk info, debug and protocol traces */
  vmk_set_log_handler (vmk_log_cb, NULL,
                       VMK_LOG_WARN + (debug ? CLAMP (atoi (debug), 0, 3) : 0));
}

/* TOD entry point, looked up by libfprint's shared driver loader */
GType fpi_tod_shared_driver_get_type (void);

G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_verimark_get_type ();
}
