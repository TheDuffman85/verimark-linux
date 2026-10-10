Run the offline TLS regression with the OpenSSL development headers installed:

```sh
cc -std=gnu11 -O2 -Wall -Wextra -I src \
  src/vmk-crypto.c src/vmk-tls.c tests/test-tls.c -o /tmp/vmk-test-tls -lcrypto
/tmp/vmk-test-tls
```

The simulated sensor decodes CertificateVerify with OpenSSL, rejects trailing
padding, verifies the host signature over the handshake transcript, derives
the session keys from its own ECDH private key, authenticates client Finished,
and sends server Finished. All 64 handshakes use generated keys; no hardware
or saved pairing credentials are needed. Do not compile with `-DNDEBUG`.
It also checks that the session ends on a clear alert or a record that does
not authenticate, that niseTls' "session resumed" alert cannot replace the
server Finished, that a clear alert 42 after the sensor's ChangeCipherSpec is
not taken as a pairing rejection, and that CBC without sequence numbers in
the MAC is refused.

`test-session` (`meson test session`) links all of libvmk against a fake EP0
device that claims to be unprovisioned and answers IDENTIFY with "match". The
default policy must refuse the session and send nothing that carries a result;
with `vmk_allow_clear_session()` (CLI) the clear session works.

## libfprint hardware harness

`fprint-test` (built with the TOD module) drives the driver through the
public libfprint API, the same calls fprintd makes. Point libfprint at the
build directory instead of installing the module:

```sh
mkdir -p /tmp/vmk-tod && ln -sf "$PWD/build/libfprint-tod-verimark.so" /tmp/vmk-tod/
export FP_TOD_DRIVERS_DIR=/tmp/vmk-tod VMK_PAIRING_DIR=/var/lib/fprint/verimark
sudo -E build/fprint-test list
sudo -E build/fprint-test enroll /tmp/right-index.print
sudo -E build/fprint-test verify /tmp/right-index.print
sudo -E build/fprint-test identify /tmp/right-index.print
sudo -E build/fprint-test delete /tmp/right-index.print
```

`sudo -E build/fprint-test suspend` identifies against the libfprint prints on
the sensor and runs `fp_device_suspend()`/`fp_device_resume()` while it waits
for the finger, as fprintd does on PrepareForSleep. Expected: suspend ok with
the identify still running, resume ok, then MATCH on touch.

`VMK_DEBUG=1..3` adds libvmk info, debug and protocol traces
(`G_MESSAGES_DEBUG=all` to see them). Stop fprintd first; only one process can
claim the sensor.
