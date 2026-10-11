# VeriMark Desktop driver for Linux

A libfprint driver for the Kensington VeriMark Desktop fingerprint key
(K62330WW, USB `047d:00f2`), so that it works with fprintd, GNOME/KDE login
and `pam_fprintd`. The sensor is a Synaptics match-in-sensor device: the
fingerprint templates are created, stored and matched inside the sensor, and
the host talks to it over a TLS session bound to a pairing key.

The protocol was reconstructed from the Windows driver
(`synaWudfBioUsb132.dll`, v6.0.9.1132).

## Parts

| path | what |
|---|---|
| `src/` | `libvmk`, the protocol library (USB transport, pairing, TLS, enroll/match, on-chip database) |
| `tod/verimark.c` | libfprint TOD module (loaded by the distribution's `libfprint-2-tod1`) |
| `cli/verimark-cli.c` | diagnostic tool that talks to the sensor without fprintd |
| `tests/` | offline TLS and session-policy tests, and a libfprint hardware harness |

## Supported systems

The driver is a libfprint TOD ("touch OEM driver") module, so it needs a
libfprint built with TOD support (`libfprint-2-tod1`). TOD is not part of
upstream libfprint; it is a separate branch that Ubuntu and Debian ship.

- **Ubuntu 24.04 and Linux Mint 22 (amd64)**: tested. The release packages
  are built on Ubuntu 24.04.
- **Other Debian and Ubuntu based distributions**: should work when built
  from source, with the same package names. The release packages may not
  install on other releases. Not tested.

## Build and install

```sh
sudo apt install build-essential meson ninja-build pkg-config \
    libssl-dev libusb-1.0-0-dev libfprint-2-tod-dev libgusb-dev
meson setup build
meson compile -C build
meson test -C build
sudo meson install -C build
sudo systemctl restart fprintd
```

This installs `libfprint-tod-verimark.so` into the TOD driver directory
(`/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/` on Ubuntu amd64) and
`verimark-cli` into `/usr/local/sbin`. Then enroll with `fprintd-enroll` or the desktop settings.

No udev rule is needed: fprintd runs as root.

## Debian package

```sh
sudo apt install debhelper dpkg-dev
dpkg-buildpackage -us -uc -b
sudo apt install ../verimark-driver_*.deb ../verimark-cli_*.deb
```

`verimark-driver` holds the TOD module and restarts fprintd when it
is installed or removed; `verimark-cli` holds the diagnostic tool, in
`/usr/sbin`. Purging the driver package (`apt purge`) deletes the pairing
secrets in `/var/lib/fprint/verimark`. If you installed with
`meson install` before, remove `/usr/local/sbin/verimark-cli` first, since
it would shadow the packaged one.

To release, set the new version in `meson.build` and `debian/changelog`, then
push a tag named after it (`git tag 0.2.0 && git push origin 0.2.0`) or run
the Release workflow on GitHub, which creates the tag. The workflow builds and
tests the packages and attaches them to a GitHub release.

## Pairing

On first use the driver pairs the host with the sensor and stores the pairing
secret in `/var/lib/fprint/verimark/<serial>.pair` (root only). The CLI uses
the same file. If the file is lost, or the sensor was paired by another host,
the driver pairs again automatically. The Windows driver then pairs again
itself the next time the key is used under Windows. To make re-pairing after
a rejection a manual step (`sudo verimark-cli pair`), configure with
`-Dauto_repair=false`; the rejection (TLS alert 42) is not authenticated, so
anyone able to inject USB traffic could otherwise force a re-pair.

## Security

The driver only works over the TLS session bound to the pairing. A sensor
that reports itself as unprovisioned is refused: GET_VERSION is not
authenticated, and a device spoofing the sensor could otherwise answer every
command, including "match", in the clear. Session errors (a record that does
not authenticate, an alert in the clear) end the session; the next open sets
up a new one. `verimark-cli` allows clear sessions for diagnostics.

Do not make the USB device node world accessible (`chmod o+rw`): any local
user could then pair their own host with the sensor and delete enrollments.

## The sensor and Windows

The sensor keeps up to 9 enrollments. Each enrollment made by this driver
carries a small payload marking it as a libfprint print. The driver only
lists, matches and clears its own enrollments; enrollments made under Windows
are left alone (`verimark-cli list` shows them as foreign records).
`verimark-cli erase` does delete everything, including Windows enrollments.

## Diagnostics

```sh
sudo systemctl stop fprintd
sudo verimark-cli info       # firmware, pairing, database usage
sudo verimark-cli list       # enrollments on the sensor
sudo verimark-cli -vvv dump  # raw object tree
sudo verimark-cli -v events  # finger events for 40 s
```

`events` logs the finger present/removed events; with `VMK_WATCH_EDGES=1` it
logs the finger down/up edge events instead (the sensor cannot report both).

For fprintd logs with protocol detail, run fprintd with `VMK_DEBUG=2` and
`G_MESSAGES_DEBUG=all`.

## License

GNU Lesser General Public License v2.1 or later (LGPL-2.1-or-later). See
[LICENSE](LICENSE).
