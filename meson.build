project('verimark-linux', 'c',
  version: '0.1.0',
  license: 'LGPL-2.1-or-later',
  meson_version: '>= 0.60',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=debugoptimized'])

# GObject/GTask callbacks have fixed signatures
add_project_arguments('-Wno-unused-parameter', language: 'c')

libcrypto = dependency('libcrypto')
vmk_args = ['-DVMK_PAIRING_DIR="@0@"'.format(get_option('pairing_dir'))]
vmk_inc = include_directories('src')

libvmk = static_library('vmk',
  'src/vmk-crypto.c', 'src/vmk-dev.c', 'src/vmk-mis.c', 'src/vmk-tls.c',
  c_args: vmk_args,
  dependencies: libcrypto,
  gnu_symbol_visibility: 'hidden',
  pic: true)
vmk_dep = declare_dependency(
  link_with: libvmk,
  include_directories: vmk_inc,
  compile_args: vmk_args,
  dependencies: libcrypto)

libusb = dependency('libusb-1.0', required: get_option('cli'))
if libusb.found()
  executable('verimark-cli', 'cli/verimark-cli.c',
    dependencies: [vmk_dep, libusb],
    install: true,
    install_dir: get_option('sbindir'))
endif

tod = dependency('libfprint-2-tod-1', required: get_option('tod'))
if tod.found()
  tod_dir = get_option('tod_driversdir')
  if tod_dir == ''
    tod_dir = tod.get_variable(pkgconfig: 'tod_driversdir')
  endif
  shared_module('fprint-tod-verimark', 'tod/verimark.c',
    c_args: '-DVMK_AUTO_REPAIR=@0@'.format(get_option('auto_repair') ? 1 : 0),
    dependencies: [vmk_dep, tod, dependency('libfprint-2'), dependency('gusb'),
                   dependency('gio-2.0')],
    gnu_symbol_visibility: 'hidden',
    install: true,
    install_dir: tod_dir)

  # hardware test harness, see tests/README.md
  executable('fprint-test', 'tests/fprint-test.c',
    dependencies: dependency('libfprint-2'))
endif

# The simulated sensor replaces vmk_raw_exchange(), so it links the TLS layer
# without vmk-dev.c.
test('tls', executable('test-tls',
  'src/vmk-crypto.c', 'src/vmk-tls.c', 'tests/test-tls.c',
  include_directories: vmk_inc,
  dependencies: libcrypto))

# A spoofed sensor that claims to be unprovisioned must not get a clear session.
test('session', executable('test-session', 'tests/test-session.c',
  dependencies: vmk_dep))
