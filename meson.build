project(
    'spdm',
    'cpp',
    version: '1.0',
    meson_version: '>=1.1.1',
    default_options: ['cpp_std=c++23', 'warning_level=3'],
)

spdmd_deps = [
    dependency('phosphor-logging'),
    dependency('sdbusplus'),
    dependency('phosphor-dbus-interfaces'),
]

sanitizer_flags = []

# Add coverage flags if enabled
if get_option('coverage')
    sanitizer_flags += ['--coverage']
endif

spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/utils.cpp',
    'requester/spdm_dbus_responder.cpp',
    'requester/component_integrity_dbus.cpp',
]

spdmd_includes = include_directories('requester')

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    cpp_args: sanitizer_flags,
    install: true,
    install_dir: 'libexec',
)

# Test subdirectory
if get_option('tests')
    # Pass sanitizer flags to tests
    sanitizer_flags_for_tests = sanitizer_flags
    subdir('tests')
endif

