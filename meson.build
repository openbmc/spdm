project(
    'spdm',
    'cpp',
    default_options: [
        'buildtype=debugoptimized',
        'cpp_std=c++23',
        'warning_level=3',
        'werror=true',
    ],
    version: '1.0',
    meson_version: '>=1.1.1',
)

phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')
sdbusplus_dep = dependency('sdbusplus')
systemd_dep = dependency('systemd')

spdmd_deps = [phosphor_dbus_interfaces_dep, phosphor_logging_dep, sdbusplus_dep]
spdmd_includes = include_directories('requester')

sanitizer_flags = []

# Add coverage flags if enabled
if get_option('coverage')
    sanitizer_flags += ['--coverage']
endif

spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/tcp_transport_discovery.cpp',
    'requester/utils/mapper.cpp',
    'requester/spdm_dbus_responder.cpp',
    'requester/component_integrity_dbus.cpp',
]

install_data(
    'service/spdmd.service',
    install_dir: systemd_dep.get_variable('systemd_system_unit_dir'),
)

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    cpp_args: sanitizer_flags,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
)

# Test subdirectory
if get_option('tests')
    # Pass sanitizer flags to tests
    sanitizer_flags_for_tests = sanitizer_flags
    subdir('tests')
endif
