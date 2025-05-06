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

cpp = meson.get_compiler('cpp')

phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')
sdbusplus_dep = dependency('sdbusplus')
systemd_dep = dependency('systemd')

# Get CLI11 dependency
if cpp.has_header('CLI/CLI.hpp')
    CLI11_dep = declare_dependency()
else
    CLI11_dep = dependency(
        'CLI11',
        include_type: 'system',
        default_options: ['tests=disabled'],
    )
endif

spdmd_deps = [
    CLI11_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
]
spdmd_includes = include_directories('requester')

spdmd_src = [
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/tcp_transport_discovery.cpp',
    'requester/policy_manager.cpp',
    'requester/utils/mapper.cpp',
    'requester/utils/paths.cpp',
    'requester/spdm_dbus_responder.cpp',
    'requester/component_integrity_dbus.cpp',
]

spdmd_lib = static_library(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
)

install_data(
    'service/spdmd.service',
    install_dir: systemd_dep.get_variable('systemd_system_unit_dir'),
)

spdm_state_dir = get_option('localstatedir') + '/lib/spdm'

conf_data = configuration_data()
conf_data.set_quoted('SPDM_STATE_DIR', spdm_state_dir)

configure_file(
    input: 'config.hpp.in',
    output: 'config.hpp',
    configuration: conf_data,
)

executable(
    'spdmd',
    'requester/spdmd.cpp',
    link_with: spdmd_lib,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
)

# Test subdirectory
if get_option('tests').allowed()
    subdir('tests')
endif
