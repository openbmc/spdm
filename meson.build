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

spdmd_deps = [phosphor_dbus_interfaces_dep, phosphor_logging_dep, sdbusplus_dep]
spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/tcp_transport_discovery.cpp',
<<<<<<< PATCH SET (43ec4c Implement SPDM Policy D-Bus interface)
    'requester/utils.cpp',
    'requester/policy_manager.cpp',
    'requester/policy_manager.hpp',
=======
    'requester/utils/mapper.cpp',
>>>>>>> BASE      (b9fc9b Add systemd service for SPDM daemon)
]

systemd = dependency('systemd', required: false)

if systemd.found()
    systemd_unit_dir = systemd.get_variable('systemd_system_unit_dir')

    install_data('service/attestation.service', install_dir: systemd_unit_dir)
endif

policy_cache_path = get_option('localstatedir') + '/lib/spdm/policy.json'

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
    cpp_args: ['-DPOLICY_CACHE_PATH="' + policy_cache_path + '"'],
)
