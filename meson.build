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

phosphor_logging_dep = dependency('phosphor-logging')
sdbusplus_dep = dependency('sdbusplus')

spdmd_deps = [phosphor_logging_dep, sdbusplus_dep]
spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/tcp_transport_discovery.cpp',
    'requester/utils.cpp',
    'requester/policy_manager.cpp',
    'requester/policy_manager.hpp',
    'requester/secure_exchange.cpp',
    'requester/secure_exchange.hpp',
]

systemd = dependency('systemd', required: false)

if systemd.found()
    systemd_unit_dir = systemd.get_variable('systemdsystemunitdir')

    install_data('service/attestation.service', install_dir: systemd_unit_dir)
endif

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
)
