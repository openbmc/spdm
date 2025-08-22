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

# Try to find libspdm using pkg-config first
libspdm_dep = dependency('libspdm', required: false)

# If pkg-config doesn't work, try to find it manually
if not libspdm_dep.found()
    libspdm_lib = meson.get_compiler('cpp').find_library('spdm', required: false)
    libspdm_platform_lib = meson.get_compiler('cpp').find_library(
        'spdm_platform',
        required: false,
    )
    libspdm_crypto_lib = meson.get_compiler('cpp').find_library(
        'spdm_crypto',
        required: false,
    )

    if libspdm_lib.found() and libspdm_platform_lib.found() and libspdm_crypto_lib.found()
        libspdm_dep = declare_dependency(
            dependencies: [
                libspdm_lib,
                libspdm_platform_lib,
                libspdm_crypto_lib,
            ],
            include_directories: include_directories(
                '/usr/local/include/libspdm',
                '/usr/local/include/libspdm/include',
            ),
        )
    else
        error('libspdm not found. Please ensure libspdm is installed.')
    endif
endif

spdmd_deps = [
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    libspdm_dep,
]
spdmd_includes = include_directories('requester', '.')

spdmd_src = [
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/tcp_transport_discovery.cpp',
    'requester/policy_manager.cpp',
    'requester/utils/mapper.cpp',
    'requester/spdm_dbus_responder.cpp',
    'requester/component_integrity_dbus.cpp',
    'requester/trusted_component_dbus.cpp',
    'requester/spdm_device_secret_lib_stub.cpp',
    'requester/libspdm_mctp_transport.cpp',
    'requester/certificate_dbus.cpp',
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

policy_cache_path = get_option('localstatedir') + '/lib/spdm/policy.json'

conf_data = configuration_data()
conf_data.set_quoted('POLICY_CACHE_PATH', policy_cache_path)
conf_data.set10('POLICY_DEFAULT_ENABLED', get_option('enabled'))
conf_data.set10(
    'POLICY_DEFAULT_SECURE_SESSION_ENABLED',
    get_option('secure-session-enabled'),
)
conf_data.set10(
    'POLICY_DEFAULT_VERIFY_CERTIFICATE',
    get_option('verify-certificate'),
)
conf_data.set10(
    'POLICY_DEFAULT_ALLOW_EXTENDED_ALGORITHMS',
    get_option('allow-extended-algorithms'),
)

# Array options are stored as comma-separated strings in config.hpp.
# e.g. ['ALL', '1.2'] -> "ALL,1.2"
foreach opt_name : [
    ['allowed-versions', 'POLICY_DEFAULT_ALLOWED_VERSIONS'],
    ['allowed-algorithms-aead', 'POLICY_DEFAULT_ALLOWED_ALGORITHMS_AEAD'],
    [
        'allowed-algorithms-base-hash',
        'POLICY_DEFAULT_ALLOWED_ALGORITHMS_BASE_HASH',
    ],
    [
        'allowed-algorithms-base-asym',
        'POLICY_DEFAULT_ALLOWED_ALGORITHMS_BASE_ASYM',
    ],
]
    conf_data.set_quoted(opt_name[1], ','.join(get_option(opt_name[0])))
endforeach

configure_file(
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
