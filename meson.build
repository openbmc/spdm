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

# Try to find libspdm using pkg-config first
libspdm_dep = dependency('libspdm', required: false)

# If pkg-config doesn't work, try to find it manually
if not libspdm_dep.found()
    libspdm_common_lib = meson.get_compiler('cpp').find_library(
        'spdm_common_lib',
        required: false,
    )
    libspdm_requester_lib = meson.get_compiler('cpp').find_library(
        'spdm_requester_lib',
        required: false,
    )
    libspdm_transport_mctp_lib = meson.get_compiler('cpp').find_library(
        'spdm_transport_mctp_lib',
        required: false,
    )
    libspdm_crypt_lib = meson.get_compiler('cpp').find_library(
        'spdm_crypt_lib',
        required: false,
    )
    libspdm_crypt_ext_lib = meson.get_compiler('cpp').find_library(
        'spdm_crypt_ext_lib',
        required: false,
    )

    if libspdm_common_lib.found() and libspdm_requester_lib.found() and libspdm_transport_mctp_lib.found() and libspdm_crypt_lib.found() and libspdm_crypt_ext_lib.found()
        libspdm_dep = declare_dependency(
            # libspdm 3.8.2 publishes mutually dependent static archives.
            # Keep them in one linker argument so Meson cannot separate the
            # group delimiters from the archives while ordering dependencies.
            link_args: [
                '-Wl,--start-group,-lspdm_requester_lib,-lspdm_transport_mctp_lib,-lspdm_common_lib,-lspdm_secured_message_lib,-lspdm_crypt_lib,-lspdm_crypt_ext_lib,-lcryptlib_openssl,-lmemlib,-lmalloclib,-lplatform_lib,-lrnglib,-ldebuglib,-lcrypto,--end-group',
            ],
            # '=' makes GCC resolve this path relative to the cross sysroot.
            compile_args: ['-I=/usr/include/libspdm'],
        )
    else
        error('libspdm not found. Please ensure libspdm is installed.')
    endif
endif

spdmd_deps = [
    CLI11_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    libspdm_dep,
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
    # Retain the local device-secret stubs, even though libspdm references
    # them only after the application archive would normally be scanned.
    link_whole: spdmd_lib,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
)

# Test subdirectory
if get_option('tests').allowed()
    subdir('tests')
endif
