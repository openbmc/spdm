project(
    'spdm',
    'cpp',
    version: '1.0',
    default_options: [
        'buildtype=debugoptimized',
        'cpp_std=c++23',
        'warning_level=3',
    ],
)

# Dependencies
sdbusplus_dep = dependency('sdbusplus')
phosphor_logging_dep = dependency('phosphor-logging')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')

# Add libspdm dependency
sdk_path = '/home/guptar/openBMC/SDK/develop/06-03-25/sysroots/armv7ahf-vfpv4d16-openbmc-linux-gnueabi'
libspdm_inc = include_directories(
    sdk_path + '/usr/include/libspdm',
    sdk_path + '/usr/include/libspdm/include'
)
libspdm_dep = declare_dependency(
    include_directories: libspdm_inc,
    link_args: ['-L' + sdk_path + '/usr/lib', '-lspdm', '-lspdm_crypto', '-lspdm_platform']
)

# Source files
spdmd_src = [
    'src/spdmd.cpp',
    'src/spdmd_app.cpp',
    'src/spdm_discovery.cpp',
    'src/mctp_discovery.cpp',
    'src/spdm_dbus_responder.cpp',
    'src/spdm_device_secret_lib_stub.cpp',
    'src/component_integrity_dbus.cpp',
    'src/trusted_component_dbus.cpp',
    'src/libspdm_mctp_transport.cpp',
]

# Include directories
spdmd_includes = include_directories('src')

# Executable
executable(
    'spdmd',
    spdmd_src,
    include_directories: spdmd_includes,
    dependencies: [
        sdbusplus_dep,
        phosphor_logging_dep,
        phosphor_dbus_interfaces_dep,
        libspdm_dep,
    ],
    install: true,
    install_dir: get_option('libexecdir'),
)

