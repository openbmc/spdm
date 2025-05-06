project(
    'spdm',
    'cpp',
    version: '1.0',
    meson_version: '>=1.1.1',
    default_options: ['cpp_std=c++23', 'warning_level=3'],
)

spdmd_deps = [
    dependency('phosphor-logging'),
    dependency('sdbusplus', required: true),
]

spdmd_src = [
    'src/spdmd.cpp',
    'src/spdmd_app.cpp',
    'src/spdm_discovery.cpp',
    'src/mctp_transport_discovery.cpp',
    'src/spdm_dbus_responder.cpp',
]

spdmd_includes = include_directories('src')

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    install: true,
    install_dir: get_option('libexecdir'),
)
