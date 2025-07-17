project(
    'spdm',
    'cpp',
    version: '1.0',
    meson_version: '>=1.1.1',
    default_options: [
        'cpp_std=c++23',
        'warning_level=3',
        'werror=true',
        'buildtype=debugoptimized',
    ],
)
spdmd_deps = [dependency('phosphor-logging'), dependency('sdbusplus')]
spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/utils.cpp',
]

spdmd_includes = include_directories('requester')
executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    install: true,
    install_dir: get_option('libexecdir'),
)

