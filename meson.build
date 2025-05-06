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

spdmd_deps = [
    phosphor_logging_dep,
    sdbusplus_dep,
]
spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
]

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
)
