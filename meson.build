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

spdmd_src = ['requester/spdmd.cpp']

spdmd_includes = include_directories('requester')

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    include_directories: spdmd_includes,
    install: true,
    install_dir: get_option('libexecdir'),
)
