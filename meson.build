project(
    'spdm',
    'cpp',
    version: '1.0',
    meson_version: '>=1.1.1',
    default_options: ['cpp_std=c++23', 'warning_level=3', 'werror=true'],
)

cpp = meson.get_compiler('cpp')
if cpp.has_header('CLI/CLI.hpp')
    CLI11_dep = declare_dependency()
else
    CLI11_dep = dependency('CLI11', include_type: 'system')
endif

spdmd_deps = [dependency('phosphor-logging'), dependency('sdbusplus'), CLI11_dep]
spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
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
