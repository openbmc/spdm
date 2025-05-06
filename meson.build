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

# Boost dependencies
boost_dep = dependency('boost')

# Source files
spdmd_src = [
    'src/spdmd.cpp',
    'src/spdmd_app.cpp',
    'src/spdm_discovery.cpp',
]

# Include directories
spdmd_includes = include_directories('src')

# Compiler flags
add_project_arguments(
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
    language: 'cpp',
)

# Executable
executable(
    'spdmd',
    spdmd_src,
    include_directories: spdmd_includes,
    dependencies: [
        sdbusplus_dep,
        phosphor_logging_dep,
        phosphor_dbus_interfaces_dep,
        boost_dep,
    ],
    install: true,
    install_dir: get_option('libexecdir'),
)

