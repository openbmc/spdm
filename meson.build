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
gtest_proj = import('cmake').subproject('googletest')
gtest_dep = gtest_proj.dependency('gtest_main')

spdmd_deps = [phosphor_dbus_interfaces_dep, phosphor_logging_dep, sdbusplus_dep]
test_env = environment()
test_env.set('POLICY_CACHE_PATH', meson.current_build_dir() / 'policy_test.json')
spdmd_src = [
    'requester/spdmd.cpp',
    'requester/spdm_discovery.cpp',
    'requester/mctp_transport_discovery.cpp',
    'requester/tcp_transport_discovery.cpp',
    'requester/policy_manager.cpp',
    'requester/utils/mapper.cpp',
]

install_data(
    'service/spdmd.service',
    install_dir: systemd_dep.get_variable('systemd_system_unit_dir'),
)

policy_cache_path = get_option('localstatedir') + '/lib/spdm/policy.json'

conf_data = configuration_data()
conf_data.set_quoted('POLICY_CACHE_PATH', policy_cache_path)

configure_file(
    output: 'config.hpp',
    configuration: conf_data,
)

executable(
    'spdmd',
    spdmd_src,
    dependencies: spdmd_deps,
    install: true,
    install_dir: get_option('libexecdir') / 'spdm',
)

policy_manager_test = executable(
    'policy_manager_test',
    [
        'requester/policy_manager.cpp',
        'tests/policy_manager_test.cpp',
    ],
    dependencies: spdmd_deps + [gtest_dep],
)

test(
    'policy_manager_test',
    policy_manager_test,
    env: test_env,
)
