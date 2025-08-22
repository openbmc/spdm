# Test dependencies (daemon deps come via spdmd_deps)
test_deps = [
    dependency('gtest', required: true),
    dependency('gtest_main', required: true),
    libspdm_dep,
]

common_src = [
    'mock_libspdm.cpp',
]

tests = [
    'test_mctp_transport_discovery',
    'test_mctp_helper',
    'test_spdm_discovery',
    'test_policy_manager',
    'test_component_integrity',
    'test_certificate_dbus',
]

foreach t : tests
    test(
        t,
        executable(
            t,
            t + '.cpp',
            common_src,
            link_with: spdmd_lib,
            dependencies: spdmd_deps + test_deps,
            include_directories: spdmd_includes,
        ),
    )
endforeach
