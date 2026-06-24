# Test dependencies (daemon deps come via spdmd_deps)
test_deps = [
    dependency('gtest', required: true),
    dependency('gtest_main', required: true),
]

tests = [
    'test_mctp_transport_discovery',
    'test_spdm_discovery',
    'test_tcp_transport_discovery',
]

foreach t : tests
    test(
        t,
        executable(
            t,
            t + '.cpp',
            link_with: spdmd_lib,
            dependencies: spdmd_deps + test_deps,
            include_directories: spdmd_includes,
        ),
    )
endforeach
