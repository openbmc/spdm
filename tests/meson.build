# Test dependencies (daemon deps come via spdmd_deps)
test_deps = [
    dependency('gtest', required: true),
    dependency('gtest_main', required: true),
    libspdm_dep,
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
    test_src = [t + '.cpp']
    test_link_args = []
    if t == 'test_component_integrity'
        test_src += ['mock_libspdm.cpp']
        test_link_args += [
            '-Wl,--wrap=libspdm_init_connection',
            '-Wl,--wrap=libspdm_deinit_context',
            '-Wl,--wrap=libspdm_get_digest',
            '-Wl,--wrap=libspdm_get_certificate',
            '-Wl,--wrap=libspdm_get_hash_size',
            '-Wl,--wrap=libspdm_get_data',
            '-Wl,--wrap=libspdm_get_measurement_ex',
        ]
    endif
    test(
        t,
        executable(
            t,
            test_src,
            link_with: spdmd_lib,
            dependencies: spdmd_deps + test_deps,
            include_directories: spdmd_includes,
            link_args: test_link_args,
        ),
    )
endforeach
