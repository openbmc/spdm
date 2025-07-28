# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright OpenBMC Authors

# Test dependencies
test_deps = [
    dependency('phosphor-logging'),
    dependency('sdbusplus', required: true),
    dependency('gtest', required: true),
    dependency('gtest_main', required: true),
    dependency('gmock', required: true),
    libspdm_dep,
]

# Common source files needed by multiple tests
common_src = [
    '../requester/mctp_transport_discovery.cpp',
    '../requester/utils.cpp',
    '../requester/libspdm_mctp_transport.cpp',
    '../requester/spdm_device_secret_lib_stub.cpp',
]

# Define test executables
tests = ['mctp_transport_discovery', 'mctp_helper']

# Build and register each test
foreach t : tests
    test(
        t,
        executable(
            t.underscorify(),
            'test_' + t + '.cpp',
            common_src,
            implicit_include_directories: false,
            dependencies: test_deps,
            include_directories: include_directories('../requester'),
            cpp_args: sanitizer_flags_for_tests + ['-DTESTING'],
        ),
    )
endforeach
