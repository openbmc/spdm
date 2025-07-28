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

# Test source files
test_src = [
    'test_mctp_transport_discovery.cpp',
    'test_mctp_helper.cpp',
    '../requester/mctp_transport_discovery.cpp',
    '../requester/utils.cpp',
    '../requester/libspdm_mctp_transport.cpp',
    '../requester/spdm_device_secret_lib_stub.cpp',
]

# Test executable
test_executable = executable(
    'test_spdm',
    test_src,
    dependencies: test_deps,
    include_directories: include_directories('../requester'),
    cpp_args: sanitizer_flags_for_tests + ['-DTESTING'],
)

# Register test
test('SPDM Tests', test_executable)
