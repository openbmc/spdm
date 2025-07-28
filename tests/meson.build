# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright OpenBMC Authors

# Test dependencies
test_deps = [
    dependency('phosphor-logging'),
    dependency('sdbusplus', required: true),
    dependency('gtest', required: true),
    dependency('gtest_main', required: true),
    dependency('gmock', required: true),
]

# Test source files
test_src = [
    'test_mctp_transport_discovery.cpp',
    '../requester/mctp_transport_discovery.cpp',
    '../requester/utils.cpp',
]

# Test executable
test_executable = executable(
    'test_mctp_transport_discovery',
    test_src,
    dependencies: test_deps,
    include_directories: include_directories('../requester'),
    cpp_args: sanitizer_flags_for_tests + ['-DTESTING'],
)

# Register test
test('MCTP Transport Discovery Tests', test_executable)
