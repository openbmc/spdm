# Test dependencies (daemon deps come via spdmd_deps)
test_deps = [
    dependency('gtest', required: true),
    dependency('gtest_main', required: true),
    dependency('gmock', required: true),
]

# Test executable
test_executable = executable(
    'test_mctp_transport_discovery',
    'test_mctp_transport_discovery.cpp',
    link_with: spdmd_lib,
    dependencies: spdmd_deps + test_deps,
    include_directories: include_directories('../requester'),
)

# Register test
test('spdm_discovery_and_mctp_transport', test_executable)
