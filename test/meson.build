# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright OpenBMC Authors

gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
if not gtest_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ],
        )
    endif
endif

spdm_discovery_test_src = [
    'spdm_discovery_test.cpp',
]

test(
    'test-spdm-discovery',
    executable(
        'spdm_discovery_test',
        spdm_discovery_test_src,
        dependencies: [gtest_dep, phosphor_logging_dep, sdbusplus_dep],
        include_directories: [include_directories('..', '../requester')],
    ),
)
