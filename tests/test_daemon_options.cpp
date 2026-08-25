// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/daemon_options.hpp"

#include <gtest/gtest.h>

namespace spdm::test
{

TEST(DaemonOptionsTest, PreservesDefaultMessageLimit)
{
    CLI::App app;
    DaemonOptions options;
    options.addTo(app);
    const char* argv[] = {"spdmd"};
    app.parse(1, argv);
    EXPECT_EQ(options.maxSpdmMessageSize, size_t{LIBSPDM_MAX_SPDM_MSG_SIZE});
}

TEST(DaemonOptionsTest, AcceptsMessageLimitsAndStateDirectory)
{
    for (const char* value : {"42", "2047", "4608"})
    {
        CLI::App app;
        DaemonOptions options;
        options.addTo(app);
        const char* argv[] = {"spdmd", "--max-spdm-message-size", value,
                              "--state-dir", "/tmp/spdm-state"};
        app.parse(5, argv);
        EXPECT_EQ(options.maxSpdmMessageSize, std::stoul(value));
        EXPECT_EQ(options.stateDir, "/tmp/spdm-state");
    }
}

TEST(DaemonOptionsTest, RejectsInvalidMessageLimits)
{
    for (const char* value : {"0", "41", "4609", "-1", "invalid", "42.5"})
    {
        CLI::App app;
        DaemonOptions options;
        options.addTo(app);
        const char* argv[] = {"spdmd", "--max-spdm-message-size", value};
        EXPECT_THROW(app.parse(3, argv), CLI::ParseError) << value;
    }
}

TEST(DaemonOptionsTest, RequiresMessageLimitValue)
{
    CLI::App app;
    DaemonOptions options;
    options.addTo(app);
    const char* argv[] = {"spdmd", "--max-spdm-message-size"};
    EXPECT_THROW(app.parse(2, argv), CLI::ParseError);
}

} // namespace spdm::test
