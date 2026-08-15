// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "utils/dbus_path.hpp"

#include <gtest/gtest.h>

namespace spdm::dbus_path
{

TEST(DbusPathTest, SanitizeReplacesDotsInIpv4Address)
{
    EXPECT_EQ(sanitize("127.0.0.1"), "127_0_0_1");
}

TEST(DbusPathTest, SanitizeReplacesColonsInIpv6Address)
{
    EXPECT_EQ(sanitize("::1"), "__1");
}

TEST(DbusPathTest, SanitizeLeavesAlnumAndUnderscoreUnchanged)
{
    EXPECT_EQ(sanitize("host_1"), "host_1");
}

TEST(DbusPathTest, SanitizeReplacesHyphensInHostname)
{
    EXPECT_EQ(sanitize("my-host.example.com"), "my_host_example_com");
}

TEST(DbusPathTest, SanitizeEmptyStringReturnsEmptyString)
{
    EXPECT_EQ(sanitize(""), "");
}

} // namespace spdm::dbus_path
