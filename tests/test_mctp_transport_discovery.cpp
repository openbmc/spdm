// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace spdm
{

class MCTPTransportDiscoveryTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ctx = std::make_unique<sdbusplus::async::context>();
    }

    void TearDown() override
    {
        ctx.reset();
    }

    std::unique_ptr<sdbusplus::async::context> ctx;
};

TEST_F(MCTPTransportDiscoveryTest, ConstructionSucceeds)
{
    ASSERT_NO_THROW({ MCTPTransportDiscovery discovery(*ctx); });
}

TEST_F(MCTPTransportDiscoveryTest, StaticTypeIsMCTP)
{
    EXPECT_EQ(MCTPTransportDiscovery::type(), TransportType::MCTP);
}

} // namespace spdm
