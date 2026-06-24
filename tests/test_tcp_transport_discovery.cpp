// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_discovery.hpp"
#include "tcp_transport_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace spdm
{

class TCPTransportDiscoveryTest : public ::testing::Test
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

TEST_F(TCPTransportDiscoveryTest, ConstructionSucceeds)
{
    ASSERT_NO_THROW({ TCPTransportDiscovery discovery(*ctx); });
}

TEST_F(TCPTransportDiscoveryTest, StaticTypeIsTCP)
{
    EXPECT_EQ(TCPTransportDiscovery::type(), TransportType::TCP);
}

} // namespace spdm
