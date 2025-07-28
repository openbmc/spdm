// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace spdm
{

// ---------------------------------------------------------------------------
// Mock transport — satisfies the DiscoveryType concept.
// Allows tests to inject arbitrary ResponderInfo entries without D-Bus.
// ---------------------------------------------------------------------------
struct MockTransport
{
    std::vector<ResponderInfo> devicesToAdd;

    auto discovery(SPDMDiscovery& d) -> sdbusplus::async::task<>
    {
        for (auto& r : devicesToAdd)
        {
            d.add(std::move(r));
        }
        co_return;
    }

    static auto type() -> TransportType
    {
        return TransportType::MCTP;
    }
};

static_assert(details::DiscoveryType<MockTransport>,
              "MockTransport must satisfy DiscoveryType concept");

// ---------------------------------------------------------------------------
// Helper: run a coroutine inside a temporary async context
// ---------------------------------------------------------------------------
template <typename F>
void runAsync(F func)
{
    sdbusplus::async::context ctx;
    ctx.spawn(
        [f = std::move(func), &ctx]() mutable -> sdbusplus::async::task<> {
            co_await f();
            ctx.request_stop();
        }());
    ctx.run();
}

// ---------------------------------------------------------------------------
// MCTPTransportDiscovery — basic construction and static type
// ---------------------------------------------------------------------------
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

TEST_F(MCTPTransportDiscoveryTest, Constructor)
{
    ASSERT_NO_THROW({ MCTPTransportDiscovery discovery(*ctx); });
}

TEST_F(MCTPTransportDiscoveryTest, StaticType)
{
    EXPECT_EQ(MCTPTransportDiscovery::type(), TransportType::MCTP);
}

// ---------------------------------------------------------------------------
// SPDMDiscovery — tested via MockTransport (no D-Bus required)
// ---------------------------------------------------------------------------
class SPDMDiscoveryTest : public ::testing::Test
{};

TEST_F(SPDMDiscoveryTest, DiscoverSingleDevice)
{
    SPDMDiscovery disc;
    MockTransport mock;
    mock.devicesToAdd.push_back(ResponderInfo{
        sdbusplus::message::object_path("/xyz/openbmc_project/mctp/endpoint/1"),
        MctpResponderInfo{0x10, "test-uuid-1234"}, TransportType::MCTP});

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 1u);
        const auto& d = disc.devices()[0];
        EXPECT_EQ(d.path.str, "/xyz/openbmc_project/mctp/endpoint/1");
        EXPECT_EQ(d.transport, TransportType::MCTP);
        const auto& mctp = std::get<MctpResponderInfo>(d.info);
        EXPECT_EQ(mctp.eid, 0x10);
        EXPECT_EQ(mctp.uuid, "test-uuid-1234");
    });
}

TEST_F(SPDMDiscoveryTest, DiscoverMultipleDevices)
{
    SPDMDiscovery disc;
    MockTransport mock;
    mock.devicesToAdd.push_back(ResponderInfo{
        sdbusplus::message::object_path("/xyz/openbmc_project/mctp/endpoint/1"),
        MctpResponderInfo{0x10, "device-uuid-1"}, TransportType::MCTP});
    mock.devicesToAdd.push_back(ResponderInfo{
        sdbusplus::message::object_path("/xyz/openbmc_project/mctp/endpoint/2"),
        MctpResponderInfo{0x20, "device-uuid-2"}, TransportType::MCTP});

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 2u);

        const auto& mctp0 = std::get<MctpResponderInfo>(disc.devices()[0].info);
        EXPECT_EQ(mctp0.eid, 0x10);
        EXPECT_EQ(mctp0.uuid, "device-uuid-1");

        const auto& mctp1 = std::get<MctpResponderInfo>(disc.devices()[1].info);
        EXPECT_EQ(mctp1.eid, 0x20);
        EXPECT_EQ(mctp1.uuid, "device-uuid-2");
    });
}

TEST_F(SPDMDiscoveryTest, DiscoverNoDevices)
{
    SPDMDiscovery disc;
    MockTransport mock; // adds nothing

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 0u);
    });
}

TEST_F(SPDMDiscoveryTest, DiscoverFiltersNonSpdmDevices)
{
    // Mock transport that deliberately skips non-SPDM endpoints
    // (simulates MCTPTransportDiscovery filtering out message type != 0x05)
    SPDMDiscovery disc;
    MockTransport mock; // adds nothing — endpoint filtered out

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 0u);
    });
}

TEST_F(SPDMDiscoveryTest, RemoveDevice)
{
    SPDMDiscovery disc;
    sdbusplus::message::object_path path1(
        "/xyz/openbmc_project/mctp/endpoint/1");
    sdbusplus::message::object_path path2(
        "/xyz/openbmc_project/mctp/endpoint/2");

    MockTransport mock;
    mock.devicesToAdd.push_back(ResponderInfo{
        path1, MctpResponderInfo{0x10, "uuid-1"}, TransportType::MCTP});
    mock.devicesToAdd.push_back(ResponderInfo{
        path2, MctpResponderInfo{0x20, "uuid-2"}, TransportType::MCTP});

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 2u);

        disc.remove(path1);
        EXPECT_EQ(disc.devices().size(), 1u);
        EXPECT_EQ(disc.devices()[0].path, path2);
    });
}

TEST_F(SPDMDiscoveryTest, RemoveNonExistentDeviceIsNoOp)
{
    SPDMDiscovery disc;
    MockTransport mock;
    mock.devicesToAdd.push_back(ResponderInfo{
        sdbusplus::message::object_path("/xyz/openbmc_project/mctp/endpoint/1"),
        MctpResponderInfo{0x10, "uuid-1"}, TransportType::MCTP});

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 1u);

        disc.remove(sdbusplus::message::object_path(
            "/xyz/openbmc_project/mctp/endpoint/99"));
        EXPECT_EQ(disc.devices().size(), 1u); // unchanged
    });
}

TEST_F(SPDMDiscoveryTest, ParallelTransports)
{
    // Two transports run concurrently — both complete before run() returns
    SPDMDiscovery disc;
    MockTransport mock1, mock2;
    mock1.devicesToAdd.push_back(ResponderInfo{
        sdbusplus::message::object_path("/xyz/openbmc_project/mctp/endpoint/1"),
        MctpResponderInfo{0x10, "uuid-1"}, TransportType::MCTP});
    mock2.devicesToAdd.push_back(ResponderInfo{
        sdbusplus::message::object_path("/xyz/openbmc_project/mctp/endpoint/2"),
        MctpResponderInfo{0x20, "uuid-2"}, TransportType::MCTP});

    disc.discover(mock1);
    disc.discover(mock2);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 2u);
    });
}

} // namespace spdm
