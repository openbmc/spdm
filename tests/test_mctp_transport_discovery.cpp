// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <unordered_map>
#include <unordered_set>

#include <gtest/gtest.h>

namespace spdm
{

/** Test-only access to SPDMDiscovery internals (see friend in
 * spdm_discovery.hpp). */
class SPDMDiscovery_TestPeer
{
  public:
    static const std::vector<ResponderInfo>& devices(const SPDMDiscovery& d)
    {
        return d.responderInfos;
    }
};

// ---------------------------------------------------------------------------
// Mock transport — satisfies the DiscoveryType concept.
// Allows tests to inject arbitrary ResponderInfo entries without D-Bus.
// ---------------------------------------------------------------------------
struct MockTransport
{
    std::vector<ResponderInfo> devicesToAdd;

    auto discovery(SPDMDiscovery& d) -> sdbusplus::async::task<>
    {
        for (const auto& r : devicesToAdd)
        {
            ResponderInfo copy(r);
            d.add(std::move(copy));
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
static auto runAsyncImpl(F func, sdbusplus::async::context& ctx)
    -> sdbusplus::async::task<>
{
    co_await func();
    ctx.request_stop();
}

template <typename F>
void runAsync(F func)
{
    sdbusplus::async::context ctx;
    ctx.spawn(runAsyncImpl(std::move(func), ctx));
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
        const auto& devs = SPDMDiscovery_TestPeer::devices(disc);
        EXPECT_EQ(devs.size(), 1u);
        const auto& d = devs[0];
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
        const auto& devs = SPDMDiscovery_TestPeer::devices(disc);
        EXPECT_EQ(devs.size(), 2u);

        std::unordered_map<std::string, MctpResponderInfo> byPath;
        for (const auto& r : devs)
        {
            byPath.emplace(r.path.str, std::get<MctpResponderInfo>(r.info));
        }
        EXPECT_EQ(byPath.size(), 2u);
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/1").eid, 0x10);
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/1").uuid,
                  "device-uuid-1");
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/2").eid, 0x20);
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/2").uuid,
                  "device-uuid-2");
    });
}

TEST_F(SPDMDiscoveryTest, DiscoverNoDevices)
{
    SPDMDiscovery disc;
    MockTransport mock; // adds nothing

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(SPDMDiscovery_TestPeer::devices(disc).size(), 0u);
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
        const auto& before = SPDMDiscovery_TestPeer::devices(disc);
        EXPECT_EQ(before.size(), 2u);

        disc.remove(path1);
        const auto& after = SPDMDiscovery_TestPeer::devices(disc);
        EXPECT_EQ(after.size(), 1u);
        EXPECT_EQ(after[0].path, path2);
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
        EXPECT_EQ(SPDMDiscovery_TestPeer::devices(disc).size(), 1u);

        disc.remove(sdbusplus::message::object_path(
            "/xyz/openbmc_project/mctp/endpoint/99"));
        EXPECT_EQ(SPDMDiscovery_TestPeer::devices(disc).size(), 1u);
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
        const auto& devs = SPDMDiscovery_TestPeer::devices(disc);
        EXPECT_EQ(devs.size(), 2u);

        std::unordered_set<std::string> paths;
        std::unordered_set<uint8_t> eids;
        for (const auto& r : devs)
        {
            paths.insert(r.path.str);
            eids.insert(std::get<MctpResponderInfo>(r.info).eid);
        }
        EXPECT_EQ(paths.count("/xyz/openbmc_project/mctp/endpoint/1"), 1u);
        EXPECT_EQ(paths.count("/xyz/openbmc_project/mctp/endpoint/2"), 1u);
        EXPECT_EQ(eids.count(0x10), 1u);
        EXPECT_EQ(eids.count(0x20), 1u);
    });
}

} // namespace spdm
