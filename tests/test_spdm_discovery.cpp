// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/message/types.hpp>

#include <unordered_map>
#include <unordered_set>

#include <gtest/gtest.h>

namespace spdm
{

// Mock transport satisfying the DiscoveryType concept.
// Injects arbitrary ResponderInfo entries without D-Bus.
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

// Helper: construct a ResponderInfo for testing.
static ResponderInfo makeResponder(int id)
{
    std::string path =
        "/xyz/openbmc_project/mctp/endpoint/" + std::to_string(id);
    std::string uuid = "test-uuid-" + std::to_string(id);
    uint8_t eid = static_cast<uint8_t>(id * 0x10);
    return ResponderInfo{sdbusplus::message::object_path(path),
                         MctpResponderInfo{eid, uuid}, TransportType::MCTP};
}

// Helper: run a coroutine inside a temporary async context.
// The lambda must be named (not an immediately-invoked temporary) to avoid
// ASAN stack-use-after-scope in the coroutine frame.
template <typename F>
void runAsync(F func)
{
    sdbusplus::async::context ctx;
    auto wrapper = [f = std::move(func),
                    &ctx]() mutable -> sdbusplus::async::task<> {
        co_await f();
        ctx.request_stop();
    };
    ctx.spawn(wrapper());
    ctx.run();
}

class SPDMDiscoveryTest : public ::testing::Test
{};

TEST_F(SPDMDiscoveryTest, DiscoverSingleDevice)
{
    SPDMDiscovery disc;
    MockTransport mock;
    mock.devicesToAdd.push_back(makeResponder(1));

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        const auto& devs = disc.devices();
        EXPECT_EQ(devs.size(), 1u);
        const auto& d = devs[0];
        EXPECT_EQ(d.path.str, "/xyz/openbmc_project/mctp/endpoint/1");
        EXPECT_EQ(d.transport, TransportType::MCTP);
        const auto& mctp = std::get<MctpResponderInfo>(d.info);
        EXPECT_EQ(mctp.eid, 0x10);
        EXPECT_EQ(mctp.uuid, "test-uuid-1");
    });
}

TEST_F(SPDMDiscoveryTest, DiscoverMultipleDevices)
{
    SPDMDiscovery disc;
    MockTransport mock;
    mock.devicesToAdd.push_back(makeResponder(1));
    mock.devicesToAdd.push_back(makeResponder(2));

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        const auto& devs = disc.devices();
        EXPECT_EQ(devs.size(), 2u);

        std::unordered_map<std::string, MctpResponderInfo> byPath;
        for (const auto& r : devs)
        {
            byPath.emplace(r.path.str, std::get<MctpResponderInfo>(r.info));
        }
        EXPECT_EQ(byPath.size(), 2u);
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/1").eid, 0x10);
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/1").uuid,
                  "test-uuid-1");
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/2").eid, 0x20);
        EXPECT_EQ(byPath.at("/xyz/openbmc_project/mctp/endpoint/2").uuid,
                  "test-uuid-2");
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

TEST_F(SPDMDiscoveryTest, RemoveDevice)
{
    SPDMDiscovery disc;
    sdbusplus::message::object_path path1(
        "/xyz/openbmc_project/mctp/endpoint/1");
    sdbusplus::message::object_path path2(
        "/xyz/openbmc_project/mctp/endpoint/2");

    MockTransport mock;
    mock.devicesToAdd.push_back(makeResponder(1));
    mock.devicesToAdd.push_back(makeResponder(2));

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 2u);

        disc.remove(path1);
        const auto& after = disc.devices();
        EXPECT_EQ(after.size(), 1u);
        EXPECT_EQ(after[0].path, path2);
    });
}

TEST_F(SPDMDiscoveryTest, RemoveNonExistentDeviceIsNoOp)
{
    SPDMDiscovery disc;
    MockTransport mock;
    mock.devicesToAdd.push_back(makeResponder(1));

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 1u);

        disc.remove(sdbusplus::message::object_path(
            "/xyz/openbmc_project/mctp/endpoint/99"));
        EXPECT_EQ(disc.devices().size(), 1u);
    });
}

TEST_F(SPDMDiscoveryTest, ParallelTransports)
{
    // Two transports run concurrently — both complete before run() returns
    SPDMDiscovery disc;
    MockTransport mock1;
    MockTransport mock2;
    mock1.devicesToAdd.push_back(makeResponder(1));
    mock2.devicesToAdd.push_back(makeResponder(2));

    disc.discover(mock1);
    disc.discover(mock2);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        const auto& devs = disc.devices();
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
