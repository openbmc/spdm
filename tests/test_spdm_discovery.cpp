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
    return ResponderInfo{sdbusplus::object_path(path),
                         MctpResponderInfo{eid, uuid}, TransportType::MCTP};
}

// Helper: run a coroutine inside a temporary async context.
template <typename F>
void runAsync(F func)
{
    sdbusplus::async::context ctx;
    ctx.spawn(func() |
              sdbusplus::async::execution::then([&]() { ctx.request_stop(); }));
    ctx.run();
}

class SPDMDiscoveryTest : public ::testing::Test
{};

TEST_F(SPDMDiscoveryTest, DiscoverSingleDevice)
{
    SPDMDiscovery disc;
    MockTransport mock;

    auto responder1 = makeResponder(1);
    mock.devicesToAdd.push_back(responder1);

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();

        const auto& devs = disc.devices();
        EXPECT_EQ(devs.size(), 1u);

        const auto& d = devs[0];
        EXPECT_EQ(d.path.str, responder1.path);
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
    auto responders = std::array{makeResponder(1), makeResponder(2)};
    mock.devicesToAdd.push_back(responders[0]);
    mock.devicesToAdd.push_back(responders[1]);

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
        const auto& mctpinfo0 = std::get<MctpResponderInfo>(responders[0].info);
        EXPECT_EQ(byPath.at(responders[0].path).eid, mctpinfo0.eid);
        EXPECT_EQ(byPath.at(responders[0].path).uuid, mctpinfo0.uuid);

        const auto& mctpinfo1 = std::get<MctpResponderInfo>(responders[1].info);
        EXPECT_EQ(byPath.at(responders[1].path).eid, mctpinfo1.eid);
        EXPECT_EQ(byPath.at(responders[1].path).uuid, mctpinfo1.uuid);
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

    MockTransport mock;
    auto responders = std::array{makeResponder(1), makeResponder(2)};
    mock.devicesToAdd.push_back(responders[0]);
    mock.devicesToAdd.push_back(responders[1]);

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        EXPECT_EQ(disc.devices().size(), 2u);

        disc.remove(responders[0].path);

        const auto& after = disc.devices();
        EXPECT_EQ(after.size(), 1u);
        EXPECT_EQ(after[0].path, responders[1].path);
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

        disc.remove(makeResponder(5).path);
        EXPECT_EQ(disc.devices().size(), 1u);
    });
}

TEST_F(SPDMDiscoveryTest, ParallelTransports)
{
    // Two transports run concurrently — both complete before run() returns
    SPDMDiscovery disc;
    MockTransport mock1;
    MockTransport mock2;

    auto responders = std::array{makeResponder(1), makeResponder(2)};
    mock1.devicesToAdd.push_back(responders[0]);
    mock2.devicesToAdd.push_back(responders[1]);

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
        EXPECT_EQ(paths.count(responders[0].path), 1u);
        EXPECT_EQ(paths.count(responders[1].path), 1u);
        EXPECT_EQ(
            eids.count(std::get<MctpResponderInfo>(responders[0].info).eid),
            1u);
        EXPECT_EQ(
            eids.count(std::get<MctpResponderInfo>(responders[1].info).eid),
            1u);
    });
}

TEST_F(SPDMDiscoveryTest, DuplicatePathIsDeduplicated)
{
    SPDMDiscovery disc;
    MockTransport mock;

    auto responder1 = makeResponder(1);
    auto responder1Dup = makeResponder(1);
    mock.devicesToAdd.push_back(responder1);
    mock.devicesToAdd.push_back(responder1Dup);

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        const auto& devs = disc.devices();
        EXPECT_EQ(devs.size(), 1u);
        EXPECT_EQ(devs[0].path, responder1.path);
    });
}

TEST_F(SPDMDiscoveryTest, DuplicatePathReplacesExisting)
{
    SPDMDiscovery disc;
    MockTransport mock;

    auto responder1 = makeResponder(1);
    // Same path, but different EID + UUID — simulates a re-add after
    // the device's state has changed (firmware update, reset, etc.).
    // The discovery surface must surface the new state, not silently
    // keep the cached one.
    ResponderInfo responder1Updated{responder1.path,
                                    MctpResponderInfo{0x99, "updated-uuid"},
                                    TransportType::MCTP};

    mock.devicesToAdd.push_back(responder1);
    mock.devicesToAdd.push_back(responder1Updated);

    disc.discover(mock);

    runAsync([&]() -> sdbusplus::async::task<> {
        co_await disc.run();
        const auto& devs = disc.devices();
        EXPECT_EQ(devs.size(), 1u);
        // Verify the replacement (second add) is what's stored, not
        // the original — confirming delete-recreate semantics rather
        // than first-wins early-return.
        const auto& mctp = std::get<MctpResponderInfo>(devs[0].info);
        EXPECT_EQ(mctp.eid, 0x99);
        EXPECT_EQ(mctp.uuid, "updated-uuid");
    });
}

} // namespace spdm
