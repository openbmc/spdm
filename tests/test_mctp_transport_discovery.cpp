// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace spdm
{

class MCTPTransportDiscoveryTest : public ::testing::Test
{
  public:
    static constexpr uint32_t testNetworkId = 1;
    static constexpr uint8_t testEid = 42;
    static constexpr auto spdmType = MCTPTransportDiscovery::spdm_message_type;
    static constexpr auto nonSpdmType =
        MCTPTransportDiscovery::spdm_message_type + 1;

    static auto spdmTypes() -> std::vector<uint8_t>
    {
        return {spdmType, nonSpdmType};
    }

    static auto nonSpdmTypes() -> std::vector<uint8_t>
    {
        return {nonSpdmType, static_cast<uint8_t>(nonSpdmType + 1)};
    }

    static auto addResponder(
        MCTPTransportDiscovery& self, SPDMDiscovery& discovery,
        const sdbusplus::object_path& path, uint32_t networkId, uint8_t eid,
        std::string&& uuid, const std::vector<uint8_t>& supportedTypes) -> bool
    {
        return self.addResponder(discovery, path, networkId, eid,
                                 std::move(uuid), supportedTypes);
    }

    // Track discovered devices through the add and remove callbacks.
    static void trackDevices(SPDMDiscovery& discovery,
                             std::vector<std::string>& paths)
    {
        discovery.onDeviceAdded([&paths](const ResponderInfo& device) {
            paths.push_back(device.path.str);
        });
        discovery.onDeviceRemoved([&paths](const sdbusplus::object_path& path) {
            std::erase(paths, path.str);
        });
    }

    static void processInterfaceRemoved(
        MCTPTransportDiscovery& self, SPDMDiscovery& discovery,
        const sdbusplus::object_path& path,
        const std::vector<std::string>& interfaces)
    {
        self.processInterfaceRemoved(discovery, path, interfaces);
    }

    static void removeAllResponders(MCTPTransportDiscovery& self,
                                    SPDMDiscovery& discovery)
    {
        self.removeAllResponders(discovery);
    }

    static constexpr auto mctpServiceName =
        MCTPTransportDiscovery::mctp_service_name;

    static auto monitorServiceLost(MCTPTransportDiscovery& self,
                                   SPDMDiscovery& discovery)
    {
        return self.monitorServiceLost(discovery);
    }

    // monitorServiceLost() waits at the startup barrier together with
    // discovery() and the other monitors; stand in for those.
    static void finishStartup(sdbusplus::async::context& ctx,
                              MCTPTransportDiscovery& self)
    {
        for (std::size_t i = 1; i < MCTPTransportDiscovery::num_startup_tasks;
             ++i)
        {
            ctx.spawn(self.startup_barrier.wait());
        }
    }

    // Stop the context, then wake monitorServiceLost() with one more
    // NameOwnerChanged so that its loop sees the stop and returns.
    static void stopMonitor(sdbusplus::async::context& ctx)
    {
        ctx.request_stop();
        auto mctpd = sdbusplus::bus_t::new_bus();
        mctpd.request_name(mctpServiceName);
    }

    static auto waitUntil(sdbusplus::async::context& ctx,
                          std::function<bool()> done)
        -> sdbusplus::async::task<bool>
    {
        using namespace std::chrono_literals;
        for (int i = 0; i < 200 && !done(); ++i)
        {
            co_await sdbusplus::async::sleep_for(ctx, 10ms);
        }
        co_return done();
    }

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

TEST_F(MCTPTransportDiscoveryTest, AddResponderWithSPDMType)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    sdbusplus::object_path path("/some/path");
    std::string uuid = "a1b2c3d4";
    std::string expectedUuid = uuid;

    bool result = addResponder(discovery, responderDb, path, testNetworkId,
                               testEid, std::move(uuid), spdmTypes());

    EXPECT_TRUE(result);
    ASSERT_EQ(responderDb.devices().size(), 1);
    const auto& device = responderDb.devices()[0];
    EXPECT_EQ(device.path, path);
    EXPECT_EQ(device.transport, TransportType::MCTP);
    ASSERT_TRUE(std::holds_alternative<MctpResponderInfo>(device.info));
    const auto& mctpInfo = std::get<MctpResponderInfo>(device.info);
    EXPECT_EQ(mctpInfo.networkId, testNetworkId);
    EXPECT_EQ(mctpInfo.eid, testEid);
    EXPECT_EQ(mctpInfo.uuid, expectedUuid);
}

TEST_F(MCTPTransportDiscoveryTest, AddResponderWithoutSPDMType)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    sdbusplus::object_path path("/some/path");
    std::string uuid = "a1b2c3d4";

    bool result = addResponder(discovery, responderDb, path, testNetworkId,
                               testEid, std::move(uuid), nonSpdmTypes());

    EXPECT_FALSE(result);
    EXPECT_TRUE(responderDb.devices().empty());
}

TEST_F(MCTPTransportDiscoveryTest, AddResponderEmptySupportedTypes)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    sdbusplus::object_path path("/some/path");
    std::string uuid = "a1b2c3d4";
    std::vector<uint8_t> supportedTypes;

    bool result = addResponder(discovery, responderDb, path, testNetworkId,
                               testEid, std::move(uuid), supportedTypes);

    EXPECT_FALSE(result);
    EXPECT_TRUE(responderDb.devices().empty());
}

TEST_F(MCTPTransportDiscoveryTest, AddResponderDeduplicatesByPath)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    sdbusplus::object_path path("/same/path");
    std::vector<uint8_t> supportedTypes = {spdmType};

    addResponder(discovery, responderDb, path, 1, 10, "uuid1", supportedTypes);
    addResponder(discovery, responderDb, path, 1, 20, "uuid2", supportedTypes);

    ASSERT_EQ(responderDb.devices().size(), 1);
    EXPECT_EQ(std::get<MctpResponderInfo>(responderDb.devices()[0].info).eid,
              10);
}

TEST_F(MCTPTransportDiscoveryTest, AddResponderInvokesAddCallback)
{
    std::vector<std::string> paths;
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;
    trackDevices(responderDb, paths);

    sdbusplus::object_path path("/dev/1");
    addResponder(discovery, responderDb, path, testNetworkId, testEid, "uuid1",
                 spdmTypes());

    EXPECT_EQ(paths, std::vector<std::string>{path.str});
}

TEST_F(MCTPTransportDiscoveryTest, SkippedResponderSkipsAddCallback)
{
    std::vector<std::string> paths;
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;
    trackDevices(responderDb, paths);

    sdbusplus::object_path path("/dev/1");
    addResponder(discovery, responderDb, path, 1, 10, "uuid1", nonSpdmTypes());
    EXPECT_TRUE(paths.empty());

    addResponder(discovery, responderDb, path, 1, 10, "uuid1", spdmTypes());
    addResponder(discovery, responderDb, path, 1, 10, "uuid1", spdmTypes());
    EXPECT_EQ(paths, std::vector<std::string>{path.str});
}

TEST_F(MCTPTransportDiscoveryTest, ProcessInterfaceRemovedInvokesRemoveCallback)
{
    std::vector<std::string> paths;
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;
    trackDevices(responderDb, paths);

    sdbusplus::object_path path1("/dev/1");
    sdbusplus::object_path path2("/dev/2");
    addResponder(discovery, responderDb, path1, 1, 10, "uuid1", spdmTypes());
    addResponder(discovery, responderDb, path2, 1, 20, "uuid2", spdmTypes());
    ASSERT_EQ(paths.size(), 2);

    processInterfaceRemoved(discovery, responderDb, path1,
                            {"org.some.other.Interface"});
    EXPECT_EQ(paths.size(), 2);

    processInterfaceRemoved(discovery, responderDb, path1,
                            {"xyz.openbmc_project.MCTP.Endpoint"});
    EXPECT_EQ(paths, std::vector<std::string>{path2.str});

    addResponder(discovery, responderDb, path1, 1, 10, "uuid1", spdmTypes());
    EXPECT_EQ(paths, (std::vector<std::string>{path2.str, path1.str}));
}

TEST_F(MCTPTransportDiscoveryTest, ProcessInterfaceRemovedMatching)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    sdbusplus::object_path path("/dev/1");
    std::vector<uint8_t> supportedTypes = {spdmType};
    addResponder(discovery, responderDb, path, 1, 10, "uuid1", supportedTypes);
    ASSERT_EQ(responderDb.devices().size(), 1);

    processInterfaceRemoved(
        discovery, responderDb, path,
        {"xyz.openbmc_project.MCTP.Endpoint", "org.some.other.Interface"});

    EXPECT_TRUE(responderDb.devices().empty());
}

TEST_F(MCTPTransportDiscoveryTest, ProcessInterfaceRemovedNonMatching)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    sdbusplus::object_path path("/dev/1");
    std::vector<uint8_t> supportedTypes = {spdmType};
    addResponder(discovery, responderDb, path, 1, 10, "uuid1", supportedTypes);
    ASSERT_EQ(responderDb.devices().size(), 1);

    processInterfaceRemoved(discovery, responderDb, path,
                            {"org.some.other.Interface"});

    ASSERT_EQ(responderDb.devices().size(), 1);
}

TEST_F(MCTPTransportDiscoveryTest, ProcessInterfaceRemovedDifferentPath)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    sdbusplus::object_path path1("/dev/1");
    sdbusplus::object_path path2("/dev/2");
    std::vector<uint8_t> supportedTypes = {spdmType};

    addResponder(discovery, responderDb, path1, 1, 10, "uuid1", supportedTypes);
    addResponder(discovery, responderDb, path2, 1, 20, "uuid2", supportedTypes);
    ASSERT_EQ(responderDb.devices().size(), 2);

    processInterfaceRemoved(discovery, responderDb, path1,
                            {"xyz.openbmc_project.MCTP.Endpoint"});

    ASSERT_EQ(responderDb.devices().size(), 1);
    EXPECT_EQ(std::get<MctpResponderInfo>(responderDb.devices()[0].info).eid,
              20);
}

TEST_F(MCTPTransportDiscoveryTest, RemoveAllRespondersEmptyDiscovery)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    ASSERT_NO_THROW(removeAllResponders(discovery, responderDb));

    EXPECT_TRUE(responderDb.devices().empty());
}

TEST_F(MCTPTransportDiscoveryTest, RemoveAllRespondersRemovesOnlyMctp)
{
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;

    std::vector<uint8_t> supportedTypes = {spdmType};
    sdbusplus::object_path mctpPath1("/dev/mctp/1");
    sdbusplus::object_path mctpPath2("/dev/mctp/2");
    sdbusplus::object_path tcpPath("/dev/tcp/1");

    addResponder(discovery, responderDb, mctpPath1, 1, 10, "uuid1",
                 supportedTypes);
    addResponder(discovery, responderDb, mctpPath2, 1, 20, "uuid2",
                 supportedTypes);
    responderDb.add(ResponderInfo{tcpPath, TcpResponderInfo{"127.0.0.1", 2323},
                                  TransportType::TCP});
    ASSERT_EQ(responderDb.devices().size(), 3);

    removeAllResponders(discovery, responderDb);

    ASSERT_EQ(responderDb.devices().size(), 1);
    EXPECT_EQ(responderDb.devices()[0].path, tcpPath);
    EXPECT_EQ(responderDb.devices()[0].transport, TransportType::TCP);
}

TEST_F(MCTPTransportDiscoveryTest, ServiceLostRemovesOnlyMctpResponders)
{
    std::vector<std::string> paths;
    MCTPTransportDiscovery discovery(*ctx);
    SPDMDiscovery responderDb;
    trackDevices(responderDb, paths);

    sdbusplus::object_path tcpPath("/dev/tcp/1");
    addResponder(discovery, responderDb, sdbusplus::object_path("/dev/mctp/1"),
                 1, 10, "uuid1", spdmTypes());
    addResponder(discovery, responderDb, sdbusplus::object_path("/dev/mctp/2"),
                 1, 20, "uuid2", spdmTypes());
    responderDb.add(ResponderInfo{tcpPath, TcpResponderInfo{"127.0.0.1", 2323},
                                  TransportType::TCP});
    ASSERT_EQ(paths.size(), 3);

    ctx->spawn(monitorServiceLost(discovery, responderDb));
    finishStartup(*ctx, discovery);

    // A second connection takes and then drops the mctpd bus name, so the
    // bus daemon sends the same NameOwnerChanged signals as when mctpd
    // starts and exits.
    ctx->spawn([](sdbusplus::async::context& ctx,
                  std::vector<std::string>& paths,
                  std::string tcpPath) -> sdbusplus::async::task<> {
        using namespace std::chrono_literals;

        auto mctpd =
            std::make_unique<sdbusplus::bus_t>(sdbusplus::bus_t::new_bus());
        mctpd->request_name(mctpServiceName);
        co_await sdbusplus::async::sleep_for(ctx, 100ms);
        EXPECT_EQ(paths.size(), 3);

        mctpd.reset();
        EXPECT_TRUE(
            co_await waitUntil(ctx, [&paths]() { return paths.size() == 1; }));
        EXPECT_EQ(paths, std::vector<std::string>{tcpPath});

        stopMonitor(ctx);
    }(*ctx, paths, tcpPath.str));

    ctx->run();
}

} // namespace spdm
