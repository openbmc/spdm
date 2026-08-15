// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <string>
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

    static void processInterfaceRemoved(
        MCTPTransportDiscovery& self, SPDMDiscovery& discovery,
        const sdbusplus::object_path& path,
        const std::vector<std::string>& interfaces)
    {
        self.processInterfaceRemoved(discovery, path, interfaces);
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

} // namespace spdm
