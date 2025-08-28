// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>

#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

PHOSPHOR_LOG2_USING;

namespace spdm
{

class MCTPTransportDiscoveryTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Create a mock async context for testing
        ctx = std::make_unique<sdbusplus::async::context>();
    }

    void TearDown() override
    {
        ctx.reset();
    }

    std::unique_ptr<sdbusplus::async::context> ctx;
};

// Test fixture for testing with mock D-Bus responses
class MCTPTransportDiscoveryWithMockTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ctx = std::make_unique<sdbusplus::async::context>();
        discovery = std::make_unique<MCTPTransportDiscovery>(*ctx);
    }

    void TearDown() override
    {
        discovery.reset();
        ctx.reset();
    }

    // Helper method to create mock managed objects
    ManagedObjects createMockManagedObjects()
    {
        ManagedObjects managedObjects;

        // Create a mock MCTP endpoint that supports SPDM
        DbusInterface mctpInterface;
        mctpInterface["EID"] = uint8_t{0x10};
        mctpInterface["SupportedMessageTypes"] =
            std::vector<uint8_t>{0x05}; // SPDM

        DbusInterface uuidInterface;
        uuidInterface["UUID"] = std::string{"test-uuid-1234"};

        DbusInterfaces interfaces;
        interfaces["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface;
        interfaces["xyz.openbmc_project.Common.UUID"] = uuidInterface;

        managedObjects[sdbusplus::message::object_path(
            "/xyz/openbmc_project/mctp/endpoint/1")] = interfaces;

        return managedObjects;
    }

    // Helper method to create mock managed objects with multiple devices
    ManagedObjects createMockMultipleDevices()
    {
        ManagedObjects managedObjects;

        // Device 1
        DbusInterface mctpInterface1;
        mctpInterface1["EID"] = uint8_t{0x10};
        mctpInterface1["SupportedMessageTypes"] = std::vector<uint8_t>{0x05};

        DbusInterface uuidInterface1;
        uuidInterface1["UUID"] = std::string{"device-uuid-1"};

        DbusInterfaces interfaces1;
        interfaces1["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface1;
        interfaces1["xyz.openbmc_project.Common.UUID"] = uuidInterface1;

        managedObjects[sdbusplus::message::object_path(
            "/xyz/openbmc_project/mctp/endpoint/1")] = interfaces1;

        // Device 2
        DbusInterface mctpInterface2;
        mctpInterface2["EID"] = uint8_t{0x20};
        mctpInterface2["SupportedMessageTypes"] = std::vector<uint8_t>{0x05};

        DbusInterface uuidInterface2;
        uuidInterface2["UUID"] = std::string{"device-uuid-2"};

        DbusInterfaces interfaces2;
        interfaces2["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface2;
        interfaces2["xyz.openbmc_project.Common.UUID"] = uuidInterface2;

        managedObjects[sdbusplus::message::object_path(
            "/xyz/openbmc_project/mctp/endpoint/2")] = interfaces2;

        return managedObjects;
    }

    std::unique_ptr<sdbusplus::async::context> ctx;
    std::unique_ptr<MCTPTransportDiscovery> discovery;
};

// Test constructor
TEST_F(MCTPTransportDiscoveryTest, Constructor)
{
    ASSERT_NO_THROW({ MCTPTransportDiscovery discovery(*ctx); });
}

// Test transport type
TEST_F(MCTPTransportDiscoveryTest, GetType)
{
    MCTPTransportDiscovery discovery(*ctx);
    EXPECT_EQ(discovery.getType(), TransportType::MCTP);
}

// Test processManagedObjects with valid SPDM device
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsValidDevice)
{
    auto managedObjects = createMockManagedObjects();
    auto devices = discovery->processManagedObjects(managedObjects);

    ASSERT_EQ(devices.size(), 1);
    EXPECT_EQ(devices[0].eid, 0x10);
    EXPECT_EQ(devices[0].objectPath, "/xyz/openbmc_project/mctp/endpoint/1");
    EXPECT_EQ(devices[0].uuid, "test-uuid-1234");
}

// Test processManagedObjects with multiple devices
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsMultipleDevices)
{
    auto managedObjects = createMockMultipleDevices();
    auto devices = discovery->processManagedObjects(managedObjects);

    ASSERT_EQ(devices.size(), 2);

    // Check first device
    EXPECT_EQ(devices[0].eid, 0x10);
    EXPECT_EQ(devices[0].objectPath, "/xyz/openbmc_project/mctp/endpoint/1");
    EXPECT_EQ(devices[0].uuid, "device-uuid-1");

    // Check second device
    EXPECT_EQ(devices[1].eid, 0x20);
    EXPECT_EQ(devices[1].objectPath, "/xyz/openbmc_project/mctp/endpoint/2");
    EXPECT_EQ(devices[1].uuid, "device-uuid-2");
}

// Test processManagedObjects with device that doesn't support SPDM
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsNoSpdmSupport)
{
    ManagedObjects managedObjects;

    // Create a mock MCTP endpoint that doesn't support SPDM
    DbusInterface mctpInterface;
    mctpInterface["EID"] = uint8_t{0x10};
    mctpInterface["SupportedMessageTypes"] =
        std::vector<uint8_t>{0x01}; // Not SPDM

    DbusInterface uuidInterface;
    uuidInterface["UUID"] = std::string{"test-uuid-1234"};

    DbusInterfaces interfaces;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface;
    interfaces["xyz.openbmc_project.Common.UUID"] = uuidInterface;

    managedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/mctp/endpoint/1")] = interfaces;

    auto devices = discovery->processManagedObjects(managedObjects);
    EXPECT_EQ(devices.size(), 0);
}

// Test processManagedObjects with missing MCTP interface
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsNoMctpInterface)
{
    ManagedObjects managedObjects;

    // Create an object without MCTP interface
    DbusInterface uuidInterface;
    uuidInterface["UUID"] = std::string{"test-uuid-1234"};

    DbusInterfaces interfaces;
    interfaces["xyz.openbmc_project.Common.UUID"] = uuidInterface;

    managedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/mctp/endpoint/1")] = interfaces;

    auto devices = discovery->processManagedObjects(managedObjects);
    EXPECT_EQ(devices.size(), 0);
}

// Test processManagedObjects with missing UUID interface
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsNoUuidInterface)
{
    ManagedObjects managedObjects;

    // Create a mock MCTP endpoint without UUID interface
    DbusInterface mctpInterface;
    mctpInterface["EID"] = uint8_t{0x10};
    mctpInterface["SupportedMessageTypes"] = std::vector<uint8_t>{0x05};

    DbusInterfaces interfaces;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface;

    managedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/mctp/endpoint/1")] = interfaces;

    auto devices = discovery->processManagedObjects(managedObjects);
    EXPECT_EQ(devices.size(), 0);
}

// Test processManagedObjects with invalid EID
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsInvalidEid)
{
    ManagedObjects managedObjects;

    // Create a mock MCTP endpoint with invalid EID
    DbusInterface mctpInterface;
    mctpInterface["EID"] = uint8_t{255}; // Invalid EID
    mctpInterface["SupportedMessageTypes"] = std::vector<uint8_t>{0x05};

    DbusInterface uuidInterface;
    uuidInterface["UUID"] = std::string{"test-uuid-1234"};

    DbusInterfaces interfaces;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface;
    interfaces["xyz.openbmc_project.Common.UUID"] = uuidInterface;

    managedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/mctp/endpoint/1")] = interfaces;

    auto devices = discovery->processManagedObjects(managedObjects);
    EXPECT_EQ(devices.size(), 0);
}

// Test processManagedObjects with empty UUID
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsEmptyUuid)
{
    ManagedObjects managedObjects;

    // Create a mock MCTP endpoint with empty UUID
    DbusInterface mctpInterface;
    mctpInterface["EID"] = uint8_t{0x10};
    mctpInterface["SupportedMessageTypes"] = std::vector<uint8_t>{0x05};

    DbusInterface uuidInterface;
    uuidInterface["UUID"] = std::string{""}; // Empty UUID

    DbusInterfaces interfaces;
    interfaces["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface;
    interfaces["xyz.openbmc_project.Common.UUID"] = uuidInterface;

    managedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/mctp/endpoint/1")] = interfaces;

    auto devices = discovery->processManagedObjects(managedObjects);
    EXPECT_EQ(devices.size(), 0);
}

// Test processManagedObjects with empty managed objects
TEST_F(MCTPTransportDiscoveryWithMockTest, ProcessManagedObjectsEmpty)
{
    ManagedObjects managedObjects;
    auto devices = discovery->processManagedObjects(managedObjects);
    EXPECT_EQ(devices.size(), 0);
}

TEST_F(MCTPTransportDiscoveryWithMockTest, ParseSpdmEMConfig_Valid)
{
    MCTPTransportDiscovery discovery(*ctx);
    // Simulate a valid managed objects map for EM config
    ManagedObjects emManagedObjects;

    // Create a mock EM endpoint with required properties
    DbusInterface emEndpointInterface;
    DbusInterface spdmMctpRequesterInterface;
    spdmMctpRequesterInterface["Authenticating"] =
        std::string{"/xyz/openbmc_project/inventory/system/chassis/device0"};
    spdmMctpRequesterInterface["EID"] = uint64_t{0x42};
    spdmMctpRequesterInterface["Name"] = std::string{"device0"};
    spdmMctpRequesterInterface["Reporting"] = std::string{
        "/xyz/openbmc_project/inventory/system/chassis/rot_device0"};
    spdmMctpRequesterInterface["TrustedComponentType"] =
        std::string{"discrete"};
    spdmMctpRequesterInterface["Type"] = std::string{"SpdmMctpRequester"};
    DbusInterfaces interfaces;
    interfaces["xyz.openbmc_project.Configuration.SpdmMctpRequester"] =
        spdmMctpRequesterInterface;

    emManagedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/inventory/system/chassis/rot_device0")] =
        interfaces;

    std::vector<spdm::ResponderInfo> devices;
    devices.push_back(spdm::ResponderInfo{
        0x42, "/au/com/codeconstruct/mctp1/networks/1/endpoints/42",
        sdbusplus::message::object_path{}, "em-uuid-42", nullptr});
    discovery.parseSpdmEMConfig(devices, emManagedObjects);

    // There should be at least one entry in devices with the correct fields
    ASSERT_FALSE(devices.empty());
    const auto& info = devices.front();
    EXPECT_EQ(info.eid, 0x42);
    EXPECT_EQ(info.objectPath,
              "/au/com/codeconstruct/mctp1/networks/1/endpoints/42");
    EXPECT_EQ(static_cast<std::string>(info.deviceObjectPath),
              "/xyz/openbmc_project/inventory/system/chassis/rot_device0");
    EXPECT_EQ(info.transport, nullptr);
    EXPECT_EQ(info.uuid, "em-uuid-42");
}

TEST_F(MCTPTransportDiscoveryWithMockTest, ParseSpdmEMConfig_MissingEid)
{
    MCTPTransportDiscovery discovery(*ctx);
    ManagedObjects emManagedObjects;

    DbusInterface spdmMctpRequesterInterface;
    spdmMctpRequesterInterface["Name"] = std::string{"device0"};
    spdmMctpRequesterInterface["Type"] = std::string{"SpdmMctpRequester"};
    spdmMctpRequesterInterface["TrustedComponentType"] =
        std::string{"discrete"};
    spdmMctpRequesterInterface["Authenticating"] =
        std::string{"/xyz/openbmc_project/inventory/system/chassis/device0"};
    spdmMctpRequesterInterface["Reporting"] = std::string{
        "/xyz/openbmc_project/inventory/system/chassis/rot_device0"};

    DbusInterfaces interfaces;
    interfaces["xyz.openbmc_project.Configuration.SpdmMctpRequester"] =
        spdmMctpRequesterInterface;

    emManagedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/inventory/system/chassis/device0")] = interfaces;

    std::vector<spdm::ResponderInfo> devices;
    devices.push_back(spdm::ResponderInfo{
        0x42, "/au/com/codeconstruct/mctp1/networks/1/endpoints/42",
        sdbusplus::message::object_path{}, "", nullptr});
    discovery.parseSpdmEMConfig(devices, emManagedObjects);

    ASSERT_FALSE(devices.empty());
    const auto& info = devices.front();
    EXPECT_EQ(info.eid, 0x42);
    EXPECT_EQ(info.objectPath,
              "/au/com/codeconstruct/mctp1/networks/1/endpoints/42");
    EXPECT_EQ(info.deviceObjectPath, sdbusplus::message::object_path{});
    EXPECT_EQ(info.transport, nullptr);
}

TEST_F(MCTPTransportDiscoveryWithMockTest, ParseSpdmEMConfig_MultipleEids)
{
    MCTPTransportDiscovery discovery(*ctx);
    // Simulate a valid managed objects map for EM config with 2 endpoints
    ManagedObjects emManagedObjects;

    // Endpoint 1
    DbusInterface spdmMctpRequesterInterface1;
    spdmMctpRequesterInterface1["Authenticating"] =
        std::string{"/xyz/openbmc_project/inventory/system/chassis/device0"};
    spdmMctpRequesterInterface1["EID"] = uint64_t{0x42};
    spdmMctpRequesterInterface1["Name"] = std::string{"device0"};
    spdmMctpRequesterInterface1["Reporting"] = std::string{
        "/xyz/openbmc_project/inventory/system/chassis/rot_device0"};
    spdmMctpRequesterInterface1["TrustedComponentType"] =
        std::string{"discrete"};
    spdmMctpRequesterInterface1["Type"] = std::string{"SpdmMctpRequester"};
    DbusInterfaces interfaces1;
    interfaces1["xyz.openbmc_project.Configuration.SpdmMctpRequester"] =
        spdmMctpRequesterInterface1;

    emManagedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/inventory/system/chassis/rot_device0")] =
        interfaces1;

    // Endpoint 2
    DbusInterface spdmMctpRequesterInterface2;
    spdmMctpRequesterInterface2["Authenticating"] =
        std::string{"/xyz/openbmc_project/inventory/system/chassis/device1"};
    spdmMctpRequesterInterface2["EID"] = uint64_t{0x43};
    spdmMctpRequesterInterface2["Name"] = std::string{"device1"};
    spdmMctpRequesterInterface2["Reporting"] = std::string{
        "/xyz/openbmc_project/inventory/system/chassis/rot_device1"};
    spdmMctpRequesterInterface2["TrustedComponentType"] =
        std::string{"discrete"};
    spdmMctpRequesterInterface2["Type"] = std::string{"SpdmMctpRequester"};
    DbusInterfaces interfaces2;
    interfaces2["xyz.openbmc_project.Configuration.SpdmMctpRequester"] =
        spdmMctpRequesterInterface2;

    emManagedObjects[sdbusplus::message::object_path(
        "/xyz/openbmc_project/inventory/system/chassis/rot_device1")] =
        interfaces2;

    std::vector<spdm::ResponderInfo> devices;
    devices.push_back(spdm::ResponderInfo{
        0x42, "/au/com/codeconstruct/mctp1/networks/1/endpoints/42",
        sdbusplus::message::object_path{}, "em-uuid-42", nullptr});
    devices.push_back(spdm::ResponderInfo{
        0x43, "/au/com/codeconstruct/mctp1/networks/1/endpoints/43",
        sdbusplus::message::object_path{}, "em-uuid-43", nullptr});
    discovery.parseSpdmEMConfig(devices, emManagedObjects);

    // There should be two entries in devices with the correct fields
    ASSERT_EQ(devices.size(), 2);

    const auto& info1 = devices[0];
    EXPECT_EQ(info1.eid, 0x42);
    EXPECT_EQ(info1.objectPath,
              "/au/com/codeconstruct/mctp1/networks/1/endpoints/42");
    EXPECT_EQ(static_cast<std::string>(info1.deviceObjectPath),
              "/xyz/openbmc_project/inventory/system/chassis/rot_device0");
    EXPECT_EQ(info1.transport, nullptr);
    EXPECT_EQ(info1.uuid, "em-uuid-42");

    const auto& info2 = devices[1];
    EXPECT_EQ(info2.eid, 0x43);
    EXPECT_EQ(info2.objectPath,
              "/au/com/codeconstruct/mctp1/networks/1/endpoints/43");
    EXPECT_EQ(static_cast<std::string>(info2.deviceObjectPath),
              "/xyz/openbmc_project/inventory/system/chassis/rot_device1");
    EXPECT_EQ(info2.transport, nullptr);
    EXPECT_EQ(info2.uuid, "em-uuid-43");
}

} // namespace spdm
