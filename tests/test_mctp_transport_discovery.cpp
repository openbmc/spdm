// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>

#include <memory>
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

        managedObjects["/xyz/openbmc_project/mctp/endpoint/1"] = interfaces;

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

        managedObjects["/xyz/openbmc_project/mctp/endpoint/1"] = interfaces1;

        // Device 2
        DbusInterface mctpInterface2;
        mctpInterface2["EID"] = uint8_t{0x20};
        mctpInterface2["SupportedMessageTypes"] = std::vector<uint8_t>{0x05};

        DbusInterface uuidInterface2;
        uuidInterface2["UUID"] = std::string{"device-uuid-2"};

        DbusInterfaces interfaces2;
        interfaces2["xyz.openbmc_project.MCTP.Endpoint"] = mctpInterface2;
        interfaces2["xyz.openbmc_project.Common.UUID"] = uuidInterface2;

        managedObjects["/xyz/openbmc_project/mctp/endpoint/2"] = interfaces2;

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

    managedObjects["/xyz/openbmc_project/mctp/endpoint/1"] = interfaces;

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

    managedObjects["/xyz/openbmc_project/mctp/endpoint/1"] = interfaces;

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

    managedObjects["/xyz/openbmc_project/mctp/endpoint/1"] = interfaces;

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

    managedObjects["/xyz/openbmc_project/mctp/endpoint/1"] = interfaces;

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

    managedObjects["/xyz/openbmc_project/mctp/endpoint/1"] = interfaces;

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

} // namespace spdm
