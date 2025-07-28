// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/component_integrity_dbus.hpp"
#include "../requester/libspdm_transport.hpp"
#include "../requester/mctp_helper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>

#include <memory>
#include <vector>

#include <gtest/gtest.h>

// Forward declaration for mock data from mock_libspdm.cpp
extern "C"
{
struct MockSpdmData
{
    void* spdmContext = nullptr;
    uint32_t initStatus = 0;   // LIBSPDM_STATUS_SUCCESS
    uint32_t digestStatus = 0; // LIBSPDM_STATUS_SUCCESS
    uint8_t mockSlotMask = 0x01;
    uint8_t mockDigestBuffer[48] = {0xAA, 0xBB, 0xCC,
                                    0xDD}; // 48-byte digest, rest will be 0
};
void set_mock_spdm_data(MockSpdmData* data);
}

PHOSPHOR_LOG2_USING;

namespace spdm
{
namespace test
{

// Mock SPDM transport for testing
class MockSpdmTransport : public SpdmTransport
{
  public:
    MockSpdmTransport() = default;
    ~MockSpdmTransport() override = default;

    // Mock initialization status
    libspdm_return_t initStatus = LIBSPDM_STATUS_SUCCESS;
    libspdm_return_t digestStatus = LIBSPDM_STATUS_SUCCESS;

    // Mock data
    uint8_t mockSlotMask = 0x01; // Single slot
    std::vector<uint8_t> mockDigestBuffer = {0xAA, 0xBB, 0xCC, 0xDD};

    // Override methods for testing
    bool initialize() override
    {
        return true;
    }

    // Set this mock as the current mock for libspdm calls
    void setAsCurrentMock()
    {
        // Create a static MockSpdmData to avoid stack allocation issues
        static MockSpdmData mockData;
        mockData.spdmContext = this->spdmContext; // Use base class spdmContext
        mockData.initStatus = this->initStatus;
        mockData.digestStatus = this->digestStatus;
        mockData.mockSlotMask = this->mockSlotMask;
        // Copy the vector data to the fixed-size array (only first 4 bytes,
        // rest remain 0)
        std::copy(this->mockDigestBuffer.begin(), this->mockDigestBuffer.end(),
                  mockData.mockDigestBuffer);
        set_mock_spdm_data(&mockData);
    }

    // Clear the current mock
    static void clearCurrentMock()
    {
        set_mock_spdm_data(nullptr);
    }

    // Set the SPDM context for testing
    void setSpdmContext(void* context)
    {
        spdmContext = context; // This sets the base class spdmContext
    }
};

// Test fixture for ComponentIntegrity tests
class ComponentIntegrityTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Create async context for testing
        asyncCtx = std::make_unique<sdbusplus::async::context>();

        // Create ComponentIntegrity instance
        componentIntegrity = std::make_unique<spdm::ComponentIntegrity>(
            *asyncCtx, "/test/component/integrity");

        // Create mock transport
        mockTransport = std::make_shared<MockSpdmTransport>();

        // Set transport in component integrity
        componentIntegrity->setTransport(mockTransport);

        // Clear any previous mock data
        MockSpdmTransport::clearCurrentMock();
    }

    void TearDown() override
    {
        // Clear mock functions
        MockSpdmTransport::clearCurrentMock();

        componentIntegrity.reset();
        mockTransport.reset();
        asyncCtx.reset();
    }

    std::unique_ptr<sdbusplus::async::context> asyncCtx;
    std::unique_ptr<spdm::ComponentIntegrity> componentIntegrity;
    std::shared_ptr<MockSpdmTransport> mockTransport;

    // Wrapper methods to access protected methods for testing
    void validateMeasurementIndices(const std::vector<size_t>& indices)
    {
        componentIntegrity->validateMeasurementIndices(indices);
    }

    void initializeSpdmConnection()
    {
        componentIntegrity->initializeSpdmConnection();
    }

    std::tuple<uint8_t, std::vector<uint8_t>, size_t> getCertificateDigests()
    {
        return componentIntegrity->getCertificateDigests();
    }
};

// Test validateMeasurementIndices with valid indices
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesValidTest)
{
    std::vector<size_t> validIndices = {0, 1, 2, 255};

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(validIndices));
}

// Test validateMeasurementIndices with invalid indices
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesInvalidTest)
{
    std::vector<size_t> invalidIndices = {0, 256, 1000};

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(invalidIndices),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

// Test initializeSpdmConnection with null transport
TEST_F(ComponentIntegrityTest, InitializeSpdmConnectionNullTransportTest)
{
    // Set transport to null
    componentIntegrity->setTransport(nullptr);

    // This should throw runtime_error
    EXPECT_THROW(initializeSpdmConnection(), std::runtime_error);
}

// Test getCertificateDigests with null transport context
TEST_F(ComponentIntegrityTest, GetCertificateDigestsNullContextTest)
{
    // Mock transport has null spdmContext, so this should throw
    EXPECT_THROW(getCertificateDigests(), std::runtime_error);
}
// Test getCertificateDigests with successful operation
TEST_F(ComponentIntegrityTest, GetCertificateDigestsSuccessTest)
{
    // Create a valid SPDM context for testing using static memory
    static uint8_t dummyContextBuffer[1024];
    mockTransport->spdmContext = dummyContextBuffer;

    // Set up mock data for successful digest operation
    mockTransport->initStatus = LIBSPDM_STATUS_SUCCESS;
    mockTransport->digestStatus = LIBSPDM_STATUS_SUCCESS;
    mockTransport->mockSlotMask = 0x01;
    mockTransport->setAsCurrentMock();

    // Test the digest functionality
    auto result = getCertificateDigests();

    // Verify the result
    auto [slotMask, digestBuffer, digestSize] = result;
    EXPECT_EQ(slotMask, 0x01);
    EXPECT_EQ(digestSize, 48); // 1 slot * 48 bytes per digest
    EXPECT_EQ(digestBuffer.size(),
              384);            // 8 slots * 48 bytes per digest (full buffer)
    EXPECT_EQ(digestBuffer[0], 0xAA);
    EXPECT_EQ(digestBuffer[1], 0xBB);
    EXPECT_EQ(digestBuffer[2], 0xCC);
    EXPECT_EQ(digestBuffer[3], 0xDD);
}

// Test getCertificateDigests with failed operation
TEST_F(ComponentIntegrityTest, GetCertificateDigestsFailureTest)
{
    // Create a valid SPDM context for testing using static memory
    static uint8_t dummyContextBuffer[1024];
    mockTransport->spdmContext = dummyContextBuffer;

    // Mock failed digest operation
    mockTransport->digestStatus = LIBSPDM_STATUS_INVALID_PARAMETER;

    // Set this mock as the current mock for libspdm calls
    mockTransport->setAsCurrentMock();

    // This should throw runtime_error
    EXPECT_THROW(getCertificateDigests(), std::runtime_error);
}

// Test initializeSpdmConnection with successful initialization
TEST_F(ComponentIntegrityTest, InitializeSpdmConnectionSuccessTest)
{
    // Set a non-null spdmContext for successful initialization using static
    // memory
    static uint8_t dummyContextBuffer[1024];
    mockTransport->setSpdmContext(dummyContextBuffer);

    // Mock successful initialization
    mockTransport->initStatus = LIBSPDM_STATUS_SUCCESS;

    // Set this mock as the current mock for libspdm calls
    mockTransport->setAsCurrentMock();

    // This should not throw
    EXPECT_NO_THROW(initializeSpdmConnection());
}

// Test initializeSpdmConnection with failed initialization
TEST_F(ComponentIntegrityTest, InitializeSpdmConnectionFailureTest)
{
    // Set a non-null spdmContext for initialization attempt using static memory
    static uint8_t dummyContextBuffer[1024];
    mockTransport->setSpdmContext(dummyContextBuffer);

    // Mock failed initialization
    mockTransport->initStatus = LIBSPDM_STATUS_INVALID_PARAMETER;

    // Set this mock as the current mock for libspdm calls
    mockTransport->setAsCurrentMock();

    // This should throw runtime_error
    EXPECT_THROW(initializeSpdmConnection(), std::runtime_error);
}

// Test initializeSpdmConnection with null spdmContext
TEST_F(ComponentIntegrityTest, InitializeSpdmConnectionNullContextTest)
{
    // Ensure spdmContext is null (default state)
    mockTransport->setSpdmContext(nullptr);

    // Mock successful initialization (but won't be reached due to null context)
    mockTransport->initStatus = LIBSPDM_STATUS_SUCCESS;

    // This should throw runtime_error due to null spdmContext
    EXPECT_THROW(initializeSpdmConnection(), std::runtime_error);
}

// Test validateMeasurementIndices with empty indices
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesEmptyTest)
{
    std::vector<size_t> emptyIndices = {};

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(emptyIndices));
}

// Test validateMeasurementIndices with large indices
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesLargeTest)
{
    std::vector<size_t> largeIndices = {0, 1, 2, 3,  4,   5,   6,
                                        7, 8, 9, 10, 100, 200, 255};

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(largeIndices));
}

// Test validateMeasurementIndices with boundary values
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesBoundaryTest)
{
    std::vector<size_t> boundaryIndices = {0, 255}; // Min and max valid values

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(boundaryIndices));
}

// Test validateMeasurementIndices with single valid index
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesSingleTest)
{
    std::vector<size_t> singleIndex = {128};

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(singleIndex));
}

// Test validateMeasurementIndices with multiple invalid indices
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesMultipleInvalidTest)
{
    std::vector<size_t> multipleInvalidIndices = {0, 256, 1000, 5000};

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(multipleInvalidIndices),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

// Test validateMeasurementIndices with mixed valid and invalid indices
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesMixedTest)
{
    std::vector<size_t> mixedIndices = {0, 255, 256,
                                        1000}; // Valid, valid, invalid, invalid

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(mixedIndices),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

// Test validateMeasurementIndices with maximum invalid index
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesMaxInvalidTest)
{
    std::vector<size_t> maxInvalidIndex = {256}; // Just above the valid range

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(maxInvalidIndex),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

// Test validateMeasurementIndices with very large invalid index
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesVeryLargeInvalidTest)
{
    std::vector<size_t> veryLargeIndex = {10000};

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(veryLargeIndex),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}
// Note: method_call tests are omitted because they require async testing

} // namespace test
} // namespace spdm
