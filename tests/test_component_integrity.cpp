// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/component_integrity_dbus.hpp"
#include "../requester/libspdm_transport.hpp"
#include "../requester/mctp_helper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>

#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

// Forward declaration for mock data from mock_libspdm.cpp
extern "C"
{
struct MockSpdmData
{
    void* spdmContext = nullptr;
    uint32_t initStatus = 0;    // LIBSPDM_STATUS_SUCCESS
    uint32_t digestStatus = 0;  // LIBSPDM_STATUS_SUCCESS
    uint32_t getCertStatus = 0; // LIBSPDM_STATUS_SUCCESS
    uint8_t mockSlotMask = 0x01;
    uint8_t mockDigestBuffer[48] = {0xAA, 0xBB, 0xCC,
                                    0xDD}; // 48-byte digest, rest will be 0
    // For certificate chain mock
    std::vector<uint8_t> mockCertChain;
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
    libspdm_return_t getCertStatus = LIBSPDM_STATUS_SUCCESS;

    // Mock data
    uint8_t mockSlotMask = 0x01; // Single slot
    std::vector<uint8_t> mockDigestBuffer = {0xAA, 0xBB, 0xCC, 0xDD};

    // For certificate chain mock
    std::vector<uint8_t> mockCertChain;

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
        mockData.getCertStatus = this->getCertStatus;
        mockData.mockSlotMask = this->mockSlotMask;
        // Copy the vector data to the fixed-size array (only first 4 bytes,
        // rest remain 0)
        std::fill(std::begin(mockData.mockDigestBuffer),
                  std::end(mockData.mockDigestBuffer), 0);
        std::copy(this->mockDigestBuffer.begin(), this->mockDigestBuffer.end(),
                  mockData.mockDigestBuffer);
        // Copy certificate chain data into the mock data struct
        mockData.mockCertChain = this->mockCertChain;
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

    std::tuple<std::string, std::vector<uint8_t>, std::vector<uint8_t>>
        getCertificate(size_t slotId)
    {
        return componentIntegrity->getCertificate(slotId);
    }
};

// Test validateMeasurementIndices with valid indices
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesValidTest)
{
    std::vector<size_t> validIndices = {1, 2, 3, 4, 5};

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
    std::vector<size_t> largeIndices = {1, 2, 3,  4,   5,   6,  7,
                                        8, 9, 10, 100, 200, 254};

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(largeIndices));
}

// Test validateMeasurementIndices with boundary values
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesBoundaryTest)
{
    std::vector<size_t> boundaryIndices = {
        1, 254}; // Min and max valid regular indices

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

// Test validateMeasurementIndices with mixing 0 and 255 (should be invalid)
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesMixZeroAnd255Test)
{
    std::vector<size_t> mixedIndices = {0, 255};

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(mixedIndices),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

// Test validateMeasurementIndices with mixing 0 and regular indices (should be
// invalid)
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesMixZeroAndRegularTest)
{
    std::vector<size_t> mixedIndices = {0, 1, 2, 3};

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(mixedIndices),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

// Test validateMeasurementIndices with mixing 255 and regular indices (should
// be invalid)
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesMix255AndRegularTest)
{
    std::vector<size_t> mixedIndices = {255, 1, 2, 3};

    // This should throw InvalidArgument
    EXPECT_THROW(
        validateMeasurementIndices(mixedIndices),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

// Test validateMeasurementIndices with single index 0 (should be valid)
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesSingleZeroTest)
{
    std::vector<size_t> singleZero = {0};

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(singleZero));
}

// Test validateMeasurementIndices with single index 255 (should be valid)
TEST_F(ComponentIntegrityTest, ValidateMeasurementIndicesSingle255Test)
{
    std::vector<size_t> single255 = {255};

    // This should not throw
    EXPECT_NO_THROW(validateMeasurementIndices(single255));
}

// --- New tests for certificate get functionality ---

/*
Helper to create a mock SPDM certificate chain buffer

Example SPDM certificate chain (randomized properties for test)
 - 0x46, 0x0e, 0x00, 0x00: SPDM cert chain header (length, reserved)
 - Next 32 bytes: certificate chain hash (randomized)
 - Remainder: DER-encoded X.509 certificate(s) (randomized fields)
Certificate in PEM format:
-----BEGIN CERTIFICATE-----
MIIBljCCATugAwIBAgIUDr9ucgGtoBPnc+y0e4rxbV3wmW8wCgYIKoZIzj0EAwIw
ODELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB09wZW5CTUMxFzAVBgNVBAMMDlNQRE0g
VGVzdCBSb290MB4XDTI1MDgyMTEyMTcyN1oXDTM1MDgyMDEyMTcyN1owODELMAkG
A1UEBhMCVVMxEDAOBgNVBAoMB09wZW5CTUMxFzAVBgNVBAMMDlNQRE0gVGVzdCBS
b290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDLed9Rv+eHHNkHqecS4f3+Uv
U4BtB3oZBikRbCBLpiiQJMsw6ymjk9slsstXk5gESaNE3Fd79tAdHfa40rlX9qMj
MCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwID
SQAwRgIhAPCvclaximTSHL1lnUe4FNFoyPVLZLlwT9Ss3IxqmrePAiEAj1Z6FsN+
i98OZQz0VqpD1QNHXr449VFiCU5m+YjrSjE=
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIBnjCCAUSgAwIBAgIULZb3lqqlNrAbwIysBeAI5MIPrFgwCgYIKoZIzj0EAwIw
ODELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB09wZW5CTUMxFzAVBgNVBAMMDlNQRE0g
VGVzdCBSb290MB4XDTI1MDgyMTEyMTcyN1oXDTM1MDgyMDEyMTcyN1owQTELMAkG
A1UEBhMCVVMxEDAOBgNVBAoMB09wZW5CTUMxIDAeBgNVBAMMF1NQRE0gSW50ZXJt
ZWRpYXRlIENBIDAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE32XzRM7IYTuw
quFOTZXCISiO56uPtP+5XKcxSG+IcTEYuDbEVRPWEhN+ZT2zTLqL6K6HLwDU+N8a
q8YmdWJCPKMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYI
KoZIzj0EAwIDSAAwRQIgGZ1FbyERGnhOgIApAqgGisflQM/4HlqRV2g4vjpvkkcC
IQCYOJgxYRbOtA9r8/q3W1PR+1OlPyXkraP+aMHXkvX+rw==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIBeTCCASCgAwIBAgIUJa0pXB1rvMrsSsIDXz/gcxEO8WwwCgYIKoZIzj0EAwIw
QTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB09wZW5CTUMxIDAeBgNVBAMMF1NQRE0g
SW50ZXJtZWRpYXRlIENBIDAxMB4XDTI1MDgyMTEyMTcyN1oXDTM1MDgyMDEyMTcy
N1owOTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB09wZW5CTUMxGDAWBgNVBAMMD1NQ
RE0gRW5kIEVudGl0eTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJGg81eQ5wPX
N6fyAqunrKcz1jEAzbApnY0bQZVnrQ9j2WaXA/KdTGSag56Tcf2X/V58k5xS3I2q
36tB2ssKwWowCgYIKoZIzj0EAwIDRwAwRAIgdtwGZ9VCOViVdHiQC9vvwai+heXb
FvJYbE1QUEIxzN8CIF58/5grHIPt6H0Zhu3niDCI9aq5BwHMRYWeEqrkEpx+
-----END CERTIFICATE-----
*/

// To reduce function size, split the mock chain into smaller static arrays.
namespace
{
static const uint8_t spdmCertChainHeader[] = {0x46, 0x0e, 0x00, 0x00};

static const uint8_t spdmCertChainHash[48] = {
    0x1b, 0x97, 0x42, 0xcd, 0xd6, 0xa5, 0x9f, 0x74, 0xb9, 0x35, 0x15, 0x32,
    0x70, 0xcc, 0xe2, 0x00, 0x22, 0xf8, 0x72, 0x0b, 0xd0, 0x35, 0xe6, 0x92,
    0xfb, 0xae, 0xf3, 0xca, 0xd0, 0xc1, 0x43, 0xb3, 0x80, 0xa4, 0x4c, 0x5f,
    0x39, 0x52, 0xa0, 0x83, 0xa7, 0xff, 0x82, 0x42, 0xa1, 0xf2, 0x5f, 0x71};

static const uint8_t spdmCert1[] = {
    0x30, 0x82, 0x01, 0x96, 0x30, 0x82, 0x01, 0x3b, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x0e, 0xbf, 0x6e, 0x72, 0x01, 0xad, 0xa0, 0x13, 0xe7,
    0x73, 0xec, 0xb4, 0x7b, 0x8a, 0xf1, 0x6d, 0x5d, 0xf0, 0x99, 0x6f, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x38, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x07, 0x4f, 0x70, 0x65, 0x6e, 0x42, 0x4d, 0x43, 0x31, 0x17, 0x30, 0x15,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x53, 0x50, 0x44, 0x4d, 0x20,
    0x54, 0x65, 0x73, 0x74, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17,
    0x0d, 0x32, 0x35, 0x30, 0x38, 0x32, 0x31, 0x31, 0x32, 0x31, 0x37, 0x32,
    0x37, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30, 0x38, 0x32, 0x30, 0x31, 0x32,
    0x31, 0x37, 0x32, 0x37, 0x5a, 0x30, 0x38, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x4f, 0x70, 0x65, 0x6e, 0x42,
    0x4d, 0x43, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0e, 0x53, 0x50, 0x44, 0x4d, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x52,
    0x6f, 0x6f, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x0c, 0xb7, 0x9d, 0xf5, 0x1b, 0xfe,
    0x78, 0x71, 0xcd, 0x90, 0x7a, 0x9e, 0x71, 0x2e, 0x1f, 0xdf, 0xe5, 0x2f,
    0x53, 0x80, 0x6d, 0x07, 0x7a, 0x19, 0x06, 0x29, 0x11, 0x6c, 0x20, 0x4b,
    0xa6, 0x28, 0x90, 0x24, 0xcb, 0x30, 0xeb, 0x29, 0xa3, 0x93, 0xdb, 0x25,
    0xb2, 0xcb, 0x57, 0x93, 0x98, 0x04, 0x49, 0xa3, 0x44, 0xdc, 0x57, 0x7b,
    0xf6, 0xd0, 0x1d, 0x1d, 0xf6, 0xb8, 0xd2, 0xb9, 0x57, 0xf6, 0xa3, 0x23,
    0x30, 0x21, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
    0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xf0, 0xaf, 0x72, 0x56, 0xb1,
    0x8a, 0x64, 0xd2, 0x1c, 0xbd, 0x65, 0x9d, 0x47, 0xb8, 0x14, 0xd1, 0x68,
    0xc8, 0xf5, 0x4b, 0x64, 0xb9, 0x70, 0x4f, 0xd4, 0xac, 0xdc, 0x8c, 0x6a,
    0x9a, 0xb7, 0x8f, 0x02, 0x21, 0x00, 0x8f, 0x56, 0x7a, 0x16, 0xc3, 0x7e,
    0x8b, 0xdf, 0x0e, 0x65, 0x0c, 0xf4, 0x56, 0xaa, 0x43, 0xd5, 0x03, 0x47,
    0x5e, 0xbe, 0x38, 0xf5, 0x51, 0x62, 0x09, 0x4e, 0x66, 0xf9, 0x88, 0xeb,
    0x4a, 0x31};

static const uint8_t spdmCert2[] = {
    0x30, 0x82, 0x01, 0x9e, 0x30, 0x82, 0x01, 0x44, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x2d, 0x96, 0xf7, 0x96, 0xaa, 0xa5, 0x36, 0xb0, 0x1b,
    0xc0, 0x8c, 0xac, 0x05, 0xe0, 0x08, 0xe4, 0xc2, 0x0f, 0xac, 0x58, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x38, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x07, 0x4f, 0x70, 0x65, 0x6e, 0x42, 0x4d, 0x43, 0x31, 0x17, 0x30, 0x15,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x53, 0x50, 0x44, 0x4d, 0x20,
    0x54, 0x65, 0x73, 0x74, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17,
    0x0d, 0x32, 0x35, 0x30, 0x38, 0x32, 0x31, 0x31, 0x32, 0x31, 0x37, 0x32,
    0x37, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30, 0x38, 0x32, 0x30, 0x31, 0x32,
    0x31, 0x37, 0x32, 0x37, 0x5a, 0x30, 0x41, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x4f, 0x70, 0x65, 0x6e, 0x42,
    0x4d, 0x43, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x17, 0x53, 0x50, 0x44, 0x4d, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d,
    0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x20, 0x30, 0x31,
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xdf, 0x65, 0xf3, 0x44, 0xce, 0xc8, 0x61, 0x3b, 0xb0,
    0xaa, 0xe1, 0x4e, 0x4d, 0x95, 0xc2, 0x21, 0x28, 0x8e, 0xe7, 0xab, 0x8f,
    0xb4, 0xff, 0xb9, 0x5c, 0xa7, 0x31, 0x48, 0x6f, 0x88, 0x71, 0x31, 0x18,
    0xb8, 0x36, 0xc4, 0x55, 0x13, 0xd6, 0x12, 0x13, 0x7e, 0x65, 0x3d, 0xb3,
    0x4c, 0xba, 0x8b, 0xe8, 0xae, 0x87, 0x2f, 0x00, 0xd4, 0xf8, 0xdf, 0x1a,
    0xab, 0xc6, 0x26, 0x75, 0x62, 0x42, 0x3c, 0xa3, 0x23, 0x30, 0x21, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30,
    0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
    0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30,
    0x45, 0x02, 0x20, 0x19, 0x9d, 0x45, 0x6f, 0x21, 0x11, 0x1a, 0x78, 0x4e,
    0x80, 0x80, 0x29, 0x02, 0xa8, 0x06, 0x8a, 0xc7, 0xe5, 0x40, 0xcf, 0xf8,
    0x1e, 0x5a, 0x91, 0x57, 0x68, 0x38, 0xbe, 0x3a, 0x6f, 0x92, 0x47, 0x02,
    0x21, 0x00, 0x98, 0x38, 0x98, 0x31, 0x61, 0x16, 0xce, 0xb4, 0x0f, 0x6b,
    0xf3, 0xfa, 0xb7, 0x5b, 0x53, 0xd1, 0xfb, 0x53, 0xa5, 0x3f, 0x25, 0xe4,
    0xad, 0xa3, 0xfe, 0x68, 0xc1, 0xd7, 0x92, 0xf5, 0xfe, 0xaf};

static const uint8_t spdmCert3[] = {
    0x30, 0x82, 0x01, 0x79, 0x30, 0x82, 0x01, 0x20, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x25, 0xad, 0x29, 0x5c, 0x1d, 0x6b, 0xbc, 0xca, 0xec,
    0x4a, 0xc2, 0x03, 0x5f, 0x3f, 0xe0, 0x73, 0x11, 0x0e, 0xf1, 0x6c, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x41, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x07, 0x4f, 0x70, 0x65, 0x6e, 0x42, 0x4d, 0x43, 0x31, 0x20, 0x30, 0x1e,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x53, 0x50, 0x44, 0x4d, 0x20,
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65,
    0x20, 0x43, 0x41, 0x20, 0x30, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35,
    0x30, 0x38, 0x32, 0x31, 0x31, 0x32, 0x31, 0x37, 0x32, 0x37, 0x5a, 0x17,
    0x0d, 0x33, 0x35, 0x30, 0x38, 0x32, 0x30, 0x31, 0x32, 0x31, 0x37, 0x32,
    0x37, 0x5a, 0x30, 0x39, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x0c, 0x07, 0x4f, 0x70, 0x65, 0x6e, 0x42, 0x4d, 0x43, 0x31,
    0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x53, 0x50,
    0x44, 0x4d, 0x20, 0x45, 0x6e, 0x64, 0x20, 0x45, 0x6e, 0x74, 0x69, 0x74,
    0x79, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0x91, 0xa0, 0xf3, 0x57, 0x90, 0xe7, 0x03, 0xd7,
    0x37, 0xa7, 0xf2, 0x02, 0xab, 0xa7, 0xac, 0xa7, 0x33, 0xd6, 0x31, 0x00,
    0xcd, 0xb0, 0x29, 0x9d, 0x8d, 0x1b, 0x41, 0x95, 0x67, 0xad, 0x0f, 0x63,
    0xd9, 0x66, 0x97, 0x03, 0xf2, 0x9d, 0x4c, 0x64, 0x9a, 0x83, 0x9e, 0x93,
    0x71, 0xfd, 0x97, 0xfd, 0x5e, 0x7c, 0x93, 0x9c, 0x52, 0xdc, 0x8d, 0xaa,
    0xdf, 0xab, 0x41, 0xda, 0xcb, 0x0a, 0xc1, 0x6a, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30,
    0x44, 0x02, 0x20, 0x76, 0xdc, 0x06, 0x67, 0xd5, 0x42, 0x39, 0x58, 0x95,
    0x74, 0x78, 0x90, 0x0b, 0xdb, 0xef, 0xc1, 0xa8, 0xbe, 0x85, 0xe5, 0xdb,
    0x16, 0xf2, 0x58, 0x6c, 0x4d, 0x50, 0x50, 0x42, 0x31, 0xcc, 0xdf, 0x02,
    0x20, 0x5e, 0x7c, 0xff, 0x98, 0x2b, 0x1c, 0x83, 0xed, 0xe8, 0x7d, 0x19,
    0x86, 0xed, 0xe7, 0x88, 0x30, 0x88, 0xf5, 0xaa, 0xb9, 0x07, 0x01, 0xcc,
    0x45, 0x85, 0x9e, 0x12, 0xaa, 0xe4, 0x12, 0x9c, 0x7e};
} // namespace

static std::vector<uint8_t> makeMockSpdmCertChain()
{
    std::vector<uint8_t> chain;
    chain.insert(chain.end(), std::begin(spdmCertChainHeader),
                 std::end(spdmCertChainHeader));
    chain.insert(chain.end(), std::begin(spdmCertChainHash),
                 std::end(spdmCertChainHash));
    chain.insert(chain.end(), std::begin(spdmCert1), std::end(spdmCert1));
    chain.insert(chain.end(), std::begin(spdmCert2), std::end(spdmCert2));
    chain.insert(chain.end(), std::begin(spdmCert3), std::end(spdmCert3));
    return chain;
}

// Test getCertificate with null transport
TEST_F(ComponentIntegrityTest, GetCertificateNullTransportTest)
{
    componentIntegrity->setTransport(nullptr);
    EXPECT_THROW(getCertificate(0), std::runtime_error);
}

// Test getCertificate with null spdmContext
TEST_F(ComponentIntegrityTest, GetCertificateNullContextTest)
{
    // Transport is set, but spdmContext is null
    EXPECT_THROW(getCertificate(0), std::runtime_error);
}

// Test getCertificate with too-small cert chain (should throw)
TEST_F(ComponentIntegrityTest, GetCertificateTooSmallChainTest)
{
    static uint8_t dummyContextBuffer[1024];
    mockTransport->spdmContext = dummyContextBuffer;
    mockTransport->getCertStatus = LIBSPDM_STATUS_SUCCESS;
    // Compose a too-small cert chain (header+hash not satisfied)
    mockTransport->mockCertChain = {0x01, 0x02, 0x03, 0x04, 0x05};
    mockTransport->setAsCurrentMock();
    EXPECT_THROW(getCertificate(0), std::runtime_error);
}

// Test getCertificate with failed libspdm_get_certificate
TEST_F(ComponentIntegrityTest, GetCertificateFailureTest)
{
    static uint8_t dummyContextBuffer[1024];
    mockTransport->spdmContext = dummyContextBuffer;
    mockTransport->getCertStatus = LIBSPDM_STATUS_INVALID_PARAMETER;
    mockTransport->mockCertChain = makeMockSpdmCertChain();
    mockTransport->setAsCurrentMock();
    EXPECT_THROW(getCertificate(0), std::runtime_error);
}

// Test getCertificate with valid mock chain
TEST_F(ComponentIntegrityTest, GetCertificateSuccessTest)
{
    static uint8_t dummyContextBuffer[1024];
    mockTransport->spdmContext = dummyContextBuffer;
    mockTransport->getCertStatus = LIBSPDM_STATUS_SUCCESS;
    mockTransport->mockCertChain = makeMockSpdmCertChain();
    mockTransport->setAsCurrentMock();
    std::string pemChain;
    std::vector<uint8_t> rawBytes;
    std::vector<uint8_t> leafCert;
    try
    {
        std::tie(pemChain, rawBytes, leafCert) = getCertificate(0);
    }
    catch (const std::exception& ex)
    {
        FAIL() << "getCertificate threw exception: " << ex.what();
    }
    EXPECT_NE(pemChain.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
    EXPECT_NE(pemChain.find("-----END CERTIFICATE-----"), std::string::npos);

    // The rawBytes should match the mockCertChain
    EXPECT_EQ(rawBytes, mockTransport->mockCertChain);
    EXPECT_EQ(rawBytes.size(), mockTransport->mockCertChain.size());

    // The PEM should contain a base64 encoding of 0x01,0x02,0x03
    // (which is AQID in base64)
    EXPECT_NE(pemChain.find("MIIBljCC"), std::string::npos);
}

// Test getCertificate with multiple DER certs in chain and check PEM base64
// content
TEST_F(ComponentIntegrityTest, GetCertificateMultipleDerCertsTest)
{
    static uint8_t dummyContextBuffer[1024];
    mockTransport->spdmContext = dummyContextBuffer;
    mockTransport->getCertStatus = LIBSPDM_STATUS_SUCCESS;
    mockTransport->mockCertChain = makeMockSpdmCertChain();
    mockTransport->setAsCurrentMock();

    auto [pemChain, rawBytes, leafCert] = getCertificate(0);

    // Should contain three PEM blocks
    size_t first = pemChain.find("-----BEGIN CERTIFICATE-----");
    size_t second = pemChain.find("-----BEGIN CERTIFICATE-----", first + 1);
    size_t third = pemChain.find("-----BEGIN CERTIFICATE-----", second + 1);
    EXPECT_NE(first, std::string::npos);
    EXPECT_NE(second, std::string::npos);
    EXPECT_NE(third, std::string::npos);

    // Check for a unique base64 prefix from each cert in the PEM output
    EXPECT_NE(pemChain.find("MIIBljCCATug"), std::string::npos);
    EXPECT_NE(pemChain.find("MIIBnjCCAUSg"), std::string::npos);
    EXPECT_NE(pemChain.find("MIIBeTCCASCg"), std::string::npos);

    // Raw bytes should match
    EXPECT_EQ(rawBytes, mockTransport->mockCertChain);
    EXPECT_EQ(rawBytes.size(), mockTransport->mockCertChain.size());
}

// Note: method_call tests are omitted because they require async testing

} // namespace test
} // namespace spdm
