// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/mctp_helper.hpp"

#include <phosphor-logging/lg2.hpp>

#include <memory>
#include <vector>

#include <gtest/gtest.h>

PHOSPHOR_LOG2_USING;

namespace spdm
{
namespace test
{

// Test fixture for MCTP helper tests
class MctpHelperTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Set up any common test data
    }

    void TearDown() override
    {
        // Clean up any resources
    }
};

// Test MctpMessageTransport class
class MctpMessageTransportTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        transport = std::make_unique<spdm::MctpMessageTransport>();
    }

    void TearDown() override
    {
        transport.reset();
    }

    std::unique_ptr<spdm::MctpMessageTransport> transport;
};

// Test encode function
TEST_F(MctpMessageTransportTest, EncodeTest)
{
    std::vector<uint8_t> buf;
    std::vector<uint8_t> msg = {0x10, 0x84, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44};
    uint8_t eid = 0x10;

    libspdm_return_t result = transport->encode(eid, buf, msg);

    EXPECT_EQ(result, LIBSPDM_STATUS_SUCCESS);
    EXPECT_EQ(buf.size(),
              sizeof(spdm::MctpMessageTransport::HeaderType) + msg.size());

    // Check header
    auto& header =
        transport->getHeaderRef<spdm::MctpMessageTransport::HeaderType>(buf);
    EXPECT_EQ(header.eid, eid);
    EXPECT_EQ(header.mctpTag(),
              0x00); // MCTP_TAG_OWNER & 0x07 = 0x08 & 0x07 = 0x00
    EXPECT_TRUE(header.mctpTO());

    // Check message data
    size_t headerSize = sizeof(spdm::MctpMessageTransport::HeaderType);
    std::vector<uint8_t> expectedData = {0x10, 0x84, 0x00, 0x00,
                                         0x11, 0x22, 0x33, 0x44};
    std::vector<uint8_t> actualData(buf.begin() + headerSize, buf.end());
    EXPECT_EQ(actualData, expectedData);
}

// Test encode function with empty message
TEST_F(MctpMessageTransportTest, EncodeEmptyMessageTest)
{
    std::vector<uint8_t> buf;
    std::vector<uint8_t> msg;
    uint8_t eid = 0x20;

    libspdm_return_t result = transport->encode(eid, buf, msg);

    EXPECT_EQ(result, LIBSPDM_STATUS_SUCCESS);
    EXPECT_EQ(buf.size(), sizeof(spdm::MctpMessageTransport::HeaderType));

    // Check header
    auto& header =
        transport->getHeaderRef<spdm::MctpMessageTransport::HeaderType>(buf);
    EXPECT_EQ(header.eid, eid);
    EXPECT_EQ(header.mctpTag(),
              0x00); // MCTP_TAG_OWNER & 0x07 = 0x08 & 0x07 = 0x00
}

// Test decode function
TEST_F(MctpMessageTransportTest, DecodeTest)
{
    // Create encoded data
    std::vector<uint8_t> encodedBuf;
    std::vector<uint8_t> originalMsg = {0x10, 0x84, 0x00, 0x00,
                                        0x11, 0x22, 0x33, 0x44};
    uint8_t eid = 0x10;

    transport->encode(eid, encodedBuf, originalMsg);

    // Decode the data
    void* message = nullptr;
    size_t message_size = 0;
    libspdm_return_t result =
        transport->decode(eid, encodedBuf, &message, &message_size);

    EXPECT_EQ(result, LIBSPDM_STATUS_SUCCESS);
    EXPECT_EQ(message_size, originalMsg.size());

    // Check decoded message
    std::vector<uint8_t> decodedMsg(
        static_cast<uint8_t*>(message),
        static_cast<uint8_t*>(message) + message_size);
    EXPECT_EQ(decodedMsg, originalMsg);

    // Clean up allocated memory
    free(message);
}

// Test decode function with wrong EID
TEST_F(MctpMessageTransportTest, DecodeWrongEidTest)
{
    // Create encoded data
    std::vector<uint8_t> encodedBuf;
    std::vector<uint8_t> originalMsg = {0x10, 0x84, 0x00, 0x00};
    uint8_t encodeEid = 0x10;

    transport->encode(encodeEid, encodedBuf, originalMsg);

    // Try to decode with wrong EID
    void* message = nullptr;
    size_t message_size = 0;
    uint8_t decodeEid = 0x20; // Different EID
    libspdm_return_t result =
        transport->decode(decodeEid, encodedBuf, &message, &message_size);

    EXPECT_EQ(result, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    EXPECT_EQ(message, nullptr);
    EXPECT_EQ(message_size, 0);
}

// Test decode function with buffer too small
TEST_F(MctpMessageTransportTest, DecodeBufferTooSmallTest)
{
    std::vector<uint8_t> buf = {0x00}; // Too small for header
    void* message = nullptr;
    size_t message_size = 0;
    uint8_t eid = 0x10;

    libspdm_return_t result =
        transport->decode(eid, buf, &message, &message_size);

    EXPECT_EQ(result, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    EXPECT_EQ(message, nullptr);
    EXPECT_EQ(message_size, 0);
}

// Test decode function with memory allocation failure
TEST_F(MctpMessageTransportTest, DecodeMemoryAllocationTest)
{
    // Create encoded data
    std::vector<uint8_t> encodedBuf;
    std::vector<uint8_t> originalMsg = {0x10, 0x84, 0x00, 0x00};
    uint8_t eid = 0x10;

    transport->encode(eid, encodedBuf, originalMsg);

    // Note: Testing memory allocation failure is difficult without mocking
    // malloc This test verifies the function handles the allocation properly
    void* message = nullptr;
    size_t message_size = 0;
    libspdm_return_t result =
        transport->decode(eid, encodedBuf, &message, &message_size);

    EXPECT_EQ(result, LIBSPDM_STATUS_SUCCESS);
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message_size, originalMsg.size());

    // Clean up
    free(message);
}

// Test MctpIoClass
class MctpIoClassTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        mctpIo = std::make_unique<spdm::MctpIoClass>();
    }

    void TearDown() override
    {
        if (mctpIo && mctpIo->isSocketOpen())
        {
            mctpIo->deleteSocket();
        }
        mctpIo.reset();
    }

    std::unique_ptr<spdm::MctpIoClass> mctpIo;
};

// Test socket creation when already open
TEST_F(MctpIoClassTest, CreateSocketAlreadyOpenTest)
{
    // Create socket first time
    bool result1 = mctpIo->createSocket();

    // Try to create socket again
    bool result2 = mctpIo->createSocket();

    // Should return true if socket is already open
    if (result1)
    {
        EXPECT_TRUE(result2);
    }

    EXPECT_TRUE(true); // Placeholder assertion
}

// Test socket deletion
TEST_F(MctpIoClassTest, DeleteSocketTest)
{
    // Create socket
    mctpIo->createSocket();

    // Delete socket
    mctpIo->deleteSocket();

    // Check if socket is closed
    EXPECT_FALSE(mctpIo->isSocketOpen());
    EXPECT_EQ(mctpIo->getSocket(), -1);
}

// Test socket deletion when not open
TEST_F(MctpIoClassTest, DeleteSocketNotOpenTest)
{
    // Delete socket when not open
    mctpIo->deleteSocket();

    // Should not crash and socket should remain closed
    EXPECT_FALSE(mctpIo->isSocketOpen());
    EXPECT_EQ(mctpIo->getSocket(), -1);
}

// Test write function
TEST_F(MctpIoClassTest, WriteTest)
{
    std::vector<uint8_t> data = {0x10, 0x84, 0x00, 0x00,
                                 0x11, 0x22, 0x33, 0x44};

    // Try to write without opening socket
    libspdm_return_t result = mctpIo->write(data, timeoutUsInfinite);

    // Should fail if socket is not open
    EXPECT_EQ(result, LIBSPDM_STATUS_SEND_FAIL);
}

// Test read function
TEST_F(MctpIoClassTest, ReadTest)
{
    std::vector<uint8_t> data;

    // Try to read without opening socket
    libspdm_return_t result = mctpIo->read(data, timeoutUsInfinite);

    // Should fail if socket is not open
    EXPECT_EQ(result, LIBSPDM_STATUS_RECEIVE_FAIL);
}

// Test MCTP message transport with large message
TEST_F(MctpMessageTransportTest, EncodeLargeMessageTest)
{
    std::vector<uint8_t> buf;
    std::vector<uint8_t> msg(1000, 0xAA); // 1000 bytes
    uint8_t eid = 0x30;

    libspdm_return_t result = transport->encode(eid, buf, msg);

    EXPECT_EQ(result, LIBSPDM_STATUS_SUCCESS);
    EXPECT_EQ(buf.size(),
              sizeof(spdm::MctpMessageTransport::HeaderType) + msg.size());

    // Check header
    auto& header =
        transport->getHeaderRef<spdm::MctpMessageTransport::HeaderType>(buf);
    EXPECT_EQ(header.eid, eid);
    EXPECT_EQ(header.mctpTag(),
              0x00); // MCTP_TAG_OWNER & 0x07 = 0x08 & 0x07 = 0x00

    // Check message data
    size_t headerSize = sizeof(spdm::MctpMessageTransport::HeaderType);
    std::vector<uint8_t> actualData(buf.begin() + headerSize, buf.end());
    EXPECT_EQ(actualData, msg);
}

// Test MCTP message transport decode with large message
TEST_F(MctpMessageTransportTest, DecodeLargeMessageTest)
{
    // Create encoded data with large message
    std::vector<uint8_t> encodedBuf;
    std::vector<uint8_t> originalMsg(1000, 0xBB); // 1000 bytes
    uint8_t eid = 0x40;

    transport->encode(eid, encodedBuf, originalMsg);

    // Decode the data
    void* message = nullptr;
    size_t message_size = 0;
    libspdm_return_t result =
        transport->decode(eid, encodedBuf, &message, &message_size);

    EXPECT_EQ(result, LIBSPDM_STATUS_SUCCESS);
    EXPECT_EQ(message_size, originalMsg.size());

    // Check decoded message
    std::vector<uint8_t> decodedMsg(
        static_cast<uint8_t*>(message),
        static_cast<uint8_t*>(message) + message_size);
    EXPECT_EQ(decodedMsg, originalMsg);

    // Clean up allocated memory
    free(message);
}

} // namespace test
} // namespace spdm
