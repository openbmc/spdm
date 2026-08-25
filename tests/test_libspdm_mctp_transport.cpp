// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/libspdm_mctp_transport.hpp"

#include <gtest/gtest.h>

namespace spdm::test
{

class SpdmMctpTransportTest : public ::testing::Test
{
  protected:
    static bool initializeContext(SpdmMctpTransport& transport)
    {
        // Exercise the real registration path without opening an MCTP socket.
        return transport.allocateContext() && transport.registerFunctions() &&
               transport.setupScratchBuffer();
    }
};

TEST_F(SpdmMctpTransportTest, RejectsLimitsOutsideProtocolAndBufferBounds)
{
    for (size_t limit : {0U, SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12 - 1U,
                         LIBSPDM_MAX_SPDM_MSG_SIZE + 1U})
    {
        EXPECT_THROW(SpdmMctpTransport(8, limit), std::invalid_argument);
    }
}

class SpdmMctpTransportLimitTest :
    public SpdmMctpTransportTest,
    public ::testing::WithParamInterface<size_t>
{};

TEST_P(SpdmMctpTransportLimitTest, AdvertisedSizesMatchConfiguredLimit)
{
    const size_t limit = GetParam();
    SpdmMctpTransport transport(8, limit);
    ASSERT_TRUE(initializeContext(transport));
    auto* context =
        static_cast<libspdm_context_t*>(transport.spdmContext.get());
    ASSERT_NE(context, nullptr);
    const auto& capability = context->local_context.capability;

    EXPECT_EQ(capability.flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP,
              0U);
    EXPECT_EQ(capability.max_spdm_msg_size, limit);
    EXPECT_EQ(capability.data_transfer_size, limit);
    EXPECT_EQ(capability.sender_data_transfer_size, limit);
    EXPECT_EQ(context->sender_buffer_size,
              limit + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE);
    EXPECT_EQ(context->receiver_buffer_size,
              limit + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE);
    EXPECT_LE(context->sender_buffer_size, transport.sendReceiveBuffer.size());
    EXPECT_LE(context->receiver_buffer_size,
              transport.sendReceiveBuffer.size());
}

INSTANTIATE_TEST_SUITE_P(
    MessageLimits, SpdmMctpTransportLimitTest,
    ::testing::Values(SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12, 2047,
                      LIBSPDM_MAX_SPDM_MSG_SIZE));

} // namespace spdm::test
