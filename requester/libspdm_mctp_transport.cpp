// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "libspdm_mctp_transport.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace spdm
{

bool SpdmMctpTransport::initialize()
{
    if (!mctpIo.createSocket())
    {
        lg2::error("Failed to create MCTP socket for EID {EID}", "EID", eid);
        return false;
    }
    if (!allocateContext())
    {
        return false;
    }

    if (!registerFunctions())
    {
        cleanupContext();
        return false;
    }

    if (!setupScratchBuffer())
    {
        cleanupContext();
        return false;
    }

    if (!configureContext())
    {
        cleanupContext();
        return false;
    }

    return true;
}

bool SpdmMctpTransport::allocateContext()
{
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    void* ctx = malloc(libspdm_get_context_size());
    if (!ctx)
    {
        lg2::error("Failed to allocate SPDM context");
        return false;
    }

    libspdm_return_t status = libspdm_init_context(ctx);
    if (status != LIBSPDM_STATUS_SUCCESS)
    {
        lg2::error("Failed to initialize SPDM context");
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
        free(ctx);
        return false;
    }

    spdmContext.reset(ctx);
    static_cast<libspdm_context_t*>(spdmContext.get())->app_context_data_ptr =
        this;
    return true;
}

bool SpdmMctpTransport::registerFunctions()
{
    libspdm_register_device_io_func(spdmContext.get(),
                                    &SpdmMctpTransport::device_send_message,
                                    &SpdmMctpTransport::device_receive_message);
    libspdm_register_transport_layer_func(
        spdmContext.get(), LIBSPDM_MAX_SPDM_MSG_SIZE,
        LIBSPDM_TRANSPORT_HEADER_SIZE, LIBSPDM_TRANSPORT_TAIL_SIZE,
        libspdm_transport_mctp_encode_message,
        libspdm_transport_mctp_decode_message);
    libspdm_register_device_buffer_func(
        spdmContext.get(), LIBSPDM_SENDER_BUFFER_SIZE,
        LIBSPDM_RECEIVER_BUFFER_SIZE, &SpdmMctpTransport::acquireBuffer,
        &SpdmMctpTransport::releaseBuffer, &SpdmMctpTransport::acquireBuffer,
        &SpdmMctpTransport::releaseBuffer);
    return true;
}

bool SpdmMctpTransport::setupScratchBuffer()
{
    size_t scratch_buffer_size =
        libspdm_get_sizeof_required_scratch_buffer(spdmContext.get());
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    scratchBuffer.reset(malloc(scratch_buffer_size));
    if (!scratchBuffer)
    {
        return false;
    }

    libspdm_set_scratch_buffer(spdmContext.get(), scratchBuffer.get(),
                               scratch_buffer_size);
    // Note: libspdm_check_context() is intentionally not called here. It runs
    // at the end of applySecureSessionConfig() once all KEY_EX caps and
    // algorithms have been set.
    return true;
}

bool SpdmMctpTransport::configureContext()
{
    if (useVersion != 0)
    {
        spdm_version_number_t spdm_version;
        parameter = {};
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = useVersion << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(spdmContext.get(), LIBSPDM_DATA_SPDM_VERSION,
                         &parameter, &spdm_version, sizeof(spdm_version));
    }

    parameter = {};
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    uint8_t data8 = 0;
    libspdm_set_data(spdmContext.get(), LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));

    data8 = supportMeasurementSpec;
    libspdm_set_data(spdmContext.get(), LIBSPDM_DATA_MEASUREMENT_SPEC,
                     &parameter, &data8, sizeof(data8));
    uint32_t data32 = supportAsymAlgo;
    libspdm_set_data(spdmContext.get(), LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = supportHashAlgo;
    libspdm_set_data(spdmContext.get(), LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));

    return true;
}

void SpdmMctpTransport::cleanupContext()
{
    scratchBuffer.reset();
    spdmContext.reset();
}

libspdm_return_t SpdmMctpTransport::device_send_message(
    void* spdm_context, size_t message_size, const void* message,
    uint64_t timeout)
{
    try
    {
        libspdm_context_t* context =
            static_cast<libspdm_context_t*>(spdm_context);
        auto transport =
            static_cast<SpdmMctpTransport*>(context->app_context_data_ptr);
        if (!transport)
        {
            lg2::error("SpdmMctpTransport instance is nullptr");
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        std::vector<uint8_t> msg(
            static_cast<const uint8_t*>(message),
            static_cast<const uint8_t*>(message) + message_size);
        timeout_us_t timeoutUs = static_cast<timeout_us_t>(timeout);
        std::vector<uint8_t> mctpMessage;
        if (transport->mctpMessageTransport.encode(
                transport->eid, mctpMessage, msg) != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to encode MCTP message");
            return LIBSPDM_STATUS_SEND_FAIL;
        }
        libspdm_return_t ret = transport->mctpIo.write(mctpMessage, timeoutUs);
        if (ret != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to send SPDM message");
            return LIBSPDM_STATUS_SEND_FAIL;
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception in device_send_message: {MSG}", "MSG", e.what());
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t SpdmMctpTransport::device_receive_message(
    void* spdm_context, size_t* message_size, void** message, uint64_t timeout)
{
    try
    {
        libspdm_context_t* context =
            static_cast<libspdm_context_t*>(spdm_context);
        auto transport =
            static_cast<SpdmMctpTransport*>(context->app_context_data_ptr);
        if (!transport)
        {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        timeout_us_t timeoutUs = static_cast<timeout_us_t>(timeout);
        std::vector<uint8_t> response;
        libspdm_return_t ret = transport->mctpIo.read(response, timeoutUs);
        if (ret != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to receive SPDM message");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        if (transport->mctpMessageTransport.decode(transport->eid, response,
                                                   message, message_size) !=
            LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to decode MCTP message");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception in device_receive_message: {MSG}", "MSG",
                   e.what());
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

libspdm_return_t SpdmMctpTransport::acquireBuffer(void* context,
                                                  void** msg_buf_ptr)
{
    libspdm_context_t* spdm_context = static_cast<libspdm_context_t*>(context);
    SpdmMctpTransport* transport =
        static_cast<SpdmMctpTransport*>(spdm_context->app_context_data_ptr);

    if (transport->sendReceiveBufferAcquired)
    {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    *msg_buf_ptr = transport->sendReceiveBuffer.data();
    transport->sendReceiveBuffer.fill(0);
    transport->sendReceiveBufferAcquired = true;

    return LIBSPDM_STATUS_SUCCESS;
}

void SpdmMctpTransport::releaseBuffer(void* context,
                                      const void* /*msg_buf_ptr*/)
{
    libspdm_context_t* spdm_context = static_cast<libspdm_context_t*>(context);
    SpdmMctpTransport* transport =
        static_cast<SpdmMctpTransport*>(spdm_context->app_context_data_ptr);
    transport->sendReceiveBufferAcquired = false;
}

} // namespace spdm
