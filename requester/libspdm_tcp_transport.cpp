// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "libspdm_tcp_transport.hpp"

extern "C"
{
#include "library/spdm_transport_tcp_lib.h"
}

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>

#define DEBUG 0

namespace spdm
{
bool SpdmTcpTransport::initialize()
{
    lg2::info("Initializing SPDM TCP transport for {IP}:{PORT}", "IP", ipAddr,
              "PORT", port);

    if (!tcpIo.createSocket())
    {
        lg2::error("Failed to create TCP socket for {IP}:{PORT}", "IP", ipAddr,
                   "PORT", port);
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

    lg2::info("SPDM TCP transport initialized successfully for {IP}:{PORT}",
              "IP", ipAddr, "PORT", port);
    return true;
}

bool SpdmTcpTransport::allocateContext()
{
    spdmContext = static_cast<void*>(malloc(libspdm_get_context_size()));
    if (!spdmContext)
    {
        lg2::error("Failed to allocate SPDM context");
        return false;
    }

    libspdm_return_t status = libspdm_init_context(spdmContext);
    if (status != LIBSPDM_STATUS_SUCCESS)
    {
        lg2::error("Failed to initialize SPDM context: 0x{STATUS:X}", "STATUS",
                   status);
        free(spdmContext);
        spdmContext = nullptr;
        return false;
    }

    // Store pointer to this transport for callback access
    libspdm_context_t* context = static_cast<libspdm_context_t*>(spdmContext);
    context->app_context_data_ptr = this;

    lg2::debug("SPDM context allocated and initialized");
    return true;
}

bool SpdmTcpTransport::registerFunctions()
{
    // Register device I/O functions
    libspdm_register_device_io_func(spdmContext,
                                    &SpdmTcpTransport::deviceSendMessage,
                                    &SpdmTcpTransport::deviceReceiveMessage);

    // The TCP framing is handled by TcpMessageTransport
    libspdm_register_transport_layer_func(
        spdmContext, LIBSPDM_MAX_SPDM_MSG_SIZE, LIBSPDM_TRANSPORT_HEADER_SIZE,
        LIBSPDM_TRANSPORT_TAIL_SIZE, libspdm_transport_tcp_encode_message,
        libspdm_transport_tcp_decode_message);

    // Register buffer management functions
    libspdm_register_device_buffer_func(
        spdmContext, LIBSPDM_SENDER_BUFFER_SIZE, LIBSPDM_RECEIVER_BUFFER_SIZE,
        &SpdmTcpTransport::spdmDeviceAcquireSenderBuffer,
        &SpdmTcpTransport::spdmDeviceReleaseSenderBuffer,
        &SpdmTcpTransport::spdmDeviceAcquireReceiverBuffer,
        &SpdmTcpTransport::spdmDeviceReleaseReceiverBuffer);

    lg2::debug("SPDM callback functions registered");
    return true;
}

bool SpdmTcpTransport::setupScratchBuffer()
{
    size_t scratchBufferSize =
        libspdm_get_sizeof_required_scratch_buffer(spdmContext);

    scratchBuffer = malloc(scratchBufferSize);
    if (scratchBuffer == nullptr)
    {
        lg2::error("Failed to allocate scratch buffer of size {SIZE}", "SIZE",
                   scratchBufferSize);
        return false;
    }

    libspdm_set_scratch_buffer(spdmContext, scratchBuffer, scratchBufferSize);

    if (!libspdm_check_context(spdmContext))
    {
        lg2::error("SPDM context check failed after scratch buffer setup");
        return false;
    }

    lg2::debug("Scratch buffer allocated: {SIZE} bytes", "SIZE",
               scratchBufferSize);
    return true;
}

bool SpdmTcpTransport::configureContext()
{
    // Set SPDM version if specified
    if (useVersion != 0)
    {
        spdm_version_number_t spdmVersion;
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdmVersion = useVersion << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(spdmContext, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdmVersion, sizeof(spdmVersion));
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    // Set capability exponent
    uint8_t data8 = 0;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));

    // Set measurement specification
    data8 = supportMeasurementSpec;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));

    // Set asymmetric algorithm
    uint32_t data32 = supportAsymAlgo;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));

    // Set hash algorithm
    data32 = supportHashAlgo;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));

    lg2::debug("SPDM context configured");
    return true;
}

void SpdmTcpTransport::cleanupContext()
{
    if (scratchBuffer)
    {
        free(scratchBuffer);
        scratchBuffer = nullptr;
    }
    if (spdmContext)
    {
        libspdm_deinit_context(spdmContext);
        free(spdmContext);
        spdmContext = nullptr;
    }
    tcpIo.closeSocket();
    lg2::debug("SPDM TCP transport resources cleaned up");
}

libspdm_return_t SpdmTcpTransport::deviceSendMessage(
    void* spdmContext, size_t messageSize, const void* message,
    uint64_t timeout)
{
    try
    {
        libspdm_context_t* context =
            static_cast<libspdm_context_t*>(spdmContext);
        auto* transport =
            static_cast<SpdmTcpTransport*>(context->app_context_data_ptr);

        if (!transport)
        {
            lg2::error("SpdmTcpTransport instance is nullptr in send callback");
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        // Create SPDM message vector
        std::vector<uint8_t> spdmMsg(
            static_cast<const uint8_t*>(message),
            static_cast<const uint8_t*>(message) + messageSize);

        // Encode for TCP transport (platform message format)
        std::vector<uint8_t> tcpMessage;
        libspdm_return_t encodeStatus =
            transport->tcpTransport.encode(tcpMessage, spdmMsg);
        if (encodeStatus != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to encode TCP message");
            return LIBSPDM_STATUS_SEND_FAIL;
        }

#if DEBUG
        if (tcpMessage.size() >= 12)
        {
            lg2::info(
                "TCP send header: cmd={CMD:02X} {C1:02X} {C2:02X} {C3:02X} "
                "type={T0:02X} {T1:02X} {T2:02X} {T3:02X} "
                "size={S0:02X} {S1:02X} {S2:02X} {S3:02X}",
                "CMD", tcpMessage[0], "C1", tcpMessage[1], "C2", tcpMessage[2],
                "C3", tcpMessage[3], "T0", tcpMessage[4], "T1", tcpMessage[5],
                "T2", tcpMessage[6], "T3", tcpMessage[7], "S0", tcpMessage[8],
                "S1", tcpMessage[9], "S2", tcpMessage[10], "S3",
                tcpMessage[11]);
        }
#endif

        // Send over TCP
        libspdm_return_t sendStatus =
            transport->tcpIo.write(tcpMessage, timeout);
        if (sendStatus != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to send SPDM message over TCP");
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        lg2::info("Sent SPDM message: {SIZE} bytes (total TCP: {TOTAL})",
                  "SIZE", messageSize, "TOTAL", tcpMessage.size());
        return LIBSPDM_STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception in TCP send: {ERROR}", "ERROR", e.what());
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t SpdmTcpTransport::deviceReceiveMessage(
    void* spdmContext, size_t* messageSize, void** message, uint64_t timeout)
{
    try
    {
        libspdm_context_t* context =
            static_cast<libspdm_context_t*>(spdmContext);
        auto* transport =
            static_cast<SpdmTcpTransport*>(context->app_context_data_ptr);

        if (!transport)
        {
            lg2::error(
                "SpdmTcpTransport instance is nullptr in receive callback");
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        // Read from TCP
        std::vector<uint8_t> tcpMessage;
        libspdm_return_t readStatus =
            transport->tcpIo.read(tcpMessage, timeout);
        if (readStatus != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to receive SPDM message over TCP");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

#if DEBUG
        if (tcpMessage.size() >= 12)
        {
            lg2::info(
                "TCP recv header: cmd={CMD:02X} {C1:02X} {C2:02X} {C3:02X} "
                "type={T0:02X} {T1:02X} {T2:02X} {T3:02X} "
                "size={S0:02X} {S1:02X} {S2:02X} {S3:02X}",
                "CMD", tcpMessage[0], "C1", tcpMessage[1], "C2", tcpMessage[2],
                "C3", tcpMessage[3], "T0", tcpMessage[4], "T1", tcpMessage[5],
                "T2", tcpMessage[6], "T3", tcpMessage[7], "S0", tcpMessage[8],
                "S1", tcpMessage[9], "S2", tcpMessage[10], "S3",
                tcpMessage[11]);
        }
#endif

        // Decode TCP transport message to extract SPDM message
        libspdm_return_t decodeStatus =
            transport->tcpTransport.decode(tcpMessage, message, messageSize);
        if (decodeStatus != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to decode TCP message");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        lg2::info("Received SPDM message: {SIZE} bytes (total TCP: {TOTAL})",
                  "SIZE", *messageSize, "TOTAL", tcpMessage.size());
        return LIBSPDM_STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception in TCP receive: {ERROR}", "ERROR", e.what());
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

libspdm_return_t SpdmTcpTransport::spdmDeviceAcquireSenderBuffer(
    void* context, void** msgBufPtr)
{
    libspdm_context_t* spdmContext = static_cast<libspdm_context_t*>(context);
    auto* transport =
        static_cast<SpdmTcpTransport*>(spdmContext->app_context_data_ptr);

    if (transport->sendReceiveBufferAcquired)
    {
        lg2::error("Send/receive buffer already acquired");
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    *msgBufPtr = transport->sendReceiveBuffer;
    libspdm_zero_mem(transport->sendReceiveBuffer,
                     sizeof(transport->sendReceiveBuffer));
    transport->sendReceiveBufferAcquired = true;

    return LIBSPDM_STATUS_SUCCESS;
}

void SpdmTcpTransport::spdmDeviceReleaseSenderBuffer(void* context,
                                                     const void* /*msgBufPtr*/)
{
    libspdm_context_t* spdmContext = static_cast<libspdm_context_t*>(context);
    auto* transport =
        static_cast<SpdmTcpTransport*>(spdmContext->app_context_data_ptr);
    transport->sendReceiveBufferAcquired = false;
}

libspdm_return_t SpdmTcpTransport::spdmDeviceAcquireReceiverBuffer(
    void* context, void** msgBufPtr)
{
    libspdm_context_t* spdmContext = static_cast<libspdm_context_t*>(context);
    auto* transport =
        static_cast<SpdmTcpTransport*>(spdmContext->app_context_data_ptr);

    if (transport->sendReceiveBufferAcquired)
    {
        lg2::error("Send/receive buffer already acquired");
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    *msgBufPtr = transport->sendReceiveBuffer;
    libspdm_zero_mem(transport->sendReceiveBuffer,
                     sizeof(transport->sendReceiveBuffer));
    transport->sendReceiveBufferAcquired = true;

    return LIBSPDM_STATUS_SUCCESS;
}

void SpdmTcpTransport::spdmDeviceReleaseReceiverBuffer(
    void* context, const void* /*msgBufPtr*/)
{
    libspdm_context_t* spdmContext = static_cast<libspdm_context_t*>(context);
    auto* transport =
        static_cast<SpdmTcpTransport*>(spdmContext->app_context_data_ptr);
    transport->sendReceiveBufferAcquired = false;
}

} // namespace spdm
