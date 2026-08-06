// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "libspdm_transport.hpp"
#include "tcp_helper.hpp"

namespace spdm
{

/**
 * @class SpdmTcpTransport
 * @brief SPDM transport implementation over TCP
 *
 * This class implements the SPDM transport interface using TCP as the
 * underlying transport protocol.
 */
class SpdmTcpTransport : public SpdmTransport
{
  public:
    /**
     * @brief Constructor for SPDM TCP Transport
     * @param ipAddress IP address of the SPDM responder
     * @param port TCP port of the SPDM responder
     */
    SpdmTcpTransport(const std::string& ipAddress, uint16_t port) :
        ipAddr(ipAddress), port(port), tcpIo(ipAddress, port)
    {}

    virtual ~SpdmTcpTransport() = default;

    /**
     * @brief Initialize the SPDM TCP transport
     *
     * Sets up the SPDM context, registers callbacks, and configures the
     * transport layer for TCP communication.
     *
     * @return true if initialization was successful, false otherwise
     */
    bool initialize() override;

    /* Public members for callback access */
    std::string ipAddr;
    uint16_t port;
    TcpIoClass tcpIo;
    TcpMessageTransport tcpTransport;

  private:
    /**
     * @brief Allocate and initialize the SPDM context
     * @return true if successful, false otherwise
     */
    bool allocateContext();

    /**
     * @brief Register callback functions with the SPDM context
     * @return true if successful, false otherwise
     */
    bool registerFunctions();

    /**
     * @brief Set up the scratch buffer for SPDM operations
     * @return true if successful, false otherwise
     */
    bool setupScratchBuffer();

    /**
     * @brief Configure SPDM context parameters
     * @return true if successful, false otherwise
     */
    bool configureContext();

    /**
     * @brief Clean up allocated resources
     */
    void cleanupContext();

    /**
     * @brief Callback function for sending SPDM messages over TCP
     * @param spdmContext The SPDM context
     * @param messageSize Size of the message to send
     * @param message Pointer to the message data
     * @param timeout Timeout value in microseconds
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t deviceSendMessage(
        void* spdmContext, size_t messageSize, const void* message,
        uint64_t timeout);

    /**
     * @brief Callback function for receiving SPDM messages over TCP
     * @param spdmContext The SPDM context
     * @param messageSize Pointer to store the size of the received message
     * @param message Pointer to store the received message data
     * @param timeout Timeout value in microseconds
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t deviceReceiveMessage(
        void* spdmContext, size_t* messageSize, void** message,
        uint64_t timeout);

    /**
     * @brief Callback function to acquire a buffer for sending messages
     * @param context The SPDM context
     * @param msgBufPtr Pointer to store the allocated buffer
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t spdmDeviceAcquireSenderBuffer(void* context,
                                                          void** msgBufPtr);

    /**
     * @brief Callback function to release a buffer used for sending messages
     * @param context The SPDM context
     * @param msgBufPtr Pointer to the buffer being released
     */
    static void spdmDeviceReleaseSenderBuffer(void* context,
                                              const void* msgBufPtr);

    /**
     * @brief Callback function to acquire a buffer for receiving messages
     * @param context The SPDM context
     * @param msgBufPtr Pointer to store the allocated buffer
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t spdmDeviceAcquireReceiverBuffer(void* context,
                                                            void** msgBufPtr);

    /**
     * @brief Callback function to release a buffer used for receiving messages
     * @param context The SPDM context
     * @param msgBufPtr Pointer to the buffer being released
     */
    static void spdmDeviceReleaseReceiverBuffer(void* context,
                                                const void* msgBufPtr);
};
}; // namespace spdm
