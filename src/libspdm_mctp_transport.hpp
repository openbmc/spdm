// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "libspdm_transport.hpp"
#include "mctp_helper.hpp"

namespace spdm
{

/**
 * @class SpdmMctpTransport
 * @brief SPDM transport implementation over MCTP
 *
 * This class implements the SPDM transport interface using MCTP as the
 * underlying transport protocol. It integrates with the libspdm library and
 * uses the existing MCTP socket infrastructure.
 */
class SpdmMctpTransport : public SpdmTransport
{
  public:
    /**
     * @brief Constructor for SPDM MCTP Transport with direct MctpTransportClass
     * creation
     *
     * @param eid MCTP Endpoint ID
     * @param io Reference to MCTP IO instance
     */
    SpdmMctpTransport(uint8_t eid, MctpIoClass& io) : eid(eid), mctpIo(io) {}

    /**
     * @brief Virtual destructor for proper cleanup
     */
    virtual ~SpdmMctpTransport() = default;

    // Make these public so they can be accessed by static callback functions
    uint8_t eid;
    MctpIoClass& mctpIo;
    MctpMessageTransport mctpMessageTransport;

    /**
     * @brief Initialize the SPDM MCTP transport
     *
     * Sets up the SPDM context, registers callbacks, and configures the
     * transport layer for MCTP communication.
     *
     * @return true if initialization was successful, false otherwise
     */
    bool initialize() override;

  private:
    static constexpr size_t MAX_MCTP_PACKET_SIZE = 65536;

    /**
     * @brief Callback function for sending SPDM messages over MCTP
     *
     * @param spdm_context The SPDM context
     * @param message_size Size of the message to send
     * @param message Pointer to the message data
     * @param timeout Timeout value in microseconds
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t device_send_message(void* spdm_context,
                                                size_t message_size,
                                                const void* message,
                                                uint64_t timeout);

    /**
     * @brief Callback function for receiving SPDM messages over MCTP
     *
     * @param spdm_context The SPDM context
     * @param message_size Pointer to store the size of the received message
     * @param message Pointer to store the received message data
     * @param timeout Timeout value in microseconds
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t device_receive_message(void* spdm_context,
                                                   size_t* message_size,
                                                   void** message,
                                                   uint64_t timeout);

    /**
     * @brief Callback function to acquire a buffer for sending messages
     *
     * @param context The SPDM context
     * @param msg_buf_ptr Pointer to store the allocated buffer
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t
        spdm_device_acquire_sender_buffer(void* context, void** msg_buf_ptr);

    /**
     * @brief Callback function to release a buffer used for sending messages
     *
     * @param context The SPDM context
     * @param msg_buf_ptr Pointer to the buffer being released
     */
    static void spdm_device_release_sender_buffer(void* context,
                                                  const void* msg_buf_ptr);

    /**
     * @brief Callback function to acquire a buffer for receiving messages
     *
     * @param context The SPDM context
     * @param msg_buf_ptr Pointer to store the allocated buffer
     * @return libspdm_return_t Status code indicating success or failure
     */
    static libspdm_return_t
        spdm_device_acquire_receiver_buffer(void* context, void** msg_buf_ptr);

    /**
     * @brief Callback function to release a buffer used for receiving messages
     *
     * @param context The SPDM context
     * @param msg_buf_ptr Pointer to the buffer being released
     */
    static void spdm_device_release_receiver_buffer(void* context,
                                                    const void* msg_buf_ptr);
};

} // namespace spdm
