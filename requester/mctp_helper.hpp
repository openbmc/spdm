// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

extern "C"
{
#include "library/spdm_return_status.h"
}

// Include net/if.h first for IFNAMSIZ and IF_NAMESIZE
#include <net/if.h>

// Save and undefine conflicting macros
#undef IFF_UP
#undef IFF_BROADCAST
#undef IFF_DEBUG
#undef IFF_LOOPBACK
#undef IFF_POINTOPOINT
#undef IFF_NOTRAILERS
#undef IFF_RUNNING
#undef IFF_NOARP
#undef IFF_PROMISC
#undef IFF_ALLMULTI
#undef IFF_MASTER
#undef IFF_SLAVE
#undef IFF_MULTICAST
#undef IFF_PORTSEL
#undef IFF_AUTOMEDIA
#undef IFF_DYNAMIC

// Other system headers
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// Define _LINUX_IF_H to prevent linux/if.h from being included again
#define _LINUX_IF_H
#include <linux/if_arp.h>
#include <linux/mctp.h>

#include <phosphor-logging/lg2.hpp>

// Standard library headers
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

#define MCTP_TYPE_SPDM 5

using timeout_us_t = uint64_t; /// in units of 1 micro second
constexpr timeout_us_t timeoutUsInfinite =
    std::numeric_limits<timeout_us_t>::max();
constexpr timeout_us_t timeoutUsMaximum = timeoutUsInfinite - 1;

namespace spdm
{
// these are for use with the mctp-demux-daemon

constexpr size_t mctpMaxMessageSize = 4096;

/** @struct NonCopyable
 *  @brief Helper class for deleting copy ops
 *  @details We often don't needed/want these and clang-tidy complains about
 * them
 */
struct NonCopyable
{
    NonCopyable() = default;
    ~NonCopyable() = default;

    NonCopyable(const NonCopyable& other) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;

    NonCopyable(NonCopyable&&) = delete;
    NonCopyable& operator=(NonCopyable&&) = delete;
};

/** @class IOClass
 *  @brief Abstract interface for writing/reading full transport+spdm packets
 * to/from some I/O medium, typically a socket, or buffers during unit-tests
 *  @details write will be called by ConnectionClass when it sends a packet,
 * read will be called by the application and the buffer provided to
 * ConnectionClass through handleRecv()
 */
// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class IOClass : NonCopyable
{
  public:
    virtual ~IOClass() = default;

    /** @brief function called by ConnectionClass when it has encoded a full
     * transport+spdm packet and wishes to send it
     *  @param[in] buf - buffer containing the data to be sent
     */
    virtual libspdm_return_t write(
        const std::vector<uint8_t>& buf,
        timeout_us_t timeout = timeoutUsInfinite) = 0;

    /** @brief function called by the application either synchronuously or after
     * receiving an event
     *  @param[out] buf - buffer into which the full packet data must be written
     */
    virtual libspdm_return_t read(std::vector<uint8_t>& buf,
                                  timeout_us_t timeout = timeoutUsInfinite) = 0;
};

/** @class MctpMessageTransport
 *  @brief Support class for transport through the mctp-demux-daemon
 *  @details This class handles encoding and decoding of MCTP transport data.
 */
class MctpMessageTransport : public NonCopyable
{
  public:
    virtual ~MctpMessageTransport() = default;

    /** @brief function called by ConnectionClass before encoding an spdm
     * message into a buffer
     *  @details it must write the size of the transport data into lay.Size,
     * besides that it can already write it's data into buf at lay.getOffset()
     *           afterwards the spdm message will be written at
     * buf[lay.getEndOffset()]
     *  @param[out] buf - buffer into which data can be written
     *  @param[in] msg - message to be encoded
     */
    libspdm_return_t encode(uint8_t eid, std::vector<uint8_t>& buf,
                            std::vector<uint8_t>& msg)
    {
        const size_t headerSize = sizeof(HeaderType);
        buf.resize(headerSize + msg.size());
        auto& header = getHeaderRef<HeaderType>(buf);
        header.mctpTag(MCTP_TAG_OWNER);
        header.eid = eid;
        std::copy(msg.begin(), msg.end(), buf.begin() + headerSize);

        return LIBSPDM_STATUS_SUCCESS;
    }

    /** @brief function called by ConnectionClass when decoding a received spdm
     * message
     *  @details it should analyze the transport data which starts at
     * buf[lay.getOffset] for correctness and set lay.Size appropriately
     * (lay.getEndOffset() must indicate where the spdm message begins)
     *  @param[in] buf - buffer containing the full received data
     *  @param[inout] lay - lay.Offset specifies where the transport layer
     * starts, lay.Size should be set to the size of the transport data
     */
    libspdm_return_t decode(uint8_t eid, std::vector<uint8_t>& buf,
                            void** message, size_t* message_size)
    {
        const auto& header = getHeaderRef<HeaderType>(buf);
        const size_t headerSize = sizeof(HeaderType);
        if (header.eid != eid)
        {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (header.mctpTO())
        {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (buf.size() <= headerSize)
        {
            lg2::error("Buffer too small to contain SPDM message");
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        *message_size = buf.size() - headerSize;
        *message = malloc(*message_size);
        if (*message == nullptr)
        {
            lg2::error("Failed to allocate memory for SPDM message");
            return LIBSPDM_STATUS_BUFFER_FULL;
        }

        std::memcpy(*message, buf.data() + headerSize, *message_size);
        return LIBSPDM_STATUS_SUCCESS;
    }

  protected:
    /** @brief function to help with writing simple statically sized headers
     * into buf
     */
    template <class T>
    static T& getHeaderRef(std::vector<uint8_t>& buf)
    {
        return *reinterpret_cast<T*>(buf.data());
    }

    /** @brief Transport header matching the mctp-demux-daemon requirements
     */
    struct HeaderType
    {
        /** @brief MCTP header data
         */
        uint8_t mctpHeader;

        /** @brief Either source or the destination EndpointID, depending on
         * whether the packet is being sent or received. Regandless though it
         * should always
         */
        uint8_t eid;

        /** @brief Get The MCTP tag type
         */
        auto mctpTag() const noexcept -> uint8_t
        {
            return static_cast<uint8_t>(mctpHeader & 0x07);
        }

        /** @brief Set MCTP header to specific tag*/
        void mctpTag(uint8_t tag) noexcept
        {
            mctpHeader = static_cast<uint8_t>(tag) | 0x08U;
        }

        /** @brieg Get MCTO TO bit
         */
        auto mctpTO() const noexcept -> bool
        {
            return mctpHeader & 0x08;
        }
    };
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class MctpIoClass : public IOClass
{
  public:
    explicit MctpIoClass() {}

    ~MctpIoClass() override
    {
        if (isSocketOpen())
        {
            deleteSocket();
        }
    }

    /**
     * @brief Creates a socket for MCTP communication in in-kernel mode.
     *
     * This function creates a socket using the MCTP protocol and binds it to
     * a specified address. If the socket creation or binding fails, it logs
     * the error and returns false.
     *
     * @return true if the socket is successfully created and bound, false
     * otherwise.
     */

    bool createSocket()
    {
        if (isSocketOpen())
        {
            return true;
        }

        socketFd = ::socket(AF_MCTP, SOCK_DGRAM, 0);
        if (socketFd < 0)
        {
            lg2::error("Failed to create MCTP socket");
            return false;
        }

        struct sockaddr_mctp addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.smctp_family = AF_MCTP;
        addr.smctp_network = MCTP_NET_ANY;
        addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
        addr.smctp_type = MCTP_TYPE_SPDM;
        addr.smctp_tag = MCTP_TAG_OWNER;

        int rc = bind(socketFd, reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr));
        if (rc < 0)
        {
            lg2::error("Failed to bind MCTP socket");
            close(socketFd);
            socketFd = -1;
            return false;
        }

        return true;
    }

    void deleteSocket()
    {
        if (socketFd >= 0)
        {
            close(socketFd);
            socketFd = -1;
        }
    }

    libspdm_return_t write(const std::vector<uint8_t>& buf,
                           timeout_us_t timeout [[maybe_unused]]) override
    {
        return writeToSocket(buf);
    }

    libspdm_return_t read(std::vector<uint8_t>& buf,
                          timeout_us_t timeout [[maybe_unused]]) override
    {
        return readFromSocket(buf);
    }

    int isSocketOpen() const
    {
        return socketFd >= 0;
    }

    int getSocket() const
    {
        return socketFd;
    }

  private:
    int socketFd = -1;

    /**
     * @brief Writes data to the MCTP socket.
     *
     * This function sends data through the MCTP socket. It uses sendto() to
     * send the data to a specific destination address.
     *
     * @param buf The buffer containing the data to send.
     * @return LIBSPDM_STATUS_SUCCESS if the data is sent successfully,
     * LIBSPDM_STATUS_SEND_FAIL otherwise.
     */
    inline libspdm_return_t writeToSocket(const std::vector<uint8_t>& buf)
    {
        if (!isSocketOpen())
        {
            lg2::error("Socket is not open");
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        struct sockaddr_mctp addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.smctp_family = AF_MCTP;
        addr.smctp_network = MCTP_NET_ANY;
        addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
        addr.smctp_type = MCTP_TYPE_SPDM;
        addr.smctp_tag = MCTP_TAG_OWNER;

        ssize_t bytesSent =
            sendto(socketFd, buf.data(), buf.size(), 0,
                   reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (bytesSent < 0)
        {
            lg2::error("Failed to send data through MCTP socket");
            return LIBSPDM_STATUS_SEND_FAIL;
        }
        return LIBSPDM_STATUS_SUCCESS;
    }

    /**
     * @brief Reads data from the MCTP socket.
     *
     * This function receives data from the MCTP socket. It uses recvfrom() to
     * receive data from any source address.
     *
     * @param buf The buffer to store the received data.
     * @return LIBSPDM_STATUS_SUCCESS if the data is read successfully,
     * LIBSPDM_STATUS_RECEIVE_FAIL otherwise.
     */
    inline libspdm_return_t readFromSocket(std::vector<uint8_t>& buf)
    {
        if (!isSocketOpen())
        {
            lg2::error("Socket is not open");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        buf.resize(mctpMaxMessageSize);
        struct sockaddr_mctp addr;
        socklen_t addrlen = sizeof(addr);

        ssize_t bytesReceived =
            recvfrom(socketFd, buf.data(), buf.size(), 0,
                     reinterpret_cast<struct sockaddr*>(&addr), &addrlen);
        if (bytesReceived < 0)
        {
            lg2::error("Failed to receive data from MCTP socket");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        buf.resize(bytesReceived);
        return LIBSPDM_STATUS_SUCCESS;
    }
};

} // namespace spdm
