// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "mctp_helper.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>

namespace spdm
{

// Maximum TCP message size for SPDM
constexpr size_t tcpMaxMessageSize = 65536;

/**
 * @brief Platform message commands for spdm_emu compatibility
 * @details These match the definitions in libspdm's spdm_emu
 */
enum class PlatformCommand : uint32_t
{
    Normal = 0x0001,   // Normal SPDM message
    Stop = 0xFFFE,     // Stop the responder
    Shutdown = 0xFFFF, // Shutdown command
};

/**
 * @brief Transport types for spdm_emu compatibility
 */
enum class PlatformTransportType : uint32_t
{
    None = 0x00,    // No transport
    MCTP = 0x01,    // MCTP transport
    PCI_DOE = 0x02, // PCI DOE transport
    TCP = 0x03,     // TCP transport
};

/**
 * @brief Platform message header size
 * @details The header consists of 3 uint32_t fields in BIG ENDIAN order:
 *          - command (4 bytes, big endian)
 *          - transportType (4 bytes, big endian)
 *          - size (4 bytes, big endian)
 *
 *          NOTE: The SPDM payload after the header is little endian
 */
constexpr size_t platformHeaderSize = 12;

/**
 * @class TcpMessageTransport
 * @brief Support class for TCP transport message encoding/decoding
 * @details This class handles encoding and decoding of SPDM messages for
 *          communication with libspdm's spdm_responder_emu.
 *
 *          Wire format for spdm_emu (from command.h in spdm-emu):
 *          +-------------------+---------------------+------------------+
 *          | Command (4 bytes) | TransportType (4B)  | Size (4 bytes)   |
 *          | BIG ENDIAN        | BIG ENDIAN          | BIG ENDIAN       |
 *          +-------------------+---------------------+------------------+
 *          |              SPDM Message (Size bytes, little endian)      |
 *          +------------------------------------------------------------+
 */
class TcpMessageTransport : public NonCopyable
{
  public:
    virtual ~TcpMessageTransport() = default;

    /**
     * @brief Encode SPDM message for TCP transport (spdm_emu format)
     * @param[out] buf Output buffer for encoded message
     * @param[in] msg SPDM message to encode
     * @return LIBSPDM_STATUS_SUCCESS on success
     */
    libspdm_return_t encode(std::vector<uint8_t>& buf,
                            const std::vector<uint8_t>& msg)
    {
        buf.resize(platformHeaderSize + msg.size());

        uint32_t command = static_cast<uint32_t>(PlatformCommand::Normal);
        uint32_t transportType =
            static_cast<uint32_t>(PlatformTransportType::TCP);
        uint32_t size = static_cast<uint32_t>(msg.size());

        // Write header fields in BIG ENDIAN (network byte order)
        buf[0] = static_cast<uint8_t>((command >> 24) & 0xFF);
        buf[1] = static_cast<uint8_t>((command >> 16) & 0xFF);
        buf[2] = static_cast<uint8_t>((command >> 8) & 0xFF);
        buf[3] = static_cast<uint8_t>(command & 0xFF);

        buf[4] = static_cast<uint8_t>((transportType >> 24) & 0xFF);
        buf[5] = static_cast<uint8_t>((transportType >> 16) & 0xFF);
        buf[6] = static_cast<uint8_t>((transportType >> 8) & 0xFF);
        buf[7] = static_cast<uint8_t>(transportType & 0xFF);

        buf[8] = static_cast<uint8_t>((size >> 24) & 0xFF);
        buf[9] = static_cast<uint8_t>((size >> 16) & 0xFF);
        buf[10] = static_cast<uint8_t>((size >> 8) & 0xFF);
        buf[11] = static_cast<uint8_t>(size & 0xFF);

        // Copy SPDM message (payload is little endian, but we just copy as-is)
        std::copy(msg.begin(), msg.end(), buf.begin() + platformHeaderSize);

        return LIBSPDM_STATUS_SUCCESS;
    }

    /**
     * @brief Decode TCP transport message to extract SPDM message
     * @param[in] buf Input buffer containing platform message
     * @param[out] message Output pointer to decoded message (caller must free)
     * @param[out] messageSize Output size of decoded message
     * @return LIBSPDM_STATUS_SUCCESS on success
     */
    libspdm_return_t decode(const std::vector<uint8_t>& buf, void** message,
                            size_t* messageSize)
    {
        if (buf.size() < platformHeaderSize)
        {
            lg2::error("TCP message too small for header: {SIZE}", "SIZE",
                       buf.size());
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        // Read header fields from BIG ENDIAN (network byte order)
        uint32_t command = (static_cast<uint32_t>(buf[0]) << 24) |
                           (static_cast<uint32_t>(buf[1]) << 16) |
                           (static_cast<uint32_t>(buf[2]) << 8) |
                           static_cast<uint32_t>(buf[3]);

        uint32_t headerTransportType =
            (static_cast<uint32_t>(buf[4]) << 24) |
            (static_cast<uint32_t>(buf[5]) << 16) |
            (static_cast<uint32_t>(buf[6]) << 8) |
            static_cast<uint32_t>(buf[7]);

        uint32_t headerSize = (static_cast<uint32_t>(buf[8]) << 24) |
                              (static_cast<uint32_t>(buf[9]) << 16) |
                              (static_cast<uint32_t>(buf[10]) << 8) |
                              static_cast<uint32_t>(buf[11]);

        (void)command; // Command not validated for now

        // Verify transport type
        if (headerTransportType !=
            static_cast<uint32_t>(PlatformTransportType::TCP))
        {
            lg2::error("Unexpected transport type: 0x{TYPE:08X}", "TYPE",
                       headerTransportType);
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        // Verify we have enough data
        if (buf.size() < platformHeaderSize + headerSize)
        {
            lg2::error("TCP message incomplete: have {HAVE}, need {NEED}",
                       "HAVE", buf.size(), "NEED",
                       platformHeaderSize + headerSize);
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        // Extract SPDM message
        *messageSize = headerSize;
        *message = malloc(*messageSize);
        if (*message == nullptr)
        {
            lg2::error("Failed to allocate memory for SPDM message");
            return LIBSPDM_STATUS_BUFFER_FULL;
        }

        std::memcpy(*message, buf.data() + platformHeaderSize, *messageSize);
        return LIBSPDM_STATUS_SUCCESS;
    }
};

/**
 * @class TcpIoClass
 * @brief TCP socket I/O implementation for SPDM communication
 * @details Handles TCP socket creation, connection, and data transfer.
 */
// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class TcpIoClass : public IOClass
{
  public:
    /**
     * @brief Constructor
     * @param ipAddress IP address of the SPDM responder
     * @param port TCP port of the SPDM responder
     */
    TcpIoClass(const std::string& ipAddress, uint16_t port) :
        ipAddr(ipAddress), port(port)
    {}

    /**
     * @brief Destructor - closes socket if open
     */
    ~TcpIoClass() override
    {
        if (isSocketOpen())
        {
            closeSocket();
        }
    }

    /**
     * @brief Create and connect TCP socket
     * @return true if socket created and connected successfully
     */
    bool createSocket()
    {
        if (isSocketOpen())
        {
            return true;
        }

        // Create TCP socket
        socketFd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (socketFd < 0)
        {
            lg2::error("Failed to create TCP socket: {ERRNO} ({ERRMSG})",
                       "ERRNO", errno, "ERRMSG", std::strerror(errno));
            return false;
        }

        // Set TCP_NODELAY to disable Nagle's algorithm for low-latency SPDM
        int flag = 1;
        if (setsockopt(socketFd, IPPROTO_TCP, TCP_NODELAY, &flag,
                       sizeof(flag)) < 0)
        {
            lg2::warning("Failed to set TCP_NODELAY: {ERRNO}", "ERRNO", errno);
            // Continue anyway, this is not fatal
        }

        // Set socket to non-blocking for connect with timeout
        int flags = fcntl(socketFd, F_GETFL, 0);
        if (flags >= 0)
        {
            fcntl(socketFd, F_SETFL, flags | O_NONBLOCK);
        }

        // Prepare server address
        struct sockaddr_in serverAddr;
        std::memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);

        if (inet_pton(AF_INET, ipAddr.c_str(), &serverAddr.sin_addr) <= 0)
        {
            lg2::error("Invalid IP address: {IP}", "IP", ipAddr);
            close(socketFd);
            socketFd = -1;
            return false;
        }

        // Attempt connection
        int rc =
            ::connect(socketFd, reinterpret_cast<struct sockaddr*>(&serverAddr),
                      sizeof(serverAddr));

        if (rc < 0)
        {
            if (errno == EINPROGRESS)
            {
                // Wait for connection with timeout (5 seconds)
                struct pollfd pfd;
                pfd.fd = socketFd;
                pfd.events = POLLOUT;

                rc = poll(&pfd, 1, connectTimeoutMs);
                if (rc <= 0)
                {
                    lg2::error(
                        "TCP connection timeout or error to {IP}:{PORT}: {ERRNO}",
                        "IP", ipAddr, "PORT", port, "ERRNO", errno);
                    close(socketFd);
                    socketFd = -1;
                    return false;
                }

                // Check for socket error
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &error, &len) <
                        0 ||
                    error != 0)
                {
                    lg2::error("TCP connection failed to {IP}:{PORT}: {ERRNO}",
                               "IP", ipAddr, "PORT", port, "ERRNO", error);
                    close(socketFd);
                    socketFd = -1;
                    return false;
                }
            }
            else
            {
                lg2::error(
                    "TCP connect failed to {IP}:{PORT}: {ERRNO} ({ERRMSG})",
                    "IP", ipAddr, "PORT", port, "ERRNO", errno, "ERRMSG",
                    std::strerror(errno));
                close(socketFd);
                socketFd = -1;
                return false;
            }
        }

        // Restore blocking mode
        if (flags >= 0)
        {
            fcntl(socketFd, F_SETFL, flags);
        }

        lg2::info("TCP socket connected to {IP}:{PORT}", "IP", ipAddr, "PORT",
                  port);
        return true;
    }

    /**
     * @brief Close the TCP socket
     */
    void closeSocket()
    {
        if (socketFd >= 0)
        {
            close(socketFd);
            socketFd = -1;
            lg2::info("TCP socket closed");
        }
    }

    /**
     * @brief Write data to TCP socket (IOClass interface)
     * @param buf Buffer containing data to send (with platform header)
     * @param timeout Timeout in microseconds
     * @return LIBSPDM_STATUS_SUCCESS on success, error code otherwise
     */
    libspdm_return_t write(const std::vector<uint8_t>& buf,
                           timeout_us_t timeout = timeoutUsInfinite) override
    {
        if (!isSocketOpen())
        {
            lg2::error("TCP socket not open for write");
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        setSocketTimeout(timeout);

        size_t totalSent = 0;
        while (totalSent < buf.size())
        {
            ssize_t sent = ::send(socketFd, buf.data() + totalSent,
                                  buf.size() - totalSent, 0);
            if (sent < 0)
            {
                if (errno == EINTR)
                {
                    continue; // Retry on interrupt
                }
                lg2::error("TCP send failed: {ERRNO} ({ERRMSG})", "ERRNO",
                           errno, "ERRMSG", std::strerror(errno));
                return LIBSPDM_STATUS_SEND_FAIL;
            }
            if (sent == 0)
            {
                lg2::error("TCP connection closed during send");
                return LIBSPDM_STATUS_SEND_FAIL;
            }
            totalSent += static_cast<size_t>(sent);
        }

        lg2::debug("TCP sent {SIZE} bytes", "SIZE", buf.size());
        return LIBSPDM_STATUS_SUCCESS;
    }

    /**
     * @brief Read data from TCP socket (IOClass interface)
     * @param buf Buffer to store received data (with platform header)
     * @param timeout Timeout in microseconds
     * @return LIBSPDM_STATUS_SUCCESS on success, error code otherwise
     */
    libspdm_return_t read(std::vector<uint8_t>& buf,
                          timeout_us_t timeout = timeoutUsInfinite) override
    {
        if (!isSocketOpen())
        {
            lg2::error("TCP socket not open for read");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        setSocketTimeout(timeout);

        // First, read the platform header (12 bytes)
        uint8_t headerBuf[12];
        size_t headerReceived = 0;

        while (headerReceived < platformHeaderSize)
        {
            ssize_t received = ::recv(socketFd, headerBuf + headerReceived,
                                      platformHeaderSize - headerReceived, 0);
            if (received < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    lg2::error("TCP receive timeout");
                    return LIBSPDM_STATUS_RECEIVE_FAIL;
                }
                lg2::error("TCP receive header failed: {ERRNO} ({ERRMSG})",
                           "ERRNO", errno, "ERRMSG", std::strerror(errno));
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            if (received == 0)
            {
                lg2::error("TCP connection closed during header read");
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            headerReceived += static_cast<size_t>(received);
        }

        // Parse header fields from BIG ENDIAN (network byte order)
        uint32_t command = (static_cast<uint32_t>(headerBuf[0]) << 24) |
                           (static_cast<uint32_t>(headerBuf[1]) << 16) |
                           (static_cast<uint32_t>(headerBuf[2]) << 8) |
                           static_cast<uint32_t>(headerBuf[3]);

        uint32_t transportType = (static_cast<uint32_t>(headerBuf[4]) << 24) |
                                 (static_cast<uint32_t>(headerBuf[5]) << 16) |
                                 (static_cast<uint32_t>(headerBuf[6]) << 8) |
                                 static_cast<uint32_t>(headerBuf[7]);

        uint32_t msgLen = (static_cast<uint32_t>(headerBuf[8]) << 24) |
                          (static_cast<uint32_t>(headerBuf[9]) << 16) |
                          (static_cast<uint32_t>(headerBuf[10]) << 8) |
                          static_cast<uint32_t>(headerBuf[11]);

        // Sanity check on message length
        if (msgLen > tcpMaxMessageSize)
        {
            lg2::error("Invalid TCP message length: {LEN}", "LEN", msgLen);
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        // Allocate buffer for full message (header + payload)
        buf.resize(platformHeaderSize + msgLen);
        std::memcpy(buf.data(), headerBuf, platformHeaderSize);

        // Read the message payload
        size_t payloadReceived = 0;
        while (payloadReceived < msgLen)
        {
            ssize_t received = ::recv(
                socketFd, buf.data() + platformHeaderSize + payloadReceived,
                msgLen - payloadReceived, 0);
            if (received < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    lg2::error("TCP receive timeout during payload");
                    return LIBSPDM_STATUS_RECEIVE_FAIL;
                }
                lg2::error("TCP receive payload failed: {ERRNO} ({ERRMSG})",
                           "ERRNO", errno, "ERRMSG", std::strerror(errno));
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            if (received == 0)
            {
                lg2::error("TCP connection closed during payload read");
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            payloadReceived += static_cast<size_t>(received);
        }

        lg2::debug(
            "TCP received {SIZE} bytes (command=0x{CMD:X}, type=0x{TYPE:X})",
            "SIZE", buf.size(), "CMD", command, "TYPE", transportType);
        return LIBSPDM_STATUS_SUCCESS;
    }

    /**
     * @brief Check if socket is open
     * @return true if socket is open and valid
     */
    bool isSocketOpen() const
    {
        return socketFd >= 0;
    }

    /**
     * @brief Get socket file descriptor
     * @return Socket file descriptor
     */
    int getSocket() const
    {
        return socketFd;
    }

  private:
    std::string ipAddr;
    uint16_t port;
    int socketFd = -1;

    // Connection timeout in milliseconds
    static constexpr int connectTimeoutMs = 5000;

    // Minimum socket timeout (5 seconds) to avoid network latency issues
    static constexpr timeout_us_t minSocketTimeoutUs = 5000000;

    /**
     * @brief Set socket timeout options
     * @param timeout Timeout in microseconds
     * @return true if timeout set successfully
     */
    bool setSocketTimeout(timeout_us_t timeout)
    {
        if (!isSocketOpen())
        {
            return false;
        }

        // Log the timeout value for debugging
        lg2::debug("Setting socket timeout: {TIMEOUT_US} us", "TIMEOUT_US",
                   timeout);

        // Handle infinite timeout
        if (timeout == timeoutUsInfinite)
        {
            timeout = 0; // 0 means no timeout for setsockopt
        }
        else if (timeout > 0 && timeout < minSocketTimeoutUs)
        {
            // Enforce minimum timeout to avoid premature timeouts
            lg2::debug("Timeout {TIMEOUT} us too short, using minimum {MIN} us",
                       "TIMEOUT", timeout, "MIN", minSocketTimeoutUs);
            timeout = minSocketTimeoutUs;
        }

        struct timeval tv;
        // Convert microseconds to seconds and microseconds
        tv.tv_sec = static_cast<time_t>(timeout / 1000000);
        tv.tv_usec = static_cast<suseconds_t>(timeout % 1000000);

        if (setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        {
            lg2::warning("Failed to set receive timeout: {ERRNO}", "ERRNO",
                         errno);
            return false;
        }

        if (setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        {
            lg2::warning("Failed to set send timeout: {ERRNO}", "ERRNO", errno);
            return false;
        }

        return true;
    }
};

} // namespace spdm
