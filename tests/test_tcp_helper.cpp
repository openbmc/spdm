// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/tcp_helper.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

namespace spdm
{
namespace test
{

// A TcpIoClass connected to a local listener standing in for the responder
class TcpIoClassTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GE(listenFd, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof(addr);
        ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr*>(&addr), len), 0);
        ASSERT_EQ(::listen(listenFd, 1), 0);
        ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr*>(&addr),
                                &len),
                  0);

        io = std::make_unique<TcpIoClass>("127.0.0.1", ntohs(addr.sin_port));
        ASSERT_TRUE(io->createSocket());
        peerFd = ::accept(listenFd, nullptr, nullptr);
        ASSERT_GE(peerFd, 0);
    }

    void TearDown() override
    {
        io.reset();
        if (peerFd >= 0)
        {
            ::close(peerFd);
        }
        if (listenFd >= 0)
        {
            ::close(listenFd);
        }
    }

    int listenFd = -1;
    int peerFd = -1;
    std::unique_ptr<TcpIoClass> io;
};

// A response that arrives after the timeout must not be read as the reply to
// the next request, so the timeout drops the connection.
TEST_F(TcpIoClassTest, ReadTimeoutClosesSocket)
{
    std::vector<uint8_t> buf;
    EXPECT_EQ(io->read(buf, 1), LIBSPDM_STATUS_RECEIVE_FAIL);
    EXPECT_FALSE(io->isSocketOpen());
}

// After a header with a bad length the stream position is unknown.
TEST_F(TcpIoClassTest, InvalidLengthClosesSocket)
{
    const uint8_t header[] = {0, 0, 0, 1, 0, 0, 0, 3, 0xff, 0xff, 0xff, 0xff};
    ASSERT_EQ(::send(peerFd, header, sizeof(header), 0),
              static_cast<ssize_t>(sizeof(header)));
    std::vector<uint8_t> buf;
    EXPECT_EQ(io->read(buf, 1), LIBSPDM_STATUS_RECEIVE_FAIL);
    EXPECT_FALSE(io->isSocketOpen());
}

// A complete response is read and the connection stays usable.
TEST_F(TcpIoClassTest, ReadResponseKeepsSocket)
{
    const uint8_t msg[] = {0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 2, 0xaa, 0xbb};
    ASSERT_EQ(::send(peerFd, msg, sizeof(msg), 0),
              static_cast<ssize_t>(sizeof(msg)));
    std::vector<uint8_t> buf;
    EXPECT_EQ(io->read(buf, 1), LIBSPDM_STATUS_SUCCESS);
    EXPECT_EQ(buf, std::vector<uint8_t>(msg, msg + sizeof(msg)));
    EXPECT_TRUE(io->isSocketOpen());
}

} // namespace test
} // namespace spdm
