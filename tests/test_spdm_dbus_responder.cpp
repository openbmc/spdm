// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/daemon_options.hpp"
#include "../requester/libspdm_transport.hpp"
#include "../requester/spdm_dbus_responder.hpp"

#include <gtest/gtest.h>

namespace spdm::test
{

class SPDMDBusResponderTest : public ::testing::Test
{
  protected:
    static std::shared_ptr<SpdmTransport> createTransport(
        const SPDMDBusResponder& responder)
    {
        return responder.createTransport();
    }

    ResponderInfo device{sdbusplus::object_path("/test/device"),
                         MctpResponderInfo{1, 8, "test-uuid"},
                         TransportType::MCTP};
};

TEST_F(SPDMDBusResponderTest, UsesParsedMessageLimitForTransport)
{
    CLI::App app;
    DaemonOptions options;
    options.addTo(app);
    const char* argv[] = {"spdmd", "--max-spdm-message-size", "2047"};
    app.parse(3, argv);

    SPDMDBusResponder responder(device, options.maxSpdmMessageSize);
    auto transport = createTransport(responder);
    ASSERT_NE(transport, nullptr);
    EXPECT_EQ(transport->maxSpdmMessageSize, 2047U);
}

TEST_F(SPDMDBusResponderTest, PreservesDefaultMessageLimit)
{
    SPDMDBusResponder responder(device);
    auto transport = createTransport(responder);
    ASSERT_NE(transport, nullptr);
    EXPECT_EQ(transport->maxSpdmMessageSize, size_t{LIBSPDM_MAX_SPDM_MSG_SIZE});
}

} // namespace spdm::test
