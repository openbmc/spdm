// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/server.hpp>

#include <memory>
#include <string>

namespace spdmd
{

class SPDMDaemon
{
  public:
    SPDMDaemon();
    int run();

  private:
    boost::asio::io_context io;

    std::unique_ptr<sdbusplus::asio::connection> conn;

    static constexpr auto busName = "xyz.openbmc_project.spdmd.spdm";

    static constexpr auto spdmRootObjectPath =
        "/xyz/openbmc_project/ComponentIntegrity";
};

} // namespace spdmd
