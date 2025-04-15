// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

// Include functional before sdbusplus to ensure std::bind_front is available
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

#include <functional>
#include <memory>

namespace spdmd
{

class SPDMDaemon
{
  public:
    SPDMDaemon();
    void run();

    /** @brief Async context for parallel coroutine execution */
    sdbusplus::async::context ctx;

    /** @brief D-Bus connection */
    sdbusplus::bus::bus& bus = ctx.get_bus();

  private:
    sdbusplus::server::manager_t objManager;

    static constexpr auto spdmRootPath = "/xyz/openbmc_project/spdmd";
    static constexpr auto spdmBusName = "xyz.openbmc_project.spdmd.spdm";
};

} // namespace spdmd
