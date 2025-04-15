// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd_app.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdmd
{

SPDMDaemon::SPDMDaemon()
{
    try
    {
        // Create D-Bus connection
        conn = std::make_unique<sdbusplus::asio::connection>(io);

        // Request D-Bus name
        conn->request_name(busName);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to initialize SPDM daemon: {ERROR}", "ERROR", e);
        throw;
    }
}

int SPDMDaemon::run()
{
    try
    {
        // Create object manager
        auto objManager = std::make_shared<sdbusplus::server::manager::manager>(
            *conn, spdmRootObjectPath);

        // Run the IO context
        io.run();
        return 0;
    }
    catch (const std::exception& e)
    {
        lg2::error("SPDM daemon error: {ERROR}", "ERROR", e);
        return -1;
    }
}

} // namespace spdmd
