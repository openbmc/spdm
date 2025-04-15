// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

PHOSPHOR_LOG2_USING;

int main()
{
    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    // Request D-Bus name
    ctx.request_name(dbusServiceName);

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
