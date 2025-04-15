// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd_app.hpp"

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

namespace spdmd
{

SPDMDaemon::SPDMDaemon() : objManager(ctx, spdmRootPath)
{
    ctx.request_name(spdmBusName);
}

void SPDMDaemon::run()
{
    info("SPDM daemon starting with sdbusplus async context");
    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();
}

} // namespace spdmd
