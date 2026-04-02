// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(sdbusplus::async::context& ctx,
                                     const ResponderInfo& respInfo) :
    asyncCtx(ctx), responderInfo(respInfo)
{
    info("Created SPDM D-Bus responder for device at {PATH}", "PATH",
         responderInfo.path);
}

auto SPDMDBusResponder::run() -> sdbusplus::async::task<>
{
    debug("Running async operations for device: {PATH}", "PATH",
          responderInfo.path);

    // Step 1: Initialize SPDM transport and connection

    // Step 2: Get certificate digests from the responder

    // Step 3: Get certificate chain and populate the certificate D-Bus

    // Step 4: Get measurements (libspdm_get_measurement)

    // Step 5: Verify and update TrustedComponent D-Bus object

    info("SPDM device operations complete: {PATH}", "PATH", responderInfo.path);
    co_return;
}

} // namespace spdm
