// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/proxy.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

void getManagedObjectsAsync(
    sdbusplus::async::context& asyncCtx, const std::string& service,
    std::function<void(bool success, ManagedObjects)> callback)
{
    // Create a proxy for the ObjectManager interface
    auto objectManager = sdbusplus::async::proxy()
                             .service(service)
                             .path("/au/com/codeconstruct/mctp1")
                             .interface("org.freedesktop.DBus.ObjectManager");

    // Spawn the async call with proper error handling
    asyncCtx.spawn(
        objectManager.call<ManagedObjects>(asyncCtx, "GetManagedObjects") |
        stdexec::then(
            [callback = std::move(callback)](ManagedObjects managedObjects) {
                // Call the callback with success
                callback(true, std::move(managedObjects));
            }) |
        stdexec::upon_error(
            [callback = std::move(callback)](std::exception_ptr ep) {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception& e)
                {
                    error("GetManagedObjects error: {ERROR}", "ERROR", e);
                    callback(false, {});
                }
            }));
}

} // namespace spdm
