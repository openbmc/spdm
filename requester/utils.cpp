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

void getManagedObjectsFromEMAsync(
    sdbusplus::async::context& asyncCtx,
    std::function<void(bool success, ManagedObjects)> callback)
{
    // Create a proxy for the ObjectManager interface
    auto objectManager = sdbusplus::async::proxy()
                             .service("xyz.openbmc_project.EntityManager")
                             .path("/xyz/openbmc_project/inventory")
                             .interface("org.freedesktop.DBus.ObjectManager");

    asyncCtx.spawn(
        objectManager.call<ManagedObjects>(asyncCtx, "GetManagedObjects") |
        stdexec::then([callback = std::move(callback)](
                          ManagedObjects emManagedObjects) mutable {
            callback(true, emManagedObjects);
        }) |
        stdexec::upon_error([callback = std::move(callback)](
                                std::exception_ptr ep) {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception& e)
            {
                error(
                    "GetManagedObjects error for service xyz.openbmc_project.EntityManager: {ERROR}",
                    "ERROR", e);
                callback(false, {});
            }
        }));
}

std::string base64Encode(const std::vector<uint8_t>& data)
{
    static const char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string base64;
    size_t i = 0;

    for (; i + 2 < data.size(); i += 3)
    {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        base64 += b64_table[(n >> 18) & 63];
        base64 += b64_table[(n >> 12) & 63];
        base64 += b64_table[(n >> 6) & 63];
        base64 += b64_table[n & 63];
    }

    if (i < data.size())
    {
        uint32_t n = data[i] << 16;
        base64 += b64_table[(n >> 18) & 63];
        if (i + 1 < data.size())
        {
            n |= data[i + 1] << 8;
            base64 += b64_table[(n >> 12) & 63];
            base64 += b64_table[(n >> 6) & 63];
            base64 += '=';
        }
        else
        {
            base64 += b64_table[(n >> 12) & 63];
            base64 += "==";
        }
    }

    return base64;
}

} // namespace spdm
