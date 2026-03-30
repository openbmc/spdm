// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/exception.hpp>

namespace spdm::utils
{

template <typename Configuration>
auto fetchProperties(sdbusplus::async::context& ctx,
                     const std::string& service,
                     const sdbusplus::message::object_path& path)
    -> sdbusplus::async::task<
        std::optional<typename Configuration::PropertiesType>>
{
    PHOSPHOR_LOG2_USING;

    try
    {
        auto properties = co_await Configuration(ctx)
                              .service(service)
                              .path(path)
                              .properties();

        co_return properties;
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        error("Failed to fetch properties from D-Bus: {ERROR}", "ERROR", e);
        co_return std::nullopt;
    }
    catch (const sdbusplus::exception::UnpackError& e)
    {
        error("Failed to unpack properties: {ERROR}", "ERROR", e);
        co_return std::nullopt;
    }
}

} // namespace spdm::utils
