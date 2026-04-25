// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/ObjectMapper/client.hpp>

#include <expected>

namespace spdm::mapper
{
PHOSPHOR_LOG2_USING;
using namespace std::string_literals;

namespace instances
{
auto by_interface(sdbusplus::async::context& ctx, std::string interface)
    -> sdbusplus::async::task<instances_t>
{
    using Mapper = sdbusplus::client::xyz::openbmc_project::ObjectMapper<>;

    auto objects = co_await [&ctx, interface]()
        -> sdbusplus::async::task<Mapper::get_sub_tree_t::return_type> {
        try
        {
            co_return co_await Mapper(ctx)
                .service(Mapper::default_service)
                .path(Mapper::instance_path)
                .get_sub_tree("/", 0,
                              std::vector<std::string>{interface});
        }
        catch (const sdbusplus::internal_exception_t& e)
        {
            info("mapper::get_sub_tree failure: {ERROR}", "ERROR", e);

            // TODO: once sdbusplus has the ability to differentiate
            //       ServiceUnknown we should catch and abort on that one
            //       instead of checking a string. Mapper being gone is a
            //       critical issue.
            if (e.name() == "org.freedesktop.DBus.Error.ServiceUnknown"s)
            {
                std::terminate();
            }
            co_return {};
        }
    }();

    instances_t results{};
    for (const auto& [path, services] : objects)
    {
        for (const auto& [service, _] : services)
        {
            results.push_back({path, service});
        }
    }

    co_return results;
}

} // namespace instances

} // namespace spdm::mapper
