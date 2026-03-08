// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/ObjectMapper/client.hpp>

namespace spdm::mapper
{
PHOSPHOR_LOG2_USING;

namespace instances
{
auto by_interface(sdbusplus::async::context& ctx, const std::string interface)
    -> sdbusplus::async::task<instances_t>
{
    using Mapper = sdbusplus::client::xyz::openbmc_project::ObjectMapper<>;

    auto objects = co_await Mapper(ctx)
                       .service(Mapper::default_service)
                       .path(Mapper::instance_path)
                       .get_sub_tree("/xyz/openbmc_project", 0,
                                     std::vector<std::string>{interface});

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
