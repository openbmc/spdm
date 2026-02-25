// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/ObjectMapper/client.hpp>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto getObjectsFromMapper(sdbusplus::async::context& ctx,
                          const std::string& interface,
                          const std::string& serviceName)
    -> sdbusplus::async::task<SubTreeType>
{
    using ObjectMapperMgr =
        sdbusplus::client::xyz::openbmc_project::ObjectMapper<>;

    try
    {
        auto objectMapperMgr = ObjectMapperMgr(ctx)
                                   .service(ObjectMapperMgr::default_service)
                                   .path(ObjectMapperMgr::instance_path);

        std::vector<std::string> interfaces{interface};

        auto subtree =
            co_await objectMapperMgr.get_sub_tree("/", 0, interfaces);

        // Filter subtree to include only objects provided by the specified
        // service
        if (!serviceName.empty())
        {
            SubTreeType serviceSpecificObjects;
            for (const auto& [objectPath, services] : subtree)
            {
                if (services.contains(serviceName))
                {
                    serviceSpecificObjects[objectPath] = services;
                }
            }
            co_return serviceSpecificObjects;
        }

        co_return subtree;
    }
    catch (const std::exception& e)
    {
        error("D-Bus error [{ERROR}] while trying to get subtree for "
              "Interface: {IFACE}",
              "ERROR", e, "IFACE", interface);
    }
}

} // namespace spdm
