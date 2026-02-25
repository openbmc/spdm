// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/ObjectMapper/client.hpp>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto getObjectsFromMapper(sdbusplus::async::context& ctx,
                          const std::string& interface)
    -> sdbusplus::async::task<SubTreeType>
{
    using ObjectMapperMgr =
        sdbusplus::client::xyz::openbmc_project::ObjectMapper<>;

    auto objectMapperMgr = ObjectMapperMgr(ctx)
                               .service(ObjectMapperMgr::default_service)
                               .path(ObjectMapperMgr::instance_path);

    co_return co_await objectMapperMgr.get_sub_tree(
        "/xyz/openbmc_project", 0, std::vector<std::string>{interface});
}

} // namespace spdm
