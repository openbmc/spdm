// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "utils.hpp"

namespace spdm
{

auto getSubTree(sdbusplus::async::context& ctx, const std::string& interface)
    -> sdbusplus::async::task<SubTreeType>
{
    constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
    constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
    constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";

    auto mapper = sdbusplus::async::proxy()
                      .service(mapperService)
                      .path(mapperPath)
                      .interface(mapperInterface);

    co_return co_await mapper.call<SubTreeType>(
        ctx, "GetSubTree", "/", 0, std::vector<std::string>{interface});
}

} // namespace spdm

