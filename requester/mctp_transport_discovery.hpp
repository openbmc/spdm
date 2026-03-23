// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

namespace spdm
{

/**
 * @brief MCTP-specific transport implementation
 * @details Handles discovery of SPDM devices over MCTP transport using D-Bus
 */
class MCTPTransportDiscovery
{
  public:
    /** @brief Construct the MCTP transport discovery handler.
     *  @param ctx Async D-Bus context used for service discovery.
     */
    explicit MCTPTransportDiscovery(sdbusplus::async::context& ctx) :
        ctx(ctx) {};

    /** @brief Run the MCTP device discovery coroutine.
     *  @param discovery SPDMDiscovery instance to register found devices with.
     */
    auto discovery(SPDMDiscovery& discovery) -> sdbusplus::async::task<>;

    /** @brief Return the transport type handled by this class.
     *  @return TransportType::MCTP
     */
    static auto type() -> TransportType
    {
        return TransportType::MCTP;
    }

  private:
    sdbusplus::async::context& ctx;
};

} // namespace spdm
