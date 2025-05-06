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
    explicit MCTPTransportDiscovery(sdbusplus::async::context& ctx) :
        ctx(ctx) {};

    auto discovery() -> sdbusplus::async::task<>;

    static auto type() -> TransportType
    {
        return TransportType::MCTP;
    }

  private:
    sdbusplus::async::context& ctx;
};

} // namespace spdm
