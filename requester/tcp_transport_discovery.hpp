// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"
#include "utils.hpp"

#include <sdbusplus/async.hpp>

namespace spdm
{

/**
 * @brief TCP-specific transport implementation
 * @details Handles discovery of SPDM devices over TCP transport using D-Bus
 */
class TCPTransportDiscovery
{
  public:
    explicit TCPTransportDiscovery(sdbusplus::async::context& ctx) :
        ctx(ctx) {};

    auto discovery(SPDMDiscovery&) -> sdbusplus::async::task<>;

    static auto type() -> TransportType
    {
        return TransportType::TCP;
    }

  private:
    sdbusplus::async::context& ctx;
};

} // namespace spdm
