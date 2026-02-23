// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>

namespace spdm
{

auto TCPTransportDiscovery::discovery() -> sdbusplus::async::task<>
{
    using namespace std::literals;
    PHOSPHOR_LOG2_USING;

    // TODO: Add real discovery, for now just adding pause
    co_await sdbusplus::async::sleep_for(ctx, 1s);

    debug("TCPTransportDiscovery: discovery complete");
}

} // namespace spdm
