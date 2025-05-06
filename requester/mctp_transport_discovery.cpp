// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include <algorithm>

namespace spdm
{

auto MCTPTransportDiscovery::discovery() -> sdbusplus::async::task<>
{
    using namespace std::literals;
    PHOSPHOR_LOG2_USING;

    // TODO: Not doing any real discovery here but pause for dramatic effect.
    co_await sdbusplus::async::sleep_for(ctx, 1s);

    debug("MCTPTransportDiscovery: discovery complete");
}

} // namespace spdm
