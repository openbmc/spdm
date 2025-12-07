// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"

namespace spdm
{

class TCPEventHandler
{
  public:
    TCPEventHandler(
        sdbusplus::async::context& ctx,
        std::vector<std::unique_ptr<spdm::SPDMDBusResponder>>& responders,
        spdm::SPDMDiscovery& discoveryProtocol);

    // Register DBus match rules for interface-added & removed
    void registerSignals();

  private:
    // DBus callbacks
    void spdmTcpResponderAdded(sdbusplus::message_t& msg);
    void spdmTcpResponderRemoved(sdbusplus::message_t& msg);
    void triggerRediscovery(std::optional<ResponderInfo> device);

    sdbusplus::async::context& ctx;
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>>& responders;
    spdm::SPDMDiscovery& discoveryProtocol;

    // Matchers
    std::unique_ptr<sdbusplus::bus::match_t> spdmTcpResponderAddedSignal;
    std::unique_ptr<sdbusplus::bus::match_t> spdmTcpResponderRemovedSignal;
};

} // namespace spdm
