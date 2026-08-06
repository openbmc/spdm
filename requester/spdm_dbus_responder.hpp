// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "component_integrity_dbus.hpp"
#include "libspdm_transport.hpp"
#include "spdm_discovery.hpp"
#include "spdm_session.hpp"
#include "spdm_session_config.hpp"
#include "trusted_component_dbus.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <string>

namespace spdm
{

/**
 * @brief D-Bus responder object for a discovered SPDM device.
 * @details Owns the ComponentIntegrity and TrustedComponent D-Bus interface
 *          objects that represent the device on the bus.
 */
class SPDMDBusResponder
{
  public:
    SPDMDBusResponder() = delete;
    SPDMDBusResponder(const SPDMDBusResponder&) = delete;
    SPDMDBusResponder& operator=(const SPDMDBusResponder&) = delete;
    SPDMDBusResponder(SPDMDBusResponder&&) = delete;
    SPDMDBusResponder& operator=(SPDMDBusResponder&&) = delete;

    /**
     * @brief Construct a new SPDM D-Bus Responder
     * @param ctx Async context for D-Bus object creation
     * @param responderInfo ResponderInfo containing device details
     */
    explicit SPDMDBusResponder(sdbusplus::async::context& ctx,
                               const ResponderInfo& responderInfo);

    ~SPDMDBusResponder() = default;

    /** @brief Device name derived from responder transport info */
    std::string name() const;

    /** @brief Associated inventory object path */
    const std::string& path() const
    {
        return responder.path.str;
    }

    /**
     * @brief Apply secure-session capability flags and algorithms to the
     * transport. Must be called after transport initialization and before
     * openSecureSession().
     */
    libspdm_return_t applySessionConfig(const SecureSessionConfig& cfg);

    /**
     * @brief Open an SPDM secure session against this device.
     *
     * Installs the peer trust anchor (resolved from cfg) before running
     * GET_DIGESTS / GET_CERTIFICATE / KEY_EXCHANGE / FINISH.
     *
     * @param cfg     Session config (used for trust-anchor resolution).
     * @param slotId  Responder cert slot to authenticate against (default 0).
     */
    libspdm_return_t openSecureSession(const SecureSessionConfig& cfg,
                                       uint8_t slotId = 0);

    /** @brief Tear down the secure session. */
    libspdm_return_t closeSecureSession();

    /** @brief True if a secure session is currently open. */
    bool secureSessionActive() const
    {
        return session && session->active();
    }

    /** @brief Device name (public for use in log messages) */
    std::string deviceName;

  private:
    ResponderInfo responder;

    /** @brief Shared transport used for the secure session. */
    std::shared_ptr<SpdmTransport> transport;
    /** @brief Active secure session (nullptr when no session). */
    std::unique_ptr<SpdmSession> session;

    /** @brief D-Bus ComponentIntegrity interface object for this device. */
    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    /** @brief D-Bus TrustedComponent interface object for this device. */
    std::unique_ptr<TrustedComponent> trustedComponent;
};

} // namespace spdm
