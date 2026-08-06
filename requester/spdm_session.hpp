// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "libspdm_transport.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace spdm
{

/**
 * Owns a single libspdm secure session for one SpdmTransport / device.
 *
 * Transport-agnostic: constructs over any SpdmTransport.
 * Lifetime: the underlying SpdmTransport must outlive this object.
 *
 * Pre-conditions for start():
 *   - transport.initialize() has succeeded
 *   - applySecureSessionConfig() has been called
 *   - libspdm_init_connection() has been called (GET_VERSION/CAPS/NEGOTIATE)
 */
class SpdmSession
{
  public:
    explicit SpdmSession(SpdmTransport& t) : transport(t) {}

    SpdmSession(const SpdmSession&) = delete;
    SpdmSession& operator=(const SpdmSession&) = delete;
    SpdmSession(SpdmSession&&) = delete;
    SpdmSession& operator=(SpdmSession&&) = delete;

    ~SpdmSession();

    /**
     * Run KEY_EXCHANGE / FINISH against the responder.
     *
     * @param slotId           Responder cert slot to authenticate against.
     * @param measHashType SPDM_CHALLENGE_REQUEST_*_MEASUREMENT_SUMMARY_HASH;
     *                         pass NO_MEASUREMENT_SUMMARY_HASH if you don't
     *                         need a measurement bound into the transcript.
     * @param sessionPolicy    Session policy bitmask (0 = none).
     * @param usePsk           Use PSK_EXCHANGE/PSK_FINISH instead of ECDHE.
     */
    libspdm_return_t start(
        uint8_t slotId,
        uint8_t measHashType =
            SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        uint8_t sessionPolicy = 0, bool usePsk = false);

    /// Send END_SESSION and tear down.
    libspdm_return_t stop(uint8_t endAttrs = 0);

    libspdm_return_t heartbeat();
    libspdm_return_t keyUpdate(bool singleDirection = true);

    /**
     * Send an application-layer request inside the secure session and read
     * the response synchronously.
     *
     * @param req      request payload
     * @param resp     output buffer
     * @param respLen  in: capacity of resp; out: actual bytes written
     */
    libspdm_return_t send(std::span<const uint8_t> req, std::span<uint8_t> resp,
                          size_t& respLen);

    bool active() const
    {
        return isActive;
    }
    uint32_t sessionId() const
    {
        return id;
    }
    uint8_t heartbeatPeriod() const
    {
        return hbPeriod;
    }

  private:
    SpdmTransport& transport;
    uint32_t id = 0;
    uint8_t hbPeriod = 0;
    bool isActive = false;
};

} // namespace spdm
