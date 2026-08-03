// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_session.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>
#include <vector>

#ifndef LIBSPDM_MAX_CERT_CHAIN_SIZE
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x1000
#endif

namespace spdm
{

namespace
{

/**
 * Run GET_DIGESTS + GET_CERTIFICATE so that libspdm caches the responder's
 * cert chain (and its hash) for the requested slot. Required before
 * libspdm_start_session in cert-based KEY_EX mode — without it, libspdm
 * fails the local pre-flight check and never sends KEY_EXCHANGE.
 */
libspdm_return_t fetchPeerCert(void* ctx, uint8_t slotId)
{
    uint8_t slotMask = 0;
    uint8_t digestBuf[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT] = {};

    libspdm_return_t st =
        libspdm_get_digest(ctx, /*session_id=*/nullptr, &slotMask, digestBuf);
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        lg2::error("Pre-session libspdm_get_digest failed: {STATUS}", "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    if ((slotMask & (1u << slotId)) == 0)
    {
        lg2::error("Responder has no cert in slot {SLOT} (mask={MASK})", "SLOT",
                   static_cast<uint32_t>(slotId), "MASK",
                   std::format("0x{:02X}", static_cast<uint32_t>(slotMask)));
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    std::vector<uint8_t> certChain(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    size_t certChainSize = certChain.size();
    st = libspdm_get_certificate(ctx, /*session_id=*/nullptr, slotId,
                                 &certChainSize, certChain.data());
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        lg2::error("Pre-session libspdm_get_certificate failed: {STATUS}",
                   "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }
    lg2::info("Fetched peer cert chain for slot {SLOT} ({SIZE} bytes)", "SLOT",
              static_cast<uint32_t>(slotId), "SIZE", certChainSize);
    return LIBSPDM_STATUS_SUCCESS;
}

} // namespace

SpdmSession::~SpdmSession()
{
    if (isActive)
    {
        stop();
    }
}

libspdm_return_t SpdmSession::start(uint8_t slotId, uint8_t measHashType,
                                    uint8_t sessionPolicy, bool usePsk)
{
    void* ctx = transport.spdmContext;
    if (!ctx)
    {
        lg2::error("SpdmSession::start: spdmContext is null");
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (isActive)
    {
        lg2::warning("SpdmSession::start called while already active");
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (!usePsk)
    {
        libspdm_return_t st = fetchPeerCert(ctx, slotId);
        if (LIBSPDM_STATUS_IS_ERROR(st))
        {
            return st;
        }
    }

    uint8_t measurementHash[LIBSPDM_MAX_HASH_SIZE] = {};
    hbPeriod = 0;

    libspdm_return_t st = libspdm_start_session(
        ctx, usePsk,
        /*psk_hint=*/nullptr, /*psk_hint_size=*/0, measHashType, slotId,
        sessionPolicy, &id, &hbPeriod, measurementHash);

    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        lg2::error("libspdm_start_session failed: {STATUS}", "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    isActive = true;
    lg2::info(
        "Secure session established: id={SESSION_ID}, heartbeat={HEARTBEAT}, psk={PSK}",
        "SESSION_ID", std::format("0x{:08X}", id), "HEARTBEAT",
        static_cast<uint32_t>(hbPeriod), "PSK", usePsk);
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t SpdmSession::stop(uint8_t endAttrs)
{
    if (!isActive)
    {
        return LIBSPDM_STATUS_SUCCESS;
    }
    void* ctx = transport.spdmContext;
    libspdm_return_t st = libspdm_stop_session(ctx, id, endAttrs);
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        lg2::error("libspdm_stop_session failed: {STATUS}", "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
    }
    isActive = false;
    return st;
}

libspdm_return_t SpdmSession::heartbeat()
{
    if (!isActive)
    {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    return libspdm_heartbeat(transport.spdmContext, id);
}

libspdm_return_t SpdmSession::keyUpdate(bool singleDirection)
{
    if (!isActive)
    {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    return libspdm_key_update(transport.spdmContext, id, singleDirection);
}

libspdm_return_t SpdmSession::send(std::span<const uint8_t> req,
                                   std::span<uint8_t> resp, size_t& respLen)
{
    if (!isActive)
    {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    respLen = resp.size();
    return libspdm_send_receive_data(transport.spdmContext, &id,
                                     /*is_app_message=*/true, req.data(),
                                     req.size(), resp.data(), &respLen);
}

} // namespace spdm
