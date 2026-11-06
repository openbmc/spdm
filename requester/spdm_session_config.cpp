// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_session_config.hpp"

#include "spdm_local_cert.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>
#include <vector>

namespace spdm
{

namespace
{

template <typename T>
libspdm_return_t setData(void* ctx, libspdm_data_type_t key, T value)
{
    libspdm_data_parameter_t p{};
    p.location = LIBSPDM_DATA_LOCATION_LOCAL;
    return libspdm_set_data(ctx, key, &p, &value, sizeof(T));
}

template <typename T>
libspdm_return_t setDataAndCheck(void* ctx, libspdm_data_type_t key, T value,
                                 const char* paramName)
{
    libspdm_return_t st = setData(ctx, key, value);
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        lg2::error("Failed to set {PARAM}: {STATUS}", "PARAM", paramName,
                   "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
    }
    return st;
}

libspdm_return_t applyVersionConfig(void* ctx, SpdmTransport& transport,
                                    uint8_t version)
{
    if (version == 0)
    {
        return LIBSPDM_STATUS_SUCCESS;
    }

    spdm_version_number_t v = static_cast<spdm_version_number_t>(
        version << SPDM_VERSION_NUMBER_SHIFT_BIT);
    libspdm_data_parameter_t p{};
    p.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_return_t st =
        libspdm_set_data(ctx, LIBSPDM_DATA_SPDM_VERSION, &p, &v, sizeof(v));
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        lg2::error("Failed to set SPDM version: {STATUS}", "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }
    transport.useVersion = version;
    return LIBSPDM_STATUS_SUCCESS;
}

} // namespace

libspdm_return_t applySecureSessionConfig(SpdmTransport& transport,
                                          const SecureSessionConfig& cfg)
{
    void* ctx = transport.spdmContext.get();
    if (!ctx)
    {
        lg2::error("applySecureSessionConfig: spdmContext is null");
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    // Apply version configuration
    libspdm_return_t st = applyVersionConfig(ctx, transport, cfg.version);
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    // Apply capability flags with transport state update
    st = setDataAndCheck(ctx, LIBSPDM_DATA_CAPABILITY_FLAGS,
                         cfg.requesterCapFlags, "CAPABILITY_FLAGS");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }
    transport.useRequesterCapabilityFlags = cfg.requesterCapFlags;

    // Apply cryptographic algorithm parameters
    st = setDataAndCheck(ctx, LIBSPDM_DATA_DHE_NAME_GROUP, cfg.dheGroup,
                         "DHE_NAME_GROUP");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    st = setDataAndCheck(ctx, LIBSPDM_DATA_KEM_ALG, cfg.kemAlg, "KEM_ALG");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    st = setDataAndCheck(ctx, LIBSPDM_DATA_AEAD_CIPHER_SUITE, cfg.aeadCipher,
                         "AEAD_CIPHER_SUITE");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    st = setDataAndCheck(ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                         transport.supportReqAsymAlgo, "REQ_BASE_ASYM_ALG");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    st = setDataAndCheck(ctx, LIBSPDM_DATA_REQ_PQC_ASYM_ALG,
                         transport.supportReqPqcAsymAlgo, "REQ_PQC_ASYM_ALG");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    st = setDataAndCheck(ctx, LIBSPDM_DATA_KEY_SCHEDULE, cfg.keySchedule,
                         "KEY_SCHEDULE");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    st = setDataAndCheck(ctx, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,
                         transport.supportOtherParamsSupport,
                         "OTHER_PARAMS_SUPPORT");
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return st;
    }

    // Final validation of the configured context
    if (!libspdm_check_context(ctx))
    {
        lg2::error("libspdm_check_context failed after secure-session config");
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t installPeerRootCert(SpdmTransport& transport)
{
    void* ctx = transport.spdmContext.get();
    if (!ctx)
    {
        lg2::error("installPeerRootCert: spdmContext is null");
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    // libspdm stores the pointer without copying and appends a new provision
    // entry on every call, so the buffer must outlive the context and must be
    // installed exactly once. The TPM chain does not change at run time, so a
    // populated storage buffer means this already ran for this transport.
    if (!transport.peerRootCertStorage.empty())
    {
        return LIBSPDM_STATUS_SUCCESS;
    }

    const std::vector<uint8_t> chain = readSlot0CertChain();
    const uint8_t* root = nullptr;
    size_t rootLen = 0;
    if (chain.empty() || !libspdm_x509_get_cert_from_cert_chain(
                             chain.data(), chain.size(), 0, &root, &rootLen))
    {
        lg2::error("No root certificate in the slot 0 cert chain");
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    // Take ownership of the bytes before handing libspdm the pointer.
    transport.peerRootCertStorage.assign(root, root + rootLen);

    libspdm_data_parameter_t p{};
    p.location = LIBSPDM_DATA_LOCATION_LOCAL;
    const libspdm_return_t st =
        libspdm_set_data(ctx, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &p,
                         transport.peerRootCertStorage.data(),
                         transport.peerRootCertStorage.size());

    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        transport.peerRootCertStorage.clear();
        lg2::error("set_data PEER_PUBLIC_ROOT_CERT failed: {STATUS}", "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    lg2::info(
        "Installed peer root cert from the slot 0 cert chain ({SIZE} bytes)",
        "SIZE", transport.peerRootCertStorage.size());

    return LIBSPDM_STATUS_SUCCESS;
}

} // namespace spdm
