// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_session_config.hpp"

#include <phosphor-logging/lg2.hpp>

#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace spdm
{

namespace
{

struct CertLoadResult
{
    std::vector<uint8_t> data;
    std::string source; // For logging: path or "in-memory blob"
};

std::vector<uint8_t> readFile(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        return {};
    }
    return {std::istreambuf_iterator<char>(f),
            std::istreambuf_iterator<char>()};
}

std::optional<CertLoadResult> loadCertFromFile(
    const std::filesystem::path& certPath, const std::string_view& context = "")
{
    std::vector<uint8_t> data = readFile(certPath.string());
    if (data.empty())
    {
        if (context.empty())
        {
            lg2::error("Failed to read peer root cert from {PATH}", "PATH",
                       certPath.string());
        }
        else
        {
            lg2::error("Failed to read peer root cert from {PATH} ({CONTEXT})",
                       "PATH", certPath.string(), "CONTEXT", context);
        }
        return std::nullopt;
    }
    return CertLoadResult{std::move(data), certPath.string()};
}

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

// Read a negotiated 32-bit algorithm selection (0 if not negotiated).
uint32_t getNegotiatedAlgo32(void* ctx, libspdm_data_type_t key)
{
    libspdm_data_parameter_t p{};
    p.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    uint32_t algo = 0;
    size_t algoSize = sizeof(algo);
    libspdm_return_t st = libspdm_get_data(ctx, key, &p, &algo, &algoSize);
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        return 0;
    }
    return algo;
}

std::optional<CertLoadResult> loadPeerRootCert(void* ctx,
                                               const SecureSessionConfig& cfg)
{
    namespace fs = std::filesystem;

    if (!cfg.peerRootCertDer.empty())
    {
        return CertLoadResult{cfg.peerRootCertDer, "in-memory blob"};
    }

    if (!cfg.peerRootCertDerPath.empty())
    {
        return loadCertFromFile(fs::path(cfg.peerRootCertDerPath));
    }

    if (!cfg.peerRootCertBaseDir.empty())
    {
        const uint32_t algo =
            getNegotiatedAlgo32(ctx, LIBSPDM_DATA_BASE_ASYM_ALGO);
        const uint32_t pqcAlgo =
            getNegotiatedAlgo32(ctx, LIBSPDM_DATA_PQC_ASYM_ALGO);
        const char* subdir = sigAlgoSubdir(algo, pqcAlgo);
        if (subdir == nullptr)
        {
            lg2::error(
                "Cannot derive cert subdir: unknown negotiated base_asym_algo {ALGO} / pqc_asym_algo {PQC_ALGO}",
                "ALGO", std::format("0x{:08X}", algo), "PQC_ALGO",
                std::format("0x{:08X}", pqcAlgo));
            return std::nullopt;
        }

        const fs::path certPath = fs::path(cfg.peerRootCertBaseDir) / subdir /
                                  cfg.peerRootCertFileName;
        return loadCertFromFile(certPath,
                                std::format("algo subdir: {}", subdir));
    }

    // No configuration provided
    return std::nullopt;
}

} // namespace

namespace
{

// Map a negotiated base_asym_algo bit to the spdm-emu sample-key folder name.
const char* baseAsymAlgoSubdir(uint32_t baseAsymAlgo)
{
    switch (baseAsymAlgo)
    {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
            return "rsa2048";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
            return "rsa3072";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
            return "rsa4096";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
            return "ecp256";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
            return "ecp384";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
            return "ecp521";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            return "sm2";
#ifdef SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            return "ed25519";
#endif
#ifdef SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            return "ed448";
#endif
        default:
            return nullptr;
    }
}

// Map a negotiated SPDM 1.4 pqc_asym_algo bit to the sample-key folder name.
const char* pqcAsymAlgoSubdir(uint32_t pqcAsymAlgo)
{
    switch (pqcAsymAlgo)
    {
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
            return "mldsa44";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
            return "mldsa65";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
            return "mldsa87";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
            return "slh-dsa-sha2-128s";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
            return "slh-dsa-shake-128s";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
            return "slh-dsa-sha2-128f";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
            return "slh-dsa-shake-128f";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
            return "slh-dsa-sha2-192s";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
            return "slh-dsa-shake-192s";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
            return "slh-dsa-sha2-192f";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
            return "slh-dsa-shake-192f";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
            return "slh-dsa-sha2-256s";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
            return "slh-dsa-shake-256s";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
            return "slh-dsa-sha2-256f";
        case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
            return "slh-dsa-shake-256f";
        default:
            return nullptr;
    }
}

} // namespace

// Map a negotiated signature algorithm to the spdm-emu sample-key folder name.
const char* sigAlgoSubdir(uint32_t baseAsymAlgo, uint32_t pqcAsymAlgo)
{
    if (pqcAsymAlgo == 0)
    {
        return baseAsymAlgoSubdir(baseAsymAlgo);
    }
    if (baseAsymAlgo == 0)
    {
        return pqcAsymAlgoSubdir(pqcAsymAlgo);
    }
    return nullptr;
}

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

libspdm_return_t installPeerRootCert(SpdmTransport& transport,
                                     const SecureSessionConfig& cfg)
{
    void* ctx = transport.spdmContext.get();
    if (!ctx)
    {
        lg2::error("installPeerRootCert: spdmContext is null");
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    // libspdm stores the pointer without copying and appends a new provision
    // entry on every call, so the buffer must outlive the context and must be
    // installed exactly once. The cert source is static config, so a populated
    // storage buffer means this already ran for this transport.
    if (!transport.peerRootCertStorage.empty())
    {
        return LIBSPDM_STATUS_SUCCESS;
    }

    std::optional<CertLoadResult> certResult = loadPeerRootCert(ctx, cfg);

    // Handle "no configuration" case
    if (!certResult)
    {
        // Check if any configuration was attempted
        const bool configAttempted =
            !cfg.peerRootCertDer.empty() || !cfg.peerRootCertDerPath.empty() ||
            !cfg.peerRootCertBaseDir.empty();

        if (configAttempted)
        {
            // Configuration was provided but loading failed (error already
            // logged)
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }

        // No configuration provided - warn if KEY_EX capability is enabled
        if (cfg.requesterCapFlags &
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP)
        {
            lg2::warning(
                "No peer root cert configured; KEY_EX signature verify will fail");
        }
        return LIBSPDM_STATUS_SUCCESS;
    }

    // Take ownership of the bytes before handing libspdm the pointer.
    transport.peerRootCertStorage = std::move(certResult->data);

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

    lg2::info("Installed peer root cert from {SOURCE} ({SIZE} bytes)", "SOURCE",
              certResult->source, "SIZE", transport.peerRootCertStorage.size());

    return LIBSPDM_STATUS_SUCCESS;
}

} // namespace spdm
