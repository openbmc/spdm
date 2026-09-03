// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_local_cert.hpp"

#include "spdm_session_config.hpp"

#include <phosphor-logging/lg2.hpp>

#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <utility>
#include <vector>

namespace spdm
{

namespace
{

/// Read the negotiated requester asym algo. 0 means the responder offered no
/// overlap, i.e. it will not ask us to authenticate.
uint16_t getNegotiatedReqAsymAlgo(void* ctx)
{
    libspdm_data_parameter_t p{};
    p.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    uint16_t algo = 0;
    size_t algoSize = sizeof(algo);
    if (LIBSPDM_STATUS_IS_ERROR(libspdm_get_data(
            ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &p, &algo, &algoSize)))
    {
        return 0;
    }
    return algo;
}

uint32_t getNegotiatedHashAlgo(void* ctx)
{
    libspdm_data_parameter_t p{};
    p.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    uint32_t algo = 0;
    size_t algoSize = sizeof(algo);
    if (LIBSPDM_STATUS_IS_ERROR(libspdm_get_data(
            ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &p, &algo, &algoSize)))
    {
        return 0;
    }
    return algo;
}

} // namespace

std::vector<uint8_t> buildSpdmCertChainBlob(std::span<const uint8_t> chainDer,
                                            uint32_t baseHashAlgo)
{
    if (chainDer.empty())
    {
        lg2::error("Cert chain blob: empty DER input");
        return {};
    }

    const size_t digestSize = libspdm_get_hash_size(baseHashAlgo);
    if (digestSize == 0)
    {
        lg2::error("Cert chain blob: unknown base hash algo {ALGO}", "ALGO",
                   std::format("0x{:08X}", baseHashAlgo));
        return {};
    }

    const size_t total =
        sizeof(spdm_cert_chain_t) + digestSize + chainDer.size();
    if (total > LIBSPDM_MAX_CERT_CHAIN_SIZE)
    {
        lg2::error("Cert chain blob: {SIZE} bytes exceeds the {MAX} byte limit",
                   "SIZE", total, "MAX",
                   static_cast<size_t>(LIBSPDM_MAX_CERT_CHAIN_SIZE));
        return {};
    }

    const uint8_t* rootCert = nullptr;
    size_t rootCertLen = 0;
    if (!libspdm_x509_get_cert_from_cert_chain(chainDer.data(), chainDer.size(),
                                               0, &rootCert, &rootCertLen))
    {
        lg2::error("Cert chain blob: no root certificate in the DER chain");
        return {};
    }

    std::vector<uint8_t> blob(total);

    // spdm_cert_chain_t is a single little-endian uint32_t length field that
    // covers the whole blob, followed by the root hash and then the chain.
    const uint32_t length = static_cast<uint32_t>(total);
    std::memcpy(blob.data(), &length, sizeof(length));

    if (!libspdm_hash_all(baseHashAlgo, rootCert, rootCertLen,
                          blob.data() + sizeof(spdm_cert_chain_t)))
    {
        lg2::error("Cert chain blob: root certificate hashing failed");
        return {};
    }

    std::memcpy(blob.data() + sizeof(spdm_cert_chain_t) + digestSize,
                chainDer.data(), chainDer.size());

    return blob;
}

libspdm_return_t installLocalRequesterCertChain(SpdmTransport& transport,
                                                const SecureSessionConfig& cfg)
{
    void* ctx = transport.spdmContext.get();
    if (!ctx)
    {
        lg2::error("installLocalRequesterCertChain: spdmContext is null");
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if (cfg.peerRootCertBaseDir.empty())
    {
        return LIBSPDM_STATUS_SUCCESS;
    }

    const uint16_t reqAsym = getNegotiatedReqAsymAlgo(ctx);
    if (reqAsym == 0)
    {
        // The responder offered no requester asym algo, so it cannot ask for
        // mutual authentication. A one-way session must still succeed.
        lg2::warning(
            "No requester asym algo negotiated; skipping local cert chain (no mutual auth)");
        return LIBSPDM_STATUS_SUCCESS;
    }

    const char* subdir = asymAlgoSubdir(reqAsym);
    if (subdir == nullptr)
    {
        lg2::error(
            "Cannot derive local cert subdir: unknown negotiated req_base_asym_alg {ALGO}",
            "ALGO", std::format("0x{:04X}", static_cast<uint32_t>(reqAsym)));
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    const std::filesystem::path chainPath =
        std::filesystem::path(cfg.peerRootCertBaseDir) / subdir /
        cfg.localCertChainFileName;

    std::ifstream f(chainPath, std::ios::binary);
    std::vector<uint8_t> der{std::istreambuf_iterator<char>(f),
                             std::istreambuf_iterator<char>()};
    if (!f || der.empty())
    {
        // We advertised MUT_AUTH_CAP, so a missing chain would surface later
        // as an opaque encapsulated-flow failure. Fail crisply here instead.
        lg2::error("Failed to read local requester cert chain from {PATH}",
                   "PATH", chainPath.string());
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    // Build into a local first: on re-entry, assigning straight into
    // localCertChainBlob would free the buffer libspdm still points at even
    // when the rebuild fails.
    std::vector<uint8_t> blob =
        buildSpdmCertChainBlob(der, getNegotiatedHashAlgo(ctx));
    if (blob.empty())
    {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    transport.localCertChainBlob = std::move(blob);

    // libspdm stores the pointer without copying, so every slot points at the
    // transport-owned buffer. Re-entry just overwrites the same pointers.
    for (uint8_t slot = 0; slot < SPDM_MAX_SLOT_COUNT; ++slot)
    {
        if ((cfg.localCertSlotMask & (1U << slot)) == 0)
        {
            continue;
        }

        libspdm_data_parameter_t p{};
        p.location = LIBSPDM_DATA_LOCATION_LOCAL;
        p.additional_data[0] = slot;
        const libspdm_return_t st =
            libspdm_set_data(ctx, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &p,
                             transport.localCertChainBlob.data(),
                             transport.localCertChainBlob.size());
        if (LIBSPDM_STATUS_IS_ERROR(st))
        {
            lg2::error(
                "set_data LOCAL_PUBLIC_CERT_CHAIN slot {SLOT} failed: {STATUS}",
                "SLOT", static_cast<uint32_t>(slot), "STATUS",
                std::format("0x{:08X}", static_cast<uint32_t>(st)));
            return st;
        }
    }

    // SPDM 1.3 puts this mask in the encapsulated DIGESTS Param1 and the
    // responder rejects the response unless it covers every provisioned slot.
    // It defaults to 0, so setting it is mandatory on 1.3 and harmless below.
    uint8_t mask = cfg.localCertSlotMask;
    libspdm_data_parameter_t maskParam{};
    maskParam.location = LIBSPDM_DATA_LOCATION_LOCAL;
    const libspdm_return_t st =
        libspdm_set_data(ctx, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
                         &maskParam, &mask, sizeof(mask));
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        lg2::error("set_data LOCAL_SUPPORTED_SLOT_MASK failed: {STATUS}",
                   "STATUS",
                   std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    lg2::info(
        "Installed local requester cert chain from {PATH} ({SIZE} bytes, slots {MASK})",
        "PATH", chainPath.string(), "SIZE", transport.localCertChainBlob.size(),
        "MASK", std::format("0x{:02X}", static_cast<uint32_t>(mask)));

    return LIBSPDM_STATUS_SUCCESS;
}

} // namespace spdm
