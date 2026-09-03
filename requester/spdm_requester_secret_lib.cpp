// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_requester_secret_lib.hpp"

#include "spdm_session_config.hpp"

extern "C"
{
// clang-format off
#include "library/spdm_crypt_lib.h"
#include "hal/library/requester/reqasymsignlib.h"
#include "library/spdm_crypt_ext_lib.h"
// clang-format on
}

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

/* Mutual authentication is not optional for spdmd: the requester advertises
 * ENCAP_CAP and MUT_AUTH_CAP unconditionally. A libspdm stripped of either
 * would drop the declaration of libspdm_requester_data_sign and silently
 * leave the FINISH signature unimplemented, so fail the build instead. */
#if !LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP ||                                 \
    !LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
#error                                                                         \
    "spdmd mutual authentication requires libspdm built with MUT_AUTH_CAP and ENCAP_CAP"
#endif

namespace spdm
{

namespace
{

std::string& keyBaseDir()
{
    static std::string dir = "/usr/share/spdm-emu";
    return dir;
}

} // namespace

void setRequesterKeyBaseDir(std::string dir)
{
    keyBaseDir() = std::move(dir);
}

const std::string& requesterKeyBaseDir()
{
    return keyBaseDir();
}

} // namespace spdm

/**
 * Sign an SPDM message with the requester's own private key.
 *
 * libspdm calls this via the requester HAL when it has to prove possession of
 * the key behind the cert chain it handed the responder during the
 * encapsulated mutual-authentication flow — for spdmd's scope that is the
 * FINISH signature (op_code == SPDM_FINISH).
 *
 * The key is read per call rather than cached so that no private key material
 * lingers in the daemon's address space between sessions; this mirrors the
 * libspdm sample secret lib.
 */
extern "C" bool libspdm_requester_data_sign(
    void* /* spdm_context */, spdm_version_number_t spdm_version,
    uint8_t key_pair_id, uint8_t op_code, uint16_t req_base_asym_alg,
    uint32_t req_pqc_asym_alg, uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t* message, size_t message_size, uint8_t* signature,
    size_t* sig_size)
{
    if (req_pqc_asym_alg != 0)
    {
        lg2::error("Requester signing: PQC algorithms are not supported");
        return false;
    }
    // spdmd never advertises MULTI_KEY_CAP, so libspdm always passes 0.
    if (key_pair_id != 0)
    {
        lg2::error("Requester signing: unexpected key_pair_id {ID}", "ID",
                   static_cast<uint32_t>(key_pair_id));
        return false;
    }

    const char* subdir = spdm::asymAlgoSubdir(req_base_asym_alg);
    if (subdir == nullptr)
    {
        lg2::error(
            "Requester signing: unknown req_base_asym_alg {ALGO}", "ALGO",
            std::format("0x{:04X}", static_cast<uint32_t>(req_base_asym_alg)));
        return false;
    }

    const std::filesystem::path keyPath =
        std::filesystem::path(spdm::requesterKeyBaseDir()) / subdir /
        "end_requester.key";

    std::ifstream f(keyPath, std::ios::binary);
    std::vector<uint8_t> pem{std::istreambuf_iterator<char>(f),
                             std::istreambuf_iterator<char>()};
    if (!f || pem.empty())
    {
        lg2::error("Requester signing: failed to read private key {PATH}",
                   "PATH", keyPath.string());
        return false;
    }

    void* keyCtx = nullptr;
    if (!libspdm_req_asym_get_private_key_from_pem(
            req_base_asym_alg, pem.data(), pem.size(), /*password=*/nullptr,
            &keyCtx))
    {
        std::ranges::fill(pem, uint8_t{0});
        lg2::error("Requester signing: failed to parse private key {PATH}",
                   "PATH", keyPath.string());
        return false;
    }

    bool result = false;
    if (is_data_hash)
    {
        result = libspdm_req_asym_sign_hash(
            spdm_version, op_code, req_base_asym_alg, base_hash_algo, keyCtx,
            message, message_size, signature, sig_size);
    }
    else
    {
        result = libspdm_req_asym_sign(spdm_version, op_code, req_base_asym_alg,
                                       base_hash_algo, keyCtx, message,
                                       message_size, signature, sig_size);
    }

    libspdm_req_asym_free(req_base_asym_alg, keyCtx);
    std::ranges::fill(pem, uint8_t{0});

    if (!result)
    {
        lg2::error("Requester signing failed for op_code {OP}", "OP",
                   std::format("0x{:02X}", static_cast<uint32_t>(op_code)));
    }
    return result;
}
