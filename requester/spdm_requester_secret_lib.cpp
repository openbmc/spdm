// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

extern "C"
{
// clang-format off
#include "library/spdm_crypt_lib.h"
#include "hal/library/requester/reqasymsignlib.h"
#include "library/spdm_crypt_ext_lib.h"
// clang-format on
}

#include <config.hpp>
#include <phosphor-logging/lg2.hpp>

#include <cstdint>
#include <format>

/* Mutual authentication is not optional for spdmd: the requester advertises
 * ENCAP_CAP and MUT_AUTH_CAP unconditionally. A libspdm stripped of either
 * would drop the declaration of libspdm_requester_data_sign and silently
 * leave the FINISH signature unimplemented, so fail the build instead. */
#if !LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP ||                                 \
    !LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
#error                                                                         \
    "spdmd mutual authentication requires libspdm built with MUT_AUTH_CAP and ENCAP_CAP"
#endif

/**
 * Sign an SPDM message with the requester's slot 0 key.
 *
 * libspdm calls this via the requester HAL when it has to prove possession of
 * the key behind the cert chain it handed the responder during the
 * encapsulated mutual-authentication flow — for spdmd's scope that is the
 * FINISH signature (op_code == SPDM_FINISH).
 *
 * The key is a TPM persistent key, so the private key never leaves the TPM.
 * libspdm negotiates either a classic (req_base_asym_alg) or an SPDM 1.4 PQC
 * (req_pqc_asym_alg) algorithm and passes 0 for the other one. It must match
 * the key type in the TPM, or signing fails.
 */
extern "C" bool libspdm_requester_data_sign(
    void* /* spdm_context */, spdm_version_number_t spdm_version,
    uint8_t key_pair_id, uint8_t op_code, uint16_t req_base_asym_alg,
    uint32_t req_pqc_asym_alg, uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t* message, size_t message_size, uint8_t* signature,
    size_t* sig_size)
{
    // spdmd never advertises MULTI_KEY_CAP, so libspdm always passes 0.
    if (key_pair_id != 0)
    {
        lg2::error("Requester signing: unexpected key_pair_id {ID}", "ID",
                   static_cast<uint32_t>(key_pair_id));
        return false;
    }

    if (!libspdm_tpm_device_init())
    {
        lg2::error(
            "Requester signing: failed to load the OpenSSL tpm2 provider");
        return false;
    }

    void* keyCtx = nullptr;
    if (!libspdm_tpm_get_pvt_key_handle(SPDM_TPM_KEY_HANDLE, &keyCtx))
    {
        lg2::error("Requester signing: failed to load TPM key {HANDLE}",
                   "HANDLE", SPDM_TPM_KEY_HANDLE);
        return false;
    }

    bool result = false;
    if (req_pqc_asym_alg != 0)
    {
        result =
            is_data_hash
                ? libspdm_req_pqc_asym_sign_hash(
                      spdm_version, op_code, req_pqc_asym_alg, base_hash_algo,
                      keyCtx, message, message_size, signature, sig_size)
                : libspdm_req_pqc_asym_sign(
                      spdm_version, op_code, req_pqc_asym_alg, base_hash_algo,
                      keyCtx, message, message_size, signature, sig_size);
        libspdm_req_pqc_asym_free(req_pqc_asym_alg, keyCtx);
    }
    else
    {
        result =
            is_data_hash
                ? libspdm_req_asym_sign_hash(
                      spdm_version, op_code, req_base_asym_alg, base_hash_algo,
                      keyCtx, message, message_size, signature, sig_size)
                : libspdm_req_asym_sign(
                      spdm_version, op_code, req_base_asym_alg, base_hash_algo,
                      keyCtx, message, message_size, signature, sig_size);
        libspdm_req_asym_free(req_base_asym_alg, keyCtx);
    }

    if (!result)
    {
        lg2::error(
            "Requester signing failed for op_code {OP} with req_base_asym_alg {ALGO} / req_pqc_asym_alg {PQC_ALGO}",
            "OP", std::format("0x{:02X}", static_cast<uint32_t>(op_code)),
            "ALGO",
            std::format("0x{:04X}", static_cast<uint32_t>(req_base_asym_alg)),
            "PQC_ALGO", std::format("0x{:08X}", req_pqc_asym_alg));
    }
    return result;
}
