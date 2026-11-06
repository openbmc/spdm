// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "libspdm_transport.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace spdm
{

struct SecureSessionConfig
{
    /// 0 = let libspdm negotiate the highest mutually supported version
    /// Set explicitly only to pin a specific version.
    uint8_t version = 0;

    uint32_t requesterCapFlags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        // PQC signatures and KEM keys make KEY_EXCHANGE_RSP, FINISH and
        // CERTIFICATE larger than many responders' DataTransferSize.
        (LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
             ? SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP
             : 0);

    uint16_t dheGroup = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    // SPDM 1.4 KEM algorithms, sent only when 1.4 is negotiated. The
    // responder selects either a DHE group or a KEM, never both.
    uint32_t kemAlg = mlKemAlgos;
    uint16_t aeadCipher = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    // Requester signing algorithms come from SpdmTransport::supportReqAsymAlgo.
    uint16_t keySchedule = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;

    /// Bit mask of cert slots to provision the local (TPM slot 0) chain into.
    uint8_t localCertSlotMask = 0x01; // slot 0
};

/**
 * Apply secure-session capability flags and algorithms to an
 * already-initialized SpdmTransport.
 *
 * Calls libspdm_check_context() internally as the final step. Does NOT
 * install the peer root certificate.
 */
libspdm_return_t applySecureSessionConfig(SpdmTransport& transport,
                                          const SecureSessionConfig& cfg);

/**
 * Install the trust anchor for the responder's cert chain.
 *
 * Requester and responder share one root CA, so the trust anchor is the root
 * certificate of our own slot 0 cert chain in the TPM.
 */
libspdm_return_t installPeerRootCert(SpdmTransport& transport);

/**
 * Provision the requester's own cert chain so libspdm can answer the
 * responder's encapsulated GET_DIGESTS / GET_CERTIFICATE during
 * session-based mutual authentication.
 *
 * The chain is the requester's slot 0 chain from the TPM. Requires
 * libspdm_init_connection to have completed (the hash algo is only
 * negotiated by then). Returns LIBSPDM_STATUS_SUCCESS and does nothing if the
 * responder negotiated neither a classic nor a PQC requester asym algo
 * (mutual auth simply will not be requested).
 */
libspdm_return_t installLocalRequesterCertChain(SpdmTransport& transport,
                                                const SecureSessionConfig& cfg);

} // namespace spdm
