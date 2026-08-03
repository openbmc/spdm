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
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;

    uint16_t dheGroup = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    uint16_t aeadCipher = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    uint16_t reqAsymAlg = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    uint16_t keySchedule = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
    uint8_t otherParamsSupport = 0;

    /// Trust anchor for verifying the responder's KEY_EXCHANGE_RSP signature.
    /// Resolution precedence (first non-empty wins):
    ///   1. peerRootCertDer       — raw DER bytes
    ///   2. peerRootCertDerPath   — explicit absolute path to a DER file
    ///   3. peerRootCertBaseDir   — base directory; the actual file is
    ///                              <baseDir>/<algoSubdir>/<peerRootCertFileName>
    ///                              and <algoSubdir> is picked from the
    ///                              negotiated base_asym_algo (e.g. ecp384).
    ///
    /// Resolution by basedir requires libspdm_init_connection to have run
    /// first, so it happens at session-open time, not in
    /// applySecureSessionConfig().
    std::vector<uint8_t> peerRootCertDer;
    std::string peerRootCertDerPath;
    std::string peerRootCertBaseDir;
    std::string peerRootCertFileName = "ca.cert.der";
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
 * Install the responder's root cert as the trust anchor.
 *
 * Reads cfg per the resolution rules in SecureSessionConfig. Returns
 * LIBSPDM_STATUS_SUCCESS and does nothing if no trust anchor is configured.
 */
libspdm_return_t installPeerRootCert(SpdmTransport& transport,
                                     const SecureSessionConfig& cfg);

} // namespace spdm
