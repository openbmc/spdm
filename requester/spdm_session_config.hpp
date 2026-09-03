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
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;

    uint16_t dheGroup = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    uint16_t aeadCipher = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    // Requester signing algorithms come from SpdmTransport::supportReqAsymAlgo.
    uint16_t keySchedule = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;

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

    /// File name of the requester's (local) cert chain, resolved as
    /// <peerRootCertBaseDir>/<algoSubdir(negotiated req asym algo)>/<file>.
    /// An empty peerRootCertBaseDir disables local-chain provisioning.
    std::string localCertChainFileName = "bundle_requester.certchain.der";
    /// Bit mask of cert slots to provision the local chain into.
    uint8_t localCertSlotMask = 0x03; // slots 0 and 1
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

/**
 * Directory name (e.g. "ecp256") for a base asym algo, matching the
 * spdm-emu sample-key layout. Returns nullptr for unknown algos.
 */
const char* asymAlgoSubdir(uint32_t baseAsymAlgo);

/**
 * Provision the requester's own cert chain so libspdm can answer the
 * responder's encapsulated GET_DIGESTS / GET_CERTIFICATE during
 * session-based mutual authentication.
 *
 * Requires libspdm_init_connection to have completed (the req asym algo is
 * only negotiated by then). Returns LIBSPDM_STATUS_SUCCESS and does nothing
 * if no base directory is configured, or if the responder negotiated no
 * requester asym algo (mutual auth simply will not be requested).
 */
libspdm_return_t installLocalRequesterCertChain(SpdmTransport& transport,
                                                const SecureSessionConfig& cfg);

} // namespace spdm
