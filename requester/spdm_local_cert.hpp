// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace spdm
{

/**
 * Read the requester's slot 0 cert chain (raw DER, root certificate first)
 * from its TPM NV index.
 *
 * Returns an empty vector on failure.
 */
std::vector<uint8_t> readSlot0CertChain();

/**
 * Build the libspdm cert-chain blob for a raw DER chain:
 *
 *   spdm_cert_chain_t{ uint32_t length } | root cert hash | DER chain
 *
 * `length` counts the whole blob. The hash is over the first (root)
 * certificate in the chain, using baseHashAlgo.
 *
 * Returns an empty vector on failure (empty input, unknown hash algo,
 * malformed chain, or a blob larger than LIBSPDM_MAX_CERT_CHAIN_SIZE).
 */
std::vector<uint8_t> buildSpdmCertChainBlob(std::span<const uint8_t> chainDer,
                                            uint32_t baseHashAlgo);

} // namespace spdm
