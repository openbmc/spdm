// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once
#include <phosphor-logging/lg2.hpp>

extern "C"
{
#include "internal/libspdm_common_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
#include "library/spdm_transport_mctp_lib.h"
}

/* libspdm only defines LIBSPDM_MAX_CERT_CHAIN_SIZE when
 * LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled (it defaults to 0). Fall
 * back to libspdm's own sizing for the signature algorithms spdmd offers:
 * ML-DSA chains reach 22 KB (ML-DSA-87). */
#ifndef LIBSPDM_MAX_CERT_CHAIN_SIZE
#if LIBSPDM_ML_DSA_SUPPORT
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x8000
#else
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x1000
#endif
#endif
/* With CHUNK_CAP negotiated, libspdm answers an encapsulated GET_CERTIFICATE
 * with the whole remaining local cert chain in one CERTIFICATE response, and
 * libspdm_check_context() requires every local chain to fit in one message.
 * The extra 0x200 bytes cover the message headers. */
#define LIBSPDM_MAX_SPDM_MSG_SIZE (LIBSPDM_MAX_CERT_CHAIN_SIZE + 0x200)
#define LIBSPDM_TRANSPORT_HEADER_SIZE 64
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE                                      \
    (LIBSPDM_TRANSPORT_HEADER_SIZE + LIBSPDM_TRANSPORT_TAIL_SIZE)
#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE                                             \
    (LIBSPDM_MAX_SPDM_MSG_SIZE + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE                                           \
    (LIBSPDM_MAX_SPDM_MSG_SIZE + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace spdm
{

static_assert(LIBSPDM_MAX_SPDM_MSG_SIZE >=
                  LIBSPDM_MAX_CERT_CHAIN_SIZE +
                      sizeof(spdm_deliver_encapsulated_response_request_t) +
                      sizeof(spdm_certificate_large_response_t),
              "an encapsulated CERTIFICATE response must hold the whole "
              "local cert chain");

/** @brief ML-DSA parameter sets libspdm is built with (SPDM 1.4). */
inline constexpr uint32_t mlDsaAlgos =
    (LIBSPDM_ML_DSA_44_SUPPORT ? SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44 : 0) |
    (LIBSPDM_ML_DSA_65_SUPPORT ? SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65 : 0) |
    (LIBSPDM_ML_DSA_87_SUPPORT ? SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87 : 0);

/** @brief ML-KEM parameter sets libspdm is built with (SPDM 1.4). */
inline constexpr uint32_t mlKemAlgos =
    (LIBSPDM_ML_KEM_512_SUPPORT ? SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512 : 0) |
    (LIBSPDM_ML_KEM_768_SUPPORT ? SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768 : 0) |
    (LIBSPDM_ML_KEM_1024_SUPPORT ? SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024 : 0);

/** @brief Custom deleter for the libspdm context: deinits then frees. */
struct SpdmContextDeleter
{
    void operator()(void* ctx) const noexcept
    {
        libspdm_deinit_context(ctx);
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
        free(ctx);
    }
};

/**
 * @brief Abstract base class for SPDM transport implementations.
 * @details Holds libspdm context and algorithm negotiation state shared by
 *          all transport backends (MCTP, PCIe-DOE, TCP, etc.).
 */
class SpdmTransport
{
  public:
    SpdmTransport() = default;
    virtual ~SpdmTransport() = default;

    /** @brief Shared send/receive buffer for SPDM messages. */
    std::array<uint8_t, LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE>
        sendReceiveBuffer{};
    /** @brief Indicates whether the send/receive buffer is currently
     * acquired. */
    bool sendReceiveBufferAcquired = false;
    /** @brief SPDM protocol version to offer. 0 offers every version libspdm
     *  supports (up to 1.4) and the highest common one is negotiated. */
    uint8_t useVersion = 0;
    /** @brief Requester capability flags to advertise. */
    uint32_t useRequesterCapabilityFlags = 0;
    /** @brief Requester slot ID used for certificate selection. */
    uint8_t useReqSlotId = 0xFF;
    /** @brief Responder capability flags. */
    uint32_t useCapabilityFlags = 0;
    /** @brief Negotiated base hash algorithm. */
    uint32_t useHashAlgo = 0;
    /** @brief Negotiated measurement hash algorithm. */
    uint32_t useMeasurementHashAlgo = 0;
    /** @brief Negotiated asymmetric algorithm for the responder. */
    uint32_t useAsymAlgo = 0;
    /** @brief Negotiated asymmetric algorithm for the requester. */
    uint16_t useReqAsymAlgo = 0;

    /** @brief Supported measurement specification (e.g. DMTF). */
    uint8_t supportMeasurementSpec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    /** @brief Supported measurement hash algorithms bitmask. */
    uint32_t supportMeasurementHashAlgo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    /** @brief Supported base hash algorithms bitmask. */
    uint32_t supportHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                               SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                               SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
    /** @brief Supported asymmetric algorithms bitmask for the responder. */
    uint32_t supportAsymAlgo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    /** @brief Supported asymmetric algorithms bitmask for the requester. */
    uint16_t supportReqAsymAlgo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    /** @brief Supported PQC asymmetric algorithms bitmask for the responder.
     *  @details Only sent when SPDM 1.4 is negotiated. The responder selects
     *           either a classic or a PQC signature algorithm, never both. */
    uint32_t supportPqcAsymAlgo = mlDsaAlgos;
    /** @brief Supported PQC asymmetric algorithms bitmask for the requester.
     */
    uint32_t supportReqPqcAsymAlgo = mlDsaAlgos;
    /** @brief Supported DHE named group algorithms bitmask. */
    uint16_t supportDheAlgo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    /** @brief Supported AEAD cipher suite bitmask. */
    uint16_t supportAeadAlgo = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    /** @brief Supported key schedule algorithm bitmask. */
    uint16_t supportKeyScheduleAlgo = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
    /** @brief Supported other parameters bitmask.
     *  @details SPDM 1.2+ KEY_EXCHANGE/PSK_EXCHANGE require OpaqueDataFmt1 to
     *           be negotiated; libspdm refuses to start a session otherwise.
     *           Ignored for 1.0/1.1. */
    uint8_t supportOtherParamsSupport = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    /** @brief libspdm data parameter used when setting/getting SPDM context
     * data. */
    libspdm_data_parameter_t parameter{};

    /** @brief Backing storage for the pointers handed to libspdm_set_data
     *         (LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT /
     *         LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN). */
    std::vector<uint8_t> peerRootCertStorage;
    std::vector<uint8_t> localCertChainBlob;

    /** @brief Opaque libspdm context — owns the memory and calls
     *         libspdm_deinit_context + free on destruction. */
    std::unique_ptr<void, SpdmContextDeleter> spdmContext;

    /** @brief Scratch buffer used by libspdm for internal operations. */
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    std::unique_ptr<void, decltype(&free)> scratchBuffer{nullptr, &free};

    /**
     * @brief Initialize the SPDM transport specific functions. This function
     * needs to be implemented by the transport layer Ex: MCTP, PCIe-DOE, etc.
     *
     * @return true if the SPDM context is initialized successfully
     * @return false if the SPDM context is not initialized successfully
     */
    virtual bool initialize() = 0;
};

} // namespace spdm
