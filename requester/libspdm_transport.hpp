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

#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
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

namespace spdm
{

/**
 * @brief Abstract base class for SPDM transport implementations.
 * @details Holds libspdm context and algorithm negotiation state shared by
 *          all transport backends (MCTP, PCIe-DOE, TCP, etc.).
 */
class SpdmTransport
{
  public:
    SpdmTransport() : spdmContext(nullptr), scratchBuffer(nullptr) {}
    ~SpdmTransport()
    {
        if (scratchBuffer)
        {
            free(scratchBuffer);
            scratchBuffer = nullptr;
        }
        if (spdmContext)
        {
            libspdm_deinit_context(spdmContext);
        }
    }
    /** @brief Shared send/receive buffer for SPDM messages. */
    uint8_t sendReceiveBuffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    /** @brief Indicates whether the send/receive buffer is currently
     * acquired. */
    bool sendReceiveBufferAcquired = false;
    /** @brief Negotiated SPDM protocol version to use. */
    uint8_t useVersion = SPDM_MESSAGE_VERSION_11;
    /** @brief Requester capability flags to advertise. */
    uint32_t useRequesterCapabilityFlags = 0;
    /** @brief Requester slot ID used for certificate selection. */
    uint8_t useReqSlotId = 0xFF;
    /** @brief Responder capability flags. */
    uint32_t useCapabilityFlags = 0;
    /** @brief Negotiated base hash algorithm. */
    uint32_t useHashAlgo;
    /** @brief Negotiated measurement hash algorithm. */
    uint32_t useMeasurementHashAlgo;
    /** @brief Negotiated asymmetric algorithm for the responder. */
    uint32_t useAsymAlgo;
    /** @brief Negotiated asymmetric algorithm for the requester. */
    uint16_t useReqAsymAlgo;

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
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    /** @brief Supported asymmetric algorithms bitmask for the requester. */
    uint16_t supportReqAsymAlgo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    /** @brief Supported DHE named group algorithms bitmask. */
    uint16_t supportDheAlgo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    /** @brief Supported AEAD cipher suite bitmask. */
    uint16_t supportAeadAlgo = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    /** @brief Supported key schedule algorithm bitmask. */
    uint16_t supportKeyScheduleAlgo = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    /** @brief Supported other parameters bitmask. */
    uint8_t supportOtherParamsSupport = 0;
    /** @brief libspdm data parameter used when setting/getting SPDM context
     * data. */
    libspdm_data_parameter_t parameter;
    /** @brief Opaque libspdm context pointer. */
    void* spdmContext;
    /** @brief Scratch buffer used by libspdm for internal operations. */
    void* scratchBuffer;

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
