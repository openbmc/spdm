// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "component_integrity_dbus.hpp"

#include "libspdm_transport.hpp"

extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
}

#include <phosphor-logging/lg2.hpp>

#include <chrono>

namespace spdm
{

/**
 * @brief Initialize ComponentIntegrity properties
 * @details Sets initial values for all ComponentIntegrity interface properties
 */
void ComponentIntegrity::initializeProperties()
{
    // Initialize with SPDM type (using enum value)
    using SecurityTechnologyType = sdbusplus::common::xyz::openbmc_project::
        attestation::ComponentIntegrity::SecurityTechnologyType;
    type(SecurityTechnologyType::SPDM);

    // Initialize with SPDM version
    type_version("1.1");

    // Enable component integrity checking
    enabled(true);

    // Initialize timestamps
    last_updated(std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count());
}

/**
 * @brief Validate measurement indices
 * @param measurementIndices Vector of measurement indices to validate
 * @throws InvalidArgument if any index is invalid
 */
void ComponentIntegrity::validateMeasurementIndices(
    const std::vector<size_t>& measurementIndices)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    for (const auto& idx : measurementIndices)
    {
        if (idx > 255)
        {
            lg2::error("Invalid measurement index: {INDEX}", "INDEX", idx);
            throw InvalidArgument();
        }
    }
}

/**
 * @brief Initialize SPDM connection
 * @throws std::runtime_error if initialization fails
 */
void ComponentIntegrity::initializeSpdmConnection()
{
    if (!transport)
    {
        lg2::error("Transport is null");
        throw std::runtime_error("SPDM transport not initialized");
    }

    if (!transport->spdmContext)
    {
        lg2::error("SPDM context is null");
        throw std::runtime_error("SPDM context not initialized");
    }

    libspdm_return_t initStatus =
        libspdm_init_connection(transport->spdmContext, false);

    if (LIBSPDM_STATUS_IS_ERROR(initStatus))
    {
        lg2::error("Failed to initialize SPDM connection, status: 0x{STATUS:x}",
                   "STATUS", initStatus);
        throw std::runtime_error("SPDM connection initialization failed");
    }
}

/**
 * @brief Get certificate digests from SPDM device
 * @return Tuple of (slotMask, digestBuffer, totalDigestSize)
 */
std::tuple<uint8_t, std::vector<uint8_t>, size_t>
    ComponentIntegrity::getCertificateDigests()
{
    lg2::info("Getting certificate digests");

    if (!transport)
    {
        lg2::error("Transport is null");
        throw std::runtime_error("SPDM transport not initialized");
    }

    if (!transport->spdmContext)
    {
        lg2::error("SPDM context is null");
        throw std::runtime_error("SPDM context not initialized");
    }

    // Buffer for digest response - each digest is 48 bytes based on SPDM
    // trace analysis
    constexpr size_t DIGEST_SIZE = 48; // Fixed size from SPDM trace
    constexpr size_t MAX_SLOTS = 8;
    std::vector<uint8_t> digestBuffer(MAX_SLOTS * DIGEST_SIZE);
    uint8_t slotMask = 0;

    auto status =
        libspdm_get_digest(transport->spdmContext, nullptr, // No session
                           &slotMask, // Output: which slots have certificates
                           digestBuffer.data()); // Output: digest data buffer

    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        lg2::error("libspdm_get_digest failed, status: 0x{STATUS:X}", "STATUS",
                   status);
        throw std::runtime_error("Failed to get certificate digests");
    }

    // Calculate actual digest data size
    size_t numSlots = __builtin_popcount(slotMask);
    size_t totalDigestSize = numSlots * DIGEST_SIZE;
    totalDigestSize = std::min(totalDigestSize, digestBuffer.size());

    lg2::info(
        "libspdm_get_digest completed, slotMask: 0x{MASK:X}, slots: {SLOTS}, size: {SIZE}",
        "MASK", static_cast<unsigned>(slotMask), "SLOTS", numSlots, "SIZE",
        totalDigestSize);

    return {slotMask, digestBuffer, totalDigestSize};
}

/**
 * @brief Async D-Bus method that handles SPDM signed measurements requests
 *
 * This function uses sdbusplus async context to execute libspdm operations
 * asynchronously without blocking the D-Bus event loop.
 */
auto ComponentIntegrity::method_call(
    spdm_get_signed_measurements_t,
    std::vector<size_t> measurementIndices [[maybe_unused]], std::string nonce,
    size_t slotId [[maybe_unused]])
    -> sdbusplus::async::task<spdm_get_signed_measurements_t::return_type>
{
    lg2::info(
        "spdmGetSignedMeasurements: Starting with path={PATH}, slotId={SLOTID}, nonce_length={NONCE_LEN}",
        "PATH", path, "SLOTID", slotId, "NONCE_LEN", nonce.length());

    try
    {
        validateMeasurementIndices(measurementIndices);
        initializeSpdmConnection();

        auto [slotMask, digestBuffer,
              totalDigestSize] = getCertificateDigests();
        auto [certPem, certRaw, certRawSize] = getCertificate(slotId);

        std::string signedMeas{};
        auto objectPath = sdbusplus::message::object_path(path);
        auto* spdmCtx =
            reinterpret_cast<libspdm_context_t*>(transport->spdmContext);
        auto hashAlgoStr = getHashingAlgorithmStr(
            spdmCtx->connection_info.algorithm.base_hash_algo);
        auto signAlgoStr = getSigningAlgorithmStr(
            spdmCtx->connection_info.algorithm.base_asym_algo);
        auto versionStr = type_version();

        co_return std::make_tuple(objectPath, hashAlgoStr, certPem, signedMeas,
                                  signAlgoStr, versionStr);
    }
    catch (const std::exception& e)
    {
        lg2::error("SPDM Get Signed Measurements FAILED: {ERROR}", "ERROR", e);
        // Return empty tuple on error
        co_return std::make_tuple(
            sdbusplus::message::object_path(path), std::string(""),
            std::string(""), std::string(""), std::string(""), type_version());
    }
}

/**
 * @brief Helper to convert DER certificate(s) to PEM string(s).
 * @param derCerts Vector of DER-encoded certificate bytes.
 * @return std::string PEM-encoded certificate chain.
 */
std::string ComponentIntegrity::derCertsToPem(
    const std::vector<uint8_t>& derCerts)
{
    std::string pemChain;
    size_t index = 0;
    size_t currentCertLen = 0;
    while (currentCertLen < derCerts.size())
    {
        const uint8_t* certPtr = nullptr;
        size_t certLen = 0;
        auto ret = libspdm_x509_get_cert_from_cert_chain(
            derCerts.data(), derCerts.size(), index, &certPtr, &certLen);
        if (!ret)
        {
            lg2::info("No more certs found in certificate chain");
            break; // No more certs
        }
        std::string base64;
        static const char b64_table[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t i = 0;
        for (; i + 2 < certLen; i += 3)
        {
            uint32_t n = (certPtr[i] << 16) | (certPtr[i + 1] << 8) |
                         certPtr[i + 2];
            base64 += b64_table[(n >> 18) & 63];
            base64 += b64_table[(n >> 12) & 63];
            base64 += b64_table[(n >> 6) & 63];
            base64 += b64_table[n & 63];
        }
        if (i < certLen)
        {
            uint32_t n = certPtr[i] << 16;
            base64 += b64_table[(n >> 18) & 63];
            if (i + 1 < certLen)
            {
                n |= certPtr[i + 1] << 8;
                base64 += b64_table[(n >> 12) & 63];
                base64 += b64_table[(n >> 6) & 63];
                base64 += '=';
            }
            else
            {
                base64 += b64_table[(n >> 12) & 63];
                base64 += "==";
            }
        }
        std::string base64Lines;
        for (size_t j = 0; j < base64.size(); j += 64)
        {
            base64Lines += base64.substr(j, 64) + "\n";
        }
        std::string pem = "-----BEGIN CERTIFICATE-----\n" + base64Lines +
                          "-----END CERTIFICATE-----\n";
        pemChain += pem;
        ++index;
        currentCertLen += certLen;
    }
    return pemChain;
}

/**
 * @brief Get the certificate chain from the SPDM device and return as PEM
 * string and raw bytes.
 * @param slotId The slot ID to fetch the certificate from.
 * @return std::tuple<std::string, std::vector<uint8_t>, size_t> PEM certificate
 * chain string, raw bytes, and size.
 */
std::tuple<std::string, std::vector<uint8_t>, size_t>
    ComponentIntegrity::getCertificate(size_t slotId)
{
    if (!transport)
    {
        lg2::error("Transport is null");
        throw std::runtime_error("SPDM transport not initialized");
    }

    if (!transport->spdmContext)
    {
        lg2::error("SPDM context is null");
        throw std::runtime_error("SPDM context not initialized");
    }
    std::vector<uint8_t> certChain(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    size_t certChainSize = certChain.size();

    libspdm_return_t status =
        libspdm_get_certificate(transport->spdmContext, nullptr, slotId,
                                &certChainSize, certChain.data());

    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        lg2::error("libspdm_get_certificate failed, status: 0x{STATUS:X}",
                   "STATUS", status);
        throw std::runtime_error("Failed to get certificate chain");
    }
    certChain.resize(certChainSize);
    size_t hash_size = 0;
    if (transport && transport->spdmContext)
    {
        hash_size = libspdm_get_hash_size(
            reinterpret_cast<libspdm_context_t*>(transport->spdmContext)
                ->connection_info.algorithm.base_hash_algo);
    }
    else
    {
        lg2::error(
            "SPDM transport or context is null when extracting hash size");
        throw std::runtime_error("SPDM transport or context is null");
    }
    constexpr size_t spdm_cert_chain_header_size =
        4; // 2 bytes Length + 2 bytes Reserved
    if (certChain.size() < spdm_cert_chain_header_size + hash_size)
    {
        lg2::error(
            "Certificate chain too small for header+hash: size={SIZE}, header+hash={HDRHASH}",
            "SIZE", certChain.size(), "HDRHASH",
            spdm_cert_chain_header_size + hash_size);
        throw std::runtime_error("Certificate chain too small");
    }
    std::vector<uint8_t> derCerts(
        certChain.begin() + spdm_cert_chain_header_size + hash_size,
        certChain.end());
    std::string pemChain = derCertsToPem(derCerts);
    return {pemChain, certChain, certChainSize};
}

/**
 * @brief Convert hashing algorithm to string representation
 * @param algo Algorithm enumeration value
 * @return String representation of algorithm
 */
std::string ComponentIntegrity::getHashingAlgorithmStr(uint16_t algo)
{
    switch (algo)
    {
        case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
            return "SHA256";
        case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
            return "SHA384";
        case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
            return "SHA512";
        default:
            lg2::error("Unknown hashing algorithm: {ALGO}", "ALGO", algo);
            return "NONE";
    }
}

std::string ComponentIntegrity::getSigningAlgorithmStr(uint16_t algo)
{
    switch (algo)
    {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
            return "RSASSA2048";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
            return "RSAPSS2048";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
            return "ECDSA_P256";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
            return "ECDSA_P384";
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
            return "ECDSA_P521";
        default:
            lg2::error("Unknown signing algorithm: {ALGO}", "ALGO", algo);
            return "NONE";
    }
}

} // namespace spdm
