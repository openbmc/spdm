// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "component_integrity_dbus.hpp"

#include "libspdm_transport.hpp"
#include "utils.hpp"

extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
}

#include <phosphor-logging/lg2.hpp>

#include <chrono>
#include <set>

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
 * @throws InvalidArgument if any index is invalid or not unique
 */
void ComponentIntegrity::validateMeasurementIndices(
    const std::vector<size_t>& measurementIndices)
{
    // Handle empty vector - treat as get all measurements
    if (measurementIndices.empty())
    {
        lg2::info(
            "No measurement indices specified, requesting all measurements (0xFF)");
        return;
    }

    // Handle special cases
    if (measurementIndices.size() == 1)
    {
        if (measurementIndices[0] == 0)
        {
            lg2::info("Requesting total number of measurements (0)");
            return;
        }
        else if (measurementIndices[0] == 255)
        {
            lg2::info("Requesting all measurements (255)");
            return;
        }
    }

    // Validate special value combinations
    validateSpecialValueCombinations(measurementIndices);

    // Validate regular indices (1-254)
    validateRegularIndices(measurementIndices);

    // Check for duplicate indices
    checkForDuplicateIndices(measurementIndices);

    lg2::info("Validated {COUNT} unique measurement indices in range 1-254",
              "COUNT", measurementIndices.size());
}

void ComponentIntegrity::validateSpecialValueCombinations(
    const std::vector<size_t>& measurementIndices)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    // Check for special values that cannot be mixed with others
    bool hasZero = false;
    bool has255 = false;
    bool hasRegularIndices = false;

    for (const auto& idx : measurementIndices)
    {
        if (idx == 0)
            hasZero = true;
        else if (idx == 255)
            has255 = true;
        else if (idx >= 1 && idx <= 254)
            hasRegularIndices = true;
    }

    // Validate special value combinations
    if (hasZero && has255)
    {
        lg2::error(
            "Cannot mix index 0 (total count) and 255 (all measurements)");
        throw InvalidArgument();
    }

    if (hasZero && hasRegularIndices)
    {
        lg2::error(
            "Cannot mix index 0 (total count) with specific measurement indices");
        throw InvalidArgument();
    }

    if (has255 && hasRegularIndices)
    {
        lg2::error(
            "Cannot mix index 255 (all measurements) with specific measurement indices");
        throw InvalidArgument();
    }
}

void ComponentIntegrity::validateRegularIndices(
    const std::vector<size_t>& measurementIndices)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    // Validate regular indices (1-254)
    for (const auto& idx : measurementIndices)
    {
        if (idx < 1 || idx > 254)
        {
            lg2::error(
                "Invalid measurement index: {INDEX}. Must be between 1-254",
                "INDEX", idx);
            throw InvalidArgument();
        }
    }
}

void ComponentIntegrity::checkForDuplicateIndices(
    const std::vector<size_t>& measurementIndices)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    // Check for duplicate indices
    std::set<size_t> uniqueIndices(measurementIndices.begin(),
                                   measurementIndices.end());
    if (uniqueIndices.size() != measurementIndices.size())
    {
        lg2::error(
            "Duplicate measurement indices found. All indices must be unique");
        throw InvalidArgument();
    }
}

/**
 * @brief Initialize SPDM connection
 * @throws std::runtime_error if initialization fails
 */
void ComponentIntegrity::initializeSpdmConnection()
{
    lg2::info("Calling ComponentIntegrity::initializeSpdmConnection()");
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
 * @brief Get signed measurements from SPDM device
 * @param measurementIndices Vector of measurement indices to request
 * @param nonce Nonce for freshness
 * @param slotId Certificate slot ID for signing
 * @return Base64 encoded signed measurements
 */
std::string ComponentIntegrity::getSignedMeasurements(
    const std::vector<size_t>& measurementIndices, const std::string& nonce,
    size_t slotId)
{
    lg2::info(
        "Getting signed measurements for slot {SLOTID}, nonce length: {NONCE_LEN}",
        "SLOTID", slotId, "NONCE_LEN", nonce.length());

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

    // If no specific indices requested, get all measurements
    std::vector<size_t> indicesToProcess = measurementIndices;
    if (indicesToProcess.empty())
    {
        lg2::info(
            "No measurement indices specified, requesting all measurements");
        indicesToProcess = {255}; // Request all measurements
    }

    // Buffer to collect all measurements
    std::vector<uint8_t> allMeasurements;

    // Loop through each measurement index and get measurements individually
    for (const auto& idx : indicesToProcess)
    {
        auto [measurementData,
              numberOfBlocks] = getSingleMeasurement(idx, slotId);
        processMeasurementData(idx, measurementData, allMeasurements,
                               numberOfBlocks);
    }

    // Convert combined measurements to base64 for D-Bus transport
    std::string base64Measurement = spdm::base64Encode(allMeasurements);

    lg2::info(
        "Successfully retrieved {COUNT} measurements, total size: {SIZE} bytes",
        "COUNT", indicesToProcess.size(), "SIZE", allMeasurements.size());

    return base64Measurement;
}

std::pair<std::vector<uint8_t>, uint8_t>
    ComponentIntegrity::getSingleMeasurement(size_t measurementIndex,
                                             size_t slotId)
{
    uint8_t measurementOperation = static_cast<uint8_t>(measurementIndex);

    // Buffer for single measurement response
    constexpr size_t MAX_MEASUREMENT_SIZE = 4096;
    std::vector<uint8_t> measurementBuffer(MAX_MEASUREMENT_SIZE);
    uint32_t measurementSize = measurementBuffer.size();
    uint8_t contentChanged = 0;
    uint8_t numberOfBlocks = 0;

    // Call libspdm to get single measurement
    libspdm_return_t status = libspdm_get_measurement(
        transport->spdmContext,
        nullptr, // No session
        0,       // request_attribute
        measurementOperation, static_cast<uint8_t>(slotId), &contentChanged,
        &numberOfBlocks, &measurementSize, measurementBuffer.data());

    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        lg2::error(
            "libspdm_get_measurement failed for index {INDEX}, status: 0x{STATUS:X}",
            "INDEX", measurementIndex, "STATUS", status);
        throw std::runtime_error("Failed to get signed measurements");
    }

    // Resize buffer to actual measurement size
    measurementBuffer.resize(measurementSize);

    return {measurementBuffer, numberOfBlocks};
}

void ComponentIntegrity::processMeasurementData(
    size_t measurementIndex, const std::vector<uint8_t>& measurementData,
    std::vector<uint8_t>& allMeasurements, uint8_t numberOfBlocks)
{
    // For index 0 (total count), we only get the count, not actual measurements
    if (measurementIndex == 0)
    {
        lg2::info("Retrieved measurement count: {COUNT} blocks", "COUNT",
                  numberOfBlocks);
        // For count-only requests, we might want to return just the count info
        // or handle it differently based on requirements
    }
    else
    {
        // Append this measurement to the combined buffer
        allMeasurements.insert(allMeasurements.end(), measurementData.begin(),
                               measurementData.end());

        lg2::info(
            "Retrieved measurement {INDEX}, size: {SIZE} bytes, blocks: {BLOCKS}",
            "INDEX", measurementIndex, "SIZE", measurementData.size(), "BLOCKS",
            numberOfBlocks);
    }
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
        auto [certPem, certRaw, certLeaf] = getCertificate(slotId);

        // Get signed measurements using libspdm
        std::string signedMeas =
            getSignedMeasurements(measurementIndices, nonce, slotId);

        std::string chassisId =
            sdbusplus::message::object_path(path).filename();
        auto objectPath = updateCertificateObject(chassisId, certPem, certLeaf);
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

std::tuple<std::string, std::vector<uint8_t>> ComponentIntegrity::derCertsToPem(
    const std::vector<uint8_t>& derCerts)
{
    std::string pemChain;
    size_t index = 0;
    size_t currentCertLen = 0;
    std::vector<uint8_t> lastCert;
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
        lastCert.assign(certPtr, certPtr + certLen);

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
    return {pemChain, lastCert};
}

/**
 * @brief Get the certificate chain from the SPDM device and return as PEM
 * string and raw bytes.
 * @param slotId The slot ID to fetch the certificate from.
 * @return std::tuple<std::string, std::vector<uint8_t>, size_t> PEM certificate
 * chain string, raw bytes, and size.
 */
std::tuple<std::string, std::vector<uint8_t>, std::vector<uint8_t>>
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
    const auto [pemChain, leafCert] = derCertsToPem(derCerts);
    return {pemChain, certChain, leafCert};
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

std::string ComponentIntegrity::updateCertificateObject(
    const std::string& chassisId, const std::string& certPem,
    const std::vector<uint8_t>& leafCert)
{
    std::string certId = "CertChain";
    if (certPem.empty())
    {
        lg2::error("Certificate PEM is empty");
        throw std::runtime_error("Certificate PEM is empty");
    }
    std::string objectPath =
        "/xyz/openbmc_project/certs/devices/" + chassisId + "/" + certId;
    if (certificateObject)
    {
        certificateObject->updateCertificateProperties(certPem, leafCert);
    }
    else
    {
        certificateObject = std::make_shared<Certificate>(asyncCtx, objectPath,
                                                          certPem, leafCert);
    }

    return objectPath;
}

} // namespace spdm
