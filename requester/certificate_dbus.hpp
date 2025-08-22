// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "xyz/openbmc_project/Certs/Certificate/aserver.hpp"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <sdbusplus/async/context.hpp>

namespace spdm
{

class Certificate :
    public sdbusplus::aserver::xyz::openbmc_project::certs::Certificate<
        Certificate, void>
{
  public:
    Certificate() = delete;
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
    Certificate(Certificate&&) = delete;
    Certificate& operator=(Certificate&&) = delete;

    /**
     * @brief Constructor for Certificate object
     * @param asyncCtx Async context for D-Bus operations
     * @param path D-Bus object path
     * @param pemChain PEM-encoded certificate chain
     * @param leafCert Leaf certificate
     */
    Certificate(sdbusplus::async::context& asyncCtx, const std::string& path,
                const std::string& pemChain,
                const std::vector<uint8_t>& leafCert);

    /**
     * @brief Update certificate properties
     * @param pemChain PEM-encoded certificate chain
     * @param leafCert Leaf certificate
     */
    void updateCertificateProperties(const std::string& pemChain,
                                     const std::vector<uint8_t>& leafCert);

    /**
     * @brief Parse certificate PEM chain
     * @param leafCert DER-encoded leaf certificate
     * @return Tuple containing issuer, subject, notBefore, notAfter, and
     * keyUsage
     */
    std::tuple<std::string, std::string, uint64_t, uint64_t,
               std::vector<std::string>>
        parseCertificatePEM(const std::vector<uint8_t>& leafCert);

    /**
     * @brief Get issuer name from DER-encoded certificate
     * @param certPtr Pointer to DER-encoded certificate
     * @param certLen Length of DER-encoded certificate
     * @return Issuer name as a string
     */
    std::string getIssuerNameFromDer(const uint8_t* certPtr, size_t certLen);

    /**
     * @brief Get a one-line string representation of an X509_NAME
     * @param name Pointer to X509_NAME
     * @return String representation of the name
     */
    static std::string getNameOneline(X509_NAME* name);

    /**
     * @brief Convert ASN1_TIME to epoch time
     * @param time Pointer to ASN1_TIME
     * @return Epoch time as uint64_t
     */
    static uint64_t asn1TimeToEpoch(const ASN1_TIME* time);

    /**
     * @brief Get key usage strings from ASN1_BIT_STRING
     * @param usage Pointer to ASN1_BIT_STRING
     * @return Vector of key usage strings
     */
    static std::vector<std::string> getKeyUsageStrings(
        const ASN1_BIT_STRING* usage);

  private:
    std::string path;
};

} // namespace spdm
