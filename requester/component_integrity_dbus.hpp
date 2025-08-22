// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "certificate_dbus.hpp"
#include "xyz/openbmc_project/Attestation/ComponentIntegrity/aserver.hpp"
#include "xyz/openbmc_project/Attestation/IdentityAuthentication/aserver.hpp"
#include "xyz/openbmc_project/Attestation/MeasurementSet/aserver.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/async/context.hpp>
#include <sdbusplus/async/server.hpp>
#include <sdbusplus/server/object.hpp>

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace spdm
{
class SpdmTransport;

namespace test
{
class ComponentIntegrityTest;
}

/** @class ComponentIntegrity
 *  @brief OpenBMC ComponentIntegrity entry implementation.
 *  @details A concrete implementation of
 *    xyz.openbmc_project.Attestation.ComponentIntegrity DBus API
 *    xyz.openbmc_project.Attestation.IdentityAuthentication DBus API
 *    xyz.openbmc_project.Attestation.MeasurementSet DBus API
 */
class ComponentIntegrity :
    public sdbusplus::aserver::xyz::openbmc_project::attestation::
        ComponentIntegrity<ComponentIntegrity, void>,
    public sdbusplus::aserver::xyz::openbmc_project::attestation::
        MeasurementSet<ComponentIntegrity, void>,
    public sdbusplus::aserver::xyz::openbmc_project::attestation::
        IdentityAuthentication<ComponentIntegrity, void>
{
  public:
    ComponentIntegrity() = delete;
    ComponentIntegrity(const ComponentIntegrity&) = delete;
    ComponentIntegrity& operator=(const ComponentIntegrity&) = delete;
    ComponentIntegrity(ComponentIntegrity&&) = delete;
    ComponentIntegrity& operator=(ComponentIntegrity&&) = delete;

    /**
     * @brief Construct a new ComponentIntegrity from a bus reference
     * @param ctx Async context for D-Bus operations
     * @param path Object path for this component
     */
    ComponentIntegrity(sdbusplus::async::context& ctx,
                       const std::string& path) :
        sdbusplus::aserver::xyz::openbmc_project::attestation::
            ComponentIntegrity<ComponentIntegrity, void>(ctx, path.c_str()),
        sdbusplus::aserver::xyz::openbmc_project::attestation::MeasurementSet<
            ComponentIntegrity, void>(ctx, path.c_str()),
        sdbusplus::aserver::xyz::openbmc_project::attestation::
            IdentityAuthentication<ComponentIntegrity, void>(ctx, path.c_str()),
        path(path), asyncCtx(ctx)
    {
        initializeProperties();
    }

    /**
     * @brief Virtual destructor
     */
    virtual ~ComponentIntegrity() = default;

    /**
     * @brief Set the SPDM transport reference
     * @param transport SPDM transport instance
     */
    void setTransport(std::shared_ptr<spdm::SpdmTransport> transportIn)
    {
        transport = transportIn;
    }

    /**
     * @brief Request stop of the async context
     */
    void stopAsyncContext()
    {
        asyncCtx.request_stop();
    }

    /**
     * @brief Update the last updated timestamp
     */
    void updateLastUpdateTime()
    {
        last_updated(std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count());
    }
    /**
     * @brief Get signed measurements from SPDM device
     * @param measurementIndices Array of measurement indices to sign
     * @param nonce 32-byte hex-encoded nonce string
     * @param slotId Certificate slot ID
     * @return Async task containing tuple with:
     *         - Certificate path
     *         - Hashing algorithm string
     *         - Public key PEM string
     *         - Signed measurements base64 string
     *         - Signing algorithm string
     *         - Version string
     * @throws xyz::openbmc_project::Common::Error::InvalidArgument on invalid
     * input
     * @throws xyz::openbmc_project::Common::Error::InternalFailure on errors
     */
    auto method_call(spdm_get_signed_measurements_t,
                     std::vector<size_t> measurementIndices, std::string nonce,
                     size_t slotId [[maybe_unused]])
        -> sdbusplus::async::task<spdm_get_signed_measurements_t::return_type>;

    /** @brief Object path for this component */
    std::string path;

  protected:
    /**
     * @brief Validate measurement indices
     * @param measurementIndices Vector of measurement indices to validate
     * @throws InvalidArgument if any index is invalid
     */
    void validateMeasurementIndices(
        const std::vector<size_t>& measurementIndices);

    /**
     * @brief Initialize SPDM connection
     * @throws std::runtime_error if initialization fails
     */
    void initializeSpdmConnection();

    /**
     * @brief Get certificate digests from SPDM device
     * @return Tuple of (slotMask, digestBuffer, totalDigestSize)
     */
    std::tuple<uint8_t, std::vector<uint8_t>, size_t> getCertificateDigests();

    /**
     * @brief Get certificate from SPDM device
     * @param slotId Certificate slot ID
     * @return Tuple of (certificate, certificateSize, leaf certificate)
     */
    std::tuple<std::string, std::vector<uint8_t>, std::vector<uint8_t>>
        getCertificate(size_t slotId);

    /**
     * @brief Helper to convert DER certificate(s) to PEM string(s).
     * @param derCerts Vector of DER-encoded certificate bytes.
     * @return std::string PEM-encoded certificate chain and the last (leaf)
     * certificate.
     */
    std::tuple<std::string, std::vector<uint8_t>> derCertsToPem(
        const std::vector<uint8_t>& derCerts);

    /**
     * @brief Convert hashing algorithm to string representation
     * @param algo Algorithm enumeration value
     * @return String representation of algorithm
     */
    std::string getHashingAlgorithmStr(uint16_t algo);

    /**
     * @brief Convert signing algorithm to string representation
     * @param algo Algorithm enumeration value
     * @return String representation of algorithm
     */
    std::string getSigningAlgorithmStr(uint16_t algo);

    /**
     * @brief Update certificate object
     * @param chassisId Chassis ID
     * @param certPem PEM-encoded certificate chain
     * @param leafCert Leaf certificate
     * @return Object path of the certificate object
     */
    std::string updateCertificateObject(const std::string& chassisId,
                                        const std::string& certPem,
                                        const std::vector<uint8_t>& leafCert);

  private:
    std::shared_ptr<spdm::SpdmTransport> transport;

    /** @brief Async context for D-Bus operations */
    sdbusplus::async::context& asyncCtx;

    /**
     * @brief Initialize ComponentIntegrity properties
     * @details Sets initial values for all ComponentIntegrity interface
     * properties
     */
    void initializeProperties();

    // Friend declaration for testing
    friend class spdm::test::ComponentIntegrityTest;

    /** @brief Certificate object */
    std::shared_ptr<Certificate> certificateObject = nullptr;
};

} // namespace spdm
