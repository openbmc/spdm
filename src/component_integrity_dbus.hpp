/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>

extern "C"
{
#include "industry_standard/spdm.h"
}

#include "xyz/openbmc_project/Attestation/ComponentIntegrity/server.hpp"
#include "xyz/openbmc_project/Attestation/IdentityAuthentication/server.hpp"
#include "xyz/openbmc_project/Attestation/MeasurementSet/server.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/server/object.hpp>

namespace spdm
{

/**
 * @brief Type alias for measurement data tuple
 * @details Contains index, type and value for a measurement
 */
using MeasurementTuple = std::tuple<uint8_t, uint8_t, std::vector<uint8_t>>;

/**
 * @class ComponentIntegrity
 * @brief SPDM Responder implementation with D-Bus interfaces
 * @details Implements ComponentIntegrity, IdentityAuthentication, and
 *          MeasurementSet interfaces for SPDM device management. This class
 *          handles device measurements, authentication, and integrity
 * verification.
 */
class ComponentIntegrity :
    public sdbusplus::server::object::object<
        sdbusplus::xyz::openbmc_project::Attestation::server::
            ComponentIntegrity,
        sdbusplus::xyz::openbmc_project::Attestation::server::
            IdentityAuthentication,
        sdbusplus::xyz::openbmc_project::Attestation::server::MeasurementSet>
{
  public:
    /** @brief Default constructor is deleted */
    ComponentIntegrity() = delete;

    /** @brief Copy constructor is deleted */
    ComponentIntegrity(const ComponentIntegrity&) = delete;

    /** @brief Assignment operator is deleted */
    ComponentIntegrity& operator=(const ComponentIntegrity&) = delete;

    /** @brief Move constructor is deleted */
    ComponentIntegrity(ComponentIntegrity&&) = delete;

    /** @brief Move assignment operator is deleted */
    ComponentIntegrity& operator=(ComponentIntegrity&&) = delete;

    /**
     * @brief Construct a new SPDM DBus Responder from a bus reference
     * @param bus D-Bus bus reference
     * @param path Object path for this responder
     */
    ComponentIntegrity(sdbusplus::bus::bus& bus, const std::string& path) :
        sdbusplus::server::object::object<
            sdbusplus::xyz::openbmc_project::Attestation::server::
                ComponentIntegrity,
            sdbusplus::xyz::openbmc_project::Attestation::server::
                IdentityAuthentication,
            sdbusplus::xyz::openbmc_project::Attestation::server::
                MeasurementSet>(
            bus, path.c_str(),
            sdbusplus::server::object::object<
                sdbusplus::xyz::openbmc_project::Attestation::server::
                    ComponentIntegrity,
                sdbusplus::xyz::openbmc_project::Attestation::server::
                    IdentityAuthentication,
                sdbusplus::xyz::openbmc_project::Attestation::server::
                    MeasurementSet>::action::defer_emit),
        m_path(path)
    {
        initializeProperties();
        initializeAuthProperties();
        initializeMeasurementProperties();
        emit_object_added();
    }
    /**
     * @brief Virtual destructor
     */
    virtual ~ComponentIntegrity() = default;

    /**
     * @brief Get signed measurements from SPDM device
     * @param measurementIndices Array of measurement indices to sign
     * @param nonce 32-byte hex-encoded nonce string
     * @param slotId Certificate slot ID
     * @return Tuple containing:
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
    std::tuple<sdbusplus::message::object_path, std::string, std::string,
               std::string, std::string, std::string>
        spdmGetSignedMeasurements(std::vector<size_t> measurementIndices,
                                  std::string nonce, size_t slotId) override;

    /**
     * @brief Update measurement set
     *
     * @param index Measurement index
     * @param type Measurement type
     * @param value Measurement value
     * @throws std::runtime_error on D-Bus errors
     */
    void updateMeasurementSet(uint8_t index, uint8_t type,
                              const std::vector<uint8_t>& value);

    /**
     * @brief Update all measurement sets
     *
     * @param measurements Vector of measurement tuples (index, type, value)
     * @throws std::runtime_error on D-Bus errors
     */
    void updateMeasurementSets(
        const std::vector<std::tuple<uint8_t, uint8_t, std::vector<uint8_t>>>&
            measurements);

  private:
    std::string m_path;
    spdm::SpdmTransport* m_transport{nullptr};
    // ComponentIntegrity properties
    /** @brief Security technology type */
    SecurityTechnologyType type{SecurityTechnologyType::SPDM};

    /** @brief Version string */
    std::string version;

    /** @brief Enabled status */
    bool enabled{true};

    /** @brief Last update timestamp */
    uint64_t lastUpdate{0};

    /** @brief Measurements hash */
    std::vector<uint8_t> measurementsHash;

    /** @brief Measurements signature */
    std::vector<uint8_t> measurementsSignature;

    // IdentityAuthentication properties
    /** @brief Verification status */
    VerificationStatus verificationStatus{VerificationStatus::Unknown};

    /** @brief Hashing algorithm */
    uint16_t hashAlgo{0};

    /** @brief Signing algorithm */
    uint16_t signAlgo{0};

    /** @brief Certificates */
    std::vector<std::tuple<uint8_t, std::string>> certificates;

    /** @brief Capabilities */
    uint32_t capabilities{0};

    // MeasurementSet properties
    /** @brief Measurements */
    std::vector<MeasurementTuple> measurements;

    /** @brief Nonce */
    std::vector<uint8_t> nonce;

    /**
     * @brief Initialize ComponentIntegrity properties
     * @details Sets initial values for all ComponentIntegrity interface
     * properties
     */
    void initializeProperties();

    /**
     * @brief Initialize IdentityAuthentication properties
     * @details Sets initial values for all IdentityAuthentication interface
     * properties
     */
    void initializeAuthProperties();

    /**
     * @brief Initialize MeasurementSet properties
     * @details Sets initial values for all MeasurementSet interface properties
     */
    void initializeMeasurementProperties();

    /**
     * @brief Update last measurement timestamp
     * @details Updates lastUpdate property with current system time
     */
    void updateLastUpdateTime();

    /**
     * @brief Convert hashing algorithm to string
     * @param algo Algorithm enumeration value
     * @return String representation of algorithm
     */
    static std::string getHashingAlgorithmStr(uint16_t algo);

    /**
     * @brief Convert signing algorithm to string
     * @param algo Algorithm enumeration value
     * @return String representation of algorithm
     */
    static std::string getSigningAlgorithmStr(uint16_t algo);
};

} // namespace spdm
