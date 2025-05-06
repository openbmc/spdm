// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "xyz/openbmc_project/Attestation/ComponentIntegrity/aserver.hpp"
#include "xyz/openbmc_project/Attestation/IdentityAuthentication/aserver.hpp"
#include "xyz/openbmc_project/Attestation/MeasurementSet/aserver.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/async/context.hpp>
#include <sdbusplus/async/server.hpp>
#include <sdbusplus/server/object.hpp>

#include <chrono>

namespace spdm
{

class ComponentIntegrity;

/** @brief One D-Bus server for the three attestation interfaces. */
using ComponentIntegrityServer = sdbusplus::async::server_t<
    ComponentIntegrity,
    sdbusplus::aserver::xyz::openbmc_project::attestation::ComponentIntegrity,
    sdbusplus::aserver::xyz::openbmc_project::attestation::MeasurementSet,
    sdbusplus::aserver::xyz::openbmc_project::attestation::
        IdentityAuthentication>;

/** @class ComponentIntegrity
 *  @brief OpenBMC ComponentIntegrity entry implementation.
 *  @details A concrete implementation of
 *    xyz.openbmc_project.Attestation.ComponentIntegrity DBus API
 *    xyz.openbmc_project.Attestation.IdentityAuthentication DBus API
 *    xyz.openbmc_project.Attestation.MeasurementSet DBus API
 */
class ComponentIntegrity : public ComponentIntegrityServer
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
        ComponentIntegrityServer(ctx, path.c_str(),
                                 sdbusplus::async::signal_action::defer_emit),
        path(path)
    {
        initializeProperties();
        emit_object_added();
    }

    /**
     * @brief Destructor
     */
    ~ComponentIntegrity() = default;

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
                     size_t slotId)
        -> sdbusplus::async::task<spdm_get_signed_measurements_t::return_type>;

  private:
    /** @brief Object path for this component */
    std::string path;

    /**
     * @brief Initialize ComponentIntegrity properties
     * @details Sets initial values for all ComponentIntegrity interface
     * properties
     */
    void initializeProperties();
};

} // namespace spdm
