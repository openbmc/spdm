// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

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

    /** @brief Async context for D-Bus operations */
    sdbusplus::async::context& asyncCtx;

  private:
    /**
     * @brief Initialize ComponentIntegrity properties
     * @details Sets initial values for all ComponentIntegrity interface
     * properties
     */
    void initializeProperties();
};

} // namespace spdm
