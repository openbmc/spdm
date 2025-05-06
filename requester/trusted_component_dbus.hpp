// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "xyz/openbmc_project/Inventory/Item/TrustedComponent/server.hpp"

#include <sdbusplus/async/context.hpp>
#include <sdbusplus/server/object.hpp>

namespace spdm
{
/**
 * @class TrustedComponent
 * @brief SPDM Responder implementation with D-Bus interfaces
 * @details Implements TrustedComponent interface for SPDM device management.
 */
class TrustedComponent :
    public sdbusplus::server::object::object<
        sdbusplus::xyz::openbmc_project::Inventory::Item::server::
            TrustedComponent>
{
  public:
    /** @brief Default constructor is deleted */
    TrustedComponent() = delete;

    /** @brief Copy constructor is deleted */
    TrustedComponent(const TrustedComponent&) = delete;

    /** @brief Assignment operator is deleted */
    TrustedComponent& operator=(const TrustedComponent&) = delete;

    /** @brief Move constructor is deleted */
    TrustedComponent(TrustedComponent&&) = delete;

    /** @brief Move assignment operator is deleted */
    TrustedComponent& operator=(TrustedComponent&&) = delete;

    /**
     * @brief Construct a new SPDM DBus Responder
     * @param ctx Async context for D-Bus operations
     * @param path Object path for this responder
     */
    TrustedComponent(sdbusplus::async::context& ctx, const std::string& path);

    /**
     * @brief Destructor
     */
    ~TrustedComponent() = default;

    /**
     * @brief Update trusted component type
     * @param type New trusted component type
     * @throws std::runtime_error on D-Bus errors
     */
    void updateTrustedComponentType(const std::string& type);

  private:
    /** @brief Object path for this component */
    std::string path;
};

} // namespace spdm
