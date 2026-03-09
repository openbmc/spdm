/**
 * @file policy_manager.hpp
 * @brief SPDM Policy D-Bus interface implementation
 * @details Implements the xyz.openbmc_project.Control.Security.SPDM.Policy
 *          D-Bus interface, providing a configurable framework for managing
 *          platform SPDM security policies with persistent configuration storage.
 */

#pragma once

#include <nlohmann/json.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/aserver.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/common.hpp>

#include <exception>
#include <expected>
#include <utility>

/**
 * @class PolicyManager
 * @brief Implementation of xyz.openbmc_project.Control.Security.SPDM.Policy D-Bus interface
 * 
 * @details Provides a configurable framework for managing platform SPDM security
 *          policies. Exposes D-Bus properties to control SPDM policy behavior as
 *          defined in the phosphor-dbus-interfaces (PDI) specification.
 * 
 *          Key features:
 *          - D-Bus interface for runtime policy configuration
 *          - Persistent storage of policy settings via JSON cache
 *          - Property-based control of SPDM security features
 *          - Integration with sdbusplus async framework
 * 
 * @note Configuration is persisted in JSON format at POLICY_CACHE_PATH.
 * 
 * @see http://github.com/openbmc/phosphor-dbus-interfaces/commit/0d84eaf4ea2ef3ac3eb09b6ac2d2b85fbebf9e85
 */
class PolicyManager :
    public sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
        Policy<PolicyManager>
{
  public:
    /**
     * @brief Constructs a PolicyManager instance
     * 
     * @param ctx Reference to the sdbusplus async context for D-Bus operations
     * @param path D-Bus object path where the Policy interface will be exposed
     * 
     * @details Initializes the PolicyManager and registers the
     *          xyz.openbmc_project.Control.Security.SPDM.Policy D-Bus interface
     *          at the specified object path, making SPDM policy properties
     *          accessible to D-Bus clients.
     */
    explicit PolicyManager(sdbusplus::async::context& ctx, auto path) :
        sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
            Policy<PolicyManager>(ctx, path)
    {}

    /**
     * @brief Persists SPDM policy configuration to cache file
     * 
     * @return std::expected<void, std::exception> Success or exception on failure
     * @retval void Successfully written configuration to cache
     * @retval std::exception Error occurred during file operations
     * 
     * @details Serializes the current SPDM policy configuration to JSON format
     *          and writes it to the cache file. Creates parent directories if
     *          needed. The JSON is formatted with 4-space indentation.
     * 
     * @throws std::system_error If directory creation or file write fails
     * 
     * @note Call after D-Bus property changes to ensure policy persistence
     *       across system reboots.
     */
    auto dump() -> std::expected<void, std::exception>;

    /**
     * @brief Loads SPDM policy configuration from persistent cache
     * 
     * @return std::expected<void, std::exception> Success or exception on failure
     * @retval void Successfully loaded and applied cached configuration
     * @retval std::exception Error occurred during file operations or parsing
     * 
     * @details Restores SPDM policy settings from the cache file if it exists.
     *          Parses the JSON content and applies the settings to D-Bus
     *          properties. Currently supports the "enabled" property as defined
     *          in the PDI specification.
     * 
     * @note If cache file doesn't exist (first boot), returns success with
     *       default policy values.
     * 
     * @see read_cache()
     */
    auto load() -> std::expected<void, std::exception>;

    /**
     * @brief Gets the SPDM enabled property value
     * 
     * @param enabled_t Type tag for the enabled property
     * @return bool Current enabled state
     * 
     * @details Returns the value of the Enabled D-Bus property, which controls
     *          whether SPDM security functionality is active on the platform.
     *          This property is defined in the PDI specification.
     */
    auto get_property(enabled_t) const
    {
        return enabled_;
    }

    /**
     * @brief Sets the SPDM enabled property value
     * 
     * @param enabled_t Type tag for the enabled property
     * @param enabled New enabled state to set
     * @return bool True if the value changed, false if it remained the same
     * 
     * @details Updates the Enabled D-Bus property value, controlling whether
     *          SPDM security functionality is active. Returns true if the value
     *          actually changed.
     * 
     * @note Call dump() after property changes to persist configuration.
     */
    auto set_property(enabled_t, auto enabled) -> bool
    {
        std::swap(enabled_, enabled);
        return enabled_ == enabled;
    }

    /**
     * @brief Gets the SecureSessionEnabled property value
     * 
     * @param secure_session_enabled_t Type tag for the secure session property
     * @return bool Current secure session enabled state
     * 
     * @details Returns the value of the SecureSessionEnabled D-Bus property,
     *          which controls whether SPDM secure sessions are enabled.
     *          This property is defined in the PDI specification.
     */
    auto get_property(secure_session_enabled_t) const
    {
        return secure_session_enabled_;
    }

    /**
     * @brief Sets the SecureSessionEnabled property value
     * 
     * @param secure_session_enabled_t Type tag for the secure session property
     * @param secure_session_enabled New secure session enabled state
     * @return bool True if the value changed, false if it remained the same
     * 
     * @details Updates the SecureSessionEnabled D-Bus property value. Returns
     *          true if the value actually changed.
     * 
     * @note Call dump() after property changes to persist configuration.
     */
    auto set_property(secure_session_enabled_t, auto secure_session_enabled)
    {
        std::swap(secure_session_enabled_, secure_session_enabled);
        return secure_session_enabled == secure_session_enabled_;
    }

  private:
    /** @brief JSON configuration storage
     *  @details Holds the current SPDM policy configuration in JSON format for
     *           runtime storage and serialization to/from the cache file.
     */
    nlohmann::json config;
    
    /** @brief Path to the policy cache file
     *  @details Filesystem path where SPDM policy configuration is persisted.
     *           Defined by the POLICY_CACHE_PATH macro at compile time.
     */
    const std::filesystem::path cache_path = POLICY_CACHE_PATH;

    /**
     * @brief Reads and parses the SPDM policy cache file
     * 
     * @return std::expected<void, std::exception> Success or exception on failure
     * @retval void Successfully read and parsed cache file
     * @retval std::exception Error occurred during file operations or JSON parsing
     * 
     * @details Internal helper that opens the cache file, parses its JSON content,
     *          and stores it in the config member. Used by load() to restore
     *          persisted SPDM policy configuration.
     * 
     * @throws std::system_error If file cannot be opened for reading
     * @throws nlohmann::json::exception If JSON parsing fails
     * 
     * @see load()
     */
    auto read_cache() -> std::expected<void, std::exception>;
};
