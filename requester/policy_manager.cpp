// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "policy_manager.hpp"

#include <systemd/sd-bus-protocol.h>

#include <config.hpp>
#include <nlohmann/json.hpp>
#include <sdbusplus/async/fdio.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/server.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <system_error>
#include <variant>
#include <vector>

namespace
{

using Policy =
    sdbusplus::common::xyz::openbmc_project::control::security::spdm::Policy;
using PolicySelection = std::variant<Policy::SpecialSetValues, std::string>;

template <typename T>
concept PolicySelectionRange =
    std::ranges::input_range<T> &&
    std::same_as<std::ranges::range_value_t<T>, PolicySelection>;

template <typename T>
auto to_json(const T& value) -> nlohmann::json
{
    if constexpr (std::same_as<T, PolicySelection>)
    {
        return std::visit(
            [](const auto& entry) -> nlohmann::json {
                using Entry = std::decay_t<decltype(entry)>;

                if constexpr (std::same_as<Entry, Policy::SpecialSetValues>)
                {
                    return Policy::convertSpecialSetValuesToString(entry);
                }
                else
                {
                    return entry;
                }
            },
            value);
    }
    else if constexpr (PolicySelectionRange<T>)
    {
        auto json = nlohmann::json::array();

        for (const auto& entry : value)
        {
            json.push_back(to_json(entry));
        }

        return json;
    }
}

template <typename T>
auto from_json(const nlohmann::json& value) -> T
{
    if constexpr (std::same_as<T, PolicySelection>)
    {
        const auto stringValue = value.get<std::string>();

        if (const auto enumValue =
                Policy::convertStringToSpecialSetValues(stringValue);
            enumValue.has_value())
        {
            return *enumValue;
        }

        return stringValue;
    }
    else if constexpr (PolicySelectionRange<T>)
    {
        T result{};

        if (!value.is_array())
        {
            return result;
        }

        if constexpr (requires(T v, std::size_t n) { v.reserve(n); })
        {
            result.reserve(value.size());
        }

        for (const auto& entry : value)
        {
            result.push_back(from_json<PolicySelection>(entry));
        }

        return result;
    }
}

} // namespace

auto PolicyManager::load() -> void
{
    PHOSPHOR_LOG2_USING;

    nlohmann::json config;

    if (!std::filesystem::exists(POLICY_CACHE_PATH))
    {
        return;
    }
    std::ifstream file(POLICY_CACHE_PATH);
    if (!file.is_open())
    {
        return;
    }
    try
    {
        config = nlohmann::json::parse(file);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        error("Failed to parse policy file, error: {ERROR}", "ERROR", e);
        std::filesystem::remove(POLICY_CACHE_PATH);
        return;
    }

    enabled_ = config.value(Policy::enabled_t::name, enabled_);
    secure_session_enabled_ = config.value(
        Policy::secure_session_enabled_t::name, secure_session_enabled_);
    verify_certificate_ =
        config.value(Policy::verify_certificate_t::name, verify_certificate_);
    allow_extended_algorithms_ = config.value(
        Policy::allow_extended_algorithms_t::name, allow_extended_algorithms_);

    if (config.contains(Policy::allowed_versions_t::name))
    {
        allowed_versions_ = from_json<decltype(allowed_versions_)>(
            config.at(Policy::allowed_versions_t::name));
    }
    if (config.contains(Policy::allowed_algorithms_aead_t::name))
    {
        allowed_algorithms_aead_ =
            from_json<decltype(allowed_algorithms_aead_)>(
                config.at(Policy::allowed_algorithms_aead_t::name));
    }
    if (config.contains(Policy::allowed_algorithms_base_hash_t::name))
    {
        allowed_algorithms_base_hash_ =
            from_json<decltype(allowed_algorithms_base_hash_)>(
                config.at(Policy::allowed_algorithms_base_hash_t::name));
    }
    if (config.contains(Policy::allowed_algorithms_base_asym_t::name))
    {
        allowed_algorithms_base_asym_ =
            from_json<decltype(allowed_algorithms_base_asym_)>(
                config.at(Policy::allowed_algorithms_base_asym_t::name));
    }
}

auto PolicyManager::dump() -> void
{
    PHOSPHOR_LOG2_USING;

    constexpr auto POLICY_CACHE_PATH_TEMP = POLICY_CACHE_PATH ".temp";

    std::filesystem::create_directories(
        std::filesystem::path(POLICY_CACHE_PATH).parent_path());

    auto config = nlohmann::json{
        {Policy::enabled_t::name, enabled_},
        {Policy::secure_session_enabled_t::name, secure_session_enabled_},
        {Policy::verify_certificate_t::name, verify_certificate_},
        {Policy::allow_extended_algorithms_t::name, allow_extended_algorithms_},
        {Policy::allowed_versions_t::name, to_json(allowed_versions_)},
        {Policy::allowed_algorithms_aead_t::name,
         to_json(allowed_algorithms_aead_)},
        {Policy::allowed_algorithms_base_hash_t::name,
         to_json(allowed_algorithms_base_hash_)},
        {Policy::allowed_algorithms_base_asym_t::name,
         to_json(allowed_algorithms_base_asym_)},
    };

    std::ofstream file(POLICY_CACHE_PATH_TEMP);

    file << config.dump(4);
    file.close();

    std::error_code err;
    std::filesystem::rename(POLICY_CACHE_PATH_TEMP, POLICY_CACHE_PATH, err);
    if (err)
    {
        std::filesystem::remove(POLICY_CACHE_PATH_TEMP);
    }

    return;
}
