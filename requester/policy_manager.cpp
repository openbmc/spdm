// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "policy_manager.hpp"

#include <systemd/sd-bus-protocol.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/async/fdio.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/server.hpp>

#include <filesystem>
#include <fstream>
#include <system_error>
#include <variant>
#include <vector>

constexpr auto POLICY_VERSION_ID = "Version";
constexpr unsigned int POLICY_VERSION = 1;

namespace
{

using Policy =
    sdbusplus::common::xyz::openbmc_project::control::security::spdm::Policy;

using SelectionArray =
    std::vector<std::variant<Policy::SpecialSetValues, std::string>>;

} // namespace

namespace nlohmann
{

template <>
struct adl_serializer<SelectionArray::value_type>
{
    static void to_json(json& j, const SelectionArray::value_type& v)
    {
        std::visit(
            [&j](const auto& val) {
                if constexpr (requires {
                                  sdbusplus::message::convert_to_string(val);
                              })
                {
                    j = sdbusplus::message::convert_to_string(val);
                }
                else
                {
                    j = val;
                }
            },
            v);
    }

    static void from_json(const json& j, SelectionArray::value_type& v)
    {
        std::string s = j;
        if (auto opt = sdbusplus::message::convert_from_string<
                Policy::SpecialSetValues>(s);
            opt.has_value())
        {
            v = *opt;
        }
        else
        {
            v = std::move(s);
        }
    }
};

template <>
struct adl_serializer<Policy::properties_t>
{
    static void to_json(json& j, const Policy::properties_t& p)
    {
        j = nlohmann::json{
            {POLICY_VERSION_ID, POLICY_VERSION},
            {Policy::enabled_t::name, p.enabled},
            {Policy::secure_session_enabled_t::name, p.secure_session_enabled},
            {Policy::verify_certificate_t::name, p.verify_certificate},
            {Policy::allow_extended_algorithms_t::name,
             p.allow_extended_algorithms},
            {Policy::allowed_versions_t::name, p.allowed_versions},
            {Policy::allowed_algorithms_aead_t::name,
             p.allowed_algorithms_aead},
            {Policy::allowed_algorithms_base_hash_t::name,
             p.allowed_algorithms_base_hash},
            {Policy::allowed_algorithms_base_asym_t::name,
             p.allowed_algorithms_base_asym},
        };
    }

    static void from_json(const json& j, Policy::properties_t& p)
    {
        size_t version = j.at(POLICY_VERSION_ID);
        if (version != POLICY_VERSION)
        {
            p = Policy::properties_t{};
            return;
        }
        p.enabled = j.at(Policy::enabled_t::name);
        p.secure_session_enabled = j.at(Policy::secure_session_enabled_t::name);
        p.verify_certificate = j.at(Policy::verify_certificate_t::name);
        p.allow_extended_algorithms =
            j.at(Policy::allow_extended_algorithms_t::name);
        p.allowed_versions = j.at(Policy::allowed_versions_t::name);
        p.allowed_algorithms_aead =
            j.at(Policy::allowed_algorithms_aead_t::name);
        p.allowed_algorithms_base_hash =
            j.at(Policy::allowed_algorithms_base_hash_t::name);
        p.allowed_algorithms_base_asym =
            j.at(Policy::allowed_algorithms_base_asym_t::name);
    }
};

} // namespace nlohmann

void PolicyManager::load()
{
    PHOSPHOR_LOG2_USING;

    if (!std::filesystem::exists(cache_path))
    {
        return;
    }
    std::ifstream file(cache_path);
    if (!file.is_open())
    {
        return;
    }

    nlohmann::json config;
    try
    {
        config = nlohmann::json::parse(file);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        error("Failed to parse policy file, error: {ERROR}", "ERROR", e);
        std::filesystem::remove(cache_path);
        return;
    }

    config.get_to(properties);
}

void PolicyManager::save()
{
    const auto tempPath = cache_path.string() + ".temp";

    std::filesystem::create_directories(cache_path.parent_path());

    auto config = nlohmann::json(properties);

    std::ofstream file(tempPath);

    file << config.dump(4);
    file.close();

    std::error_code err;
    std::filesystem::rename(tempPath, cache_path, err);
    if (err)
    {
        std::filesystem::remove(tempPath);
        throw std::system_error(err, "failed to save policy cache file");
    }
}
