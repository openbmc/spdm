// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "policy_manager.hpp"

#include <systemd/sd-bus-protocol.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/fdio.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/server.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <variant>
#include <vector>

constexpr auto policyVersionID = "Version";
constexpr unsigned int policyVersion = 1;

namespace
{
using Policy = spdm::Policy;
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
        j = {
            {policyVersionID, policyVersion},
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
        size_t version = j.at(policyVersionID);
        if (version != policyVersion)
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

namespace spdm
{

PolicyManagerBase::PolicyManagerBase(std::filesystem::path&& cachePath) :
    cachePath(std::move(cachePath))
{}

PolicyManagerBase::~PolicyManagerBase() = default;

void PolicyManagerBase::save(const Policy::properties_t& properties)
{
    const auto tempPath = cachePath.string() + ".temp";

    std::filesystem::create_directories(cachePath.parent_path());

    auto config = nlohmann::json(properties);

    std::ofstream file(tempPath);
    file << config.dump(4);
    file.close();

    std::error_code err;
    std::filesystem::rename(tempPath, cachePath, err);
    if (err)
    {
        std::filesystem::remove(tempPath);
        throw std::system_error(err, "failed to save policy cache file");
    }
}

auto PolicyManagerBase::load() -> Policy::properties_t
{
    PHOSPHOR_LOG2_USING;

    if (!std::filesystem::exists(cachePath))
    {
        return {};
    }
    std::ifstream file(cachePath);
    if (!file.is_open())
    {
        return {};
    }

    nlohmann::json config;
    try
    {
        config = nlohmann::json::parse(file);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        error("Failed to parse policy file, error: {ERROR}", "ERROR", e);
        std::filesystem::remove(cachePath);
        return {};
    }

    Policy::properties_t properties;
    config.get_to(properties);
    return properties;
}

} // namespace spdm
