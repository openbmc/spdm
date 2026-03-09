#include "policy_manager.hpp"

#include <systemd/sd-bus-protocol.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/async/fdio.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/server.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <system_error>

auto PolicyManager::load()
{
    PHOSPHOR_LOG2_USING;

    using Policy = sdbusplus::common::xyz::openbmc_project::control::security::
        spdm::Policy;

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
    }

    enabled_ = config.value(Policy::enabled_t::name, enabled_);
    secure_session_enabled_ = config.value(
        Policy::secure_session_enabled_t::name, secure_session_enabled_);
    verify_certificate_ =
        config.value(Policy::verify_certificate_t::name, verify_certificate_);
    allow_extended_algorithms_ = config.value(
        Policy::allow_extended_algorithms_t::name, allow_extended_algorithms_);
}

auto PolicyManager::dump()
{
    PHOSPHOR_LOG2_USING;

    using Policy = sdbusplus::common::xyz::openbmc_project::control::security::
        spdm::Policy;

    constexpr auto POLICY_CACHE_PATH_TEMP = POLICY_CACHE_PATH ".temp";

    std::filesystem::create_directories(
        std::filesystem::path(POLICY_CACHE_PATH).parent_path());

    nlohmann::json config = {
        {Policy::enabled_t::name, enabled_},
        {Policy::secure_session_enabled_t::name, secure_session_enabled_},
        {Policy::verify_certificate_t::name, verify_certificate_},
        {Policy::allow_extended_algorithms_t::name, allow_extended_algorithms_},
    };

    std::ofstream file(POLICY_CACHE_PATH_TEMP);

    file << config.dump(4);
    file.close();

    std::error_code err;
    std::filesystem::rename(POLICY_CACHE_PATH_TEMP, POLICY_CACHE_PATH, err);
    if (err) {
        std::filesystem::remove(POLICY_CACHE_PATH_TEMP);
    }

    return;
}
