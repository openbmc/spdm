#include "policy_manager.hpp"

#include <systemd/sd-bus-protocol.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/async/fdio.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/server.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <system_error>

auto PolicyManager::load() -> std::expected<void, std::error_code>
{
    PHOSPHOR_LOG2_USING;

    using Policy = sdbusplus::common::xyz::openbmc_project::control::security::
        spdm::Policy;

    nlohmann::json config;

    if (std::filesystem::exists(POLICY_CACHE_PATH))
    {
        std::ifstream file(POLICY_CACHE_PATH);
        if (!file.is_open())
        {
            return std::unexpected(
                std::error_code(errno, std::system_category()));
        }
        try
        {
            config = nlohmann::json::parse(file);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            error("Failed to parse policy file, error: {ERROR}", "ERROR",
                  e.what());
            return std::unexpected(
                std::make_error_code(std::errc::invalid_argument));
        }

        enabled_ = config.value(Policy::enabled_t::name, enabled_);
        secure_session_enabled_ = config.value(
            Policy::secure_session_enabled_t::name, secure_session_enabled_);
        verify_certificate_ = config.value(Policy::verify_certificate_t::name,
                                           verify_certificate_);
        allow_extended_algorithms_ =
            config.value(Policy::allow_extended_algorithms_t::name,
                         allow_extended_algorithms_);
    }

    return {};
}

auto PolicyManager::dump() -> std::expected<void, std::error_code>
{
    PHOSPHOR_LOG2_USING;

    using Policy = sdbusplus::common::xyz::openbmc_project::control::security::
        spdm::Policy;

    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(POLICY_CACHE_PATH).parent_path(), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }

    nlohmann::json config = {
        {Policy::enabled_t::name, enabled_},
        {Policy::secure_session_enabled_t::name, secure_session_enabled_},
        {Policy::verify_certificate_t::name, verify_certificate_},
        {Policy::allow_extended_algorithms_t::name, allow_extended_algorithms_},
    };

    std::ofstream file(POLICY_CACHE_PATH ".temp");
    if (!file.is_open())
    {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    file << config.dump(4);
    file.close();

    std::filesystem::rename(POLICY_CACHE_PATH ".temp", POLICY_CACHE_PATH, ec);
    if (ec)
    {
        return std::unexpected(ec);
    }

    return {};
}
