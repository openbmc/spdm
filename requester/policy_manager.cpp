#include "policy_manager.hpp"
#include <systemd/sd-bus-protocol.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/async/fdio.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/server.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <system_error>

auto PolicyManager::load() -> std::expected<void, std::exception>
{
    if (std::filesystem::exists(cache_path))
    {
        if (const auto result = read_cache(); !result)
        {
            return std::unexpected(result.error());
        }

        for (auto& [key, value] : config.items())
        {
            if (key == "enabled")
            {
                set_property(enabled_t{}, value.get<bool>());
            }
        }
    }

    return {};
}

auto PolicyManager::dump() -> std::expected<void, std::exception>
{
    std::error_code ec;
    std::filesystem::create_directories(cache_path.parent_path(), ec);
    if (ec)
    {
        return std::unexpected(std::system_error(ec));
    }

    std::ofstream file(cache_path);
    if (!file.is_open())
    {
        return std::unexpected(
            std::system_error(errno, std::system_category()));
    }

    file << config.dump(4);
    file.close();

    return {};
}

auto PolicyManager::read_cache() -> std::expected<void, std::exception>
{
    std::ifstream file(cache_path);
    if (!file.is_open())
    {
        return std::unexpected(
            std::system_error(errno, std::system_category()));
    }
    config = nlohmann::json::parse(file);
    file.close();
    return {};
}
