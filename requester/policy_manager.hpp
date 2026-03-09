#pragma once

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/aserver.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/common.hpp>

#include <expected>
#include <system_error>
#include <utility>

class PolicyManager :
    public sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
        Policy<PolicyManager>
{
  public:
    explicit PolicyManager(sdbusplus::async::context& ctx, auto path) :
        sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
            Policy<PolicyManager>(ctx, path)
    {
        PHOSPHOR_LOG2_USING;

        if (auto result = load(); !result)
        {
            warning("failed to load cached policy, falling back to default");
        }
    }

    auto dump() -> std::expected<void, std::error_code>;

    auto load() -> std::expected<void, std::error_code>;

    auto set_property(enabled_t, auto enabled) -> bool
    {
        return update_property(enabled_, enabled);
    }

    auto set_property(secure_session_enabled_t, auto secure_session_enabled)
        -> bool
    {
        return update_property(secure_session_enabled_, secure_session_enabled);
    }

  private:
    template <typename T, typename U, typename F = std::nullptr_t>
        requires std::assignable_from<T&, U> && std::equality_comparable<T> &&
                 (std::same_as<F, std::nullptr_t> ||
                  std::invocable<F, const T&>)
    auto update_property(T& current, U&& value, F&& f = nullptr) -> bool
    {
        PHOSPHOR_LOG2_USING;

        if (current == value)
        {
            return false;
        }

        current = std::forward<U>(value);

        if constexpr (!std::same_as<F, std::nullptr_t>)
        {
            std::invoke(std::forward<F>(f), std::as_const(current));
        }

        if (auto result = dump(); !result)
        {
            warning("failed to dump policy cache");
        }
        return true;
    }
};
