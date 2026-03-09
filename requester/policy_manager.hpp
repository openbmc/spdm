// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/aserver.hpp>

#include <expected>
#include <functional>
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

        load();
    }

    auto dump() -> void;

    auto load() -> void;

    auto set_property(enabled_t, auto enabled) -> bool
    {
        return update_property(enabled_, enabled, enabled_callback_);
    }

    auto set_property(secure_session_enabled_t, auto secure_session_enabled)
        -> bool
    {
        return update_property(secure_session_enabled_, secure_session_enabled,
                               secure_session_enabled_callback_);
    }

    template <typename F>
        requires std::invocable<F, bool>
    auto on_enabled(F&& callback) -> void
    {
        enabled_callback_ = std::forward<F>(callback);
    }

    template <typename F>
        requires std::invocable<F, bool>
    auto on_secure_session_enabled(F&& callback) -> void
    {
        secure_session_enabled_callback_ = std::forward<F>(callback);
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

        dump();
        return true;
    }

    std::function<void(bool)> enabled_callback_{nullptr};
    std::function<void(bool)> secure_session_enabled_callback_{nullptr};
};
