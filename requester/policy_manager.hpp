// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/aserver.hpp>

#include <filesystem>
#include <functional>
#include <utility>

class PolicyManager :
    public sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
        Policy<PolicyManager>
{
  public:
    explicit PolicyManager(sdbusplus::async::context& ctx, auto path,
                           std::filesystem::path cache_path = {}) :
        sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
            Policy<PolicyManager>(ctx, path),
        cache_path_(std::move(cache_path))
    {
        PHOSPHOR_LOG2_USING;

        load();
    }

    virtual ~PolicyManager() = default;

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

    auto set_property(verify_certificate_t, auto verify_certificate) -> bool
    {
        return update_property(verify_certificate_, verify_certificate,
                               verify_certificate_callback_);
    }

    auto set_property(allow_extended_algorithms_t,
                      auto allow_extended_algorithms) -> bool
    {
        return update_property(allow_extended_algorithms_,
                               allow_extended_algorithms,
                               allow_extended_algorithms_callback_);
    }

    auto set_property(allowed_versions_t, auto allowed_versions) -> bool
    {
        return update_property(allowed_versions_, allowed_versions);
    }

    auto set_property(allowed_algorithms_aead_t, auto allowed_algorithms_aead)
        -> bool
    {
        return update_property(allowed_algorithms_aead_,
                               allowed_algorithms_aead);
    }

    auto set_property(allowed_algorithms_base_hash_t,
                      auto allowed_algorithms_base_hash) -> bool
    {
        return update_property(allowed_algorithms_base_hash_,
                               allowed_algorithms_base_hash);
    }

    auto set_property(allowed_algorithms_base_asym_t,
                      auto allowed_algorithms_base_asym) -> bool
    {
        return update_property(allowed_algorithms_base_asym_,
                               allowed_algorithms_base_asym);
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

    template <typename F>
        requires std::invocable<F, bool>
    auto on_verify_certificate(F&& callback) -> void
    {
        verify_certificate_callback_ = std::forward<F>(callback);
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

    auto dump() -> void;

    auto load() -> void;

    auto unmarshal_config(const nlohmann::json& config) -> void;

    auto marshal_config() -> nlohmann::json;

    std::function<void(bool)> enabled_callback_{nullptr};
    std::function<void(bool)> secure_session_enabled_callback_{nullptr};
    std::function<void(bool)> verify_certificate_callback_{nullptr};
    std::function<void(bool)> allow_extended_algorithms_callback_{nullptr};
    std::filesystem::path cache_path_;
};
