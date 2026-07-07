// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once
#define SDBUSPLUS_ASYNC_NEW_PROPERTY_MEMBERS

#include "utils/paths.hpp"

#include <nlohmann/json.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/aserver.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/common.hpp>

#include <filesystem>
#include <utility>

namespace spdm
{

using Policy =
    sdbusplus::common::xyz::openbmc_project::control::security::spdm::Policy;
template <typename T>
using PolicyServer =
    sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::Policy<
        T>;

struct NoObserver
{};

class PolicyManagerBase
{
  protected:
    explicit PolicyManagerBase(std::filesystem::path&& cachePath);
    ~PolicyManagerBase();

    void save(const Policy::properties_t& properties);
    auto load() -> Policy::properties_t;

    std::filesystem::path cachePath;
};

template <typename Observer = NoObserver>
class PolicyManager final :
    public PolicyServer<PolicyManager<Observer>>,
    private PolicyManagerBase,
    public Observer
{
  public:
    explicit PolicyManager(
        sdbusplus::async::context& ctx, auto path,
        std::filesystem::path cachePath = paths::policy_cache()) :
        PolicyServer<PolicyManager<Observer>>(ctx, path),
        PolicyManagerBase(std::move(cachePath))
    {
        auto properties = PolicyManagerBase::load();
        this->properties = std::move(properties);
    }

    auto set_property(Policy::enabled_t, auto&& value) -> bool
    {
        return update_property(Policy::enabled_t{}, this->properties.enabled,
                               std::forward<decltype(value)>(value));
    }

    auto set_property(Policy::secure_session_enabled_t, auto&& value) -> bool
    {
        return update_property(Policy::secure_session_enabled_t{},
                               this->properties.secure_session_enabled,
                               std::forward<decltype(value)>(value));
    }

    auto set_property(Policy::verify_certificate_t, auto&& value) -> bool
    {
        return update_property(Policy::verify_certificate_t{},
                               this->properties.verify_certificate,
                               std::forward<decltype(value)>(value));
    }

    auto set_property(Policy::allow_extended_algorithms_t, auto&& value) -> bool
    {
        return update_property(Policy::allow_extended_algorithms_t{},
                               this->properties.allow_extended_algorithms,
                               std::forward<decltype(value)>(value));
    }

    auto set_property(Policy::allowed_versions_t, auto&& value) -> bool
    {
        return update_property(Policy::allowed_versions_t{},
                               this->properties.allowed_versions,
                               std::forward<decltype(value)>(value));
    }

    auto set_property(Policy::allowed_algorithms_aead_t, auto&& value) -> bool
    {
        return update_property(Policy::allowed_algorithms_aead_t{},
                               this->properties.allowed_algorithms_aead,
                               std::forward<decltype(value)>(value));
    }

    auto set_property(Policy::allowed_algorithms_base_hash_t, auto&& value)
        -> bool
    {
        return update_property(Policy::allowed_algorithms_base_hash_t{},
                               this->properties.allowed_algorithms_base_hash,
                               std::forward<decltype(value)>(value));
    }

    auto set_property(Policy::allowed_algorithms_base_asym_t, auto&& value)
        -> bool
    {
        return update_property(Policy::allowed_algorithms_base_asym_t{},
                               this->properties.allowed_algorithms_base_asym,
                               std::forward<decltype(value)>(value));
    }

  private:
    template <typename Tag, typename T, typename U>
    auto update_property(Tag, T& current, U&& value) -> bool
    {
        if (current == value)
        {
            return false;
        }

        current = std::forward<U>(value);

        if constexpr (requires {
                          this->on_update(Tag{}, std::as_const(current));
                      })
        {
            this->on_update(Tag{}, std::as_const(current));
        }

        save(this->properties);
        return true;
    }
};

} // namespace spdm
