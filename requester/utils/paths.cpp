// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "paths.hpp"

#include <config.hpp>

namespace
{

auto& state_dir()
{
    static auto dir = std::filesystem::path(SPDM_STATE_DIR);
    return dir;
}

} // namespace

namespace spdm::paths
{

void set_state_dir(std::filesystem::path dir)
{
    state_dir() = std::move(dir);
}

auto policy_cache() -> std::filesystem::path
{
    static const auto cache = state_dir() / "policy.json";
    return cache;
}

} // namespace spdm::paths
