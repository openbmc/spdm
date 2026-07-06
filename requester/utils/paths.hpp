// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <filesystem>

namespace spdm::paths
{
auto policy_cache() -> std::filesystem::path;

void set_state_dir(std::filesystem::path dir);
} // namespace spdm::paths
