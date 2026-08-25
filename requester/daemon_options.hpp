// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_message_limits.hpp"

#include <CLI/CLI.hpp>

#include <cstddef>
#include <filesystem>

namespace spdm
{

struct DaemonOptions
{
    std::filesystem::path stateDir;
    size_t maxSpdmMessageSize = LIBSPDM_MAX_SPDM_MSG_SIZE;

    void addTo(CLI::App& app)
    {
        app.add_option("--state-dir", stateDir,
                       "Override the SPDM state directory");
        app.add_option("--max-spdm-message-size", maxSpdmMessageSize,
                       "Maximum raw SPDM message size in bytes")
            ->check(CLI::Range(size_t{SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12},
                               size_t{LIBSPDM_MAX_SPDM_MSG_SIZE}))
            ->capture_default_str();
    }
};

} // namespace spdm
