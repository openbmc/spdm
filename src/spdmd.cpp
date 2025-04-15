// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd_app.hpp"

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

// Main function must be in global namespace
int main()
{
    try
    {
        auto app = spdmd::SPDMDaemon();
        app.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e)
    {
        error("Fatal error: {ERROR}", "ERROR", e);
        return EXIT_FAILURE;
    }
}
