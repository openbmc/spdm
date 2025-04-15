// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd_app.hpp"

#include <phosphor-logging/lg2.hpp>

// Main function must be in global namespace
int main()
{
    try
    {
        auto app = spdmd::SPDMDaemon();
        return app.run();
    }
    catch (const std::exception& e)
    {
        lg2::error("Fatal error: {ERROR}", "ERROR", e);
        return EXIT_FAILURE;
    }
}
