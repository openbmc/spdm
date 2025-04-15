// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include <xyz/openbmc_project/Attestation/ComponentIntegrity/common.hpp>

constexpr const char* objManagerPath = sdbusplus::common::xyz::openbmc_project::
    attestation::ComponentIntegrity::instance_path;
constexpr const char* dbusServiceName = "xyz.openbmc_project.spdm.requester";
