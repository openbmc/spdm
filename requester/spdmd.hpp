// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include <xyz/openbmc_project/Attestation/ComponentIntegrity/common.hpp>

constexpr auto objManagerPath = sdbusplus::common::xyz::openbmc_project::
    attestation::ComponentIntegrity::namespace_path;
constexpr auto dbusServiceName = "xyz.openbmc_project.spdm.requester";
