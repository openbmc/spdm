// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <string>

namespace spdm
{

/**
 * Set the base directory holding the requester's private keys in the
 * spdm-emu sample-key layout (<dir>/<algoSubdir>/end_requester.key).
 *
 * Process-wide by design: libspdm_requester_data_sign is a free C callback
 * with no user-data pointer, and the key location is a property of the
 * image, not of an individual device.
 *
 * Defaults to /usr/share/spdm-emu.
 */
void setRequesterKeyBaseDir(std::string dir);

/** @brief Current requester private-key base directory. */
const std::string& requesterKeyBaseDir();

} // namespace spdm
