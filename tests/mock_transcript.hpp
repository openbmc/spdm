// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <cstdint>
#include <vector>

namespace spdm::test
{

/** @brief What the mocked libspdm calls write to the libspdm message log, and
 *         what spdmd passed to libspdm_get_measurement_ex(). */
struct MockTranscript
{
    /** @brief Negotiated version returned by libspdm_get_data(), in
     *         VersionNumberEntry form (0x1100 = 1.1, 0x1200 = 1.2). */
    uint16_t spdmVersion = 0x1100;
    /** @brief Logged by libspdm_init_connection() on success. */
    std::vector<uint8_t> vca;
    /** @brief Logged per GET_MEASUREMENTS exchange. */
    std::vector<uint8_t> request;
    std::vector<uint8_t> response;
    /** @brief Recorded per libspdm_get_measurement_ex() call. */
    std::vector<uint8_t> requestAttributes;
    std::vector<std::vector<uint8_t>> nonces;
};

/** @brief The transcript mock shared by mock_libspdm.cpp and the tests. */
MockTranscript& mockTranscript();

} // namespace spdm::test
