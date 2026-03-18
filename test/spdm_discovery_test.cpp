// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/spdm_discovery.hpp"

#include <gtest/gtest.h>

namespace spdm::test
{

class TestSPDMDiscovery : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Setup code will go here
    }

    void TearDown() override
    {
        // Teardown code will go here
    }
};

TEST_F(TestSPDMDiscovery, BasicTest)
{
    // Test cases will go here
}

} // namespace spdm::test
