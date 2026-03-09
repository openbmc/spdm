// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/policy_manager.hpp"

#include <nlohmann/json.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/common.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using CommonPolicy =
    sdbusplus::common::xyz::openbmc_project::control::security::spdm::Policy;
using Selection = std::variant<CommonPolicy::SpecialSetValues, std::string>;

class PolicyManagerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        std::ostringstream oss;
        oss << "/tmp/spdm_test_cache_"
            << ::testing::UnitTest::GetInstance()->current_test_info()->name();
        test_cache_path_ = oss.str();

        std::error_code ec;
        std::filesystem::remove(test_cache_path_, ec);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove(test_cache_path_, ec);
    }

    auto readCacheJson() const -> nlohmann::json
    {
        std::ifstream file(test_cache_path_);
        EXPECT_TRUE(file.is_open());
        return nlohmann::json::parse(file);
    }

    std::filesystem::path test_cache_path_;
};

TEST_F(PolicyManagerTest, UnchangedEnabledDoesNotPersistOrInvokeCallback)
{
    sdbusplus::async::context ctx;
    PolicyManager manager(ctx, "/xyz/openbmc_project/spdm/test0",
                          test_cache_path_);

    bool callbackCalled = false;
    manager.on_enabled([&](bool) { callbackCalled = true; });

    EXPECT_FALSE(manager.set_property(CommonPolicy::enabled_t{}, false));
    EXPECT_FALSE(std::filesystem::exists(test_cache_path_));
    EXPECT_FALSE(callbackCalled);
}

TEST_F(PolicyManagerTest, EnabledChangePersistsAndInvokesCallback)
{
    sdbusplus::async::context ctx;
    PolicyManager manager(ctx, "/xyz/openbmc_project/spdm/test1",
                          test_cache_path_);

    bool callbackValue = false;
    int callbackCount = 0;
    manager.on_enabled([&](bool value) {
        callbackValue = value;
        ++callbackCount;
    });

    EXPECT_TRUE(manager.set_property(CommonPolicy::enabled_t{}, true));
    EXPECT_EQ(callbackCount, 1);
    EXPECT_TRUE(callbackValue);

    const auto cache = readCacheJson();
    EXPECT_TRUE(cache.at(CommonPolicy::enabled_t::name).get<bool>());
}

TEST_F(PolicyManagerTest, SecureSessionChangePersistsAndInvokesCallback)
{
    sdbusplus::async::context ctx;
    PolicyManager manager(ctx, "/xyz/openbmc_project/spdm/test2",
                          test_cache_path_);

    bool callbackValue = false;
    int callbackCount = 0;
    manager.on_secure_session_enabled([&](bool value) {
        callbackValue = value;
        ++callbackCount;
    });

    EXPECT_TRUE(
        manager.set_property(CommonPolicy::secure_session_enabled_t{}, true));
    EXPECT_EQ(callbackCount, 1);
    EXPECT_TRUE(callbackValue);

    const auto cache = readCacheJson();
    EXPECT_TRUE(
        cache.at(CommonPolicy::secure_session_enabled_t::name).get<bool>());
}

TEST_F(PolicyManagerTest, VerifyCertificateChangePersistsAndInvokesCallback)
{
    sdbusplus::async::context ctx;
    PolicyManager manager(ctx, "/xyz/openbmc_project/spdm/test3",
                          test_cache_path_);

    bool callbackValue = false;
    int callbackCount = 0;
    manager.on_verify_certificate([&](bool value) {
        callbackValue = value;
        ++callbackCount;
    });

    EXPECT_TRUE(
        manager.set_property(CommonPolicy::verify_certificate_t{}, true));
    EXPECT_EQ(callbackCount, 1);
    EXPECT_TRUE(callbackValue);

    const auto cache = readCacheJson();
    EXPECT_TRUE(cache.at(CommonPolicy::verify_certificate_t::name).get<bool>());
}

TEST_F(PolicyManagerTest, AllowedVersionsPersistSelectionsAndSkipDuplicateWrite)
{
    sdbusplus::async::context ctx;
    PolicyManager manager(ctx, "/xyz/openbmc_project/spdm/test4",
                          test_cache_path_);

    const std::vector<Selection> versions{
        CommonPolicy::SpecialSetValues::ALL,
        std::string{"1.3"},
    };

    EXPECT_TRUE(
        manager.set_property(CommonPolicy::allowed_versions_t{}, versions));

    const auto cache = readCacheJson();
    const auto& jsonVersions = cache.at(CommonPolicy::allowed_versions_t::name);
    ASSERT_TRUE(jsonVersions.is_array());
    ASSERT_EQ(jsonVersions.size(), 2);
    EXPECT_EQ(
        jsonVersions.at(0).get<std::string>(),
        "xyz.openbmc_project.Control.Security.SPDM.Policy.SpecialSetValues.ALL");
    EXPECT_EQ(jsonVersions.at(1).get<std::string>(), "1.3");

    EXPECT_FALSE(
        manager.set_property(CommonPolicy::allowed_versions_t{}, versions));
}

} // namespace
