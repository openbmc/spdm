// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/policy_manager.hpp"

#include <nlohmann/json.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/client.hpp>

#include <filesystem>
#include <format>
#include <fstream>
#include <thread>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using PolicyClient =
    sdbusplus::client::xyz::openbmc_project::control::security::spdm::Policy<>;
using Selection = std::variant<PolicyClient::SpecialSetValues, std::string>;

class PolicyManagerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ctx = std::make_unique<sdbusplus::async::context>();

        auto test_prefix = std::format(
            "spdm_test_{}_{}",
            ::testing::UnitTest::GetInstance()->current_test_info()->name(),
            std::this_thread::get_id());

        cache_path = std::filesystem::path("/tmp") / test_prefix;

        std::error_code ec;
        std::filesystem::remove(cache_path, ec);

        manager_path = std::format("/xyz/openbmc_project/spdm/{}", test_prefix),

        manager =
            std::make_unique<PolicyManager>(*ctx, manager_path, cache_path);

        service_name =
            std::format("xyz.openbmc_project.spdm.test.{}", test_prefix);

        ctx->request_name(service_name.c_str());
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove(cache_path, ec);

        manager.reset();
        ctx.reset();
    }

    auto readCacheJson() const -> nlohmann::json
    {
        std::ifstream file(cache_path);
        EXPECT_TRUE(file.is_open());
        return nlohmann::json::parse(file);
    }

    void run()
    {
        ctx->spawn(sdbusplus::async::execution::just() |
                   sdbusplus::async::execution::then([this]() {
                       ctx->request_stop();
                   }));
        ctx->run();
    }

    auto client()
    {
        return PolicyClient(*ctx).service(service_name).path(manager_path);
    }

    std::filesystem::path cache_path;
    std::unique_ptr<sdbusplus::async::context> ctx;
    std::string service_name;

    std::string manager_path;
    std::unique_ptr<PolicyManager> manager;
};

TEST_F(PolicyManagerTest, UnchangedEnabledDoesNotPersistOrInvokeCallback)
{
    bool callbackCalled = false;
    manager->on_enabled([&](bool) { callbackCalled = true; });

    ctx->spawn([this, &callbackCalled]() -> sdbusplus::async::task<> {
        co_await client().enabled(false);
        EXPECT_FALSE(std::filesystem::exists(cache_path));
        EXPECT_FALSE(callbackCalled);
    }());

    run();
}

TEST_F(PolicyManagerTest, EnabledChangePersistsAndInvokesCallback)
{
    bool callbackValue = false;
    int callbackCount = 0;
    manager->on_enabled([&](bool value) {
        callbackValue = value;
        ++callbackCount;
    });

    ctx->spawn(
        [this, &callbackValue, &callbackCount]() -> sdbusplus::async::task<> {
            co_await client().enabled(true);
            EXPECT_EQ(callbackCount, 1);
            EXPECT_TRUE(callbackValue);

            const auto cache = readCacheJson();
            EXPECT_TRUE(cache.at(PolicyClient::enabled_t::name).get<bool>());
        }());

    run();
}

TEST_F(PolicyManagerTest, SecureSessionChangePersistsAndInvokesCallback)
{
    bool callbackValue = false;
    int callbackCount = 0;
    manager->on_secure_session_enabled([&](bool value) {
        callbackValue = value;
        ++callbackCount;
    });

    ctx->spawn([this, &callbackValue,
                &callbackCount]() -> sdbusplus::async::task<> {
        co_await client().secure_session_enabled(true);
        EXPECT_EQ(callbackCount, 1);
        EXPECT_TRUE(callbackValue);

        const auto cache = readCacheJson();
        EXPECT_TRUE(
            cache.at(PolicyClient::secure_session_enabled_t::name).get<bool>());
    }());

    run();
}

TEST_F(PolicyManagerTest, VerifyCertificateChangePersistsAndInvokesCallback)
{
    bool callbackValue = false;
    int callbackCount = 0;
    manager->on_verify_certificate([&](bool value) {
        callbackValue = value;
        ++callbackCount;
    });

    ctx->spawn(
        [this, &callbackValue, &callbackCount]() -> sdbusplus::async::task<> {
            co_await client().verify_certificate(true);
            EXPECT_EQ(callbackCount, 1);
            EXPECT_TRUE(callbackValue);

            const auto cache = readCacheJson();
            EXPECT_TRUE(
                cache.at(PolicyClient::verify_certificate_t::name).get<bool>());
        }());

    run();
}

TEST_F(PolicyManagerTest, AllowedVersionsPersistSelectionsAndSkipDuplicateWrite)
{
    const std::vector<Selection> versions{
        PolicyClient::SpecialSetValues::ALL,
        std::string{"1.3"},
    };

    ctx->spawn([this, &versions]() -> sdbusplus::async::task<> {
        co_await client().allowed_versions(versions);

        const auto cache = readCacheJson();
        const auto& jsonVersions =
            cache.at(PolicyClient::allowed_versions_t::name);
        EXPECT_TRUE(jsonVersions.is_array());
        EXPECT_EQ(jsonVersions.size(), 2);
        EXPECT_EQ(
            jsonVersions.at(0).get<std::string>(),
            "xyz.openbmc_project.Control.Security.SPDM.Policy.SpecialSetValues.ALL");
        EXPECT_EQ(jsonVersions.at(1).get<std::string>(), "1.3");

        // TODO: Should check that we didn't write JSON twice.
        co_await client().allowed_versions(versions);
    }());

    run();
}

} // namespace
