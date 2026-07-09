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

using CommonPolicy =
    sdbusplus::common::xyz::openbmc_project::control::security::spdm::Policy;
using PolicyClient =
    sdbusplus::client::xyz::openbmc_project::control::security::spdm::Policy<>;
using Selection = std::variant<PolicyClient::SpecialSetValues, std::string>;

using namespace spdm;

struct PropertyObserver
{
    bool enabledValue = false;
    int enabledCount = 0;
    bool sessionValue = false;
    int sessionCount = 0;
    bool certValue = false;
    int certCount = 0;
    int allowedCount = 0;

    void on_update(CommonPolicy::enabled_t, bool value)
    {
        enabledValue = value;
        ++enabledCount;
    }

    void on_update(CommonPolicy::secure_session_enabled_t, bool value)
    {
        sessionValue = value;
        ++sessionCount;
    }

    void on_update(CommonPolicy::verify_certificate_t, bool value)
    {
        certValue = value;
        ++certCount;
    }

    void on_update(CommonPolicy::allowed_versions_t, auto&&)
    {
        ++allowedCount;
    }
};

class PolicyManagerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ctx = std::make_unique<sdbusplus::async::context>();

        auto testPrefix = std::format(
            "spdm_test_{}_{}",
            ::testing::UnitTest::GetInstance()->current_test_info()->name(),
            std::this_thread::get_id());

        cachePath = std::filesystem::path("/tmp") / testPrefix;

        std::error_code ec;
        std::filesystem::remove(cachePath, ec);

        managerPath = std::format("/xyz/openbmc_project/spdm/{}", testPrefix),

        manager = std::make_unique<PolicyManager<PropertyObserver>>(
            *ctx, managerPath, cachePath);

        serviceName =
            std::format("xyz.openbmc_project.spdm.test.{}", testPrefix);

        ctx->request_name(serviceName.c_str());
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove(cachePath, ec);

        manager.reset();
        ctx.reset();
    }

    auto readCacheJson() const -> nlohmann::json
    {
        std::ifstream file(cachePath);
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
        return PolicyClient(*ctx).service(serviceName).path(managerPath);
    }

    std::filesystem::path cachePath;
    std::unique_ptr<sdbusplus::async::context> ctx;
    std::string serviceName;

    std::string managerPath;
    std::unique_ptr<PolicyManager<PropertyObserver>> manager;
};

TEST_F(PolicyManagerTest, UnchangedEnabledDoesNotPersistOrInvokeCallback)
{
    ctx->spawn([](auto self) -> sdbusplus::async::task<> {
        co_await self->client().enabled(co_await self->client().enabled());
        EXPECT_FALSE(std::filesystem::exists(self->cachePath));
        EXPECT_EQ(self->manager->enabledCount, 0);
    }(this));

    run();
}

TEST_F(PolicyManagerTest, EnabledChangePersistsAndInvokesCallback)
{
    ctx->spawn([](auto self) -> sdbusplus::async::task<> {
        auto change = !co_await self->client().enabled();
        co_await self->client().enabled(change);
        EXPECT_EQ(self->manager->enabledCount, 1);
        EXPECT_EQ(self->manager->enabledValue, change);

        const auto cache = self->readCacheJson();
        EXPECT_EQ(cache.at(PolicyClient::enabled_t::name).template get<bool>(),
                  change);
    }(this));

    run();
}

TEST_F(PolicyManagerTest, SecureSessionChangePersistsAndInvokesCallback)
{
    ctx->spawn([](auto self) -> sdbusplus::async::task<> {
        auto change = !co_await self->client().secure_session_enabled();
        co_await self->client().secure_session_enabled(change);
        EXPECT_EQ(self->manager->sessionCount, 1);
        EXPECT_TRUE(self->manager->sessionValue);

        const auto cache = self->readCacheJson();
        EXPECT_EQ(cache.at(PolicyClient::secure_session_enabled_t::name)
                      .template get<bool>(),
                  change);
    }(this));

    run();
}

TEST_F(PolicyManagerTest, VerifyCertificateChangePersistsAndInvokesCallback)
{
    ctx->spawn([](auto self) -> sdbusplus::async::task<> {
        auto change = !co_await self->client().verify_certificate();
        co_await self->client().verify_certificate(change);
        EXPECT_EQ(self->manager->certCount, 1);
        EXPECT_EQ(self->manager->certValue, change);

        const auto cache = self->readCacheJson();
        EXPECT_EQ(cache.at(PolicyClient::verify_certificate_t::name)
                      .template get<bool>(),
                  change);
    }(this));

    run();
}

TEST_F(PolicyManagerTest, AllowedVersionsPersistSelectionsAndSkipDuplicateWrite)
{
    ctx->spawn([](auto self) -> sdbusplus::async::task<> {
        const std::vector<Selection> versions{
            PolicyClient::SpecialSetValues::ALL,
            std::string{"1.3"},
        };

        co_await self->client().allowed_versions(versions);

        const auto cache = self->readCacheJson();
        const auto& jsonVersions =
            cache.at(PolicyClient::allowed_versions_t::name);
        EXPECT_TRUE(jsonVersions.is_array());
        EXPECT_EQ(jsonVersions.size(), 2);
        EXPECT_EQ(
            jsonVersions.at(0).template get<std::string>(),
            "xyz.openbmc_project.Control.Security.SPDM.Policy.SpecialSetValues.ALL");
        EXPECT_EQ(jsonVersions.at(1).template get<std::string>(), "1.3");
        EXPECT_EQ(self->manager->allowedCount, 1);

        co_await self->client().allowed_versions(versions);
        EXPECT_EQ(self->manager->allowedCount, 1);
    }(this));

    run();
}
