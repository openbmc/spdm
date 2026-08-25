// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "responder_manager.hpp"

#include <chrono>
#include <deque>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace spdm::test
{
namespace
{
using namespace std::chrono_literals;

struct TestResponder
{
    explicit TestResponder(int& live) : live(live)
    {
        ++live;
    }

    ~TestResponder()
    {
        --live;
    }

    int& live;
};

using Manager = ResponderManager<TestResponder>;

struct Timer
{
    std::chrono::seconds delay;
    Manager::Retry retry;
};

class ResponderManagerTest : public ::testing::Test
{
  protected:
    ResponderManagerTest() :
        manager([this](std::chrono::seconds delay, Manager::Retry retry) {
            timers.push_back({delay, std::move(retry)});
        })
    {}

    Manager::Factory factory(int failures, int device = 1)
    {
        return [this, failures, device]() mutable {
            attempts.push_back(device);
            if (failures > 0)
            {
                --failures;
                return std::unique_ptr<TestResponder>{};
            }
            return std::make_unique<TestResponder>(live);
        };
    }

    void fireNext()
    {
        ASSERT_FALSE(timers.empty());
        auto retry = std::move(timers.front().retry);
        timers.pop_front();
        retry();
    }

    std::deque<Timer> timers;
    std::vector<int> attempts;
    int live = 0;
    Manager manager;
};

TEST_F(ResponderManagerTest, ImmediateSuccessNeedsNoRetry)
{
    manager.add("/endpoint/1", factory(0));

    EXPECT_EQ(attempts, (std::vector<int>{1}));
    EXPECT_EQ(live, 1);
    EXPECT_TRUE(timers.empty());

    manager.remove("/endpoint/1");
    EXPECT_EQ(live, 0);
}

TEST_F(ResponderManagerTest, FailedInitializationRetriesUntilSuccess)
{
    manager.add("/endpoint/1", factory(2));
    ASSERT_EQ(timers.size(), 1U);
    EXPECT_EQ(timers.front().delay, 1s);
    EXPECT_EQ(live, 0);

    fireNext();
    ASSERT_EQ(timers.size(), 1U);
    EXPECT_EQ(timers.front().delay, 2s);
    EXPECT_EQ(live, 0);

    fireNext();
    EXPECT_EQ(attempts, (std::vector<int>{1, 1, 1}));
    EXPECT_EQ(live, 1);
    EXPECT_TRUE(timers.empty());
}

TEST_F(ResponderManagerTest, RetryBackoffStopsGrowingAtThirtySeconds)
{
    manager.add("/endpoint/1", factory(100));

    for (auto expected : {1s, 2s, 4s, 8s, 16s, 30s, 30s})
    {
        ASSERT_EQ(timers.size(), 1U);
        EXPECT_EQ(timers.front().delay, expected);
        fireNext();
    }
    EXPECT_EQ(live, 0);
    EXPECT_EQ(attempts.size(), 8U);
    EXPECT_EQ(timers.size(), 1U);
}

TEST_F(ResponderManagerTest, RemovalInvalidatesPendingRetry)
{
    manager.add("/endpoint/1", factory(1));
    manager.remove("/endpoint/1");
    fireNext();

    EXPECT_EQ(attempts, (std::vector<int>{1}));
    EXPECT_EQ(live, 0);
    EXPECT_TRUE(timers.empty());
}

TEST_F(ResponderManagerTest, OldRetryCannotReviveRediscoveredEndpoint)
{
    manager.add("/endpoint/1", factory(1, 1));
    manager.remove("/endpoint/1");
    manager.add("/endpoint/1", factory(0, 2));
    fireNext();

    EXPECT_EQ(attempts, (std::vector<int>{1, 2}));
    EXPECT_EQ(live, 1);
    EXPECT_TRUE(timers.empty());
}

TEST_F(ResponderManagerTest, DuplicateAddsDoNotCreateAnotherRetryOrResponder)
{
    manager.add("/endpoint/1", factory(1, 1));
    manager.add("/endpoint/1", factory(0, 2));
    ASSERT_EQ(timers.size(), 1U);
    EXPECT_EQ(attempts, (std::vector<int>{1}));

    fireNext();
    manager.add("/endpoint/1", factory(0, 3));

    EXPECT_EQ(attempts, (std::vector<int>{1, 1}));
    EXPECT_EQ(live, 1);
    EXPECT_TRUE(timers.empty());
}

TEST_F(ResponderManagerTest, OnePendingEndpointDoesNotBlockAnother)
{
    manager.add("/endpoint/1", factory(1, 1));
    manager.add("/endpoint/2", factory(0, 2));
    EXPECT_EQ(live, 1);

    fireNext();

    EXPECT_EQ(attempts, (std::vector<int>{1, 2, 1}));
    EXPECT_EQ(live, 2);
    manager.remove("/endpoint/1");
    EXPECT_EQ(live, 1);
}

TEST_F(ResponderManagerTest, DestructionInvalidatesPendingRetry)
{
    {
        Manager temporary(
            [this](std::chrono::seconds delay, Manager::Retry retry) {
                timers.push_back({delay, std::move(retry)});
            });
        temporary.add("/endpoint/1", factory(1));
    }
    fireNext();

    EXPECT_EQ(attempts, (std::vector<int>{1}));
    EXPECT_EQ(live, 0);
    EXPECT_TRUE(timers.empty());
}

TEST_F(ResponderManagerTest, RemovalDuringInitializationDiscardsResponder)
{
    manager.add("/endpoint/1", [this] {
        manager.remove("/endpoint/1");
        return std::make_unique<TestResponder>(live);
    });

    EXPECT_EQ(live, 0);
    EXPECT_TRUE(timers.empty());
}

TEST_F(ResponderManagerTest, RemovingUnknownPathDoesNotCancelOtherRetry)
{
    manager.add("/endpoint/1", factory(1));
    manager.remove("/endpoint/2");
    fireNext();

    EXPECT_EQ(attempts, (std::vector<int>{1, 1}));
    EXPECT_EQ(live, 1);
}

} // namespace
} // namespace spdm::test
