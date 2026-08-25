// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace spdm
{

/** Own ready responders and retry initialization while their endpoints exist.
 *
 * The factory returns nullptr on initialization failure. The scheduler must
 * defer its callback by the requested delay. Both run on the same event loop
 * as add() and remove().
 */
template <typename Responder>
class ResponderManager
{
  public:
    using Factory = std::function<std::unique_ptr<Responder>()>;
    using Retry = std::function<void()>;
    using Schedule = std::function<void(std::chrono::seconds, Retry)>;

    explicit ResponderManager(Schedule schedule) : schedule(std::move(schedule))
    {}

    ResponderManager(const ResponderManager&) = delete;
    ResponderManager& operator=(const ResponderManager&) = delete;
    ResponderManager(ResponderManager&&) = delete;
    ResponderManager& operator=(ResponderManager&&) = delete;

    ~ResponderManager()
    {
        for (auto& [path, state] : responders)
        {
            state->present = false;
        }
    }

    void add(const std::string& path, Factory factory)
    {
        if (responders.contains(path))
        {
            return;
        }
        auto state = std::make_shared<State>(std::move(factory), schedule);
        responders.emplace(path, state);
        initialize(std::move(state));
    }

    void remove(const std::string& path)
    {
        auto it = responders.find(path);
        if (it == responders.end())
        {
            return;
        }
        it->second->present = false;
        it->second->responder.reset();
        responders.erase(it);
    }

  private:
    struct State
    {
        State(Factory factory, Schedule schedule) :
            factory(std::move(factory)), schedule(std::move(schedule))
        {}

        Factory factory;
        Schedule schedule;
        std::unique_ptr<Responder> responder;
        std::chrono::seconds delay{1};
        bool present = true;
    };

    static void initialize(std::shared_ptr<State> state)
    {
        if (!state->present)
        {
            return;
        }

        auto responder = state->factory();
        if (!state->present)
        {
            return;
        }
        if (responder)
        {
            state->responder = std::move(responder);
            return;
        }

        const auto delay = state->delay;
        constexpr std::chrono::seconds maxDelay{30};
        state->delay = std::min(delay * 2, maxDelay);
        state->schedule(delay, [weak = std::weak_ptr<State>(state)] {
            if (auto pending = weak.lock())
            {
                initialize(std::move(pending));
            }
        });
    }

    Schedule schedule;
    std::map<std::string, std::shared_ptr<State>> responders;
};

} // namespace spdm
