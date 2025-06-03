extern "C"
{
#include "internal/libspdm_common_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
#include "library/spdm_transport_mctp_lib.h"
}
#include <phosphor-logging/lg2.hpp>

#include <coroutine>
#include <future>
#include <iostream>
#include <memory>
#include <thread>

namespace requester
{

/** Coroutine wrapper **/
struct Coroutine
{
    struct promise_type
    {
        uint8_t data;
        bool detached = false;

        Coroutine get_return_object()
        {
            return Coroutine{
                std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        std::suspend_never initial_suspend()
        {
            return {};
        }

        auto final_suspend() noexcept
        {
            struct awaiter
            {
                bool await_ready() const noexcept
                {
                    return false;
                }
                void await_resume() const noexcept {}

                std::coroutine_handle<> await_suspend(
                    std::coroutine_handle<promise_type> h) noexcept
                {
                    if (h.promise().detached)
                        h.destroy();
                    return std::noop_coroutine();
                }
            };
            return awaiter{};
        }

        void unhandled_exception()
        {
            try
            {
                throw;
            }
            catch (const std::exception& e)
            {
                lg2::error("Caught exception:: {HANDLER_EXCEPTION}",
                           "HANDLER_EXCEPTION", e.what());
            }
        }

        void return_value(uint8_t value) noexcept
        {
            data = value;
        }
    };

    bool await_ready() const noexcept
    {
        return handle.done();
    }
    uint8_t await_resume() const noexcept
    {
        return handle.promise().data;
    }
    bool await_suspend(std::coroutine_handle<>)
    {
        return true;
    }

    void detach()
    {
        if (!handle)
            return;
        if (handle.done())
            handle.destroy();
        else
            handle.promise().detached = true;
        handle = nullptr;
    }

    mutable std::coroutine_handle<promise_type> handle;
};

} // namespace requester

// Task<T>: coroutine-friendly async wrapper

template <typename T>
struct Task
{
    struct Awaiter
    {
        std::shared_ptr<std::promise<T>> prom;
        std::shared_ptr<std::future<T>> fut;
        std::coroutine_handle<> handle;

        Awaiter(std::shared_ptr<std::promise<T>> p,
                std::shared_ptr<std::future<T>> f) :
            prom(std::move(p)), fut(std::move(f))
        {}

        bool await_ready() const noexcept
        {
            return fut->wait_for(std::chrono::seconds(0)) ==
                   std::future_status::ready;
        }

        void await_suspend(std::coroutine_handle<> h)
        {
            handle = h;
            std::thread([fut = fut, h]() mutable {
                try
                {
                    fut->wait();
                    if (!h.done())
                        h.resume();
                }
                catch (...)
                {
                    // log error if needed
                }
            }).detach();
        }

        T await_resume()
        {
            return fut->get();
        }
    };

    Task()
    {
        prom = std::make_shared<std::promise<T>>();
        fut = std::make_shared<std::future<T>>(prom->get_future());
    }

    Task(std::future<T>&& f)
    {
        prom = nullptr;
        fut = std::make_shared<std::future<T>>(std::move(f));
    }

    auto operator co_await()
    {
        return Awaiter{prom, fut};
    }

    T get()
    {
        return fut->get();
    }

    std::shared_ptr<std::promise<T>> prom;
    std::shared_ptr<std::future<T>> fut;
};

// Constants
constexpr size_t DIGEST_SIZE = 48; // Fixed size from SPDM trace

// Note: libspdm_return_t and libspdm_context_t are defined in libspdm headers

// Async version of libspdm_get_digest
inline Task<
    std::tuple<std::string, std::string, std::string, std::string, std::string>>
    get_digest_async(void* ctx, int slotID, const std::string& path)
{
    auto fut = std::async(std::launch::async, [=]() {
        auto initStatus = libspdm_init_connection(ctx, false);
        if (LIBSPDM_STATUS_IS_ERROR(initStatus))
        {
            std::cout << "Failed to initialize SPDM connection, status: 0x"
                      << std::hex << initStatus << std::dec << std::endl;
            lg2::error(
                "Failed to initialize SPDM connection, status: 0x{STATUS:x}",
                "STATUS", initStatus);
            throw std::runtime_error("SPDM connection initialization failed");
        }

        uint8_t slotMask = 0;
        std::array<uint8_t, 256> digestBuffer{};

        auto status = libspdm_get_digest(ctx, nullptr, &slotMask,
                                         digestBuffer.data());
        if (status != LIBSPDM_STATUS_SUCCESS)
        {
            std::cout << "libspdm_get_digest failed, status: 0x" << std::hex
                      << status << std::dec << std::endl;
            lg2::error("libspdm_get_digest failed, status: 0x{STATUS:X}",
                       "STATUS", status);
            return std::make_tuple(std::string(), std::string(), std::string(),
                                   std::string(), std::string());
        }

        size_t numSlots = __builtin_popcount(slotMask);
        size_t totalDigestSize = std::min(numSlots * DIGEST_SIZE,
                                          digestBuffer.size());

        std::cout << "libspdm_get_digest completed, slotMask: 0x" << std::hex
                  << static_cast<unsigned>(slotMask) << std::dec
                  << ", slots: " << numSlots << ", size: " << totalDigestSize
                  << std::endl;
        lg2::info(
            "libspdm_get_digest completed, slotMask: 0x{MASK:X}, slots: {SLOTS}, size: {SIZE}",
            "MASK", static_cast<unsigned>(slotMask), "SLOTS", numSlots, "SIZE",
            totalDigestSize);

        std::string signedMeas;
        return std::make_tuple(path, std::string("Test"),
                               std::string("public_key_pem"), signedMeas,
                               std::string("Test"));
    });
    return Task<std::tuple<std::string, std::string, std::string, std::string,
                           std::string>>(std::move(fut));
}

// Coroutine using Task and returning Coroutine
inline requester::Coroutine run_connection(void* ctx)
{
    auto digestResult =
        co_await get_digest_async(ctx, 1, "/xyz/openbmc_project/spdm/1");
    co_return 0;
}

// If we implement the GetMeasurement D-Bus API as an asynchronous call,
we can leverage coroutines to avoid blocking—even within the GetMeasurement API itself.
For example, in the approach shown in the launch function, 
the API can return immediately without waiting for the measurement to complete.

Once the coroutine finishes execution in the background, 
it can update the measurement data and set a status property accordingly.
Clients invoking this API can monitor the status property to determine the result
whether it succeeded or failed—and then read the updated measurement data.

inline void launch(void* ctx)
{
    auto c = run_connection(ctx);
    c.detach(); // non-blocking
}
