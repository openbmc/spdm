#pragma once

#include <com/ibm/Attestation/SecureExchange/SecureExchange/aserver.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/context.hpp>

class SecureExchange :
    public sdbusplus::aserver::com::ibm::attestation::secure_exchange::
        SecureExchange<SecureExchange>
{
  public:
    explicit SecureExchange(sdbusplus::async::context& ctx, auto path) :
        sdbusplus::aserver::com::ibm::attestation::secure_exchange::
            SecureExchange<SecureExchange>(ctx, path)
    {}

    auto method_call(exchange_app_data_t) -> void
    {
        PHOSPHOR_LOG2_USING;

        debug("SecureExchange: start exchange app data");
    }
};
