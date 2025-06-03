#pragma once

#include "libspdm_transport.hpp"

#include <memory>
#include <string>

namespace spdm
{

/**
 * @brief Information about a discovered SPDM responder
 * @details Contains identification and connection information for an SPDM
 * device discovered during the discovery phase
 */
struct ResponderInfo
{
    std::string objectPath;
    uint8_t eid;
    std::string uuid;
    std::shared_ptr<spdm::SpdmTransport> transport;

    // Default constructor
    ResponderInfo() = default;

    // Constructor with parameters
    ResponderInfo(std::string path, uint8_t endpoint_id,
                  std::string device_uuid,
                  std::shared_ptr<spdm::SpdmTransport> trans) :
        objectPath(std::move(path)), eid(endpoint_id),
        uuid(std::move(device_uuid)), transport(std::move(trans))
    {}

    // Move constructor and assignment
    ResponderInfo(ResponderInfo&&) noexcept = default;
    ResponderInfo& operator=(ResponderInfo&&) noexcept = default;

    // Delete copy operations since we have shared_ptr members
    ResponderInfo(const ResponderInfo&) = delete;
    ResponderInfo& operator=(const ResponderInfo&) = delete;
};

} // namespace spdm
