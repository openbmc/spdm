// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mock_transcript.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

// Include libspdm types
extern "C"
{
typedef uint32_t libspdm_return_t;
#define LIBSPDM_STATUS_SUCCESS 0
#define LIBSPDM_STATUS_INVALID_PARAMETER 1
}

// Function pointer types for libspdm functions
typedef libspdm_return_t (*libspdm_init_connection_func_t)(void*, bool);
typedef libspdm_return_t (*libspdm_get_digest_func_t)(void*, const uint32_t*,
                                                      uint8_t*, void*);
typedef void (*libspdm_deinit_context_func_t)(void*);
typedef libspdm_return_t (*libspdm_get_cert_func_t)(void*, const uint32_t*,
                                                    uint8_t, size_t*, void*);
typedef uint32_t (*libspdm_get_hash_size_func_t)(uint32_t);

// Global function pointers that can be redirected
static libspdm_init_connection_func_t g_libspdm_init_connection = nullptr;
static libspdm_get_digest_func_t g_libspdm_get_digest = nullptr;
static libspdm_get_cert_func_t g_libspdm_get_cert = nullptr;
static libspdm_deinit_context_func_t g_libspdm_deinit_context = nullptr;
static libspdm_get_hash_size_func_t g_libspdm_get_hash_size = nullptr;

// Mock data structure
struct MockSpdmData
{
    void* spdmContext = nullptr;
    libspdm_return_t initStatus = LIBSPDM_STATUS_SUCCESS;
    libspdm_return_t digestStatus = LIBSPDM_STATUS_SUCCESS;
    libspdm_return_t getCertStatus = LIBSPDM_STATUS_SUCCESS;
    uint8_t mockSlotMask = 0x01;
    uint8_t mockDigestBuffer[48] = {0xAA, 0xBB, 0xCC,
                                    0xDD}; // 48-byte digest, rest will be 0
    std::vector<uint8_t> mockCertChain = {};
};

// Global mock data (stored by value, not pointer)
static MockSpdmData g_mockData;
static bool g_mockDataValid = false;

// Function to set mock data
extern "C" void set_mock_spdm_data(MockSpdmData* data)
{
    if (data)
    {
        // Deep copy the data
        g_mockData = *data;
        g_mockDataValid = true;
    }
    else
    {
        g_mockDataValid = false;
    }
}

// Function to set the real libspdm function pointers
extern "C" void set_real_libspdm_functions(
    libspdm_init_connection_func_t init_func,
    libspdm_get_digest_func_t digest_func,
    libspdm_get_cert_func_t get_cert_func,
    libspdm_deinit_context_func_t deinit_func,
    libspdm_get_hash_size_func_t get_hash_size_func)
{
    g_libspdm_init_connection = init_func;
    g_libspdm_get_digest = digest_func;
    g_libspdm_get_cert = get_cert_func;
    g_libspdm_deinit_context = deinit_func;
    g_libspdm_get_hash_size = get_hash_size_func;
}

// Real libspdm message log functions; the mocks below write to the log the
// way libspdm does, so the tests see the transcript spdmd returns.
extern "C" void libspdm_append_msg_log(void* spdm_context, void* message,
                                       size_t message_size);

namespace spdm::test
{
MockTranscript& mockTranscript()
{
    static MockTranscript transcript;
    return transcript;
}
} // namespace spdm::test

static void appendToMessageLog(void* spdm_context, std::vector<uint8_t> bytes)
{
    if (!bytes.empty())
    {
        libspdm_append_msg_log(spdm_context, bytes.data(), bytes.size());
    }
}

// Mock wrapper for libspdm_init_connection
extern "C" libspdm_return_t __wrap_libspdm_init_connection(
    void* spdm_context, bool get_version_only)
{
    if (g_mockDataValid && g_mockData.spdmContext == spdm_context)
    {
        if (g_mockData.initStatus == LIBSPDM_STATUS_SUCCESS)
        {
            appendToMessageLog(spdm_context, spdm::test::mockTranscript().vca);
        }
        return g_mockData.initStatus;
    }

    // If no mock data or context doesn't match, call the real function
    if (g_libspdm_init_connection)
    {
        return g_libspdm_init_connection(spdm_context, get_version_only);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

// Mock wrapper for libspdm_deinit_context
extern "C" void __wrap_libspdm_deinit_context(void* spdm_context)
{
    (void)spdm_context; // Suppress unused parameter warning

    // For testing, we just ignore the call and don't do anything destructive
    // This prevents the segmentation fault when the destructor is called

    // If we had a real function pointer, we could call it here
    // if (g_libspdm_deinit_context)
    // {
    //     g_libspdm_deinit_context(spdm_context);
    // }
}

// Mock wrapper for libspdm_get_digest
extern "C" libspdm_return_t __wrap_libspdm_get_digest(
    void* spdm_context, const uint32_t* session_id, uint8_t* slot_mask,
    void* total_digest_buffer)
{
    if (g_mockDataValid && g_mockData.spdmContext == spdm_context)
    {
        if (slot_mask)
        {
            *slot_mask = g_mockData.mockSlotMask;
        }
        if (total_digest_buffer)
        {
            uint8_t* buffer = static_cast<uint8_t*>(total_digest_buffer);
            std::copy(g_mockData.mockDigestBuffer,
                      g_mockData.mockDigestBuffer + 48, buffer);
        }
        return g_mockData.digestStatus;
    }

    // If no mock data or context doesn't match, call the real function
    if (g_libspdm_get_digest)
    {
        return g_libspdm_get_digest(spdm_context, session_id, slot_mask,
                                    total_digest_buffer);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

// Mock wrapper for libspdm_get_certificate
extern "C" libspdm_return_t __wrap_libspdm_get_certificate(
    void* spdm_context, const uint32_t* session_id, uint8_t slot_id,
    size_t* cert_chain_size, void* cert_chain)
{
    (void)session_id; // Suppress unused parameter warning
    (void)slot_id;    // Suppress unused parameter warning

    if (g_mockDataValid && g_mockData.spdmContext == spdm_context)
    {
        if (cert_chain && cert_chain_size)
        {
            size_t to_copy =
                std::min(*cert_chain_size, g_mockData.mockCertChain.size());
            std::copy(g_mockData.mockCertChain.begin(),
                      g_mockData.mockCertChain.begin() + to_copy,
                      static_cast<uint8_t*>(cert_chain));
            *cert_chain_size = to_copy;
        }
        return g_mockData.getCertStatus;
    }

    // If no mock data or context doesn't match, call the real function
    if (g_libspdm_get_cert)
    {
        return g_libspdm_get_cert(spdm_context, session_id, slot_id,
                                  cert_chain_size, cert_chain);
    }
    return LIBSPDM_STATUS_SUCCESS;
}

// Mock wrapper for libspdm_get_hash_size
extern "C" uint32_t __wrap_libspdm_get_hash_size(uint32_t base_hash_algo)
{
    (void)base_hash_algo;
    // Always return 48 for the mock
    return 48;
}

// Mock wrapper for libspdm_get_data: only the negotiated SPDM version is
// requested by the code under test.
extern "C" libspdm_return_t __wrap_libspdm_get_data(
    void* spdm_context, uint32_t data_type, const void* parameter, void* data,
    size_t* data_size)
{
    (void)spdm_context;
    (void)data_type;
    (void)parameter;
    uint16_t version = spdm::test::mockTranscript().spdmVersion;
    if (data == nullptr || data_size == nullptr || *data_size < sizeof(version))
    {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    std::copy_n(reinterpret_cast<const uint8_t*>(&version), sizeof(version),
                static_cast<uint8_t*>(data));
    *data_size = sizeof(version);
    return LIBSPDM_STATUS_SUCCESS;
}

// Mock wrapper for libspdm_get_measurement_ex: record what spdmd asked for
// and log one GET_MEASUREMENTS request and MEASUREMENTS response.
extern "C" libspdm_return_t __wrap_libspdm_get_measurement_ex(
    void* spdm_context, const uint32_t* session_id, uint8_t request_attribute,
    uint8_t measurement_operation, uint8_t slot_id, uint8_t* content_changed,
    uint8_t* number_of_blocks, uint32_t* measurement_record_length,
    void* measurement_record, const void* requester_nonce_in,
    void* requester_nonce, void* responder_nonce, void* opaque_data,
    size_t* opaque_data_size)
{
    (void)session_id;
    (void)measurement_operation;
    (void)slot_id;
    (void)content_changed;
    (void)measurement_record;
    (void)requester_nonce;
    (void)responder_nonce;
    (void)opaque_data;
    (void)opaque_data_size;

    auto& transcript = spdm::test::mockTranscript();
    transcript.requestAttributes.push_back(request_attribute);
    const auto* nonce = static_cast<const uint8_t*>(requester_nonce_in);
    transcript.nonces.emplace_back();
    if (nonce != nullptr)
    {
        transcript.nonces.back().assign(nonce, nonce + 32);
    }

    appendToMessageLog(spdm_context, transcript.request);
    appendToMessageLog(spdm_context, transcript.response);

    if (number_of_blocks != nullptr)
    {
        *number_of_blocks = 1;
    }
    if (measurement_record_length != nullptr)
    {
        *measurement_record_length = 0;
    }
    return LIBSPDM_STATUS_SUCCESS;
}
