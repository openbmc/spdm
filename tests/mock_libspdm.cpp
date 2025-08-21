// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

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
typedef size_t (*libspdm_get_hash_size_func_t)(uint32_t);

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

// Mock wrapper for libspdm_init_connection
extern "C" libspdm_return_t libspdm_init_connection(void* spdm_context,
                                                    bool get_version_only)
{
    if (g_mockDataValid && g_mockData.spdmContext == spdm_context)
    {
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
extern "C" void libspdm_deinit_context(void* spdm_context)
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
extern "C" libspdm_return_t libspdm_get_digest(
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
extern "C" libspdm_return_t libspdm_get_certificate(
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
extern "C" size_t libspdm_get_hash_size(uint32_t base_hash_algo)
{
    (void)base_hash_algo;
    // Always return 48 for the mock
    return 48;
}
