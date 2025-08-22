// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "certificate_dbus.hpp"

extern "C"
{
#include "internal/libspdm_common_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
}

#include <cstring>
#include <string>
#include <vector>

namespace spdm
{

Certificate::Certificate(sdbusplus::async::context& asyncCtx,
                         const std::string& path, const std::string& pemChain,
                         const std::vector<uint8_t>& leafCert) :
    sdbusplus::aserver::xyz::openbmc_project::certs::Certificate<
        Certificate, void>(asyncCtx, path.c_str()),
    path(path)
{
    certificate_string(pemChain);
    const auto [issuer_t, subject_t, notBefore, notAfter, keyUsage] =
        parseCertificatePEM(leafCert);
    issuer(issuer_t);
    subject(subject_t);
    valid_not_before(notBefore);
    valid_not_after(notAfter);
    key_usage(keyUsage);
}

std::string Certificate::getNameOneline(X509_NAME* name)
{
    if (!name)
        return "";
    char buffer[256] = {};
    if (X509_NAME_oneline(name, buffer, sizeof(buffer)))
    {
        return buffer;
    }
    return "";
}

uint64_t Certificate::asn1TimeToEpoch(const ASN1_TIME* time)
{
    if (!time)
        return 0;

    struct tm t;
    memset(&t, 0, sizeof(t));
    if (ASN1_TIME_to_tm(time, &t) != 1)
        return 0;
    time_t epoch = timegm(&t);
    return static_cast<uint64_t>(epoch);
}

std::vector<std::string> Certificate::getKeyUsageStrings(
    const ASN1_BIT_STRING* usage)
{
    std::vector<std::string> result;
    if (!usage)
        return result;

    static const std::array<std::string_view, 9> keyUsageMap = {
        "DigitalSignature", // 0
        "NonRepudiation",   // 1
        "KeyEncipherment",  // 2
        "DataEncipherment", // 3
        "KeyAgreement",     // 4
        "KeyCertSign",      // 5
        "CRLSigning",       // 6
        "EncipherOnly",     // 7
        "DecipherOnly"      // 8
    };

    for (int i = 0; i < static_cast<int>(keyUsageMap.size()); ++i)
    {
        if (ASN1_BIT_STRING_get_bit(usage, i))
        {
            result.emplace_back(keyUsageMap[i]);
        }
    }
    return result;
}

std::string Certificate::getIssuerNameFromDer(const uint8_t* certPtr,
                                              size_t certLen)
{
    if (!certPtr || certLen == 0)
    {
        return "";
    }

    const unsigned char* certDataPtr = certPtr;
    X509* certificateX509 = d2i_X509(nullptr, &certDataPtr, certLen);
    if (!certificateX509)
    {
        return "";
    }

    std::string issuerStr =
        getNameOneline(X509_get_issuer_name(certificateX509));
    X509_free(certificateX509);
    return issuerStr;
}

std::tuple<std::string, std::string, uint64_t, uint64_t,
           std::vector<std::string>>
    Certificate::parseCertificatePEM(const std::vector<uint8_t>& leafCert)
{
    std::string issuer, subject;
    uint64_t notBefore = 0, notAfter = 0;
    std::vector<std::string> keyUsage;

    if (leafCert.empty())
    {
        return {"", "", 0, 0, {}};
    }

    const unsigned char* certDataPtr = leafCert.data();
    X509* certificateX509 = d2i_X509(nullptr, &certDataPtr, leafCert.size());
    if (!certificateX509)
    {
        return {"", "", 0, 0, {}};
    }

    issuer = getNameOneline(X509_get_issuer_name(certificateX509));
    subject = getNameOneline(X509_get_subject_name(certificateX509));
    notBefore = asn1TimeToEpoch(X509_get0_notBefore(certificateX509));
    notAfter = asn1TimeToEpoch(X509_get0_notAfter(certificateX509));

    int critical = 0;
    ASN1_BIT_STRING* usage = (ASN1_BIT_STRING*)X509_get_ext_d2i(
        certificateX509, NID_key_usage, &critical, nullptr);
    keyUsage = getKeyUsageStrings(usage);
    if (usage)
    {
        ASN1_BIT_STRING_free(usage);
    }

    X509_free(certificateX509);
    return {issuer, subject, notBefore, notAfter, keyUsage};
}

void Certificate::updateCertificateProperties(
    const std::string& pemChain, const std::vector<uint8_t>& leafCert)
{
    certificate_string(pemChain);
    const auto [issuer_t, subject_t, notBefore, notAfter, keyUsage] =
        parseCertificatePEM(leafCert);
    issuer(issuer_t);
    subject(subject_t);
    valid_not_before(notBefore);
    valid_not_after(notAfter);
    key_usage(keyUsage);
}

} // namespace spdm
