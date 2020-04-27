#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#define _UNICODE
#define UNICODE

#include <windows_fido_bridge/base64.hpp>
#include <windows_fido_bridge/communication.hpp>

#include <nlohmann/json.hpp>

#include <windows.h>
#include "webauthn.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

using json = nlohmann::json;

namespace {

std::wstring string_to_wide_string(const std::string& str) {
    std::array<wchar_t, 32768> wide_string_buffer;
    int num_bytes_written = MultiByteToWideChar(CP_UTF8, 0, str.data(), str.size(), wide_string_buffer.data(), wide_string_buffer.size());
    return std::wstring{wide_string_buffer.data(), num_bytes_written};
}

std::string wide_string_to_string(const std::wstring& wide_str) {
    std::array<char, 32768> string_buffer;
    int num_bytes_written = WideCharToMultiByte(CP_UTF8, 0, wide_str.data(), wide_str.size(), string_buffer.data(), string_buffer.size(), nullptr, nullptr);
    return std::string{string_buffer.data(), num_bytes_written};
}

}  // namespace

namespace wfb {

PCWEBAUTHN_CREDENTIAL_ATTESTATION create_credential(const json& parameters) {
    std::wstring relying_party_id = string_to_wide_string(parameters["application"].get<std::string>());

    WEBAUTHN_RP_ENTITY_INFORMATION entity_info = {
        .dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        .pwszId = relying_party_id.c_str(),
        .pwszName = relying_party_id.c_str(),
    };

    std::vector<uint8_t> user_id{WEBAUTHN_MAX_USER_ID_LENGTH};

    // Assume null
    // TODO: actually handle this
    const char* null_str = "(null)";
    size_t null_str_length = strlen(null_str);
    std::memcpy(user_id.data(), null_str, null_str_length);

    WEBAUTHN_USER_ENTITY_INFORMATION user_info = {
        .dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        .cbId = null_str_length,
        .pbId = user_id.data(),
        .pwszName = L"(null)",
        .pwszIcon = nullptr,
        .pwszDisplayName = L"(null)",
    };

    std::vector<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> cose_credential_parameter_values;
    cose_credential_parameter_values.push_back(
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER{
            .dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            .lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        }
    );

    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS cose_credential_parameters{
        cose_credential_parameter_values.size(),
        cose_credential_parameter_values.data()
    };

    auto challenge_str_b64 = parameters["challenge"].get<std::string>();
    std::string challenge_str = base64_decode(challenge_str_b64);

    WEBAUTHN_CLIENT_DATA client_data = {
        .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        .cbClientDataJSON = challenge_str.size(),
        .pbClientDataJSON = reinterpret_cast<PBYTE>(challenge_str.data()),
        .pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    WEBAUTHN_CREDENTIAL_ATTESTATION* credential_attestation = nullptr;

    auto result = WebAuthNAuthenticatorMakeCredential(
        GetForegroundWindow(),
        &entity_info,
        &user_info,
        &cose_credential_parameters,
        &client_data,
        nullptr,
        &credential_attestation
    );

    std::wcerr << WebAuthNGetErrorName(result) << "\n";

    return credential_attestation;
}

PWEBAUTHN_ASSERTION create_signature(const json& parameters) {
    std::wstring relying_party_id = string_to_wide_string(parameters["application"].get<std::string>());

    auto message_str_b64 = parameters["message"].get<std::string>();
    std::string message_str = base64_decode(message_str_b64);

    auto client_data = WEBAUTHN_CLIENT_DATA{
        .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        .cbClientDataJSON = message_str.size(),
        .pbClientDataJSON = reinterpret_cast<PBYTE>(message_str.data()),
        .pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    std::cerr << "message length: " << message_str.size() << "\n";

    auto credential_id_b64 = parameters["key_handle"].get<std::string>();
    std::string credential_id_str = base64_decode(credential_id_b64);

    std::array<WEBAUTHN_CREDENTIAL, 1> credentials_arr = {
        WEBAUTHN_CREDENTIAL{
            .dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            .cbId = credential_id_str.size(),
            .pbId = reinterpret_cast<PBYTE>(credential_id_str.data()),
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        },
    };

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {
        .dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
        .CredentialList = WEBAUTHN_CREDENTIALS{
            .cCredentials = 1,
            .pCredentials = credentials_arr.data(),
        },
    };

    WEBAUTHN_ASSERTION* assertion = nullptr;

    auto result = WebAuthNAuthenticatorGetAssertion(
        GetForegroundWindow(),
        relying_party_id.c_str(),
        &client_data,
        &options,
        &assertion
    );

    std::wcerr << WebAuthNGetErrorName(result) << "\n";

    return assertion;
}

extern "C" INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
    std::cerr << WebAuthNGetApiVersionNumber() << "\n";

    std::string raw_parameters = receive_message(fileno(stdin));
    json parameters = json::parse(raw_parameters);

    if (parameters["type"] == "create") {
        std::cerr << "Creating credential\n";

        PCWEBAUTHN_CREDENTIAL_ATTESTATION raw_output = create_credential(parameters);

        std::cerr << "Constructing output\n";

        json output = {
            {"attestation_object", base64_encode(
                raw_output->pbAttestationObject,
                raw_output->cbAttestationObject
            )},
            {"credential_id", base64_encode(
                raw_output->pbCredentialId,
                raw_output->cbCredentialId
            )},
        };

        send_message(fileno(stdout), output);
    } else if (parameters["type"] == "sign") {
        std::cerr << "Creating signature\n";

        PWEBAUTHN_ASSERTION assertion = create_signature(parameters);

        std::cerr << "Constructing output\n";

        json output = {
            {"signature", base64_encode(assertion->pbSignature, assertion->cbSignature)},
            {"authenticator_data", base64_encode(assertion->pbAuthenticatorData, assertion->cbAuthenticatorData)},
        };

        send_message(fileno(stdout), output);
    } else {
        std::cerr << "ERROR: unrecognized type!\n";
        abort();
    }

    std::cerr << "Done!\n";

    return 0;
}

}  // namespace wfb
