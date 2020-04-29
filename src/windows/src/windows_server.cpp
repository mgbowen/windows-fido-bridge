#include "windows_error.hpp"
#include "windows_util.hpp"

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

#include <windows.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include "webauthn.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <system_error>
#include <vector>

namespace wfb {

WEBAUTHN_CREDENTIAL_ATTESTATION* create_credential(const wfb::cbor_map& parameters) {
    std::wstring relying_party_id = string_to_wide_string(parameters.at<std::string>("application"));

    WEBAUTHN_RP_ENTITY_INFORMATION entity_info = {
        .dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        .pwszId = relying_party_id.c_str(),
        .pwszName = L"OpenSSH via windows-fido-bridge",
    };

    // OpenSSH doesn't give us this, so just use a placeholder
    std::string user_id = "(null)";

    WEBAUTHN_USER_ENTITY_INFORMATION user_info = {
        .dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        .cbId = static_cast<DWORD>(user_id.size()),
        .pbId = reinterpret_cast<BYTE*>(user_id.data()),
        .pwszName = L"SSH user",
        .pwszIcon = nullptr,
        .pwszDisplayName = L"SSH user",
    };

    std::array<WEBAUTHN_COSE_CREDENTIAL_PARAMETER, 1> cose_credential_parameters_array{
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER{
            .dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            .lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        },
    };

    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS cose_credential_parameters{
        static_cast<DWORD>(cose_credential_parameters_array.size()),
        cose_credential_parameters_array.data()
    };

    auto challenge_str = parameters.at<byte_string>("challenge");

    WEBAUTHN_CLIENT_DATA client_data = {
        .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        .cbClientDataJSON = static_cast<DWORD>(challenge_str.size()),
        .pbClientDataJSON = reinterpret_cast<BYTE*>(challenge_str.data()),
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

WEBAUTHN_ASSERTION* create_signature(const wfb::cbor_map& parameters) {
    byte_string message = parameters.at<byte_string>("message");

    auto client_data = WEBAUTHN_CLIENT_DATA{
        .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        .cbClientDataJSON = static_cast<DWORD>(message.size()),
        .pbClientDataJSON = reinterpret_cast<PBYTE>(message.data()),
        .pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    auto credential_id = parameters.at<byte_string>("key_handle");

    std::array<WEBAUTHN_CREDENTIAL, 1> credentials_arr = {
        WEBAUTHN_CREDENTIAL{
            .dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            .cbId = static_cast<DWORD>(credential_id.size()),
            .pbId = reinterpret_cast<PBYTE>(credential_id.data()),
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        },
    };

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {
        .dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
        .CredentialList = WEBAUTHN_CREDENTIALS{
            .cCredentials = static_cast<DWORD>(credentials_arr.size()),
            .pCredentials = credentials_arr.data(),
        },
    };

    std::wstring relying_party_id = string_to_wide_string(parameters.at<std::string>("application"));

    WEBAUTHN_ASSERTION* assertion = nullptr;

    auto result = WebAuthNAuthenticatorGetAssertion(
        GetForegroundWindow(),
        relying_party_id.c_str(),
        &client_data,
        &options,
        &assertion
    );

    return assertion;
}

extern "C" INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
    // Set stdin and stdout to binary mode to prevent issues with reading and
    // writing CBOR between us and the Linux bridge.
    int read_fd = _fileno(stdin);
    int write_fd = _fileno(stdout);

    _setmode(read_fd, _O_BINARY);
    _setmode(write_fd, _O_BINARY);

    wfb::byte_vector raw_parameters = receive_message(read_fd);
    auto parameters = wfb::parse_cbor<cbor_map>(raw_parameters);

    if (parameters["type"] == "create") {
        PCWEBAUTHN_CREDENTIAL_ATTESTATION raw_output = create_credential(parameters);

        std::string attobj = {
            raw_output->pbAttestationObject,
            raw_output->pbAttestationObject + raw_output->cbAttestationObject
        };

        std::string credid = {
            raw_output->pbCredentialId,
            raw_output->pbCredentialId + raw_output->cbCredentialId
        };

        cbor_map output = {
            {"attestation_object", byte_string{attobj.cbegin(), attobj.cend()}},
            {"credential_id", byte_string{credid.cbegin(), credid.cend()}},
        };

        auto raw_cbor_output = wfb::dump_cbor(output);
        send_message(write_fd, raw_cbor_output);
    } else if (parameters["type"] == "sign") {
        PWEBAUTHN_ASSERTION assertion = create_signature(parameters);

        byte_string signature{assertion->pbSignature,
                              assertion->pbSignature + assertion->cbSignature};

        byte_string authenticator_data{
            assertion->pbAuthenticatorData,
            assertion->pbAuthenticatorData + assertion->cbAuthenticatorData
        };

        cbor_map output = {{"signature", signature}, {"authenticator_data", authenticator_data}};
        send_message(write_fd, wfb::dump_cbor(output));
    } else {
        std::cerr << "ERROR: unrecognized type!\n";
        abort();
    }

    std::cerr << "Done!\n";

    return 0;
}

}  // namespace wfb
