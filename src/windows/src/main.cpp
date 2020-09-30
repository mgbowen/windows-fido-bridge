#include "webauthn_linking.hpp"
#include "window.hpp"
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

namespace {

webauthn_methods webauthn = webauthn_methods::load();

using unique_webauthn_assertion_ptr =
    std::unique_ptr<WEBAUTHN_ASSERTION, decltype(&WebAuthNFreeAssertion)>;

using unique_webauthn_credential_attestation_ptr =
    std::unique_ptr<WEBAUTHN_CREDENTIAL_ATTESTATION, decltype(&WebAuthNFreeCredentialAttestation)>;

struct handle_bridge_request_parameters {
    int read_fd;
    int write_fd;
    HWND hwnd;
};

DWORD WINAPI handle_bridge_request(const handle_bridge_request_parameters& handle_params);

unique_webauthn_credential_attestation_ptr create_credential(
    HWND window_handle,
    const cbor_map& parameters
);

unique_webauthn_assertion_ptr create_assertion(HWND window_handle, const cbor_map& parameters);

auto make_unique_webauthn_credential_attestation_ptr(WEBAUTHN_CREDENTIAL_ATTESTATION* ptr) {
    return unique_webauthn_credential_attestation_ptr(ptr, webauthn.FreeCredentialAttestation);
}

auto make_unique_webauthn_assertion_ptr(WEBAUTHN_ASSERTION* ptr) {
    return unique_webauthn_assertion_ptr(ptr, webauthn.FreeAssertion);
}

extern "C" INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
    // Set stdin and stdout to binary mode to prevent issues with reading and
    // writing CBOR between us and the Linux bridge.
    int read_fd = _fileno(stdin);
    int write_fd = _fileno(stdout);

    _setmode(read_fd, _O_BINARY);
    _setmode(write_fd, _O_BINARY);

    // Create a window for the WebAuthN dialogs to attach to. Normally, we'd use
    // something like GetConsoleWindow as the WebAuthN dialog parent window, but
    // it doesn't seem to work with a few major console terminals, namely
    // Windows Terminal and VS Code (for the former, see
    // https://github.com/microsoft/terminal/issues/2988). To make sure the
    // WebAuthN dialogs consistently show up properly, we instead create our own
    // invisible, always-on-top window that the WebAuthN dialogs attach to,
    // which means the dialogs will always show up (outside of weird edge cases
    // like another always-on-top window being higher in the Z-order).
    wfb::window win(hInstance);
    win.show_window();

    // Run the WebAuthN calls inside another thread to allow our window to
    // properly handle its message loop (the WebAuthN API is blocking,
    // unfortunately).
    handle_bridge_request_parameters params{
        .read_fd = read_fd,
        .write_fd = write_fd,
        .hwnd = win.hwnd(),
    };

    HANDLE thread_handle = CreateThread(
        nullptr,  // Thread attributes
        0,  // Default stack size
        reinterpret_cast<LPTHREAD_START_ROUTINE>(&handle_bridge_request),
        &params,
        0,  // Creation flags
        nullptr  // Output thread ID
    );

    // Wait for the created thread to exit; in the meantime, run the window's
    // message loop
    win.run_message_loop(thread_handle);

    // Thread is complete, close the window and wait for the message loop to
    // stop
    SendMessage(win.hwnd(), WM_CLOSE, 0, 0);
    win.run_message_loop();

    return 0;
}

DWORD WINAPI handle_bridge_request(const handle_bridge_request_parameters& handle_params) {
    wfb::byte_vector raw_request_parameters = receive_message(handle_params.read_fd);
    auto request_parameters = wfb::parse_cbor<cbor_map>(raw_request_parameters);

    if (request_parameters.at("type") == "create") {
        unique_webauthn_credential_attestation_ptr raw_output =
            create_credential(handle_params.hwnd, request_parameters);

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
        send_message(handle_params.write_fd, raw_cbor_output);
    } else if (request_parameters.at("type") == "sign") {
        unique_webauthn_assertion_ptr assertion = create_assertion(handle_params.hwnd, request_parameters);

        byte_string signature{assertion->pbSignature,
                              assertion->pbSignature + assertion->cbSignature};

        byte_string authenticator_data{
            assertion->pbAuthenticatorData,
            assertion->pbAuthenticatorData + assertion->cbAuthenticatorData
        };

        cbor_map output = {{"signature", signature}, {"authenticator_data", authenticator_data}};
        send_message(handle_params.write_fd, wfb::dump_cbor(output));
    } else {
        std::cerr << "ERROR: unrecognized type!\n";
        abort();
    }

    return 0;
}

unique_webauthn_credential_attestation_ptr create_credential(
    HWND window_handle,
    const wfb::cbor_map& parameters
) {
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

    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = {
        .dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
        .dwUserVerificationRequirement = static_cast<DWORD>(
            parameters.at<bool>("user_verification_required")
                ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        ),
    };

    WEBAUTHN_CREDENTIAL_ATTESTATION* raw_credential_attestation = nullptr;

    auto result = webauthn.AuthenticatorMakeCredential(
        window_handle,
        &entity_info,
        &user_info,
        &cose_credential_parameters,
        &client_data,
        &options,
        &raw_credential_attestation
    );

    auto credential_attestation = make_unique_webauthn_credential_attestation_ptr(
        raw_credential_attestation
    );

    if (result != S_OK) {
        std::string error_str = wide_string_to_string(webauthn.GetErrorName(result));
        throw_windows_exception(result, "Failed to make WebAuthN credential ({})"_format(error_str));
    }

    return credential_attestation;
}

unique_webauthn_assertion_ptr create_assertion(HWND window_handle, const wfb::cbor_map& parameters) {
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
        .dwUserVerificationRequirement = static_cast<DWORD>(
            parameters.at<bool>("user_verification_required")
                ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        ),
    };

    std::wstring relying_party_id = string_to_wide_string(parameters.at<std::string>("application"));

    WEBAUTHN_ASSERTION* raw_assertion = nullptr;

    auto result = webauthn.AuthenticatorGetAssertion(
        window_handle,
        relying_party_id.c_str(),
        &client_data,
        &options,
        &raw_assertion
    );

    auto assertion = make_unique_webauthn_assertion_ptr(raw_assertion);

    if (result != S_OK) {
        std::string error_str = wide_string_to_string(webauthn.GetErrorName(result));
        throw_windows_exception(result, "Failed to get WebAuthN assertion ({})"_format(error_str));
    }

    return assertion;
}

}  // namespace

}  // namespace wfb
