#include "webauthn.hpp"
#include "window.hpp"

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/openssh.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>
#include <windows_fido_bridge/windows_error.hpp>
#include <windows_fido_bridge/windows_util.hpp>

#include <spdlog/spdlog.h>

#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include "webauthn.h"

extern "C" {

#include "sk-api.h"

}

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <vector>

namespace wfb {

namespace {

bool verify_supported_crypto_algorithm(uint8_t alg);

template <typename TCallback>
auto run_with_win32_window(TCallback callback) -> std::invoke_result_t<TCallback, HWND>;

bool is_user_verification_required(std::string_view application, uint8_t flags);
bool is_user_verification_required_flag_set(uint8_t flags);

std::optional<parsed_sk_option> find_sk_option(
    std::span<const parsed_sk_option> sk_options, std::string_view option_name
) {
    for (const parsed_sk_option& sk_option : sk_options) {
        if (sk_option.name == option_name) {
            return sk_option;
        }
    }

    return std::nullopt;
}

}  // namespace

std::tuple<int, unique_sk_enroll_response_ptr> sk_enroll_safe(
    uint32_t alg,
    std::span<const uint8_t> challenge,
    std::string_view application,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
) {
    std::optional<parsed_sk_option> user_sk_option = find_sk_option(sk_options, "user");
    std::string ssh_user = user_sk_option ? user_sk_option->value : "SSH user";

    unique_webauthn_credential_attestation_ptr result = run_with_win32_window(
        [&](HWND window_handle) {
            return create_windows_webauthn_credential(
                window_handle,
                alg,
                application,
                ssh_user,
                challenge,
                is_user_verification_required(application, flags)
            );
        }
    );

    byte_string raw_attestation_object{
        result->pbAttestationObject,
        result->pbAttestationObject + result->cbAttestationObject,
    };

    spdlog::debug("Parsing CBOR attestation object");
    cbor_map attestation_object;
    std::string attestation_statement_format;

    
    try {
        attestation_object = parse_cbor<cbor_map>(raw_attestation_object);
        spdlog::debug("Map keys in CBOR attestation object: {}", cbor_array{attestation_object.keys()}.dump_debug());

        attestation_statement_format = extract_attestation_object_format(attestation_object);
    } catch (const std::exception& ex) {
        spdlog::critical("Failed to parse attestation object: {}", ex.what());
        return {SSH_SK_ERR_GENERAL, nullptr};
    }

    authenticator_data auth_data;

    try {
        std::optional<byte_vector> raw_auth_data = attestation_object.try_at<byte_vector>("authData");
        if (!raw_auth_data) {
            spdlog::critical("Missing authenticator data from attestation object");
            return {SSH_SK_ERR_GENERAL, nullptr};
        }

        auth_data = authenticator_data::parse({*raw_auth_data});
        spdlog::debug("Parsed authenticator data:");
        log_multiline(auth_data.dump_debug(), "  | ");
    } catch (const std::exception& ex) {
        spdlog::critical("Failed to parse authenticator data: {}", ex.what());
        return {SSH_SK_ERR_GENERAL, nullptr};
    }

    spdlog::debug("Parsing attestation statement data in attestation object");
    std::optional<cbor_map> raw_attestation_statement = attestation_object.try_at<cbor_map>("attStmt");
    if (!raw_attestation_statement) {
        spdlog::critical("Missing attestation statement in attestation object");
        return {SSH_SK_ERR_GENERAL, nullptr};
    }

    const cbor_map& attestation_statement = *raw_attestation_statement;

    std::optional<cbor_byte_string> raw_signature = attestation_statement.try_at<cbor_byte_string>("sig");
    if (!raw_signature) {
        spdlog::critical("Missing signature in attestation statement");
        return {SSH_SK_ERR_GENERAL, nullptr};
    }

    const cbor_byte_string& signature = *raw_signature;

    std::optional<cbor_array> raw_certificate_array = attestation_statement.try_at<cbor_array>("x5c");
    std::optional<byte_vector> x5c_certificate;
    if (raw_certificate_array) {
        spdlog::debug("Certificate array is present in attestation statement");
        const cbor_array& certificate_array = *raw_certificate_array;
        if (certificate_array.size() < 1) {
            spdlog::critical(
                "Certificate array in present in attestation statement, but it contains no certificates"
            );
            return {SSH_SK_ERR_GENERAL, nullptr};
        }

        x5c_certificate = certificate_array[0].get<cbor_byte_string>();
    } else if (attestation_statement_format != "packed") {
        // "packed" statements allow omitting an x5c element, which indicates
        // the key is performing self-attestation, but "fido-u2f" statements
        // are required to have it.
        spdlog::critical(
            "Missing certificate array in attestation statement, but self-attestation is not permitted"
        );
        return {SSH_SK_ERR_GENERAL, nullptr};
    } else {
        spdlog::debug("Certificate array is missing from attestation statement, assuming self-attestation");
    }

    spdlog::debug("Attestation statement parsed successfully");

    unique_sk_enroll_response_ptr response(
        reinterpret_cast<sk_enroll_response*>(calloc(1, sizeof(sk_enroll_response)))
    );

    std::tie(response->public_key, response->public_key_len) =
        calloc_from_data(auth_data.attested_credential->public_key);

    std::tie(response->key_handle, response->key_handle_len) =
        calloc_from_data(auth_data.attested_credential->id);

    std::tie(response->signature, response->signature_len) = calloc_from_data(signature);

    if (x5c_certificate) {
        std::tie(response->attestation_cert, response->attestation_cert_len) = calloc_from_data(*x5c_certificate);
    } else {
        // No x5c certificate was specified, so don't pass one to OpenSSH.
        response->attestation_cert = nullptr;
        response->attestation_cert_len = 0;
    }

#if WFB_SK_API_VERSION == 7
    // TODO: provide the raw CBOR-encoded attestation data from the security key
    response->authdata = nullptr;
    response->authdata_len = 0;
#endif

    spdlog::debug("Key enrollment successfully completed");
    return {0, std::move(response)};
}

std::tuple<int, unique_sk_sign_response_ptr> sk_sign_safe(
    uint32_t alg,
    std::span<const uint8_t> data_bytes,
    std::string_view application,
    std::span<const uint8_t> key_handle_bytes,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
) {
    dump_sk_sign_inputs(alg, data_bytes, application, key_handle_bytes, flags, pin, sk_options);

    if (!verify_supported_crypto_algorithm(alg)) {
        return {SSH_SK_ERR_UNSUPPORTED, nullptr};
    }

    unique_webauthn_assertion_ptr result = run_with_win32_window([&](HWND window_handle) {
        return create_windows_webauthn_assertion(
            window_handle,
            application,
            data_bytes,
            key_handle_bytes,
            is_user_verification_required(application, flags)
        );
    });

    byte_string raw_signature{
        result->pbSignature,
        result->pbSignature + result->cbSignature,
    };

    byte_string raw_authenticator_data{
        result->pbAuthenticatorData,
        result->pbAuthenticatorData + result->cbAuthenticatorData
    };

    auto auth_data = authenticator_data::parse({raw_authenticator_data});
    spdlog::debug("Parsed authenticator data:");
    log_multiline(auth_data.dump_debug(), "  | ");

    unique_sk_sign_response_ptr response(
        reinterpret_cast<sk_sign_response*>(calloc(1, sizeof(sk_sign_response)))
    );

    response->flags = auth_data.flags;
    response->counter = auth_data.signature_count;

    fido_signature signature;
    switch (alg) {
        case SSH_SK_ED25519:
            signature = fido_signature::parse_ed25519_sk_signature(raw_signature);
            break;
        case SSH_SK_ECDSA:
            signature = fido_signature::parse_ecdsa_sk_signature(raw_signature);
            break;
        default:
            throw std::runtime_error("Unrecognized OpenSSH algorithm {}"_format(alg));
    }

    if (signature.sig_r) {
        std::tie(response->sig_r, response->sig_r_len) = calloc_from_data(*signature.sig_r);
    }

    if (signature.sig_s) {
        std::tie(response->sig_s, response->sig_s_len) = calloc_from_data(*signature.sig_s);
    }

    return {0, std::move(response)};
}

namespace {

bool verify_supported_crypto_algorithm(uint8_t alg) {
    // Windows' WebAuthn API does not support any of OpenSSH's supported
    // algorithms other than ECDSA.
    if (alg == SSH_SK_ECDSA || alg == SSH_SK_ED25519) {
        return true;
    }

    std::string algo_name;
    switch (alg) {
        default:
            algo_name = "(unknown, sk-api ID = 0x{:02x})"_format(alg);
            break;
    }

    spdlog::critical(
        "The cryptographic algorithm \"{}\" is not supported by Microsoft's WebAuthn API. Try "
        "using \"ecdsa-sk\" instead.",
        algo_name
    );

    return false;
}

template <typename TCallback>
using run_with_win32_window_callback_return_type = std::invoke_result_t<TCallback, HWND>;

template <typename TCallback>
auto run_with_win32_window(
    TCallback callback
) -> run_with_win32_window_callback_return_type<TCallback> {
    using return_type = run_with_win32_window_callback_return_type<TCallback>;

    // Create a window for the WebAuthn dialogs to attach to. Normally, we'd use
    // something like GetConsoleWindow as the WebAuthn dialog parent window, but
    // it doesn't seem to work with a few major console terminals, namely
    // Windows Terminal and VS Code (for the former, see
    // https://github.com/microsoft/terminal/issues/2988). To make sure the
    // WebAuthn dialogs consistently show up properly, we instead create our own
    // invisible, always-on-top window that the WebAuthn dialogs attach to,
    // which means the dialogs will always show up (outside of weird edge cases
    // like another always-on-top window being higher in the Z-order).
    HMODULE calling_process_module_handle = GetModuleHandle(nullptr);
    window win(calling_process_module_handle);
    win.show_window();

    struct thread_params {
        TCallback* callback_ptr;
        HWND window_handle;

        std::unique_ptr<return_type> result;
        std::exception_ptr exception;
    } params {
        .callback_ptr = &callback,
        .window_handle = win.hwnd(),
    };

    spdlog::debug("Spawning background thread");

    {

        auto thread_handle = unique_win32_handle_ptr(
            reinterpret_cast<HANDLE>(
#ifdef __CYGWIN__
                CreateThread(
#else
                _beginthreadex(
#endif
                    nullptr,
                    0,  // Default stack size.
                    +[](void* raw_params) -> unsigned int {
                        auto params = reinterpret_cast<thread_params*>(raw_params);

                        try {
                            params->result = std::make_unique<return_type>(
                                (*params->callback_ptr)(params->window_handle)
                            );
                        } catch (...) {
                            params->exception = std::current_exception();
                        }

                        return 0;
                    },
                    &params,
                    0,  // Start running immediately.
                    nullptr  // Unused output thread ID.
                )
            )
        );

        // Wait for the created thread to exit; in the meantime, run the
        // window's message loop.
        win.run_message_loop(thread_handle.get());
    }

    // Thread is complete, close the window and wait for the message loop to
    // stop.
    SendMessage(win.hwnd(), WM_CLOSE, 0, 0);
    win.run_message_loop();

    if (params.exception != nullptr) {
        std::rethrow_exception(params.exception);
    }

    return std::move(*params.result);
}

bool is_user_verification_required(std::string_view application, uint8_t flags) {
    constexpr const char* env_var_name = "WINDOWS_FIDO_BRIDGE_FORCE_USER_VERIFICATION";
    if (get_environment_variable(env_var_name)) {
        spdlog::debug(
            "Forcing user verification because the environment variable \"{}\" is set to any value",
            env_var_name
        );
        return true;
    }

    if (application == "ssh:windows-fido-bridge-verify-required") {
        // Special marker that tells windows-fido-bridge to ask for user
        // verification without OpenSSH knowing. We do this to avoid a useless
        // prompt in OpenSSH that asks for a PIN which we can't use even if the
        // user gives it to us.
        spdlog::debug("Forcing user verification because the application name indicates to");
        return true;
    }

    return is_user_verification_required_flag_set(flags);
}

bool is_user_verification_required_flag_set(uint8_t flags) {
    return (flags & SSH_SK_USER_VERIFICATION_REQD) == SSH_SK_USER_VERIFICATION_REQD;
}

}  // namespace

}  // namespace wfb
