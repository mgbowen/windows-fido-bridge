#include "bridge.hpp"
#include "webauthn.hpp"

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/exceptions.hpp>
#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

extern "C" {

#include "sk-api.h"

}

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#include <sys/wait.h>
#include <unistd.h>

namespace wfb {

namespace {

CUSTOM_EXCEPTION(unrecognized_but_required_option_error, "A required option is not recognized");

struct parsed_sk_option {
    std::string name;
    std::string value;
    bool required{false};
};

void set_up_logger();

void log_multiline_binary(const uint8_t* buffer, size_t length, const std::string& indent_str = "");
void log_sk_options(const std::vector<parsed_sk_option>& options, const std::string& indent_str);

bool is_user_verification_required(const std::string_view& application, uint8_t flags);
bool is_user_verification_required_flag_set(uint8_t flags);

bool verify_supported_crypto_algorithm(uint8_t alg);

std::vector<parsed_sk_option> parse_options(const sk_option* const* raw_options);
void fill_parameters_with_options(wfb::cbor_map& parameters,
                                  const std::vector<parsed_sk_option>& options);

constexpr std::string_view SK_API_OPTION_USER = "user";

}  // namespace

extern "C" {

// Return the version of the middleware API
uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

// Enroll a U2F key (private key generation)
int sk_enroll(uint32_t alg, const uint8_t* challenge, size_t challenge_len,
              const char* application, uint8_t flags, const char* pin,
              sk_option** raw_options, sk_enroll_response** enroll_response) {
    set_up_logger();

    std::vector<parsed_sk_option> options = parse_options(raw_options);

    spdlog::debug("Parameters from OpenSSH:");
    spdlog::debug("    Algorithm: {}", alg);
    spdlog::debug("    Challenge:");
    log_multiline_binary(challenge, challenge_len, "      | ");
    spdlog::debug("    Application: \"{}\"", application);
    spdlog::debug("    Flags: 0b{:08b}", flags);
    spdlog::debug("    PIN: {}", pin != nullptr ? "(present)" : "(not present)");
    spdlog::debug("    Options:");
    log_sk_options(options, "        ");

    if (!verify_supported_crypto_algorithm(alg)) {
        return SSH_SK_ERR_UNSUPPORTED;
    }

    wfb::cbor_map parameters = {
        {"type", "create"},
        {"challenge", byte_string{challenge, challenge + challenge_len}},
        {"application", application},

        // Explicitly only check the flag provided by OpenSSH (and not the force
        // environment variable) so the user doesn't accidentally create keys
        // that require user verification without them specifying it explicitly
        // on ssh-keygen's command line.
        {"user_verification_required", is_user_verification_required_flag_set(flags)},
    };

    try {
        fill_parameters_with_options(parameters, options);
    } catch (const unrecognized_but_required_option_error&) {
        return SSH_SK_ERR_UNSUPPORTED;
    }

    byte_vector raw_output = invoke_windows_bridge(wfb::dump_cbor(parameters));
    auto output = parse_cbor<cbor_map>(raw_output);

    auto raw_attestation_object = output.at<byte_string>("attestation_object");
    auto attestation_object = parse_cbor<cbor_map>(raw_attestation_object);
    auto auth_data = authenticator_data::parse({attestation_object.at<byte_vector>("authData")});
    auto attestation_statement = attestation_object.at<cbor_map>("attStmt");
    byte_vector signature = attestation_statement.at<cbor_byte_string>("sig");
    byte_vector x5c = attestation_statement.at<cbor_array>("x5c")[0].get<cbor_byte_string>();

    // Construct the response to send back to OpenSSH. The ownership of the
    // memory we allocate here is transferred to OpenSSH; they are responsible
    // for deallocating it.
    auto response = reinterpret_cast<sk_enroll_response*>(calloc(1, sizeof(**enroll_response)));

    std::tie(response->public_key, response->public_key_len) =
        calloc_from_data(auth_data.attested_credential->public_key);

    std::tie(response->key_handle, response->key_handle_len) =
        calloc_from_data(auth_data.attested_credential->id);

    std::tie(response->signature, response->signature_len) = calloc_from_data(signature);
    std::tie(response->attestation_cert, response->attestation_cert_len) = calloc_from_data(x5c);

#if WFB_SK_API_VERSION == 7
    // TODO: provide the raw CBOR-encoded attestation data from the security key
    response->authdata = nullptr;
    response->authdata_len = 0;
#endif

    *enroll_response = response;
    return 0;
}

// Sign a challenge
int sk_sign(uint32_t alg, const uint8_t* data, size_t datalen,
            const char* application, const uint8_t* key_handle, size_t key_handle_len,
            uint8_t flags, const char* pin, sk_option** raw_options,
            struct sk_sign_response** sign_response) {
    set_up_logger();

    spdlog::debug("Parameters from OpenSSH:");
    spdlog::debug("    Algorithm: {}", alg);
    spdlog::debug("    Data:");
    log_multiline_binary(data, datalen, "      | ");
    spdlog::debug("    Application: \"{}\"", application);
    spdlog::debug("    Key handle:");
    log_multiline_binary(key_handle, key_handle_len, "      | ");
    spdlog::debug("    Flags: 0b{:08b}", flags);
    spdlog::debug("    PIN: {}", pin != nullptr ? "(present)" : "(not present)");

    std::vector<parsed_sk_option> options = parse_options(raw_options);

    if (!verify_supported_crypto_algorithm(alg)) {
        return SSH_SK_ERR_UNSUPPORTED;
    }

    wfb::cbor_map parameters = {
        {"type", "sign"},
        {"message", byte_string{data, data + datalen}},
        {"application", application},
        {"key_handle", byte_string{key_handle, key_handle + key_handle_len}},
        {"user_verification_required", is_user_verification_required(application, flags)},
    };

    try {
        fill_parameters_with_options(parameters, options);
    } catch (const unrecognized_but_required_option_error&) {
        return SSH_SK_ERR_UNSUPPORTED;
    }

    byte_vector raw_output = invoke_windows_bridge(wfb::dump_cbor(parameters));
    auto output = wfb::parse_cbor<cbor_map>(raw_output);

    byte_string raw_auth_data = output.at<byte_string>("authenticator_data");
    auto auth_data = authenticator_data::parse({raw_auth_data});

    auto response = reinterpret_cast<sk_sign_response*>(calloc(1, sizeof(**sign_response)));

    response->flags = auth_data.flags;
    response->counter = auth_data.signature_count;

    auto raw_signature = output.at<byte_string>("signature");
    auto signature = fido_signature::parse(raw_signature);

    std::tie(response->sig_r, response->sig_r_len) = calloc_from_data(signature.sig_r);
    std::tie(response->sig_s, response->sig_s_len) = calloc_from_data(signature.sig_s);

    *sign_response = response;
    return 0;
}

// Enumerate all resident keys
int sk_load_resident_keys(const char *pin, struct sk_option **options,
                          struct sk_resident_key ***rks, size_t *nrks) {
    return SSH_SK_ERR_UNSUPPORTED;
}

}  // extern "C"

namespace {

void set_up_logger() {
    auto logger = spdlog::stderr_color_mt("wfb-middleware");
    logger->set_level(
        get_environment_variable("WINDOWS_FIDO_BRIDGE_DEBUG")
            ? spdlog::level::debug
            : spdlog::level::warn
    );
    spdlog::set_default_logger(logger);
}

void log_multiline_binary(const uint8_t* buffer, size_t length, const std::string& indent_str) {
    std::stringstream ss;
    wfb::dump_binary(ss, buffer, length);

    std::string token;
    while (std::getline(ss, token, '\n')) {
        spdlog::debug("{}{}"_format(indent_str, token));
    }
}

void log_sk_options(const std::vector<parsed_sk_option>& options, const std::string& indent_str) {
    if (options.empty()) {
        spdlog::debug("{}(No options provided)"_format(indent_str));
        return;
    }

    for (const parsed_sk_option& option : options) {
        spdlog::debug(
            "{}* \"{}\" = \"{}\" (required = {})",
            indent_str,
            option.name,
            option.value,
            option.required
        );
    }
}

bool verify_supported_crypto_algorithm(uint8_t alg) {
    // Windows' WebAuthn API does not support any of OpenSSH's supported
    // algorithms other than ECDSA.
    if (alg == SSH_SK_ECDSA) {
        return true;
    }

    std::string algo_name;
    switch (alg) {
        case SSH_SK_ED25519:
            algo_name = "ed25519-sk";
            break;
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

std::vector<parsed_sk_option> parse_options(const sk_option* const* raw_options) {
    std::vector<parsed_sk_option> result;

    if (raw_options != nullptr) {
        const sk_option* const* current_ptr = raw_options;
        while (*current_ptr != nullptr) {
            const sk_option* current_option = *current_ptr;
            result.emplace_back(parsed_sk_option{
                .name = current_option->name,
                .value = current_option->value,
                .required = current_option->required != 0,
            });

            current_ptr++;
        }
    }

    return result;
}

void fill_parameters_with_options(wfb::cbor_map& parameters,
                                  const std::vector<parsed_sk_option>& options) {
    for (const parsed_sk_option& option : options) {
        if (option.name == SK_API_OPTION_USER) {
            parameters["user"] = option.value;
        } else if (option.required) {
            // We don't recognize the option, but it's marked as required; per
            // OpenSSH's spec, we should error out.
            std::string msg = "Unrecognized but required option \"{}\" specified"_format(option.name);
            spdlog::critical(msg);
            throw unrecognized_but_required_option_error(msg);
        }
    }
}

bool is_user_verification_required(const std::string_view& application, uint8_t flags) {
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
