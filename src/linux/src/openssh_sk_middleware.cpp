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


void log_sk_options(const std::vector<parsed_sk_option>& options, const std::string& indent_str);

bool is_user_verification_required(const std::string_view& application, uint8_t flags);
bool is_user_verification_required_flag_set(uint8_t flags);

bool verify_supported_crypto_algorithm(uint8_t alg);

std::vector<parsed_sk_option> parse_options(const sk_option* const* raw_options);
void fill_parameters_with_options(wfb::cbor_map& parameters,
                                  const std::vector<parsed_sk_option>& options);

constexpr std::string_view SK_API_OPTION_USER = "user";
constexpr const char* LOG_NAME = "wfb-middleware";

}  // namespace

extern "C" {

// Return the version of the middleware API
uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

std::string extract_attestation_object_format(const cbor_map& attestation_object) {
    auto raw_attestation_object_format = attestation_object.try_at("fmt");
    spdlog::debug(
        "Attestation object format: {}",
        raw_attestation_object_format ? raw_attestation_object_format->dump_debug() : "(missing)"
    );
    if (!raw_attestation_object_format) {
        throw std::runtime_error("Missing attestation object format");
    }

    auto format = static_cast<std::string>(raw_attestation_object_format->get<cbor_text_string>());
    if (format != "packed" && format != "fido-u2f") {
        throw std::runtime_error("Invalid or unknown attestation object format");
    }

    return format;
}

// Enroll a U2F key (private key generation)
int sk_enroll(uint32_t alg, const uint8_t* challenge, size_t challenge_len,
              const char* application, uint8_t flags, const char* pin,
              sk_option** raw_options, sk_enroll_response** enroll_response) {
    set_up_logger(LOG_NAME);

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

    spdlog::debug("Parsing CBOR response received from Windows bridge");
    auto output = parse_cbor<cbor_map>(raw_output);
    std::optional<byte_string> raw_attestation_object = output.try_at<byte_string>("attestation_object");
    if (!raw_attestation_object) {
        spdlog::critical("Missing attestation object in Windows bridge response");
        return SSH_SK_ERR_GENERAL;
    }

    spdlog::debug("Parsing CBOR attestation object");
    cbor_map attestation_object;
    std::string attestation_statement_format;

    try {
        attestation_object = parse_cbor<cbor_map>(*raw_attestation_object);
        spdlog::debug("Map keys in CBOR attestation object: {}", cbor_array{attestation_object.keys()}.dump_debug());

        attestation_statement_format = extract_attestation_object_format(attestation_object);
    } catch (const std::exception& ex) {
        spdlog::critical("Failed to parse attestation object: {}", ex.what());
        return SSH_SK_ERR_GENERAL;
    }

    authenticator_data auth_data;

    try {
        std::optional<byte_vector> raw_auth_data = attestation_object.try_at<byte_vector>("authData");
        if (!raw_auth_data) {
            spdlog::critical("Missing authenticator data from attestation object");
            return SSH_SK_ERR_GENERAL;
        }

        auth_data = authenticator_data::parse({*raw_auth_data});
        spdlog::debug("Parsed authenticator data:");
        log_multiline(auth_data.dump_debug(), "  | ");
    } catch (const std::exception& ex) {
        spdlog::critical("Failed to parse authenticator data: {}", ex.what());
        return SSH_SK_ERR_GENERAL;
    }

    spdlog::debug("Parsing attestation statement data in attestation object");
    std::optional<cbor_map> raw_attestation_statement = attestation_object.try_at<cbor_map>("attStmt");
    if (!raw_attestation_statement) {
        spdlog::critical("Missing attestation statement in attestation object");
        return SSH_SK_ERR_GENERAL;
    }

    const cbor_map& attestation_statement = *raw_attestation_statement;

    std::optional<cbor_byte_string> raw_signature = attestation_statement.try_at<cbor_byte_string>("sig");
    if (!raw_signature) {
        spdlog::critical("Missing signature in attestation statement");
        return SSH_SK_ERR_GENERAL;
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
            return SSH_SK_ERR_GENERAL;
        }

        x5c_certificate = certificate_array[0].get<cbor_byte_string>();
    } else if (attestation_statement_format != "packed") {
        // "packed" statements allow omitting an x5c element, which indicates
        // the key is performing self-attestation, but "fido-u2f" statements
        // are required to have it.
        spdlog::critical(
            "Missing certificate array in attestation statement, but self-attestation is not permitted"
        );
        return SSH_SK_ERR_GENERAL;
    } else {
        spdlog::debug("Certificate array is missing from attestation statement, assuming self-attestation");
    }

    spdlog::debug("Attestation statement parsed successfully");

    // Construct the response to send back to OpenSSH. The ownership of the
    // memory we allocate here is transferred to OpenSSH; they are responsible
    // for deallocating it.
    auto response = reinterpret_cast<sk_enroll_response*>(calloc(1, sizeof(**enroll_response)));

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

    *enroll_response = response;

    spdlog::debug("Key enrollment successfully completed");
    return 0;
}

// Sign a challenge
int sk_sign(uint32_t alg, const uint8_t* data, size_t datalen,
            const char* application, const uint8_t* key_handle, size_t key_handle_len,
            uint8_t flags, const char* pin, sk_option** raw_options,
            struct sk_sign_response** sign_response) {
    set_up_logger(LOG_NAME);

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
    spdlog::debug("Parsed authenticator data:");
    log_multiline(auth_data.dump_debug(), "  | ");

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
