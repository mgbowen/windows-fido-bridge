#include "bridge.hpp"

#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/openssh.hpp>

extern "C" {

#include "sk-api.h"

}

namespace wfb {

namespace {

constexpr std::string_view LOG_NAME = "linux-middleware";

std::tuple<int, unique_sk_enroll_response_ptr> sk_enroll_safe_bridged(
    uint32_t alg,
    std::span<const uint8_t> challenge,
    std::string_view application,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
) {
    auto request_message = cbor_map({
        {"request_type", "sk_enroll"},
        {"request_parameters", cbor_map({
            {"alg", alg},
            {"challenge", challenge},
            {"application", application},
            {"flags", flags},
            {"sk_options", parsed_sk_options_to_cbor_array(sk_options)},
        })},
    });
    auto raw_request_message = dump_cbor(request_message);

    spdlog::debug("Sending CBOR to bridge: {}", request_message.dump_debug());
    byte_vector raw_response_message = invoke_windows_bridge(raw_request_message);
    auto response_message = parse_cbor<cbor_map>(raw_response_message);
    spdlog::debug("Received CBOR from bridge: {}", response_message.dump_debug());
    
    auto return_code = response_message.at<int>("return_code");
    spdlog::debug("Bridge return code: {}", return_code);

    if (return_code != 0) {
        return {-1, nullptr};
    }

    const auto& response_parameters = response_message.at<cbor_map>("response_parameters");

    unique_sk_enroll_response_ptr response(
        reinterpret_cast<sk_enroll_response*>(calloc(1, sizeof(sk_enroll_response)))
    );

    std::tie(response->public_key, response->public_key_len) =
        calloc_from_data(response_parameters.at<cbor_byte_string>("public_key"));
    std::tie(response->key_handle, response->key_handle_len) =
        calloc_from_data(response_parameters.at<cbor_byte_string>("key_handle"));
    std::tie(response->signature, response->signature_len) =
        calloc_from_data(response_parameters.at<cbor_byte_string>("signature"));
    std::tie(response->attestation_cert, response->attestation_cert_len) =
        calloc_from_data(response_parameters.at<cbor_byte_string>("attestation_cert"));
    std::tie(response->authdata, response->authdata_len) =
        calloc_from_data(response_parameters.at<cbor_byte_string>("authdata"));

    return {0, std::move(response)};
}

std::tuple<int, unique_sk_sign_response_ptr> sk_sign_safe_bridged(
    uint32_t alg,
    std::span<const uint8_t> data_bytes,
    std::string_view application,
    std::span<const uint8_t> key_handle_bytes,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
) {
    auto request_message = cbor_map({
        {"request_type", "sk_sign"},
        {"request_parameters", cbor_map({
            {"alg", alg},
            {"data", data_bytes},
            {"application", application},
            {"key_handle", key_handle_bytes},
            {"flags", flags},
            {"sk_options", parsed_sk_options_to_cbor_array(sk_options)},
        })},
    });
    auto raw_request_message = dump_cbor(request_message);

    spdlog::debug("Sending CBOR to bridge: {}", request_message.dump_debug());
    byte_vector raw_response_message = invoke_windows_bridge(raw_request_message);
    auto response_message = parse_cbor<cbor_map>(raw_response_message);
    spdlog::debug("Received CBOR from bridge: {}", response_message.dump_debug());
    
    auto return_code = response_message.at<int>("return_code");
    spdlog::debug("Bridge return code: {}", return_code);

    if (return_code != 0) {
        return {-1, nullptr};
    }

    const auto& response_parameters = response_message.at<cbor_map>("response_parameters");

    unique_sk_sign_response_ptr response(
        reinterpret_cast<sk_sign_response*>(calloc(1, sizeof(sk_sign_response)))
    );

    response->flags = response_parameters.at<uint8_t>("flags");
    response->counter = response_parameters.at<uint32_t>("counter");
    std::tie(response->sig_r, response->sig_r_len) =
        calloc_from_data(response_parameters.at<cbor_byte_string>("sig_r"));
    std::tie(response->sig_s, response->sig_s_len) =
        calloc_from_data(response_parameters.at<cbor_byte_string>("sig_s"));

    return {0, std::move(response)};
}

}  // namespace

}  // namespace wfb

extern "C" {

// Return the version of the middleware API
uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

int sk_enroll(
    uint32_t alg,
    const uint8_t* raw_challenge,
    size_t raw_challenge_size,
    const char* raw_application,
    uint8_t flags,
    const char* raw_pin,
    sk_option** raw_options,
    sk_enroll_response** enroll_response
) {
    return wfb::sk_enroll_entry_point_unsafe(
        alg,
        raw_challenge,
        raw_challenge_size,
        raw_application,
        flags,
        raw_pin,
        raw_options,
        enroll_response,
        wfb::LOG_NAME,
        wfb::sk_enroll_safe_bridged
    );
}

int sk_sign(
    uint32_t alg,
    const uint8_t* raw_data,
    size_t raw_data_size,
    const char* raw_application,
    const uint8_t* raw_key_handle,
    size_t raw_key_handle_size,
    uint8_t flags,
    const char* raw_pin,
    sk_option** raw_options,
    struct sk_sign_response** sign_response
) {
    return wfb::sk_sign_entry_point_unsafe(
        alg,
        raw_data,
        raw_data_size,
        raw_application,
        raw_key_handle,
        raw_key_handle_size,
        flags,
        raw_pin,
        raw_options,
        sign_response,
        wfb::LOG_NAME,
        wfb::sk_sign_safe_bridged
    );
}

int sk_load_resident_keys(
    const char* pin,
    sk_option** options,
    sk_resident_key*** rks,
    size_t* nrks
) {
    return SSH_SK_ERR_UNSUPPORTED;
}

}  // extern "C"
