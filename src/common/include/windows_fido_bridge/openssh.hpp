#pragma once

#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

#include <spdlog/spdlog.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

// OpenSSH forward declarations.
struct sk_option;
struct sk_enroll_response;
struct sk_sign_response;

namespace wfb {

namespace detail {

// OpenSSH constant forward declaration.
constexpr const unsigned int ssh_sk_error_code_general = -1;

}  // namespace detail

struct parsed_sk_option {
    std::string name;
    std::string value;
    bool required{false};
};

std::vector<parsed_sk_option> parse_sk_options(const sk_option* const* raw_options);

cbor_array parsed_sk_options_to_cbor_array(std::span<const parsed_sk_option> sk_options);
std::vector<parsed_sk_option> cbor_array_to_parsed_sk_options(cbor_array sk_options);

void dump_sk_enroll_inputs(
    uint32_t alg,
    std::span<const uint8_t> challenge,
    std::string_view application,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
);

void dump_sk_sign_inputs(
    uint32_t alg,
    std::span<const uint8_t> data_bytes,
    std::string_view application,
    std::span<const uint8_t> key_handle_bytes,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
);

struct sk_enroll_response_deleter {
    void operator()(sk_enroll_response* ptr) const noexcept;
};

using unique_sk_enroll_response_ptr = std::unique_ptr<sk_enroll_response, sk_enroll_response_deleter>;

struct sk_sign_response_deleter {
    void operator()(sk_sign_response* ptr) const noexcept;
};

using unique_sk_sign_response_ptr = std::unique_ptr<sk_sign_response, sk_sign_response_deleter>;

template <typename SafeSkEnrollEntryPoint>
int sk_enroll_entry_point_unsafe(
    uint32_t alg,
    const uint8_t* raw_challenge,
    size_t raw_challenge_size,
    const char* raw_application,
    uint8_t flags,
    const char* raw_pin,
    sk_option** raw_options,
    sk_enroll_response** enroll_response,
    std::string_view log_name,
    SafeSkEnrollEntryPoint safe_sk_enroll_entry_point
) {
    try {
        set_up_logger(log_name);

        std::span<const uint8_t> challenge{raw_challenge, raw_challenge_size};
        std::string_view application = possibly_null_c_str_to_string_view(raw_application);
        std::string_view pin = possibly_null_c_str_to_string_view(raw_pin);
        std::vector<parsed_sk_option> sk_options = parse_sk_options(raw_options);

        dump_sk_enroll_inputs(alg, challenge, application, flags, pin, sk_options);

        int return_code;
        unique_sk_enroll_response_ptr response_ptr;

        std::tie(return_code, response_ptr) = safe_sk_enroll_entry_point(
            alg, challenge, application, flags, pin, sk_options
        );

        if (return_code != 0) {
            return return_code;
        }

        *enroll_response = response_ptr.release();
        return 0;
    } catch (const std::exception& ex) {
        spdlog::critical(ex.what());
        return detail::ssh_sk_error_code_general;
    } catch (...) {
        spdlog::critical("Unknown error");
        return detail::ssh_sk_error_code_general;
    }
}

template <typename SafeSkSignEntryPoint>
int sk_sign_entry_point_unsafe(
    uint32_t alg,
    const uint8_t* raw_data,
    size_t raw_data_size,
    const char* raw_application,
    const uint8_t* raw_key_handle,
    size_t raw_key_handle_size,
    uint8_t flags,
    const char* raw_pin,
    sk_option** raw_options,
    struct sk_sign_response** sign_response,
    std::string_view log_name,
    SafeSkSignEntryPoint safe_sk_sign_entry_point
) {
    try {
        set_up_logger(log_name);

        std::span<const uint8_t> data{raw_data, raw_data_size};
        std::string_view application = possibly_null_c_str_to_string_view(raw_application);
        std::span<const uint8_t> key_handle{raw_key_handle, raw_key_handle_size};
        std::string_view pin = possibly_null_c_str_to_string_view(raw_pin);
        std::vector<parsed_sk_option> options = parse_sk_options(raw_options);

        int return_code;
        unique_sk_sign_response_ptr response_ptr;

        std::tie(return_code, response_ptr) = safe_sk_sign_entry_point(
            alg, data, application, key_handle, flags, pin, options
        );

        if (return_code != 0) {
            return return_code;
        }

        *sign_response = response_ptr.release();
        return 0;
    } catch (const std::exception& ex) {
        spdlog::critical(ex.what());
        return detail::ssh_sk_error_code_general;
    } catch (...) {
        spdlog::critical("Unknown error");
        return detail::ssh_sk_error_code_general;
    }
}

}  // namespace wfb
