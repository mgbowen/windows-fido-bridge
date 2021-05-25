#include <windows_fido_bridge/openssh_sk_middleware.hpp>
#include <windows_fido_bridge/windows_util.hpp>

extern "C" {

#include <sk-api.h>

}  // extern "C"

namespace {

constexpr std::string_view LOG_NAME = "win32-middleware";

}  // namespace

extern "C" {

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
        LOG_NAME,
        wfb::sk_enroll_safe
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
        LOG_NAME,
        wfb::sk_sign_safe
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
