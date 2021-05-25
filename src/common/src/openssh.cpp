#include <windows_fido_bridge/openssh.hpp>

#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/util.hpp>

#include <spdlog/spdlog.h>

extern "C" {

#include <sk-api.h>

}

#include <iostream>

// Validate OpenSSH constant forward declarations.
static_assert(
    SSH_SK_ERR_GENERAL == wfb::detail::ssh_sk_error_code_general,
    "Forward declaration of SSH_SK_ERR_GENERAL is inconsistent"
);

namespace wfb {

namespace {

void log_sk_options(std::span<const parsed_sk_option> options, std::string_view indent_str);

}  // namespace

std::vector<parsed_sk_option> parse_sk_options(const sk_option* const* raw_options) {
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

cbor_array parsed_sk_options_to_cbor_array(std::span<const parsed_sk_option> sk_options) {
    cbor_array result;

    for (const parsed_sk_option& sk_option : sk_options) {
        result.push_back(cbor_map({
            {"name", sk_option.name},
            {"value", sk_option.value},
            {"required", sk_option.required ? 1 : 0},
        }));
    }

    return result;
}

std::vector<parsed_sk_option> cbor_array_to_parsed_sk_options(cbor_array sk_options) {
    std::vector<parsed_sk_option> result;

    for (cbor_value sk_option_value : sk_options.vector()) {
        auto sk_option_map = sk_option_value.get<cbor_map>();

        result.push_back(parsed_sk_option{
            .name = sk_option_map.at<cbor_text_string>("name"),
            .value = sk_option_map.at<cbor_text_string>("value"),
            .required = sk_option_map.at<cbor_integer>("required") != 0,
        });
    }

    return result;
}

void dump_sk_enroll_inputs(
    uint32_t alg,
    std::span<const uint8_t> challenge,
    std::string_view application,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
) {
    spdlog::debug("Parameters from OpenSSH:");
    spdlog::debug("    Algorithm: {}", alg);
    spdlog::debug("    Challenge:");
    log_multiline_binary(challenge, "      | ");
    spdlog::debug("    Application: \"{}\"", application);
    spdlog::debug("    Flags: 0b{:08b}", flags);
    spdlog::debug("    PIN: {}", !pin.empty() ? "(present)" : "(not present)");
    spdlog::debug("    Options:");
    log_sk_options(sk_options, "        ");
}

void dump_sk_sign_inputs(
    uint32_t alg,
    std::span<const uint8_t> data_bytes,
    std::string_view application,
    std::span<const uint8_t> key_handle_bytes,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
) {
    spdlog::debug("Parameters from OpenSSH:");
    spdlog::debug("    Algorithm: {}", alg);
    spdlog::debug("    Data:");
    log_multiline_binary(data_bytes, "      | ");
    spdlog::debug("    Application: \"{}\"", application);
    spdlog::debug("    Key handle:");
    log_multiline_binary(key_handle_bytes, "      | ");
    spdlog::debug("    Flags: 0b{:08b}", flags);
    spdlog::debug("    PIN: {}", !pin.empty() ? "(present)" : "(not present)");
    spdlog::debug("    Options:");
    log_sk_options(sk_options, "        ");
}

void sk_enroll_response_deleter::operator()(sk_enroll_response* ptr) const noexcept {
    
}

void sk_sign_response_deleter::operator()(sk_sign_response* ptr) const noexcept {
    
}

namespace {

void log_sk_options(std::span<const parsed_sk_option> options, std::string_view indent_str) {
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

}  // namespace

}  // namespace wfb
