#include "binary_io.hpp"

#include <windows_fido_bridge/base64.hpp>
#include <windows_fido_bridge/communication.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

extern "C" {

#include "sk-api.h"

}

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>

#include <sys/wait.h>
#include <unistd.h>

using json = nlohmann::json;

using namespace fmt::literals;

struct attested_credential_data {
    std::array<uint8_t, 16> authenticator_attestation_guid;
    std::vector<uint8_t> id;
    std::vector<uint8_t> public_key;

    attested_credential_data(const std::vector<uint8_t>& buffer, size_t* num_bytes_parsed = nullptr)
        : attested_credential_data(buffer.data(), buffer.size(), num_bytes_parsed) {}

    attested_credential_data(const uint8_t* buffer, size_t length, size_t* num_bytes_parsed = nullptr) {

    }
};

struct authenticator_data_extension {

};

struct authenticator_data {
    std::array<uint8_t, 32> relying_party_id_hash;

    uint8_t flags;
    bool user_present_result;
    bool user_verified_result;
    bool attested_credential_data_included;
    bool extension_data_included;

    uint32_t signature_count;
    std::optional<attested_credential_data> attested_credential;
    std::optional<std::vector<authenticator_data_extension>> extensions;

    authenticator_data(const std::vector<uint8_t>& buffer) : authenticator_data(buffer.data(), buffer.size()) {}

    authenticator_data(const uint8_t* buffer, size_t length) {
        if (length < 37) {
            throw std::runtime_error("Expected at least 37 bytes, but got {} bytes"_format(length));
        }

        size_t pos = 0;

        size_t rp_id_hash_size = relying_party_id_hash.size();
        std::memcpy(relying_party_id_hash.data(), buffer, rp_id_hash_size);
        pos += rp_id_hash_size;

        flags = buffer[pos++];
        user_present_result = flags & (1 << 0);
        user_verified_result = flags & (1 << 2);
        attested_credential_data_included = flags & (1 << 6);
        extension_data_included = flags & (1 << 7);

        // Big-endian 32-bit unsigned integer
        signature_count = buffer[pos] << 24 | buffer[pos + 1] << 16 | buffer[pos + 2] << 8 | buffer[pos + 3];
        pos += 4;

        if (attested_credential_data_included) {
            // pos equals the number of bytes read so far
            size_t expected_num_bytes = pos + 18;
            if (expected_num_bytes < length) {
                throw std::runtime_error("Expected at least {} bytes, but got {} bytes"_format(expected_num_bytes, length));
            }
        }
    }

    void dump() {
        std::cerr << "Relying party ID hash: ";

        for (uint8_t byte : relying_party_id_hash) {
            std::cerr << "{:02x}"_format(byte);
        }

        std::cerr << "\n";
        std::cerr << "Flags: 0x{:02x}\n"_format(flags);
        std::cerr << "    User present result: {}\n"_format(user_present_result);
        std::cerr << "    User verified result: {}\n"_format(user_verified_result);
        std::cerr << "    Attested credential data included: {}\n"_format(attested_credential_data_included);
        std::cerr << "    Extension data included: {}\n"_format(extension_data_included);
        std::cerr << "Signature count: {}\n"_format(signature_count);
    }
};

void dump_binary(const uint8_t* buffer, size_t length) {
    for (int i = 0; i < length; i++) {
        if (i > 0 && i % 16 == 0) {
            std::cerr << ' ';

            for (int ascii_i = 0; ascii_i < 16; ascii_i++) {
                char c = buffer[((i - 1) / 16 * 16) + ascii_i];
                if (c >= 0x20 && c <= 0x7e) {
                    std::cerr << c;
                } else {
                    std::cerr << '.';
                }
            }

            std::cerr << "\n";
        }

        std::cerr << "{:02x} "_format((uint8_t)buffer[i]);
    }

    std::cerr << "\n";
}

void dump_binary(const std::vector<uint8_t>& binary) {
    dump_binary(reinterpret_cast<const uint8_t*>(binary.data()), binary.size());
}

void dump_binary(const std::string& binary) {
    dump_binary(reinterpret_cast<const uint8_t*>(binary.data()), binary.size());
}

int main() {
    using namespace wfb;

    std::string raw_contents;

    {
        std::ifstream in("/home/mgbowen/windows_fido_bridge/sample_output.json", std::ios::in | std::ios::binary);
        if (!in) {
            std::cerr << "ERROR: failed to open file\n";
            return SSH_SK_ERR_GENERAL;
        }

        in.seekg(0, std::ios::end);
        raw_contents.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&raw_contents[0], raw_contents.size());
    }

    json contents = json::parse(raw_contents);
    std::string raw_attestation_object = base64_decode(contents["attestation_object"].get<std::string>());

    std::cerr << "Raw attestation object bytes:\n";
    dump_binary(raw_attestation_object);
    std::cerr << "\n";

    json attestation_object = json::from_cbor(raw_attestation_object);
    const std::vector<uint8_t>& auth_data_bytes = *attestation_object["authData"].get_ptr<const json::binary_t*>();

    std::cerr << "Raw auth data bytes:\n";
    dump_binary(auth_data_bytes);
    std::cerr << "\n";

    authenticator_data auth_data{auth_data_bytes};
    auth_data.dump();

    return 0;
}

extern "C" {

namespace wfb {

/* Return the version of the middleware API */
uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

/* Enroll a U2F key (private key generation) */
int sk_enroll2(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
              const char *application, uint8_t flags, const char *pin,
              struct sk_option **options, struct sk_enroll_response **enroll_response) {
    std::cerr << "In sk_enroll()" << std::endl;

    std::array<int, 2> out_to_child_pipe{};
    pipe(out_to_child_pipe.data());

    std::array<int, 2> in_from_child_pipe{};
    pipe(in_from_child_pipe.data());

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork" << std::endl;
        return SSH_SK_ERR_GENERAL;
    }

    if (pid == 0) {
        // Child
        std::cerr << "In child after fork()" << std::endl;

        // Close the ends of the pipes that we don't need
        close(out_to_child_pipe[1]);
        close(in_from_child_pipe[0]);

        // Replace stdin with the read end of the output pipe
        dup2(out_to_child_pipe[0], fileno(stdin));

        // Replace stdout with the write end of the input pipe
        dup2(in_from_child_pipe[1], fileno(stdout));

        const char* windows_server_path = "/home/mgbowen/windows_fido_bridge/build/windows_server/windows_server/windows_server.exe";
        int result = execl(windows_server_path, nullptr);
        if (result == -1) {
            std::cerr << "FATAL: failed to exec (" << strerror(errno) << ")" << std::endl;
            std::flush(std::cerr);
            std::abort();
        }
    } else {
        // Parent
        std::cerr << "In parent after fork()" << std::endl;

        // Send parameters to child
        json parameters = {
            {"challenge", base64_encode(challenge, challenge_len)},
            {"application", std::string{application}},
        };

        send_message(out_to_child_pipe[1], parameters);

        std::string raw_result = receive_message(in_from_child_pipe[0]);
        json result = json::parse(raw_result);
        std::cerr << raw_result << "\n";

        pid_t wait_result = waitpid(pid, 0, 0);
        if (wait_result == -1) {
            std::cerr << "ERROR: failed to wait for child to complete" << std::endl;
            return SSH_SK_ERR_GENERAL;
        }

        std::cerr << "Wait result: " << wait_result << std::endl;
    }

    return 0;
}

/* Sign a challenge */
int sk_sign(uint32_t alg, const uint8_t *message, size_t message_len,
            const char *application, const uint8_t *key_handle, size_t key_handle_len,
            uint8_t flags, const char *pin, struct sk_option **options,
            struct sk_sign_response **sign_response) {
    return SSH_SK_ERR_UNSUPPORTED;
}

/* Enumerate all resident keys */
int sk_load_resident_keys(const char *pin, struct sk_option **options,
                          struct sk_resident_key ***rks, size_t *nrks) {
    return SSH_SK_ERR_UNSUPPORTED;
}

}  // extern "C"

}  // namespace wfb
