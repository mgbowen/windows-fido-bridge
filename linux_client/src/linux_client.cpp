#include "binary_io.hpp"
#include "util.hpp"
#include "webauthn.hpp"

#include <windows_fido_bridge/base64.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/format.hpp>

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

extern "C" {

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
            {"challenge", wfb::base64_encode(challenge, challenge_len)},
            {"application", std::string{application}},
        };

        wfb::send_message(out_to_child_pipe[1], parameters);

        std::string raw_result = wfb::receive_message(in_from_child_pipe[0]);
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
