#include "bridge.hpp"

#include "posix_pipe.hpp"

#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/exceptions.hpp>
#include <windows_fido_bridge/format.hpp>

#include <spdlog/spdlog.h>

#include <dlfcn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>

namespace fs = std::filesystem;

namespace {

// https://stackoverflow.com/a/51993539
fs::path get_library_path() {
    Dl_info dl_info;
    dladdr((void*)get_library_path, &dl_info);
    return fs::absolute(fs::path(dl_info.dli_fname));
}

}  // namespace

namespace wfb {

byte_vector invoke_windows_bridge(std::string_view args) {
    return invoke_windows_bridge(args.data(), args.size());
}

byte_vector invoke_windows_bridge(const byte_vector& args) {
    return invoke_windows_bridge(args.data(), args.size());
}

byte_vector invoke_windows_bridge(const char* buffer, size_t length) {
    return invoke_windows_bridge(reinterpret_cast<const uint8_t*>(buffer), length);
}

byte_vector invoke_windows_bridge(const uint8_t* buffer, size_t length) {
    spdlog::debug("Invoking Windows bridge with the following parameters:");
    log_multiline_binary(buffer, length, "  | ");

    posix_pipe out_to_child_pipe;
    posix_pipe in_from_child_pipe;

    spdlog::debug("Forking.");

    pid_t pid = fork();
    if (pid < 0) {
        throw_errno_exception("Failed to fork while attempting to invoke the Windows bridge");
    }

    if (pid == 0) {
        //
        // Child
        //
        try {
            // Close the ends of the pipes that we don't need
            out_to_child_pipe.close_write();
            in_from_child_pipe.close_read();

            // Replace stdin and stdout with the pipes we made earlier to allow easy
            // communication with the parent
            dup2(out_to_child_pipe.read_fd(), fileno(stdin));
            dup2(in_from_child_pipe.write_fd(), fileno(stdout));

            // We expect the Windows bridge executable to be in the same
            // directory as the OpenSSH middleware library
            fs::path middleware_library_path = get_library_path();
            spdlog::debug(
                "[Windows bridge child] Detected own library file path is \"{}\".",
                middleware_library_path.string()
            );

            std::string windows_exe_path =
                (middleware_library_path.parent_path() / "windowsfidobridge.exe").string();
            spdlog::debug(
                "[Windows bridge child] Using Windows bridge at \"{}\".", windows_exe_path
            );

            // For environment variables to be propagated between WSL and Win32
            // processes, we need to set the WSLENV environment variable, see:
            // https://devblogs.microsoft.com/commandline/share-environment-vars-between-wsl-and-windows/.
            std::string wslenv_var_name = "WSLENV";
            std::stringstream wslenv_value_ss;
            std::optional<std::string> existing_wslenv_value = get_environment_variable(wslenv_var_name);
            if (existing_wslenv_value) {
                wslenv_value_ss << *existing_wslenv_value;
            }

            constexpr std::string_view env_vars[] = {
                "WINDOWS_FIDO_BRIDGE_DEBUG",
                "WINDOWS_FIDO_BRIDGE_FORCE_USER_VERIFICATION",
            };
            for (const auto& env_var : env_vars) {
                if (wslenv_value_ss.tellp() > 0) {
                    wslenv_value_ss << ":";
                }

                wslenv_value_ss << env_var;
            }

            std::string wslenv_value = wslenv_value_ss.str();

            spdlog::debug(
                "[Windows bridge child] Setting {} environment variable to \"{}\".",
                wslenv_var_name,
                wslenv_value
            );
            setenv(wslenv_var_name.c_str(), wslenv_value.c_str(), 1);

            spdlog::debug("[Windows bridge child] Execing.");
            execl(windows_exe_path.c_str(), windows_exe_path.c_str(), nullptr);

            // exec* should not return; if we get to this point, it failed
            throw_errno_exception("Failed to exec into Windows bridge at \"{}\""_format(windows_exe_path));
        } catch (const std::exception& ex) {
            std::cerr << "ERROR: caught exception while attempting to invoke the Windows bridge: "
                         "{}\nAborting\n"_format(ex.what());
            std::fflush(stderr);
            std::abort();
        } catch (...) {
            std::cerr << "ERROR: caught unknown exception attempting to invoke the Windows bridge\n"
                         "Aborting\n";
            std::fflush(stderr);
            std::abort();
        }
    }

    //
    // Parent
    //

    spdlog::debug("Child process PID = {}", pid);

    // Close the ends of the pipes that we don't need
    out_to_child_pipe.close_read();
    in_from_child_pipe.close_write();

    // Send parameters to the child process
    spdlog::debug("Sending parameters to child process.");
    wfb::send_message(out_to_child_pipe.write_fd(), buffer, length);

    // Receive the output back
    spdlog::debug("Parameters sent to child process, waiting for reply.");
    byte_vector output = receive_message(in_from_child_pipe.read_fd());

    spdlog::debug("Reply received from child process:");
    log_multiline_binary(output.data(), output.size(), "  | ");

    spdlog::debug("Waiting for child process to exit.");

    int status = 0;
    pid_t wait_result = waitpid(pid, &status, 0);
    if (wait_result == -1 || !WIFEXITED(status)) {
        throw_errno_exception("Failed to wait for child process while invoking the Windows bridge");
    }

    int exit_code = WEXITSTATUS(status);
    if (exit_code != 0) {
        throw std::runtime_error("Child process exited with code {}"_format(exit_code));
    }

    return output;
}

}  // namespace wfb
