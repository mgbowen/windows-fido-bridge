#include "bridge.hpp"

#include "posix_pipe.hpp"

#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/exceptions.hpp>
#include <windows_fido_bridge/format.hpp>

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
    return dl_info.dli_fname;
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
    posix_pipe out_to_child_pipe;
    posix_pipe in_from_child_pipe;

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
            std::string windows_exe_path = (get_library_path().parent_path() / "windowsfidobridge.exe").string();
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

    // Close the ends of the pipes that we don't need
    out_to_child_pipe.close_read();
    in_from_child_pipe.close_write();

    // Send parameters to the child process
    wfb::send_message(out_to_child_pipe.write_fd(), buffer, length);

    // Receive the output back
    byte_vector output = receive_message(in_from_child_pipe.read_fd());

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
