#pragma once

#include <windows_fido_bridge/util.hpp>

#include <array>
#include <iostream>
#include <optional>
#include <sstream>

namespace wfb {

class posix_pipe {
public:
    posix_pipe();
    ~posix_pipe() noexcept;

    NON_COPYABLE(posix_pipe);
    MOVABLE(posix_pipe);

    int read_fd() const;
    int write_fd() const;

    void close_read();
    void close_write();

private:
    struct posix_pipe_fd {
        explicit posix_pipe_fd(int fd);
        ~posix_pipe_fd() noexcept;

        NON_COPYABLE(posix_pipe_fd);
        NON_MOVABLE(posix_pipe_fd);

        int fd() const noexcept;

    private:
        int _fd;
    };

    std::optional<posix_pipe_fd> _read, _write;
};

}  // namespace wfb
