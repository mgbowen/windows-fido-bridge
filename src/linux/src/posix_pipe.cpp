#include "posix_pipe.hpp"

#include <windows_fido_bridge/exceptions.hpp>
#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/util.hpp>

#include <array>
#include <iostream>
#include <optional>
#include <sstream>

#include <sys/wait.h>
#include <unistd.h>

namespace wfb {

//
// posix_pipe::posix_pipe_fd
//

posix_pipe::posix_pipe_fd::posix_pipe_fd(int fd) : _fd(fd) {
    if (fd < 0) {
        throw std::invalid_argument("File descriptor {} must be >= 0"_format(fd));
    }
}

posix_pipe::posix_pipe_fd::~posix_pipe_fd() noexcept {
    if (_fd < 0) {
        return;
    }

    if (close(_fd) != 0) {
        // In a destructor, plus not much we can do anyways, so just
        // log the error and move on.
        std::stringstream ss;
        ss << "ERROR: failed to close posix pipe file descriptor {}: "_format(_fd)
            << strerror(errno) << "\n";
        std::cerr << ss.str();
    }

    _fd = -1;
}

posix_pipe::posix_pipe_fd::posix_pipe_fd(posix_pipe::posix_pipe_fd&& other) : _fd(other._fd) {
    other._fd = -1;
}

posix_pipe::posix_pipe_fd& posix_pipe::posix_pipe_fd::operator=(posix_pipe::posix_pipe_fd&& other) {
    _fd = other._fd;
    other._fd = -1;
    return *this;
}

int posix_pipe::posix_pipe_fd::fd() const noexcept { return _fd; }

//
// posix_pipe
//

posix_pipe::posix_pipe() {
    std::array<int, 2> raw_pipes{};
    if (pipe(raw_pipes.data()) != 0) {
        throw_errno_exception();
    }

    _read.emplace(raw_pipes[0]);
    _write.emplace(raw_pipes[1]);
}

posix_pipe::~posix_pipe() noexcept = default;

int posix_pipe::read_fd() const {
    if (!_read) {
        throw std::logic_error("Read end of pipe is closed");
    }

    return _read->fd();
}

int posix_pipe::write_fd() const {
    if (!_write) {
        throw std::logic_error("Write end of pipe is closed");
    }

    return _write->fd();
}

void posix_pipe::close_read() { _read.reset(); }
void posix_pipe::close_write() { _write.reset(); }

}  // namespace wfb
