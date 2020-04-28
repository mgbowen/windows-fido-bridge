#pragma once

#include <windows_fido_bridge/types.hpp>

#include <string_view>

namespace wfb {

void send_message(int fd, std::string_view message);
void send_message(int fd, const byte_vector& message);
void send_message(int fd, const char* message_buffer, size_t message_length);
void send_message(int fd, const uint8_t* message_buffer, size_t message_length);

byte_vector receive_message(int fd);

}  // namespace wfb
