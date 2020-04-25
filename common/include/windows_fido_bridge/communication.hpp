#pragma once

#include <nlohmann/json_fwd.hpp>

#include <string>

namespace wfb {

void send_message(int fd, const std::string& message);
void send_message(int fd, const nlohmann::json& message);
std::string receive_message(int fd);

}  // namespace wfb
