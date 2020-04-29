#pragma once

#include <string>

namespace wfb {

std::wstring string_to_wide_string(const std::string& str);
std::string wide_string_to_string(const std::wstring& wide_str);

}  // namespace wfb
