#pragma once

#include <cstdint>

// https://stackoverflow.com/a/2575145
#ifndef _WINDEF_
class HINSTANCE__;
using HINSTANCE = HINSTANCE__*;
using HMODULE = HINSTANCE;
class HWND__;
using HWND = HWND__*;
using HANDLE = void*;
using ATOM = uint16_t;
#endif
