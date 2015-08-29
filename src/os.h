#ifndef __OS_H__
#define __OS_H__

#undef OS_WINDOWS
#undef OS_UNIX
#undef OS_MAC_OSX
#undef OS_LINUX

#if defined(__APPLE__) || defined(__MACH__)
#define OS_MAC_OSX
#endif

#if defined(__unix__) || defined(__unix)
#define OS_UNIX
#endif

#if defined(_WIN32) || defined(_WIN64)
#define OS_WINDOWS
#endif

#if defined(__linux__)
#define OS_LINUX
#endif

#endif