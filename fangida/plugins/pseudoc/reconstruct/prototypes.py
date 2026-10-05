"""常见 C 库函数的小型原型表与格式串实参计数。

原型只用于"名字已由 Loader/链接证据给出"的调用目标：名字来自符号表、导入表或
已验证的 PLT/桩函数链接，本模块不猜测名字。原型给出固定参数的个数、类型与名字，
以及可变参数函数的格式串位置；可变参数的个数只在格式串可完整解析时才确定。
类型名只使用 valid_type 接受的标量/指针名（FILE * 等写成 void *）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Prototype:
    """一个已知函数的声明：返回类型、固定参数 (名字, 类型)、是否可变参数、格式串参数下标。"""
    name: str
    return_type: str
    parameters: tuple[tuple[str, str], ...]
    variadic: bool = False
    format_index: int | None = None   # printf/scanf 家族的格式串参数位置
    format_kind: str = ""             # "printf" 或 "scanf"
    returns_name: str = ""            # 用于给接收返回值的变量起名
    noreturn: bool = False


def _p(name, return_type, *parameters, variadic=False, format_index=None, format_kind="", returns="", noreturn=False):
    return Prototype(name, return_type, tuple(parameters), variadic, format_index, format_kind, returns, noreturn)


# 名字 → 原型。参数名尽量直观（str/format/size/ptr…），供参数改名与阅读。
_TABLE = (
    # 标准输出与格式化
    _p("puts", "int32_t", ("str", "const char *")),
    _p("putchar", "int32_t", ("ch", "int32_t")),
    _p("getchar", "int32_t", returns="ch"),
    _p("fputs", "int32_t", ("str", "const char *"), ("stream", "void *")),
    _p("fputc", "int32_t", ("ch", "int32_t"), ("stream", "void *")),
    _p("putc", "int32_t", ("ch", "int32_t"), ("stream", "void *")),
    _p("fgetc", "int32_t", ("stream", "void *"), returns="ch"),
    _p("getc", "int32_t", ("stream", "void *"), returns="ch"),
    _p("fgets", "char *", ("buf", "char *"), ("size", "int32_t"), ("stream", "void *"), returns="line"),
    _p("printf", "int32_t", ("format", "const char *"), variadic=True, format_index=0, format_kind="printf"),
    _p("fprintf", "int32_t", ("stream", "void *"), ("format", "const char *"), variadic=True, format_index=1, format_kind="printf"),
    _p("dprintf", "int32_t", ("fd", "int32_t"), ("format", "const char *"), variadic=True, format_index=1, format_kind="printf"),
    _p("sprintf", "int32_t", ("buf", "char *"), ("format", "const char *"), variadic=True, format_index=1, format_kind="printf"),
    _p("snprintf", "int32_t", ("buf", "char *"), ("size", "size_t"), ("format", "const char *"), variadic=True, format_index=2, format_kind="printf"),
    _p("asprintf", "int32_t", ("out", "char **"), ("format", "const char *"), variadic=True, format_index=1, format_kind="printf"),
    _p("scanf", "int32_t", ("format", "const char *"), variadic=True, format_index=0, format_kind="scanf"),
    _p("fscanf", "int32_t", ("stream", "void *"), ("format", "const char *"), variadic=True, format_index=1, format_kind="scanf"),
    _p("sscanf", "int32_t", ("str", "const char *"), ("format", "const char *"), variadic=True, format_index=1, format_kind="scanf"),
    _p("vprintf", "int32_t", ("format", "const char *"), ("args", "void *")),
    _p("vfprintf", "int32_t", ("stream", "void *"), ("format", "const char *"), ("args", "void *")),
    _p("vsnprintf", "int32_t", ("buf", "char *"), ("size", "size_t"), ("format", "const char *"), ("args", "void *")),
    _p("perror", "void", ("str", "const char *")),
    # 字符串
    _p("strlen", "size_t", ("str", "const char *"), returns="length"),
    _p("strnlen", "size_t", ("str", "const char *"), ("max_length", "size_t"), returns="length"),
    _p("strcmp", "int32_t", ("left", "const char *"), ("right", "const char *"), returns="cmp"),
    _p("strncmp", "int32_t", ("left", "const char *"), ("right", "const char *"), ("n", "size_t"), returns="cmp"),
    _p("strcasecmp", "int32_t", ("left", "const char *"), ("right", "const char *"), returns="cmp"),
    _p("strncasecmp", "int32_t", ("left", "const char *"), ("right", "const char *"), ("n", "size_t"), returns="cmp"),
    _p("strcpy", "char *", ("dst", "char *"), ("src", "const char *")),
    _p("strncpy", "char *", ("dst", "char *"), ("src", "const char *"), ("n", "size_t")),
    _p("strlcpy", "size_t", ("dst", "char *"), ("src", "const char *"), ("size", "size_t")),
    _p("strcat", "char *", ("dst", "char *"), ("src", "const char *")),
    _p("strncat", "char *", ("dst", "char *"), ("src", "const char *"), ("n", "size_t")),
    _p("strlcat", "size_t", ("dst", "char *"), ("src", "const char *"), ("size", "size_t")),
    _p("strchr", "char *", ("str", "const char *"), ("ch", "int32_t"), returns="found"),
    _p("strrchr", "char *", ("str", "const char *"), ("ch", "int32_t"), returns="found"),
    _p("strstr", "char *", ("haystack", "const char *"), ("needle", "const char *"), returns="found"),
    _p("strdup", "char *", ("str", "const char *"), returns="copy"),
    _p("strndup", "char *", ("str", "const char *"), ("n", "size_t"), returns="copy"),
    _p("strtok", "char *", ("str", "char *"), ("delimiters", "const char *"), returns="token"),
    _p("strerror", "char *", ("error", "int32_t"), returns="message"),
    _p("atoi", "int32_t", ("str", "const char *"), returns="number"),
    _p("atol", "long", ("str", "const char *"), returns="number"),
    _p("strtol", "long", ("str", "const char *"), ("end", "char **"), ("base", "int32_t"), returns="number"),
    _p("strtoul", "long", ("str", "const char *"), ("end", "char **"), ("base", "int32_t"), returns="number"),
    _p("strtoll", "int64_t", ("str", "const char *"), ("end", "char **"), ("base", "int32_t"), returns="number"),
    _p("strtoull", "uint64_t", ("str", "const char *"), ("end", "char **"), ("base", "int32_t"), returns="number"),
    # 内存
    _p("memcpy", "void *", ("dst", "void *"), ("src", "const void *"), ("n", "size_t")),
    _p("memmove", "void *", ("dst", "void *"), ("src", "const void *"), ("n", "size_t")),
    _p("memset", "void *", ("dst", "void *"), ("value", "int32_t"), ("n", "size_t")),
    _p("memcmp", "int32_t", ("left", "const void *"), ("right", "const void *"), ("n", "size_t"), returns="cmp"),
    _p("memchr", "void *", ("ptr", "const void *"), ("value", "int32_t"), ("n", "size_t"), returns="found"),
    _p("bzero", "void", ("dst", "void *"), ("n", "size_t")),
    _p("malloc", "void *", ("size", "size_t"), returns="buffer"),
    _p("calloc", "void *", ("count", "size_t"), ("size", "size_t"), returns="buffer"),
    _p("realloc", "void *", ("ptr", "void *"), ("size", "size_t"), returns="buffer"),
    _p("free", "void", ("ptr", "void *")),
    # 文件与 I/O
    _p("fopen", "void *", ("path", "const char *"), ("mode", "const char *"), returns="file"),
    _p("fdopen", "void *", ("fd", "int32_t"), ("mode", "const char *"), returns="file"),
    _p("fclose", "int32_t", ("stream", "void *")),
    _p("fflush", "int32_t", ("stream", "void *")),
    _p("fread", "size_t", ("ptr", "void *"), ("size", "size_t"), ("count", "size_t"), ("stream", "void *"), returns="count"),
    _p("fwrite", "size_t", ("ptr", "const void *"), ("size", "size_t"), ("count", "size_t"), ("stream", "void *"), returns="count"),
    _p("fseek", "int32_t", ("stream", "void *"), ("offset", "long"), ("whence", "int32_t")),
    _p("ftell", "long", ("stream", "void *"), returns="position"),
    _p("open", "int32_t", ("path", "const char *"), ("flags", "int32_t"), variadic=True, returns="fd"),
    _p("close", "int32_t", ("fd", "int32_t")),
    _p("read", "long", ("fd", "int32_t"), ("buf", "void *"), ("count", "size_t"), returns="count"),
    _p("write", "long", ("fd", "int32_t"), ("buf", "const void *"), ("count", "size_t"), returns="count"),
    _p("lseek", "int64_t", ("fd", "int32_t"), ("offset", "int64_t"), ("whence", "int32_t"), returns="position"),
    _p("unlink", "int32_t", ("path", "const char *")),
    _p("access", "int32_t", ("path", "const char *"), ("mode", "int32_t")),
    # _FORTIFY_SOURCE 检查版本
    _p("__printf_chk", "int32_t", ("flag", "int32_t"), ("format", "const char *"), variadic=True, format_index=1, format_kind="printf"),
    _p("__fprintf_chk", "int32_t", ("stream", "void *"), ("flag", "int32_t"), ("format", "const char *"), variadic=True, format_index=2, format_kind="printf"),
    _p("__sprintf_chk", "int32_t", ("buf", "char *"), ("flag", "int32_t"), ("buf_size", "size_t"), ("format", "const char *"), variadic=True, format_index=3, format_kind="printf"),
    _p("__snprintf_chk", "int32_t", ("buf", "char *"), ("size", "size_t"), ("flag", "int32_t"), ("buf_size", "size_t"), ("format", "const char *"), variadic=True, format_index=4, format_kind="printf"),
    _p("__memcpy_chk", "void *", ("dst", "void *"), ("src", "const void *"), ("n", "size_t"), ("dst_size", "size_t")),
    _p("__memmove_chk", "void *", ("dst", "void *"), ("src", "const void *"), ("n", "size_t"), ("dst_size", "size_t")),
    _p("__memset_chk", "void *", ("dst", "void *"), ("value", "int32_t"), ("n", "size_t"), ("dst_size", "size_t")),
    _p("__strcpy_chk", "char *", ("dst", "char *"), ("src", "const char *"), ("dst_size", "size_t")),
    _p("__strcat_chk", "char *", ("dst", "char *"), ("src", "const char *"), ("dst_size", "size_t")),
    _p("__strncpy_chk", "char *", ("dst", "char *"), ("src", "const char *"), ("n", "size_t"), ("dst_size", "size_t")),
    _p("__puts_chk", "int32_t", ("str", "const char *")),
    # 进程与环境
    _p("atexit", "int32_t", ("callback", "void *")),
    _p("__cxa_atexit", "int32_t", ("destructor", "void *"), ("object", "void *"), ("dso_handle", "void *")),
    _p("__cxa_finalize", "void", ("dso_handle", "void *")),
    _p("__strchr_chk", "char *", ("text", "const char *"), ("value", "int32_t"), ("size", "size_t"), returns="found"),
    _p("kill", "int32_t", ("pid", "int32_t"), ("signal", "int32_t")),
    _p("exit", "void", ("status", "int32_t"), noreturn=True),
    _p("_exit", "void", ("status", "int32_t"), noreturn=True),
    _p("abort", "void", noreturn=True),
    _p("__stack_chk_fail", "void", noreturn=True),
    _p("getenv", "char *", ("name", "const char *"), returns="value"),
    _p("system", "int32_t", ("command", "const char *")),
    _p("sleep", "uint32_t", ("seconds", "uint32_t")),
    _p("time", "int64_t", ("out", "int64_t *"), returns="now"),
    _p("rand", "int32_t", returns="random"),
    _p("srand", "void", ("seed", "uint32_t")),
    _p("toupper", "int32_t", ("ch", "int32_t")),
    _p("tolower", "int32_t", ("ch", "int32_t")),
    _p("isatty", "int32_t", ("fd", "int32_t")),
    _p("getpid", "int32_t", returns="pid"),
    _p("fork", "int32_t", returns="pid"),
)

# 常见 Windows API（kernel32/user32）。HANDLE/HMODULE/指针写成 void *，DWORD/UINT 写成 uint32_t，
# BOOL 写成 int32_t，LPCWSTR 写成 const wchar_t *（PE 宽字符串字面量写作 L"..."）。
_WINDOWS = (
    _p("GetModuleHandleW", "void *", ("module_name", "const wchar_t *"), returns="module"),
    _p("GetModuleHandleA", "void *", ("module_name", "const char *"), returns="module"),
    _p("GetProcAddress", "void *", ("module", "void *"), ("proc_name", "const char *"), returns="proc"),
    _p("LoadLibraryW", "void *", ("file_name", "const wchar_t *"), returns="module"),
    _p("LoadLibraryA", "void *", ("file_name", "const char *"), returns="module"),
    _p("LoadLibraryExW", "void *", ("file_name", "const wchar_t *"), ("file", "void *"), ("flags", "uint32_t"), returns="module"),
    _p("LoadLibraryExA", "void *", ("file_name", "const char *"), ("file", "void *"), ("flags", "uint32_t"), returns="module"),
    _p("FreeLibrary", "int32_t", ("module", "void *")),
    _p("GetModuleFileNameW", "uint32_t", ("module", "void *"), ("file_name", "wchar_t *"), ("size", "uint32_t"), returns="length"),
    _p("GetModuleFileNameA", "uint32_t", ("module", "void *"), ("file_name", "char *"), ("size", "uint32_t"), returns="length"),
    _p("ExitProcess", "void", ("exit_code", "uint32_t"), noreturn=True),
    _p("TerminateProcess", "int32_t", ("process", "void *"), ("exit_code", "uint32_t")),
    _p("GetLastError", "uint32_t", returns="error"),
    _p("SetLastError", "void", ("error", "uint32_t")),
    _p("Sleep", "void", ("milliseconds", "uint32_t")),
    _p("CloseHandle", "int32_t", ("handle", "void *")),
    _p("GetCurrentProcess", "void *", returns="process"),
    _p("GetCurrentProcessId", "uint32_t", returns="pid"),
    _p("GetCurrentThread", "void *", returns="thread"),
    _p("GetCurrentThreadId", "uint32_t", returns="tid"),
    _p("GetStdHandle", "void *", ("std_handle", "uint32_t"), returns="handle"),
    _p("WaitForSingleObject", "uint32_t", ("handle", "void *"), ("milliseconds", "uint32_t"), returns="wait_result"),
    _p("GetExitCodeProcess", "int32_t", ("process", "void *"), ("exit_code", "uint32_t *")),
    _p("GetProcessHeap", "void *", returns="heap"),
    _p("HeapAlloc", "void *", ("heap", "void *"), ("flags", "uint32_t"), ("size", "size_t"), returns="buffer"),
    _p("HeapReAlloc", "void *", ("heap", "void *"), ("flags", "uint32_t"), ("ptr", "void *"), ("size", "size_t"), returns="buffer"),
    _p("HeapFree", "int32_t", ("heap", "void *"), ("flags", "uint32_t"), ("ptr", "void *")),
    _p("HeapSize", "size_t", ("heap", "void *"), ("flags", "uint32_t"), ("ptr", "const void *"), returns="size"),
    _p("VirtualAlloc", "void *", ("address", "void *"), ("size", "size_t"), ("allocation_type", "uint32_t"), ("protect", "uint32_t"), returns="buffer"),
    _p("VirtualFree", "int32_t", ("address", "void *"), ("size", "size_t"), ("free_type", "uint32_t")),
    _p("VirtualProtect", "int32_t", ("address", "void *"), ("size", "size_t"), ("new_protect", "uint32_t"), ("old_protect", "uint32_t *")),
    _p("VirtualQuery", "size_t", ("address", "const void *"), ("buffer", "void *"), ("length", "size_t")),
    _p("InitializeCriticalSection", "void", ("section", "void *")),
    _p("InitializeCriticalSectionAndSpinCount", "int32_t", ("section", "void *"), ("spin_count", "uint32_t")),
    _p("EnterCriticalSection", "void", ("section", "void *")),
    _p("LeaveCriticalSection", "void", ("section", "void *")),
    _p("DeleteCriticalSection", "void", ("section", "void *")),
    _p("TlsAlloc", "uint32_t", returns="tls_index"),
    _p("TlsGetValue", "void *", ("tls_index", "uint32_t"), returns="value"),
    _p("TlsSetValue", "int32_t", ("tls_index", "uint32_t"), ("value", "void *")),
    _p("TlsFree", "int32_t", ("tls_index", "uint32_t")),
    _p("GetCommandLineW", "wchar_t *", returns="command_line"),
    _p("GetCommandLineA", "char *", returns="command_line"),
    _p("GetStartupInfoW", "void", ("startup_info", "void *")),
    _p("QueryPerformanceCounter", "int32_t", ("counter", "int64_t *")),
    _p("GetSystemTimeAsFileTime", "void", ("file_time", "void *")),
    _p("GetTickCount", "uint32_t", returns="ticks"),
    _p("GetTickCount64", "uint64_t", returns="ticks"),
    _p("IsDebuggerPresent", "int32_t"),
    _p("IsProcessorFeaturePresent", "int32_t", ("feature", "uint32_t")),
    _p("SetUnhandledExceptionFilter", "void *", ("filter", "void *"), returns="previous"),
    _p("UnhandledExceptionFilter", "int32_t", ("exception_info", "void *")),
    _p("RtlCaptureContext", "void", ("context", "void *")),
    _p("InitializeSListHead", "void", ("list_head", "void *")),
    _p("SetConsoleCtrlHandler", "int32_t", ("handler", "void *"), ("add", "int32_t")),
    _p("CreateFileW", "void *", ("file_name", "const wchar_t *"), ("desired_access", "uint32_t"), ("share_mode", "uint32_t"),
       ("security_attributes", "void *"), ("creation_disposition", "uint32_t"), ("flags_and_attributes", "uint32_t"),
       ("template_file", "void *"), returns="file"),
    _p("CreateFileA", "void *", ("file_name", "const char *"), ("desired_access", "uint32_t"), ("share_mode", "uint32_t"),
       ("security_attributes", "void *"), ("creation_disposition", "uint32_t"), ("flags_and_attributes", "uint32_t"),
       ("template_file", "void *"), returns="file"),
    _p("ReadFile", "int32_t", ("file", "void *"), ("buffer", "void *"), ("bytes_to_read", "uint32_t"),
       ("bytes_read", "uint32_t *"), ("overlapped", "void *")),
    _p("WriteFile", "int32_t", ("file", "void *"), ("buffer", "const void *"), ("bytes_to_write", "uint32_t"),
       ("bytes_written", "uint32_t *"), ("overlapped", "void *")),
    _p("SetFilePointer", "uint32_t", ("file", "void *"), ("distance", "int32_t"), ("distance_high", "int32_t *"), ("method", "uint32_t")),
    _p("GetFileSize", "uint32_t", ("file", "void *"), ("size_high", "uint32_t *"), returns="size"),
    _p("MultiByteToWideChar", "int32_t", ("code_page", "uint32_t"), ("flags", "uint32_t"), ("multi_byte", "const char *"),
       ("multi_byte_length", "int32_t"), ("wide", "wchar_t *"), ("wide_length", "int32_t"), returns="length"),
    _p("WideCharToMultiByte", "int32_t", ("code_page", "uint32_t"), ("flags", "uint32_t"), ("wide", "const wchar_t *"),
       ("wide_length", "int32_t"), ("multi_byte", "char *"), ("multi_byte_length", "int32_t"),
       ("default_char", "const char *"), ("used_default_char", "int32_t *"), returns="length"),
    _p("GetEnvironmentVariableW", "uint32_t", ("name", "const wchar_t *"), ("buffer", "wchar_t *"), ("size", "uint32_t"), returns="length"),
    _p("SetEnvironmentVariableW", "int32_t", ("name", "const wchar_t *"), ("value", "const wchar_t *")),
    _p("lstrlenW", "int32_t", ("str", "const wchar_t *"), returns="length"),
    _p("lstrlenA", "int32_t", ("str", "const char *"), returns="length"),
    _p("OutputDebugStringW", "void", ("message", "const wchar_t *")),
    _p("OutputDebugStringA", "void", ("message", "const char *")),
    _p("MessageBoxW", "int32_t", ("window", "void *"), ("text", "const wchar_t *"), ("caption", "const wchar_t *"), ("type", "uint32_t")),
    _p("MessageBoxA", "int32_t", ("window", "void *"), ("text", "const char *"), ("caption", "const char *"), ("type", "uint32_t")),
    _p("wcslen", "size_t", ("str", "const wchar_t *"), returns="length"),
)

# POSIX / pthread / 网络 / 动态链接 / Android（bionic）常用接口。类型只用本模块允许的词汇：
# 结构体与句柄指针写作 void *，ssize_t/off_t/time_t 写作 int64_t，函数指针写作 void *。
_POSIX = (
    # bionic _FORTIFY_SOURCE 与内部接口
    _p("__FD_ISSET_chk", "int32_t", ("fd", "int32_t"), ("set", "const void *"), ("size", "size_t")),
    _p("__FD_SET_chk", "void", ("fd", "int32_t"), ("set", "void *"), ("size", "size_t")),
    _p("__errno", "int32_t *", returns="error_slot"),
    _p("__assert2", "void", ("file", "const char *"), ("line", "int32_t"), ("function", "const char *"),
       ("expression", "const char *"), noreturn=True),
    _p("__fgets_chk", "char *", ("dst", "char *"), ("size", "int32_t"), ("stream", "void *"), ("dst_size", "size_t"), returns="line"),
    _p("__open_2", "int32_t", ("path", "const char *"), ("flags", "int32_t"), returns="fd"),
    _p("__openat_2", "int32_t", ("dirfd", "int32_t"), ("path", "const char *"), ("flags", "int32_t"), returns="fd"),
    _p("__read_chk", "int64_t", ("fd", "int32_t"), ("buffer", "void *"), ("count", "size_t"), ("buffer_size", "size_t"), returns="count"),
    _p("__strlcpy_chk", "size_t", ("dst", "char *"), ("src", "const char *"), ("size", "size_t"), ("dst_size", "size_t")),
    _p("__strlen_chk", "size_t", ("text", "const char *"), ("size", "size_t"), returns="length"),
    _p("__strncat_chk", "char *", ("dst", "char *"), ("src", "const char *"), ("n", "size_t"), ("dst_size", "size_t")),
    _p("__strncpy_chk2", "char *", ("dst", "char *"), ("src", "const char *"), ("n", "size_t"), ("dst_size", "size_t"), ("src_size", "size_t")),
    _p("__strrchr_chk", "char *", ("text", "const char *"), ("value", "int32_t"), ("size", "size_t"), returns="found"),
    _p("__vsnprintf_chk", "int32_t", ("dst", "char *"), ("size", "size_t"), ("flags", "int32_t"), ("dst_size", "size_t"),
       ("format", "const char *"), ("arguments", "void *")),
    _p("__vsprintf_chk", "int32_t", ("dst", "char *"), ("flags", "int32_t"), ("dst_size", "size_t"),
       ("format", "const char *"), ("arguments", "void *")),
    _p("__system_property_find_nth", "void *", ("index", "uint32_t"), returns="property"),
    _p("__system_property_get", "int32_t", ("name", "const char *"), ("value", "char *"), returns="length"),
    _p("__system_property_read", "int32_t", ("property", "const void *"), ("name", "char *"), ("value", "char *"), returns="length"),
    _p("__android_log_print", "int32_t", ("priority", "int32_t"), ("tag", "const char *"), ("format", "const char *"),
       variadic=True, format_index=2, format_kind="printf"),
    _p("android_set_abort_message", "void", ("message", "const char *")),
    # 进程、时间与系统信息
    _p("getpagesize", "int32_t"), _p("getppid", "int32_t"), _p("gettid", "int32_t"), _p("getuid", "uint32_t"),
    _p("random", "int64_t"), _p("inotify_init", "int32_t", returns="fd"), _p("closelog", "void"),
    _p("sysconf", "int64_t", ("name", "int32_t")),
    _p("getauxval", "uint64_t", ("type", "uint64_t")),
    _p("uname", "int32_t", ("info", "void *")),
    _p("usleep", "int32_t", ("microseconds", "uint32_t")),
    _p("nanosleep", "int32_t", ("request", "const void *"), ("remaining", "void *")),
    _p("clock_gettime", "int32_t", ("clock", "int32_t"), ("time", "void *")),
    _p("gettimeofday", "int32_t", ("time", "void *"), ("zone", "void *")),
    _p("gmtime", "void *", ("time", "const void *")), _p("localtime", "void *", ("time", "const void *")),
    _p("mktime", "int64_t", ("time", "void *")),
    _p("waitpid", "int32_t", ("pid", "int32_t"), ("status", "int32_t *"), ("options", "int32_t")),
    _p("prctl", "int32_t", ("option", "int32_t"), variadic=True),
    _p("ptrace", "int64_t", ("request", "int32_t"), variadic=True),
    _p("syscall", "int64_t", ("number", "int64_t"), variadic=True),
    _p("openlog", "void", ("ident", "const char *"), ("option", "int32_t"), ("facility", "int32_t")),
    _p("syslog", "void", ("priority", "int32_t"), ("format", "const char *"), variadic=True, format_index=1, format_kind="printf"),
    _p("signal", "void *", ("signal", "int32_t"), ("handler", "void *")),
    _p("sigaction", "int32_t", ("signal", "int32_t"), ("action", "const void *"), ("old", "void *")),
    _p("sigaddset", "int32_t", ("set", "void *"), ("signal", "int32_t")),
    _p("sigemptyset", "int32_t", ("set", "void *")),
    _p("sem_init", "int32_t", ("semaphore", "void *"), ("shared", "int32_t"), ("value", "uint32_t")),
    # 文件系统
    _p("fcntl", "int32_t", ("fd", "int32_t"), ("command", "int32_t"), variadic=True),
    _p("ioctl", "int32_t", ("fd", "int32_t"), ("request", "int32_t"), variadic=True),
    _p("feof", "int32_t", ("stream", "void *")), _p("ferror", "int32_t", ("stream", "void *")),
    _p("pclose", "int32_t", ("stream", "void *")),
    _p("popen", "void *", ("command", "const char *"), ("mode", "const char *"), returns="stream"),
    _p("opendir", "void *", ("path", "const char *"), returns="directory"),
    _p("readdir", "void *", ("directory", "void *"), returns="entry"),
    _p("closedir", "int32_t", ("directory", "void *")),
    _p("stat", "int32_t", ("path", "const char *"), ("info", "void *")),
    _p("statfs", "int32_t", ("path", "const char *"), ("info", "void *")),
    _p("fstatat", "int32_t", ("dirfd", "int32_t"), ("path", "const char *"), ("info", "void *"), ("flags", "int32_t")),
    _p("chmod", "int32_t", ("path", "const char *"), ("mode", "uint32_t")),
    _p("mkdir", "int32_t", ("path", "const char *"), ("mode", "uint32_t")),
    _p("rmdir", "int32_t", ("path", "const char *")),
    _p("rename", "int32_t", ("old_path", "const char *"), ("new_path", "const char *")),
    _p("symlink", "int32_t", ("target", "const char *"), ("link", "const char *")),
    _p("readlink", "int64_t", ("path", "const char *"), ("buffer", "char *"), ("size", "size_t"), returns="length"),
    _p("getcwd", "char *", ("buffer", "char *"), ("size", "size_t")),
    _p("basename", "char *", ("path", "const char *")),
    _p("utimensat", "int32_t", ("dirfd", "int32_t"), ("path", "const char *"), ("times", "const void *"), ("flags", "int32_t")),
    _p("inotify_add_watch", "int32_t", ("fd", "int32_t"), ("path", "const char *"), ("mask", "uint32_t")),
    _p("poll", "int32_t", ("fds", "void *"), ("count", "uint64_t"), ("timeout", "int32_t")),
    _p("select", "int32_t", ("count", "int32_t"), ("read", "void *"), ("write", "void *"), ("error", "void *"), ("timeout", "void *")),
    # 内存映射
    _p("mmap", "void *", ("address", "void *"), ("length", "size_t"), ("protection", "int32_t"), ("flags", "int32_t"),
       ("fd", "int32_t"), ("offset", "int64_t"), returns="mapping"),
    _p("munmap", "int32_t", ("address", "void *"), ("length", "size_t")),
    _p("mprotect", "int32_t", ("address", "void *"), ("length", "size_t"), ("protection", "int32_t")),
    _p("mincore", "int32_t", ("address", "void *"), ("length", "size_t"), ("vector", "uint8_t *")),
    _p("posix_memalign", "int32_t", ("result", "void *"), ("alignment", "size_t"), ("size", "size_t")),
    # 动态链接
    _p("dlopen", "void *", ("path", "const char *"), ("flags", "int32_t"), returns="handle"),
    _p("dlsym", "void *", ("handle", "void *"), ("symbol", "const char *"), returns="symbol"),
    _p("dlclose", "int32_t", ("handle", "void *")),
    _p("dladdr", "int32_t", ("address", "const void *"), ("info", "void *")),
    _p("dl_iterate_phdr", "int32_t", ("callback", "void *"), ("data", "void *")),
    # 线程
    _p("pthread_create", "int32_t", ("thread", "void *"), ("attributes", "const void *"), ("start", "void *"), ("argument", "void *")),
    _p("pthread_once", "int32_t", ("control", "void *"), ("routine", "void *")),
    _p("pthread_key_create", "int32_t", ("key", "uint32_t *"), ("destructor", "void *")),
    _p("pthread_key_delete", "int32_t", ("key", "uint32_t")),
    _p("pthread_getspecific", "void *", ("key", "uint32_t")),
    _p("pthread_setspecific", "int32_t", ("key", "uint32_t"), ("value", "const void *")),
    _p("pthread_attr_init", "int32_t", ("attributes", "void *")),
    _p("pthread_attr_destroy", "int32_t", ("attributes", "void *")),
    _p("pthread_attr_setdetachstate", "int32_t", ("attributes", "void *"), ("state", "int32_t")),
    _p("pthread_attr_setstacksize", "int32_t", ("attributes", "void *"), ("size", "size_t")),
    _p("pthread_cond_broadcast", "int32_t", ("condition", "void *")),
    _p("pthread_cond_wait", "int32_t", ("condition", "void *"), ("mutex", "void *")),
    _p("pthread_mutex_init", "int32_t", ("mutex", "void *"), ("attributes", "const void *")),
    _p("pthread_mutex_destroy", "int32_t", ("mutex", "void *")),
    _p("pthread_mutex_lock", "int32_t", ("mutex", "void *")),
    _p("pthread_mutex_trylock", "int32_t", ("mutex", "void *")),
    _p("pthread_mutex_unlock", "int32_t", ("mutex", "void *")),
    _p("pthread_mutexattr_init", "int32_t", ("attributes", "void *")),
    _p("pthread_mutexattr_destroy", "int32_t", ("attributes", "void *")),
    _p("pthread_mutexattr_settype", "int32_t", ("attributes", "void *"), ("type", "int32_t")),
    _p("pthread_rwlock_rdlock", "int32_t", ("lock", "void *")),
    _p("pthread_rwlock_wrlock", "int32_t", ("lock", "void *")),
    _p("pthread_rwlock_unlock", "int32_t", ("lock", "void *")),
    # 网络
    _p("socket", "int32_t", ("domain", "int32_t"), ("type", "int32_t"), ("protocol", "int32_t"), returns="fd"),
    _p("bind", "int32_t", ("fd", "int32_t"), ("address", "const void *"), ("length", "uint32_t")),
    _p("listen", "int32_t", ("fd", "int32_t"), ("backlog", "int32_t")),
    _p("accept", "int32_t", ("fd", "int32_t"), ("address", "void *"), ("length", "uint32_t *"), returns="client"),
    _p("setsockopt", "int32_t", ("fd", "int32_t"), ("level", "int32_t"), ("name", "int32_t"), ("value", "const void *"), ("length", "uint32_t")),
    _p("sendto", "int64_t", ("fd", "int32_t"), ("buffer", "const void *"), ("length", "size_t"), ("flags", "int32_t"),
       ("address", "const void *"), ("address_length", "uint32_t"), returns="sent"),
    _p("recvfrom", "int64_t", ("fd", "int32_t"), ("buffer", "void *"), ("length", "size_t"), ("flags", "int32_t"),
       ("address", "void *"), ("address_length", "uint32_t *"), returns="received"),
    _p("recvmsg", "int64_t", ("fd", "int32_t"), ("message", "void *"), ("flags", "int32_t"), returns="received"),
    _p("getaddrinfo", "int32_t", ("node", "const char *"), ("service", "const char *"), ("hints", "const void *"), ("result", "void *")),
    _p("freeaddrinfo", "void", ("info", "void *")),
    _p("inet_ntoa", "char *", ("address", "uint32_t")),
    _p("inet_ntop", "const char *", ("family", "int32_t"), ("source", "const void *"), ("buffer", "char *"), ("size", "uint32_t")),
    _p("inet_pton", "int32_t", ("family", "int32_t"), ("source", "const char *"), ("buffer", "void *")),
    # 字符与字符串
    _p("isalnum", "int32_t", ("value", "int32_t")), _p("isalpha", "int32_t", ("value", "int32_t")),
    _p("isspace", "int32_t", ("value", "int32_t")),
    _p("atoll", "int64_t", ("text", "const char *")), _p("llabs", "int64_t", ("value", "int64_t")),
    _p("pow", "double", ("base", "double"), ("exponent", "double")),
    _p("strcasestr", "char *", ("text", "const char *"), ("needle", "const char *"), returns="found"),
    _p("strcoll", "int32_t", ("left", "const char *"), ("right", "const char *"), returns="cmp"),
    _p("strcspn", "size_t", ("text", "const char *"), ("reject", "const char *")),
    _p("strspn", "size_t", ("text", "const char *"), ("accept", "const char *")),
    _p("strpbrk", "char *", ("text", "const char *"), ("accept", "const char *"), returns="found"),
    _p("strtok_r", "char *", ("text", "char *"), ("delimiters", "const char *"), ("state", "void *"), returns="token"),
    _p("strxfrm", "size_t", ("dst", "char *"), ("src", "const char *"), ("n", "size_t")),
    _p("vasprintf", "int32_t", ("result", "void *"), ("format", "const char *"), ("arguments", "void *")),
)

PROTOTYPES: dict[str, Prototype] = {item.name: item for item in _TABLE + _POSIX + _WINDOWS}

# 当前函数自身名字匹配时使用的“定义”原型（不是调用目标）。
DEFINITIONS: dict[str, Prototype] = {
    "main": _p("main", "int32_t", ("argc", "int32_t"), ("argv", "char **")),
}

_VERSION = re.compile(r"@.*$")


def normalize_name(name: object) -> str:
    """去掉 Mach-O 前导下划线、ELF 版本后缀与 PE 导入前缀，得到库函数名。"""
    if not isinstance(name, str):
        return ""
    text = _VERSION.sub("", name.strip())
    for prefix in ("__imp_", "_imp__"):
        if text.startswith(prefix) and len(text) > len(prefix):
            text = text[len(prefix):]
    # Mach-O 符号带一个前导下划线；__stack_chk_fail 本身以两个下划线开头。
    if text not in PROTOTYPES and text.startswith("_") and text[1:] in PROTOTYPES:
        text = text[1:]
    if text not in PROTOTYPES and text not in DEFINITIONS and text.startswith("_") and text[1:] in DEFINITIONS:
        text = text[1:]
    return text


_LOOKUPS: dict[str, Prototype | None] = {}


def lookup(name: object) -> Prototype | None:
    """按（规范化后的）名字查找调用目标的原型；未知名字返回 None。字符串名字的结果有界缓存。"""
    if type(name) is not str:
        return PROTOTYPES.get(normalize_name(name))
    try:
        return _LOOKUPS[name]
    except KeyError:
        pass
    found = _LOOKUPS[name] = PROTOTYPES.get(normalize_name(name))
    if len(_LOOKUPS) > 8192:
        _LOOKUPS.clear()
        _LOOKUPS[name] = found
    return found


def definition(name: object) -> Prototype | None:
    """当前函数自身名字的已知定义（如 main）。"""
    return DEFINITIONS.get(normalize_name(name))


_PRINTF_FLAGS = set("-+ #0'")
_PRINTF_CONVERSIONS = {**{c: "int" for c in "diouxXcCpn"}, **{c: "pointer" for c in "sS"},
                       **{c: "float" for c in "fFeEgGaA"}, "D": "int", "O": "int", "U": "int"}
_LENGTHS = ("hh", "ll", "h", "l", "j", "z", "t", "L", "q")


def format_arguments(text: str, kind: str = "printf") -> tuple[int, int] | None:
    """返回 (整数/指针实参个数, 浮点实参个数)；无法完整解析（位置参数 %n$ 等）时返回 None。

    printf：`*` 宽度/精度各消耗一个 int 实参；%% 不消耗。
    scanf：所有转换都消耗一个指针实参，`%*d` 抑制赋值不消耗；%[...] 扫描集按指针计。
    """
    if not isinstance(text, str) or len(text) > 4096:
        return None
    integers = floats = 0
    index, length = 0, len(text)
    while index < length:
        if text[index] != "%":
            index += 1
            continue
        index += 1
        if index >= length:
            return None
        if text[index] == "%":
            index += 1
            continue
        if kind == "scanf":
            suppressed = False
            if text[index] == "*":
                suppressed, index = True, index + 1
            while index < length and text[index].isdigit():
                index += 1
            if index < length and text[index] == "$":
                return None
            for modifier in _LENGTHS:
                if text.startswith(modifier, index):
                    index += len(modifier)
                    break
            if index >= length:
                return None
            conversion = text[index]
            if conversion == "[":
                close = text.find("]", index + 2 if text.startswith("[^]", index) or text.startswith("[]", index) else index + 1)
                if close < 0:
                    return None
                index = close + 1
            elif conversion in "diouxXcspnfFeEgGaACS":
                index += 1
            else:
                return None
            if not suppressed:
                integers += 1  # scanf 的全部实参都是指针
            continue
        # printf
        start = index
        while index < length and text[index].isdigit():
            index += 1
        if index < length and text[index] == "$":
            return None  # 位置参数：不按顺序消耗，放弃推断
        index = start
        while index < length and text[index] in _PRINTF_FLAGS:
            index += 1
        if index < length and text[index] == "*":
            integers, index = integers + 1, index + 1
        else:
            while index < length and text[index].isdigit():
                index += 1
        if index < length and text[index] == ".":
            index += 1
            if index < length and text[index] == "*":
                integers, index = integers + 1, index + 1
            else:
                while index < length and text[index].isdigit():
                    index += 1
        for modifier in _LENGTHS:
            if text.startswith(modifier, index):
                index += len(modifier)
                break
        if index >= length:
            return None
        category = _PRINTF_CONVERSIONS.get(text[index])
        if category is None:
            return None
        index += 1
        if category == "float":
            floats += 1
        else:
            integers += 1
    return integers, floats


def printf_int_arguments(text: str) -> tuple[bool, ...] | None:
    """printf 格式串依次消耗的每个实参是否按 int 读取（无长度修饰或 h/hh 的 d/i/o/u/x/X/c，
    以及 `*` 宽度/精度）。含浮点转换或无法完整解析时返回 None。

    供伪 C 去掉这些实参外层到 64 位整数的转换：printf 只读取其低 32 位。
    """
    if not isinstance(text, str) or len(text) > 4096:
        return None
    kinds: list[bool] = []
    index, length = 0, len(text)
    while index < length:
        if text[index] != "%":
            index += 1
            continue
        index += 1
        if index >= length:
            return None
        if text[index] == "%":
            index += 1
            continue
        start = index
        while index < length and text[index].isdigit():
            index += 1
        if index < length and text[index] == "$":
            return None
        index = start
        while index < length and text[index] in _PRINTF_FLAGS:
            index += 1
        if index < length and text[index] == "*":
            kinds.append(True)
            index += 1
        else:
            while index < length and text[index].isdigit():
                index += 1
        if index < length and text[index] == ".":
            index += 1
            if index < length and text[index] == "*":
                kinds.append(True)
                index += 1
            else:
                while index < length and text[index].isdigit():
                    index += 1
        modifier = ""
        for candidate in _LENGTHS:
            if text.startswith(candidate, index):
                modifier = candidate
                index += len(candidate)
                break
        if index >= length:
            return None
        conversion = text[index]
        category = _PRINTF_CONVERSIONS.get(conversion)
        if category is None or category == "float":
            return None
        index += 1
        kinds.append(category == "int" and conversion in "diouxXc" and modifier in {"", "h", "hh"})
    return tuple(kinds)
