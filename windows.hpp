#pragma once

// Standard C/C++ Headers:
#include <string>

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Standard C/C++ Libraries:
#include <list>

// Precompiled Headers:
#include "nstd.hpp"

namespace windows
{
    namespace process
    {
        struct process_info
        {
            DWORD process_id;
            std::wstring process_name;
        };

        std::list<process_info> list_processes();

        class process
        {
        private:
            HANDLE _handle = NULL;
        public:
            process(DWORD process_id, DWORD desired_access = PROCESS_ALL_ACCESS);
            ~process();

            bool search_memory(const void* data, size_t size);
        };
    }
}


namespace windows
{
    namespace registry
    {
        class key
        {
        private:
            HKEY _key = NULL; // a valid value must not be NULL. Reference: https://stackoverflow.com/a/65723594
        public:
            key(const std::string& sub, DWORD desired_access = KEY_ALL_ACCESS);
            key(const key& key) = delete;
            key(HKEY&& key) noexcept;
            key(key&& key) noexcept;
            ~key();

            key create_key(const std::string& name, DWORD desired_access = KEY_ALL_ACCESS);

            void set_dword(const std::string& name, DWORD value);
            void set_string(const std::string& name, const std::string& value);
            void set_expand_string(const std::string& name, const std::string& value);
            void set_multi_string(const std::string& name, const std::initializer_list<std::string>& values);
        };
    }
}


namespace windows
{
    namespace event_log
    {
        void setup(const std::string& source, DWORD bytes = 1024 * 1024);
        void report(HANDLE hLog, const std::string& log, WORD type, DWORD event_id);

        class log
        {
        private:
            HANDLE _event_source;
        public:
            log(const std::string& source);
            log(const log& key) = delete;
            log(log&& log) = delete;
            ~log();

            template<typename... Args>
            void info(const std::string& format, const Args&... args) { report(_event_source, nstd::format(format, args...), EVENTLOG_INFORMATION_TYPE, 1); }

            template<typename... Args>
            void debug(const std::string& format, const Args&... args) { report(_event_source, nstd::format(format, args...), EVENTLOG_AUDIT_SUCCESS, 1); }

            template<typename... Args>
            void warning(const std::string& format, const Args&... args) { report(_event_source, nstd::format(format, args...), EVENTLOG_WARNING_TYPE, 1); }

            template<typename... Args>
            void error(const std::string& format, const Args&... args) { report(_event_source, nstd::format(format, args...), EVENTLOG_ERROR_TYPE, 1); }
        };
    }
}