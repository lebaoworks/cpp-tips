#pragma once

// Standard C/C++ Headers:
#include <string>

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Standard C/C++ Libraries:
#include <list>
#include <vector>

// Precompiled Headers:
#include "nstd.hpp"

namespace windows
{
    namespace process
    {
        struct process_info
        {
            DWORD id;
            std::wstring name;
            DWORD parent_id;
        };

        std::list<process_info> list();

        class process
        {
        private:
            HANDLE _handle = NULL;
        public:
            
            //
            // Constructors
            // 
            
            // Open current process with all access.
            process();

            // Open process with desired_access.
            process(DWORD process_id, DWORD desired_access = PROCESS_ALL_ACCESS);
            
            ~process();

            //
            // Observers
            // 

            // Get process image path.
            // Required desired_access:
            //      PROCESS_QUERY_INFORMATION
            std::wstring image_path() const;

            // Get process command line
            // Required desired_access:
            //      PROCESS_QUERY_INFORMATION
            //      PROCESS_VM_READ
            std::wstring command_line() const;

            // Check if process memory space contains data.
            // Required desired_access:
            //      PROCESS_QUERY_INFORMATION
            //      PROCESS_VM_READ
            bool search_memory(const void* data, size_t size) const;
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
            std::string _path;
            
            key(HKEY&& key, std::string&& path) noexcept;

        public:
            key(const std::string& sub, DWORD desired_access = KEY_ALL_ACCESS);
            key(const key& key) = delete;
            key(key&& key) noexcept;
            ~key();

            const std::string& get_path() const noexcept;

            key subkey(const std::string& sub_path, DWORD desired_access = KEY_ALL_ACCESS) const;

            key create_key(const std::string& name, DWORD desired_access = KEY_ALL_ACCESS);

            void set_dword(const std::string& name, DWORD value);
            void set_string(const std::string& name, const std::string& value);
            void set_expand_string(const std::string& name, const std::string& value);
            void set_multi_string(const std::string& name, const std::initializer_list<std::string>& values);

            std::vector<uint8_t> get_raw(const std::string& name, DWORD& type) const;
            DWORD get_dword(const std::string& name) const;
            std::string get_string(const std::string& name) const;
            std::string get_expand_string(const std::string& name) const;
            std::list<std::string> get_multi_string(const std::string& name) const;

            std::list<std::string> list_subkeys() const;
            std::list<std::string> list_values() const;
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