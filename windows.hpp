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
    namespace file
    {
        struct file_info
        {
            std::wstring name;
            DWORD attributes;
            size_t size;
            FILETIME creation_time;
            FILETIME last_access_time;
            FILETIME last_write_time;

            /// @brief Check if the file is a directory.
            /// @return true if it is, false otherwise.
            bool is_directory() const noexcept;
        };

        /// @brief List all files in the directory.
        /// @param path directory path.
        /// @return list of files.
        std::list<file_info> list(const std::wstring& path);

    }
}

namespace windows
{
    namespace disk
    {
        /// @brief List all disks.
        /// @return list of disks.
        /// @note currently only list fixed and removable drives.
        std::list<std::string> list_logical();
    }
}

namespace windows
{
    namespace process
    {
        struct process_info
        {
            DWORD id = 0;
            std::wstring name = L"";
            DWORD parent_id = 0;
        };

        /// @brief List all running processes.
        /// @return list of processes.
        std::list<process_info> list();

        class process
        {
        private:
            HANDLE _handle = NULL;
        public:
            
            /// @brief Default constructor. Object is reference to current process.
            process();

            /// @brief Open process by process id.
            /// @param process_id process id.
            /// @param desired_access access to the process.
            process(DWORD process_id, DWORD desired_access = PROCESS_ALL_ACCESS);
            
            /// @brief Destructor.
            ~process();

            /// @brief Get process image full path.
            /// @return Full path to the process image.
            /// @note require `PROCESS_QUERY_INFORMATION` access.
            std::wstring image_path() const;

            /// @brief Get process command line.
            /// @return Command line of the process.
            /// @note require `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access.
            std::wstring command_line() const;

            /// @brief Search memory space of the process.
            /// @param data data to search.
            /// @param size size of the data.
            /// @return true if data found, false otherwise.
            /// @note require `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access.
            bool search_memory(const void* data, size_t size) const;
        };
    }
}

namespace windows
{
    namespace registry
    {
        struct expand_error : std::runtime_error
        {
            expand_error(const std::string& what) : std::runtime_error(what) {}
            ~expand_error() = default;
        };

        class key
        {
        private:
            HKEY _handle = NULL; // Valid handle should not be NULL according to https://stackoverflow.com/a/65723594.
            std::wstring _path;

            key(HKEY&& key, std::wstring&& path) noexcept;

        public:
            /// @brief Constructor.
            /// @param key_path full path to the key.
            /// @param desired_access access to the key.
            /// @exception Strong exception guarantee.
            key(const std::wstring& key_path, DWORD desired_access = KEY_ALL_ACCESS);

            key(const key& key) = delete;

            /// @brief Move constructor.
            /// @param key the key to be moved-from.
            key(key&& key) noexcept;

            /// @brief Destructor.
            ~key();

            /// @brief Get this registry key full path.
            /// @return Full path to the key.
            const std::wstring& get_path() const noexcept;

            /// @brief Open sub key.
            /// @param key_name name of the key to open.
            /// @param desired_access access to the key.
            /// @return Sub key.
            key open_key(const std::wstring& key_name, DWORD desired_access = KEY_ALL_ACCESS) const;

            /// @brief Create sub key.
            /// @param key_name name of the key to create.
            /// @param desired_access access to the key.
            /// @return Created key.
            /// @note If subkey key_name exists, open the existing key.
            /// @note require `KEY_CREATE_SUB_KEY` access.
            key create_key(const std::wstring& key_name, DWORD desired_access = KEY_ALL_ACCESS);

            /// @brief Delete sub key.
            /// @param key_name name of the key to delete.
            /// @note require `KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE` access.
            void delete_key(const std::wstring& key_name);

            /// @brief Delete key value.
            /// @param value_name name of the value to delete. 
            /// @note require `KEY_SET_VALUE` access.
            void delete_value(const std::wstring& value_name);

            /// @brief Set REG_DWORD value to registry key.
            /// @param value_name value's name.
            /// @param value DWORD to set.
            /// @note require `KEY_SET_VALUE` access.
            void set_dword(const std::wstring& value_name, DWORD value);

            /// @brief Set REG_SZ value to registry key.
            /// @param value_name value's name.
            /// @param value REG_SZ to set.
            /// @note require `KEY_SET_VALUE` access.
            void set_string(const std::wstring& value_name, const std::wstring& value);

            /// @brief Set REG_EXPAND_SZ value to registry key.
            /// @param value_name value's name.
            /// @param value REG_EXPAND_SZ to set.
            /// @note require `KEY_SET_VALUE` access.
            void set_expand_string(const std::wstring& value_name, const std::wstring& value);

            /// @brief Set REG_MULTI_SZ value to registry key.
            /// @param value_name value's name.
            /// @param values list of strings to set.
            /// @note require `KEY_SET_VALUE` access.
            void set_multi_string(const std::wstring& value_name, const std::list<std::wstring>& values);

            /// @brief get REG_DWORD value from registry key.
            /// @param value_name value's name.
            /// @return DWORD value.
            /// @note require `KEY_READ` access.
            DWORD get_dword(const std::wstring& value_name) const;

            /// @brief get REG_SZ value from registry key.
            /// @param value_name value's name.
            /// @return String value.
            std::wstring get_string(const std::wstring& value_name) const;

            /// @brief get REG_EXPAND_SZ value from registry key.
            /// @param value_name value's name.
            /// @param expand set true to expand environment variables in string value.
            /// @return String value.
            /// @note require `KEY_READ` access.
            /// @note if @p expand = true, and string value failed to expand, throws `windows::registry::expand_error`.
            std::wstring get_expand_string(const std::wstring& value_name, bool expand = false) const;

            /// @brief Get REG_MULTI_SZ value from registry key.
            /// @param value_name value's name.
            /// @return list of strings.
            /// @note require `KEY_READ` access.
            std::list<std::wstring> get_multi_string(const std::wstring& value_name) const;

            /// @brief List all sub keys of registry key.
            /// @return subkeys' name.
            /// @note require `KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS` access.
            std::list<std::wstring> list_subkeys() const;

            struct value_info
            {
                std::wstring name;
                DWORD type;
            };

            /// @brief List all value of registry key.
            /// @return value's infomation.
            /// @note require `KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS` access.
            std::list<value_info> list_values() const;
        };
    }
}

namespace windows
{
    namespace user
    {
        /// @brief Check if current process as administrator.
        /// @return true if it is, false otherwise.
        bool is_admin();
    }
}

namespace windows
{
    namespace event_log
    {
        /// @brief Setup logging source in EventLog.
        /// @param source name of source.
        /// @param bytes maximum size of the event logs in bytes.
        /// @note setup() must run in context of an administrator.
        void setup(const std::wstring& group, const std::wstring& source, DWORD bytes = 1024 * 1024);

        class log
        {
        private:
            HANDLE _event_source;

            void report(WORD type, const std::string& log);

        public:
            log(const std::wstring& source);
            log(const log& key) = delete;
            log(log&& log) = delete;
            ~log();

            template<typename... Args>
            void info(const std::string& format, const Args&... args) { report(EVENTLOG_INFORMATION_TYPE, nstd::format(format, args...)); }

            template<typename... Args>

            void debug(const std::string& format, const Args&... args) { report(EVENTLOG_AUDIT_SUCCESS, nstd::format(format, args...)); }

            template<typename... Args>
            void warning(const std::string& format, const Args&... args) { report(EVENTLOG_WARNING_TYPE, nstd::format(format, args...)); }

            template<typename... Args>
            void error(const std::string& format, const Args&... args) { report(EVENTLOG_ERROR_TYPE, nstd::format(format, args...)); }
        };
    }
}