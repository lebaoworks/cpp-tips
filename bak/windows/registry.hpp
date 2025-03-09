#pragma once

// Standard C/C++ Headers:
#include <string>
#include <stdexcept>
#include <list>

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

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