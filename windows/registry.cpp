#include "registry.hpp"

// Standard C/C++ Libraries:
#include <map>
#include <memory>

// Precompiled Headers:
#include "../nstd.hpp"

namespace windows
{
    namespace registry
    {
        static std::map<std::wstring, HKEY> root_keys = {
            {L"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
            {L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
            {L"HKEY_CURRENT_USER", HKEY_CURRENT_USER },
            {L"HKEY_USERS", HKEY_USERS },
        };

        key::key(const std::wstring& path, DWORD desired_access)
        {
            // Trim \ character from the end of the path
            _path = std::wstring(path.begin(), std::find_if(path.begin(), path.end(), [](wchar_t ch) { return ch == L'\\'; }));

            auto root_end = path.find(L"\\");
            std::wstring root = root_end == std::wstring::npos ? path : path.substr(0, root_end);
            std::wstring sub = root_end == std::wstring::npos ? L"" : path.substr(root_end + 1);

            auto ite = root_keys.find(root);
            if (ite == root_keys.end())
                throw nstd::invalid_argument("invalid root key");
            auto status = RegOpenKeyExW(ite->second, sub.c_str(), 0, desired_access, &_handle);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("open key error: %d", status);
        };

        key::key(HKEY&& key, std::wstring&& path) noexcept : _handle(key), _path(std::move(path)) { key = NULL; }

        key::key(key&& key) noexcept : _handle(key._handle), _path(std::move(key._path))
        {
            key._handle = NULL;
            key._path.clear();
        }

        key::~key() { if (_handle != NULL) RegCloseKey(_handle); }

        const std::wstring& key::get_path() const noexcept { return _path; }

        key key::open_key(const std::wstring& key_name, DWORD desired_access) const
        {
            if (key_name.find(L"\\") != std::wstring::npos)
                throw std::invalid_argument("invalid name");

            HKEY handle;
            auto status = RegOpenKeyExW(_handle, key_name.c_str(), 0, desired_access, &handle);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("open sub key error: %d", status);
            // Clean-up
            defer{ if (handle != NULL) CloseHandle(handle); };

            return key(std::move(handle), _path + L"\\" + key_name);
        }

        key key::create_key(const std::wstring& key_name, DWORD desired_access)
        {
            if (key_name.find(L"\\") != std::wstring::npos)
                throw std::invalid_argument("invalid name");

            HKEY handle;
            auto status = RegCreateKeyExW(_handle, key_name.c_str(), NULL, NULL, 0, desired_access, NULL, &handle, NULL);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("create sub key error: %d", status);
            return key(std::move(handle), _path + L"\\" + key_name);
        }

        void key::delete_key(const std::wstring& key_name)
        {
            auto status = RegDeleteTreeW(_handle, key_name.c_str());
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("delete key error: %d", status);
        }

        void key::delete_value(const std::wstring& value_name)
        {
            auto status = RegDeleteKeyValueW(_handle, NULL, value_name.c_str());
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("delete value error: %d", status);
        }

        void key::set_dword(const std::wstring& value_name, DWORD value)
        {
            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_DWORD, &value, sizeof(value));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value dword error: %d", status);
        }

        void key::set_string(const std::wstring& value_name, const std::wstring& value)
        {
            // Size in bytes includes null terminating character.
            size_t cb_size = (value.length() + 1) * sizeof(wchar_t);
            if (cb_size > MAXDWORD)
                throw std::invalid_argument("string too long");
            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_SZ, value.c_str(), static_cast<DWORD>(cb_size));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value string error: %d", status);
        }

        void key::set_expand_string(const std::wstring& value_name, const std::wstring& value)
        {
            size_t cb_size = (value.length() + 1) * sizeof(wchar_t);
            if (cb_size > MAXDWORD)
                throw std::invalid_argument("string too long");
            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_EXPAND_SZ, value.c_str(), static_cast<DWORD>(cb_size));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value expand string error: %d", status);
        }

        void key::set_multi_string(const std::wstring& value_name, const std::list<std::wstring>& values)
        {
            size_t cb_size = 2;
            for (auto& value : values)
                cb_size += (value.length() + 1) * sizeof(wchar_t);
            if (cb_size > MAXDWORD)
                throw std::invalid_argument("string too long");

            auto buffer = std::make_unique<uint8_t[]>(cb_size);
            uint8_t* ptr = buffer.get();
            for (auto& value : values)
            {
                size_t size_to_write = (value.length() + 1) * sizeof(wchar_t);
                std::memcpy(ptr, value.c_str(), size_to_write);
                ptr += size_to_write;
            }
            // Write last terminating character
            *reinterpret_cast<wchar_t*>(ptr) = NULL;

            auto status = RegSetKeyValueW(_handle, NULL, value_name.c_str(), REG_MULTI_SZ, buffer.get(), static_cast<DWORD>(cb_size));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value multi string error: %d", status);
        }

        DWORD key::get_dword(const std::wstring& value_name) const
        {
            DWORD ret;
            DWORD cb_size = sizeof(DWORD);
            auto status = RegGetValueW(_handle, NULL, value_name.c_str(), RRF_RT_REG_DWORD, NULL, reinterpret_cast<LPBYTE>(&ret), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value dword error: %d", status);
            return ret;
        }

        std::wstring key::get_string(const std::wstring& value_name) const
        {
            DWORD type;
            DWORD cb_size = 0;
            auto status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, NULL, &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            std::wstring ret((cb_size + 1) / 2, 0);
            status = RegQueryValueExW(_handle, value_name.c_str(), NULL, &type, reinterpret_cast<LPBYTE>(&ret[0]), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);
            if (type != REG_SZ)
                throw nstd::runtime_error("type mismatch");

            ret.resize(wcsnlen(ret.c_str(), cb_size / 2));
            return ret;
        }

        std::wstring key::get_expand_string(const std::wstring& value_name, bool expand) const
        {
            DWORD cb_size = 0;
            auto status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, NULL, &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            DWORD type;
            std::wstring ret((cb_size + 1) / 2, 0);
            status = RegQueryValueExW(_handle, value_name.c_str(), NULL, &type, reinterpret_cast<LPBYTE>(&ret[0]), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read expand string error: %d", status);
            if (type != REG_EXPAND_SZ)
                throw nstd::runtime_error("type mismatch");
            ret.resize(wcsnlen(ret.c_str(), cb_size / 2));

            if (expand)
            {
                DWORD size = 4096;
                std::wstring temp(size, 0);
                do
                {
                    DWORD needed = ExpandEnvironmentStringsW(ret.c_str(), &temp[0], size);
                    if (needed == 0)
                        throw windows::registry::expand_error(std::to_string(GetLastError()));
                    if (needed <= size)
                    {
                        temp.resize(needed - 1);
                        break;
                    }
                    size = (size > MAXDWORD / 2) ? MAXDWORD : size * 2;
                    temp.resize(size);
                } while (true);
                ret = std::move(temp);
            }

            return ret;
        }

        std::list<std::wstring> key::get_multi_string(const std::wstring& value_name) const
        {
            DWORD cb_size = 0;
            auto status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, NULL, &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            auto buffer = std::make_unique<uint8_t[]>(cb_size);
            status = RegQueryValueExW(_handle, value_name.c_str(), NULL, NULL, buffer.get(), &cb_size);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("read value error: %d", status);

            uint8_t* ptr = buffer.get();
            std::list<std::wstring> ret;
            while (*reinterpret_cast<wchar_t*>(ptr) != NULL)
            {
                ret.emplace_back(reinterpret_cast<wchar_t*>(ptr));
                ptr += (ret.back().length() + 1) * sizeof(wchar_t);
            }
            return ret;
        }

        std::list<std::wstring> key::list_subkeys() const
        {
            DWORD count = 0;
            DWORD max_len = 0;
            auto error = RegQueryInfoKeyW(
                _handle,
                NULL,
                NULL,
                NULL,
                &count,
                &max_len,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);
            if (error != ERROR_SUCCESS)
                throw nstd::runtime_error("query key info error: %d", error);

            std::list<std::wstring> ret;
            auto name = std::make_unique<wchar_t[]>(max_len + 1);
            for (DWORD i = 0; i < count; i++)
            {
                DWORD len = max_len + 1;
                error = RegEnumKeyExW(
                    _handle,
                    i,
                    name.get(),
                    &len,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
                if (error != ERROR_SUCCESS)
                    continue;

                ret.emplace_back(&name[0], len);
            }
            return ret;
        }

        std::list<key::value_info> key::list_values() const
        {
            DWORD count = 0;
            DWORD max_len = 0;
            auto error = RegQueryInfoKeyW(
                _handle,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                &count,
                &max_len,
                NULL,
                NULL,
                NULL);
            if (error != ERROR_SUCCESS)
                throw nstd::runtime_error("list values error: %d", error);

            std::list<value_info> ret;
            auto name = std::make_unique<wchar_t[]>(max_len + 1);
            for (DWORD i = 0; i < count; i++)
            {
                DWORD len = max_len + 1;
                DWORD type;
                error = RegEnumValueW(
                    _handle,
                    i,
                    name.get(),
                    &len,
                    NULL,
                    &type,
                    NULL,
                    NULL);
                if (error != ERROR_SUCCESS)
                    continue;

                value_info info;
                info.name = std::wstring(&name[0], len);
                info.type = type;
                ret.emplace_back(std::move(info));
            }
            return ret;
        }
    }
}