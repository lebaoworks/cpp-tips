#include "nstd.hpp"
#include "windows.hpp"

#include <map>
#include <memory>

namespace windows
{
    namespace registry
    {
        static std::map<std::string, HKEY> root_keys = {
            {"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
            {"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
            {"HKEY_CURRENT_USER", HKEY_CURRENT_USER },
            {"HKEY_USERS", HKEY_LOCAL_MACHINE },
        };

        LSTATUS open(const std::string& path, DWORD desired_access, HKEY& hKey)
        {
            auto root_end = path.find("\\");
            if (root_end == std::string::npos)
            {
                auto ite = root_keys.find(path);
                if (ite == root_keys.end())
                    throw nstd::runtime_error("unknown root key");
                return RegOpenKeyExA(ite->second, NULL, 0, desired_access, &hKey);
            }
            auto ite = root_keys.find(path.substr(0, root_end));
            if (ite == root_keys.end())
                throw nstd::runtime_error("unknown root key");

            auto sub = path.substr(root_end + 1);
            return RegOpenKeyExA(ite->second, sub.c_str(), 0, desired_access, &hKey);
        }

        key::key(const std::string& path, DWORD access_desired)
        {
            auto status = open(path, access_desired, _key);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("open key error: %d", status);
        };

        key::key(HKEY&& key) noexcept { _key = key; }

        key::key(key&& key) noexcept
        {
            if (_key != NULL) RegCloseKey(_key);
            _key = key._key;
            key._key = NULL;
        }

        key::~key() { if (_key != NULL) RegCloseKey(_key); }

        key key::create_key(const std::string& name, DWORD access_desired)
        {
            HKEY hkey;
            auto status = RegCreateKeyExA(_key, name.c_str(), NULL, NULL, 0, access_desired, NULL, &hkey, NULL);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value dword error: %d", status);
            return key(std::move(hkey));
        }

        void key::set_dword(const std::string& name, DWORD value)
        {
            auto status = RegSetKeyValueA(_key, NULL, name.c_str(), REG_DWORD, &value, sizeof(value));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value dword error: %d", status);
        }

        void key::set_string(const std::string& name, const std::string& value)
        {
            if (value.length() >= 0xFFFFFFFF)
                throw std::runtime_error("value too long");
            auto status = RegSetKeyValueA(_key, NULL, name.c_str(), REG_SZ, value.c_str(), static_cast<DWORD>(value.length() + 1));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value string error: %d", status);
        }

        void key::set_expand_string(const std::string& name, const std::string& value)
        {
            if (value.length() >= 0xFFFFFFFF)
                throw std::runtime_error("value too long");
            auto status = RegSetKeyValueA(_key, NULL, name.c_str(), REG_EXPAND_SZ, value.c_str(), static_cast<DWORD>(value.length() + 1));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value expand string error: %d", status);
        }

        void key::set_multi_string(const std::string& name, const std::initializer_list<std::string>& values)
        {
            size_t len = 1;
            for (auto& value : values)
                len += value.length() + 1;
            if (len >= 0xFFFFFFFF)
                throw std::runtime_error("value too long");

            auto buffer = std::make_unique<char[]>(len);
            std::memset(buffer.get(), 0, len);
            auto ptr = buffer.get();
            for (auto& value : values)
            {
                std::memcpy(ptr, value.c_str(), value.length());
                ptr += value.length() + 1;
            }
            auto status = RegSetKeyValueA(_key, NULL, name.c_str(), REG_MULTI_SZ, buffer.get(), static_cast<DWORD>(len));
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value multi string error: %d", status);
        }
    }
}

namespace windows
{
    namespace event_log
    {
        void setup(const std::string& source, DWORD bytes)
        {
            auto key = windows::registry::key(R"(HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog)", REG_CREATED_NEW_KEY).create_key(source);
            key.set_dword("Retention", 0);
            key.set_dword("MaxSize", bytes);
            key.set_multi_string("Sources", { source });

            auto sub = key.create_key(source);
            sub.set_dword("CustomSource", 1);
            sub.set_expand_string("EventMessageFile", R"(%SystemRoot%\System32\EventCreate.exe)");
            sub.set_dword("TypesSupported", EVENTLOG_SUCCESS | EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE | EVENTLOG_AUDIT_SUCCESS | EVENTLOG_AUDIT_FAILURE);
        }

        void report(HANDLE hLog, const std::string& log, WORD type, DWORD event_id)
        {
            const char* s[] = { log.c_str() };
            WORD len = log.length() >= 65535 ? 65535 : static_cast<WORD>(log.length());
            if (ReportEventA(hLog, type, 0, event_id, NULL, 1, len, s, (PVOID) log.c_str()) != TRUE)
                throw nstd::runtime_error("ReportEventA error: %d", GetLastError());
        }

        log::log(const std::string& source)
        {
            _event_source = RegisterEventSourceA(NULL, source.c_str());
            if (_event_source == NULL)
                throw nstd::runtime_error("RegisterEventSource(%s) error: %d", source.c_str(), GetLastError());
        }

        log::~log()
        {
            DeregisterEventSource(_event_source);
        }


    }
}