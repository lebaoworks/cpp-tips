#include "windows.hpp"

// Standard C/C++ Libraries:
#include <map>
#include <memory>

// Standard Windows Headers:
#include <tlhelp32.h>

namespace windows
{
    namespace process
    {
        std::list<process_info> list_processes()
        {
            auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                throw nstd::runtime_error("snapshot process error %d", GetLastError());
            defer { CloseHandle(snapshot); };

            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(snapshot, &pe) == FALSE)
                throw nstd::runtime_error("find snapshot first process error: %d", GetLastError());
            
            std::list<process_info> ret;
            do
            {
                process_info pi;
                pi.process_id = pe.th32ProcessID;
                pi.process_name = pe.szExeFile;
                ret.emplace_back(std::move(pi));
            } while (Process32NextW(snapshot, &pe));

            return ret;
        }

        process::process(DWORD process_id, DWORD desired_access)
        {
            _handle = OpenProcess(desired_access, FALSE, process_id);
            if (_handle == NULL)
                throw nstd::runtime_error("open process error %d", GetLastError());
        }
        
        process::~process()
        {
            CloseHandle(_handle);
        }

        bool process::search_memory(const void* data, size_t size)
        {
            if (data == nullptr)
                throw std::invalid_argument("null data");

            SYSTEM_INFO si;
            GetSystemInfo(&si);

            MEMORY_BASIC_INFORMATION info;
            std::vector<uint8_t> chunk(0x10000);
            void* p = nullptr;
            while (p < si.lpMaximumApplicationAddress)
            {
                if (VirtualQueryEx(_handle, p, &info, sizeof(info)) != sizeof(info))
                    break;
                p = info.BaseAddress;
                if (info.AllocationProtect != 0 &&
                    info.Protect != 0 &&
                    info.State != MEM_RESERVE)
                {
                    chunk.resize(info.RegionSize);
                    SIZE_T read;
                    if (ReadProcessMemory(_handle, p, &chunk[0], info.RegionSize, &read))
                        for (size_t i = 0; i < (read - size); ++i)
                            if (memcmp(data, &chunk[i], size) == 0)
                                return true;
                }
                p = reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(p) + info.RegionSize);
            }
            return false;
        }
    }
}

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

            auto sub = nstd::encoding::utf8_to_wide(path.substr(root_end + 1));
            return RegOpenKeyExW(ite->second, sub.c_str(), 0, desired_access, &hKey);
        }

        key::key(const std::string& path, DWORD desired_access) : _path(path)
        {
            auto status = open(path, desired_access, _key);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("open key error: %d", status);
        };

        key::key(HKEY&& key, std::string&& path) noexcept : _path(std::move(path)), _key(key) {}

        key::key(key&& key) noexcept : _key(key._key), _path(std::move(key._path))
        {
            if (key._key != NULL)
            {
                RegCloseKey(key._key);
                key._key = NULL;
            }
        }

        key::~key() { if (_key != NULL) RegCloseKey(_key); }

        const std::string& key::get_path() const noexcept { return _path; }

        key key::subkey(const std::string& sub_path, DWORD desired_access) const
        {
            auto path = _path;
            if (path.back() != '\\')
                path += '\\';
            path += sub_path;
            return key(path, desired_access);
        }

        key key::create_key(const std::string& name, DWORD desired_access)
        {
            auto path = _path;
            if (path.back() != '\\')
                path += '\\';
            path += name;

            HKEY hkey;
            auto status = RegCreateKeyExA(_key, name.c_str(), NULL, NULL, 0, desired_access, NULL, &hkey, NULL);
            if (status != ERROR_SUCCESS)
                throw nstd::runtime_error("set value dword error: %d", status);
            return key(std::move(hkey), std::move(path));
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

        std::list<std::string> key::list_subkeys() const
        {
            DWORD count = 0;
            DWORD max_len = 0;
            auto error = RegQueryInfoKeyW(
                _key,
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
                throw nstd::runtime_error("list subkeys error: %d", error);

            std::list<std::string> ret;
            std::vector<wchar_t> name(max_len + 1);
            for (DWORD i = 0; i < count; i++)
            {
                DWORD len = max_len + 1;
                error = RegEnumKeyExW(
                    _key,
                    i,
                    &name[0],
                    &len,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
                if (error != ERROR_SUCCESS)
                    continue;

                std::string utf8 = nstd::encoding::wide_to_utf8(std::wstring(&name[0], len));
                ret.emplace_back(std::move(utf8));
            }
            return ret;
        }
        std::list<std::string> key::list_values() const
        {
            DWORD count = 0;
            DWORD max_len = 0;
            auto error = RegQueryInfoKeyW(
                _key,
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

            std::list<std::string> ret;
            std::vector<wchar_t> name(max_len + 1);
            for (DWORD i = 0; i < count; i++)
            {
                DWORD len = max_len + 1;
                error = RegEnumValueW(
                    _key,
                    i,
                    &name[0],
                    &len,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
                if (error != ERROR_SUCCESS)
                    continue;

                std::string utf8 = nstd::encoding::wide_to_utf8(std::wstring(&name[0], len));
                ret.emplace_back(std::move(utf8));
            }
            return ret;
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