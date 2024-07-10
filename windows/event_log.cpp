#include "event_log.hpp"

// Additional Headers:
#include "registry.hpp"

namespace windows
{
    namespace event_log
    {
        void setup(const std::wstring& group, const std::wstring& source, DWORD bytes)
        {
            auto key = windows::registry::key(LR"(HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog)", REG_CREATED_NEW_KEY).create_key(group);
            key.set_dword(L"Retention", 0);
            key.set_dword(L"MaxSize", bytes);

            std::list<std::wstring> sources = {source};
            try
            {
                for (auto& src : key.get_multi_string(L"Sources"))
                    if (src != source)
                        sources.emplace_back(std::move(src));
            } catch (...) {}
            key.set_multi_string(L"Sources", sources);

            auto sub = key.create_key(source);
            sub.set_dword(L"CustomSource", 1);
            sub.set_expand_string(L"EventMessageFile", LR"(%SystemRoot%\System32\EventCreate.exe)");
            sub.set_dword(L"TypesSupported", EVENTLOG_SUCCESS | EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE | EVENTLOG_AUDIT_SUCCESS | EVENTLOG_AUDIT_FAILURE);
        }

        void log::report(WORD type, const std::string& log)
        {
            const char* s[] = { log.c_str() };
            WORD len = log.length() >= 65535 ? 65535 : static_cast<WORD>(log.length());
            if (ReportEventA(_event_source, type, 0, 1, NULL, 1, len, s, (PVOID) log.c_str()) != TRUE)
                throw nstd::runtime_error("ReportEventA error: %d", GetLastError());
        }

        log::log(const std::wstring& source)
        {
            _event_source = RegisterEventSourceW(NULL, source.c_str());
            if (_event_source == NULL)
                throw nstd::runtime_error("RegisterEventSource(%ws) error: %d", source.c_str(), GetLastError());
        }

        log::~log()
        {
            DeregisterEventSource(_event_source);
        }
    }
}