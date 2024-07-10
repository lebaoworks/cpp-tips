#pragma once

// Standard C/C++ Headers:
#include <string>

// Standard Windows Headers:
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Precompiled Headers:
#include "../nstd.hpp"

namespace windows
{
    namespace event_log
    {
        /// @brief Setup logging source in EventLog.
        /// @param group name of group.
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