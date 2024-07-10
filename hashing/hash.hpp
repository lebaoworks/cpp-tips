#pragma once

#include <string>
#include "../encoding/encode.hpp"

namespace hashing
{
    template<typename HashType>
    class hash
    {
    private:
        HashType _ctx;

    public:
        inline void feed(const void* data, size_t size) noexcept
        {
            _ctx.feed(data, size);
        }

        inline decltype(auto) digest() noexcept
        {
            auto ctx = _ctx;
            return ctx.finalize();
        }

        inline std::string hex_digest()
        {
            auto d = digest();
            return encoding::hex(d.data, sizeof(d.data));
        }
    };
}

#include "md5.hpp"
#include "sha1.hpp"
#include "sha256.hpp"