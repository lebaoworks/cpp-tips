#pragma once

// Defer
#include <memory>

struct defer_dummy {};
template<class F>
struct deferer
{
    F _f;
    deferer(F&& f) noexcept : _f(f) {}
    ~deferer() { _f(); }
};
template<class F>
inline deferer<F> operator*(defer_dummy, F&& f) noexcept { return deferer<F>(std::move(f)); }
#define DEFER_(LINE) zz_defer##LINE
#define DEFER(LINE) DEFER_(LINE)
#define defer auto DEFER(__LINE__) = defer_dummy{} *[&]()

// Format
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>

namespace nstd
{
    template<typename... Args>
    std::string format(const std::string& format, const Args&... args)
    {
        int size_s = std::snprintf(nullptr, 0, format.c_str(), args...);
        if (size_s < 0) throw std::runtime_error("Error during formatting");
        std::string ret(size_s, '\x00');
        std::snprintf(&ret[0], size_s + 1, format.c_str(), args...);
        return ret;
    }
}

// Format exception
#include <stdexcept>
#include <string>

namespace nstd
{
    struct runtime_error : public std::runtime_error
    {
        template<typename... Args>
        runtime_error(const std::string& format, const Args&... args) :
            std::runtime_error(nstd::format(format, args...)) {}
    };

    struct invalid_argument : public std::invalid_argument
    {
        template<typename... Args>
        invalid_argument(const std::string& format, const Args&... args) :
            std::invalid_argument(nstd::format(format, args...)) {}
    };
}

// Encoding
#include <string>
#include <stdexcept>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <locale>
#include <codecvt>
#endif

namespace nstd
{
    namespace encoding
    {
    #ifdef _WIN32
        inline std::wstring utf8_to_wide(const std::string& utf8_str)
        {
            if (utf8_str.length() > INT_MAX)
                throw std::invalid_argument("string too long");
            int cb = static_cast<int>(utf8_str.length());

            auto cch = MultiByteToWideChar(
                CP_UTF8,                                    // Code page -> UTF-8
                MB_ERR_INVALID_CHARS | MB_PRECOMPOSED,      // Flags -> Fail if an invalid input character is encountered + Using single character for base and nonspacing
                utf8_str.c_str(),                           // MultiByteStr
                cb,                                         // MultiByteStr size in bytes
                NULL,                                       // WideStr
                0);                                         // WideStr size in characters -> 0 to get final size
            if (cch == 0)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());
            
            std::wstring ret(cch, L'\x00');
            auto cch2 = MultiByteToWideChar(
                CP_UTF8,                                    // Code page -> UTF-8
                MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,      // Flags -> Fail if an invalid input character is encountered + Using single character for base and nonspacing
                utf8_str.c_str(),                           // MultiByteStr
                cb,                                         // MultiByteStr size in bytes
                &ret[0],                                    // WideStr
                cch + 1);                                   // WideStr size in characters
            if (cch2 != cch)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());
            return ret;
        }

        inline std::string wide_to_utf8(const std::wstring& wide_str)
        {
            if (wide_str.length() > INT_MAX)
                throw std::invalid_argument("string too long");
            int cch = static_cast<int>(wide_str.length());

            auto cb = WideCharToMultiByte(
                CP_UTF8,                                    // Code page -> UTF-8
                WC_ERR_INVALID_CHARS | WC_DISCARDNS,        // Flags -> Fail if an invalid input character is encountered + Discard nonspacing
                wide_str.c_str(),                           // WideStr
                cch,                                        // WideStr size in characters
                NULL,                                       // MultiByteStr
                0,                                          // MultiByteStr size in bytes -> 0 to get final size
                NULL,                                       // DefaultChar -> Don't care, discard anyway
                NULL);                                      // UsedDefaultChar
            if (cb == 0)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());

            std::string ret(cb, '\x00');
            auto cb2 = WideCharToMultiByte(
                CP_UTF8,                                    // Code page -> UTF-8
                WC_ERR_INVALID_CHARS | WC_DISCARDNS,        // Flags -> Fail if an invalid input character is encountered + Discard nonspacing
                wide_str.c_str(),                           // WideStr
                cch,                                        // WideStr size in characters
                &ret[0],                                    // MultiByteStr
                cb + 1,                                     // MultiByteStr size in bytes
                NULL,                                       // DefaultChar -> Don't care, discard anyway
                NULL);                                      // UsedDefaultChar -> Don't care
            if (cb2 != cb)
                throw nstd::runtime_error("convert failed, error: %d", GetLastError());
            return ret;
        }
    #else
        inline std::wstring utf8_to_wide(const std::string& str)
        {
            return std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().from_bytes(str);
        }

        inline std::string wide_to_utf8(const std::wstring& wstr)
        {
            return std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().to_bytes(wstr);
        }
    #endif

        inline std::string hex(void* data, size_t size)
        {
            static const char characters[] = "0123456789ABCDEF";
            std::string ret(64, 0);
            auto buf = const_cast<char*>(ret.data());
            auto d = reinterpret_cast<uint8_t*>(data);
            for (size_t i = 0; i < size; ++i, ++d)
            {
                *buf++ = characters[*d >> 4];
                *buf++ = characters[*d & 0x0F];
            }
            return ret;
        }
    }
}

// Hash
#include <cstdint>
#include <string>
#include <sstream>
namespace nstd
{
    namespace hash
    {
        class MD5;
        class SHA1;

        // Source: https://github.com/System-Glitch/SHA256/
        class SHA256
        {
        public:
            struct digest
            {
                uint8_t data[32];
            };

        private:
            static constexpr uint32_t K[] = {
                0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
                0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
                0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
                0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
                0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
                0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
                0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
                0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
                0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
            };
            static inline uint32_t rotr(uint32_t x, uint32_t n) noexcept { return (x >> n) | (x << (32 - n)); }
            static inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) noexcept { return (e & f) ^ (~e & g); }
            static inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) noexcept { return (a & (b | c)) | (b & c); }
            static inline uint32_t sig0(uint32_t x) noexcept { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
            static inline uint32_t sig1(uint32_t x) noexcept { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

            struct context
            {
                uint8_t  data[64] = { 0 };
                uint32_t blocklen = 0;
                uint64_t bitlen = 0;
                uint32_t state[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

                inline void update(const void* data, size_t size) noexcept
                {
                    auto d = reinterpret_cast<const uint8_t*>(data);
                    for (size_t i = 0; i < size; ++i, ++d)
                    {
                        this->data[blocklen++] = *d;
                        if (blocklen == 64)
                        {
                            transform();
                            bitlen += 512;
                            blocklen = 0;
                        }
                    }
                }

                inline void transform() noexcept
                {
                    uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
                    uint32_t st[8];

                    // Split data in 32 bit blocks for the 16 first words
                    for (int i = 0, j = 0; i < 16; i++, j += 4) 
                        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);

                    // Remaining 48 blocks
                    for (int k = 16; k < 64; k++)
                        m[k] = SHA256::sig1(m[k - 2]) + m[k - 7] + SHA256::sig0(m[k - 15]) + m[k - 16];
                    

                    for (int i = 0; i < 8; i++)
                        st[i] = state[i];

                    for (int i = 0; i < 64; i++)
                    {
                        maj = SHA256::majority(st[0], st[1], st[2]);
                        xorA = SHA256::rotr(st[0], 2) ^ SHA256::rotr(st[0], 13) ^ SHA256::rotr(st[0], 22);

                        ch = choose(st[4], st[5], st[6]);

                        xorE = SHA256::rotr(st[4], 6) ^ SHA256::rotr(st[4], 11) ^ SHA256::rotr(st[4], 25);

                        sum = m[i] + K[i] + st[7] + ch + xorE;
                        newA = xorA + maj + sum;
                        newE = st[3] + sum;

                        st[7] = st[6];
                        st[6] = st[5];
                        st[5] = st[4];
                        st[4] = newE;
                        st[3] = st[2];
                        st[2] = st[1];
                        st[1] = st[0];
                        st[0] = newA;
                    }

                    for (uint8_t i = 0; i < 8; i++)
                        state[i] += st[i];
                }

                inline digest finalize() noexcept
                {
                    // padding
                    uint64_t i = blocklen;
                    uint8_t end = blocklen < 56 ? 56 : 64;

                    data[i++] = 0x80; // Append a bit 1
                    while (i < end)
                        data[i++] = 0x00; // Pad with zeros

                    if (blocklen >= 56)
                    {
                        transform();
                        memset(data, 0, 56);
                    }

                    // Append to the padding the total message's length in bits and transform.
                    bitlen += uint64_t(blocklen) * 8;
                    data[63] = uint8_t(bitlen);
                    data[62] = uint8_t(bitlen >> 8);
                    data[61] = uint8_t(bitlen >> 16);
                    data[60] = uint8_t(bitlen >> 24);
                    data[59] = uint8_t(bitlen >> 32);
                    data[58] = uint8_t(bitlen >> 40);
                    data[57] = uint8_t(bitlen >> 48);
                    data[56] = uint8_t(bitlen >> 56);
                    transform();

                    // Write to digest big-endian
                    struct SHA256::digest digest;
                    for (uint8_t i = 0; i < 4; i++)
                        for (uint8_t j = 0; j < 8; j++)
                            digest.data[i + (j * 4)] = (state[j] >> (24 - i * 8)) & 0x000000ff;
                    
                    return digest;
                }
            };
            
            context _ctx;

        public:
            SHA256() = default;
            ~SHA256()  = default;

            inline void feed(const void* data, size_t size) noexcept
            {
                _ctx.update(data, size);
            }

            inline digest digest() noexcept
            {
                auto ctx = _ctx;
                return ctx.finalize();
            }

            inline std::string hex_digest()
            {
                auto d = digest();
                return nstd::encoding::hex(d.data, sizeof(d.data));
            }
        };
    }
}