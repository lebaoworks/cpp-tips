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
            std::string ret(size*2, 0);
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
        // Source: https://opensource.apple.com/source/WTF/WTF-7605.3.8/wtf/MD5.cpp.auto.html
        class MD5
        {
        public:
            struct digest
            {
                uint8_t data[16];
            };

        private:
            struct context
            {
                uint32_t m_buf[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
                uint32_t m_bits[2] = { 0 };
                uint8_t m_in[64] = { 0 };

                static void to_little_endian_4bytes(void* data, size_t size) noexcept
                {
                    auto d = reinterpret_cast<uint8_t*>(data);

                    do
                    {
                        *reinterpret_cast<uint32_t*>(d) = static_cast<uint32_t>(d[3] << 8 | d[2]) << 16 | d[1] << 8 | d[0];
                        d += sizeof(uint32_t);
                    } while (--size);
                }

                static inline uint32_t f1(uint32_t x, uint32_t y, uint32_t z) noexcept { return z ^ (x & (y ^ z)); }
                static inline uint32_t f2(uint32_t x, uint32_t y, uint32_t z) noexcept { return y ^ (z & (x ^ y)); }
                static inline uint32_t f3(uint32_t x, uint32_t y, uint32_t z) noexcept { return x ^ y ^ z; }
                static inline uint32_t f4(uint32_t x, uint32_t y, uint32_t z) noexcept { return y ^ (x | ~z); }

                template<typename F>
                static inline void step(F f, uint32_t& w, uint32_t x, uint32_t y, uint32_t z, uint32_t data, uint32_t s) noexcept
                {
                    w += f(x, y, z) + data;
                    w = w << s | w >> (32 - s);
                    w += x;
                }

                static inline void transform(uint32_t buf[4], const uint32_t in[16]) noexcept
                {
                    uint32_t a = buf[0];
                    uint32_t b = buf[1];
                    uint32_t c = buf[2];
                    uint32_t d = buf[3];

                    step(f1, a, b, c, d, in[0] + 0xd76aa478, 7);
                    step(f1, d, a, b, c, in[1] + 0xe8c7b756, 12);
                    step(f1, c, d, a, b, in[2] + 0x242070db, 17);
                    step(f1, b, c, d, a, in[3] + 0xc1bdceee, 22);
                    step(f1, a, b, c, d, in[4] + 0xf57c0faf, 7);
                    step(f1, d, a, b, c, in[5] + 0x4787c62a, 12);
                    step(f1, c, d, a, b, in[6] + 0xa8304613, 17);
                    step(f1, b, c, d, a, in[7] + 0xfd469501, 22);
                    step(f1, a, b, c, d, in[8] + 0x698098d8, 7);
                    step(f1, d, a, b, c, in[9] + 0x8b44f7af, 12);
                    step(f1, c, d, a, b, in[10] + 0xffff5bb1, 17);
                    step(f1, b, c, d, a, in[11] + 0x895cd7be, 22);
                    step(f1, a, b, c, d, in[12] + 0x6b901122, 7);
                    step(f1, d, a, b, c, in[13] + 0xfd987193, 12);
                    step(f1, c, d, a, b, in[14] + 0xa679438e, 17);
                    step(f1, b, c, d, a, in[15] + 0x49b40821, 22);

                    step(f2, a, b, c, d, in[1] + 0xf61e2562, 5);
                    step(f2, d, a, b, c, in[6] + 0xc040b340, 9);
                    step(f2, c, d, a, b, in[11] + 0x265e5a51, 14);
                    step(f2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
                    step(f2, a, b, c, d, in[5] + 0xd62f105d, 5);
                    step(f2, d, a, b, c, in[10] + 0x02441453, 9);
                    step(f2, c, d, a, b, in[15] + 0xd8a1e681, 14);
                    step(f2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
                    step(f2, a, b, c, d, in[9] + 0x21e1cde6, 5);
                    step(f2, d, a, b, c, in[14] + 0xc33707d6, 9);
                    step(f2, c, d, a, b, in[3] + 0xf4d50d87, 14);
                    step(f2, b, c, d, a, in[8] + 0x455a14ed, 20);
                    step(f2, a, b, c, d, in[13] + 0xa9e3e905, 5);
                    step(f2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
                    step(f2, c, d, a, b, in[7] + 0x676f02d9, 14);
                    step(f2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

                    step(f3, a, b, c, d, in[5] + 0xfffa3942, 4);
                    step(f3, d, a, b, c, in[8] + 0x8771f681, 11);
                    step(f3, c, d, a, b, in[11] + 0x6d9d6122, 16);
                    step(f3, b, c, d, a, in[14] + 0xfde5380c, 23);
                    step(f3, a, b, c, d, in[1] + 0xa4beea44, 4);
                    step(f3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
                    step(f3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
                    step(f3, b, c, d, a, in[10] + 0xbebfbc70, 23);
                    step(f3, a, b, c, d, in[13] + 0x289b7ec6, 4);
                    step(f3, d, a, b, c, in[0] + 0xeaa127fa, 11);
                    step(f3, c, d, a, b, in[3] + 0xd4ef3085, 16);
                    step(f3, b, c, d, a, in[6] + 0x04881d05, 23);
                    step(f3, a, b, c, d, in[9] + 0xd9d4d039, 4);
                    step(f3, d, a, b, c, in[12] + 0xe6db99e5, 11);
                    step(f3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
                    step(f3, b, c, d, a, in[2] + 0xc4ac5665, 23);

                    step(f4, a, b, c, d, in[0] + 0xf4292244, 6);
                    step(f4, d, a, b, c, in[7] + 0x432aff97, 10);
                    step(f4, c, d, a, b, in[14] + 0xab9423a7, 15);
                    step(f4, b, c, d, a, in[5] + 0xfc93a039, 21);
                    step(f4, a, b, c, d, in[12] + 0x655b59c3, 6);
                    step(f4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
                    step(f4, c, d, a, b, in[10] + 0xffeff47d, 15);
                    step(f4, b, c, d, a, in[1] + 0x85845dd1, 21);
                    step(f4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
                    step(f4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
                    step(f4, c, d, a, b, in[6] + 0xa3014314, 15);
                    step(f4, b, c, d, a, in[13] + 0x4e0811a1, 21);
                    step(f4, a, b, c, d, in[4] + 0xf7537e82, 6);
                    step(f4, d, a, b, c, in[11] + 0xbd3af235, 10);
                    step(f4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
                    step(f4, b, c, d, a, in[9] + 0xeb86d391, 21);

                    buf[0] += a;
                    buf[1] += b;
                    buf[2] += c;
                    buf[3] += d;
                }

                inline void feed(const void* data, size_t size) noexcept
                {
                    auto d = reinterpret_cast<const uint8_t*>(data);

                    // Update bits count
                    uint32_t t = m_bits[0];
                    uint32_t low = (size << 3) & 0xFFFFFFFF;
                    uint32_t high = static_cast<uint32_t>(size >> 29);
                    if (0xFFFFFFFF - t > low)
                        m_bits[0] = t + low;
                    else
                    {
                        m_bits[0] = low - (0xFFFFFFFF - t);
                        m_bits[1]++;
                    }                        
                    m_bits[1] += high;

                    t = (t >> 3) & 0x3f; // Bytes already in shsInfo->data

                    // Handle any leading odd-sized chunks

                    if (t)
                    {
                        uint8_t* p = m_in + t;

                        t = 64 - t;
                        if (size < t)
                        {
                            memcpy(p, d, size);
                            return;
                        }
                        memcpy(p, d, t);
                        to_little_endian_4bytes(m_in, 16);
                        transform(m_buf, reinterpret_cast<uint32_t*>(m_in)); // m_in is 4-byte aligned.
                        d += t;
                        size -= t;
                    }

                    // Process data in 64-byte chunks

                    while (size >= 64)
                    {
                        memcpy(m_in, d, 64);
                        to_little_endian_4bytes(m_in, 16);
                        transform(m_buf, reinterpret_cast<uint32_t*>(m_in)); // m_in is 4-byte aligned.
                        d += 64;
                        size -= 64;
                    }

                    // Handle any remaining bytes of data.
                    memcpy(m_in, d, size);
                }

                inline MD5::digest finalize() noexcept
                {
                    // Compute number of bytes mod 64
                    unsigned count = (m_bits[0] >> 3) & 0x3F;

                    // Set the first char of padding to 0x80.  This is safe since there is
                    // always at least one byte free
                    uint8_t* p = m_in + count;
                    *p++ = 0x80;

                    // Bytes of padding needed to make 64 bytes
                    count = 64 - 1 - count;

                    // Pad out to 56 mod 64
                    if (count < 8)
                    {
                        // Two lots of padding:  Pad the first block to 64 bytes
                        memset(p, 0, count);
                        to_little_endian_4bytes(m_in, 16);
                        transform(m_buf, reinterpret_cast<uint32_t*>(m_in)); // m_in is 4-byte aligned.

                        // Now fill the next block with 56 bytes
                        memset(m_in, 0, 56);
                    }
                    else
                    {
                        // Pad block to 56 bytes
                        memset(p, 0, count - 8);
                    }
                    to_little_endian_4bytes(m_in, 14);

                    // Append length in bits and transform
                    memcpy(m_in + 56, m_bits, sizeof(m_bits));

                    transform(m_buf, reinterpret_cast<uint32_t*>(m_in));
                    to_little_endian_4bytes(reinterpret_cast<uint8_t*>(m_buf), 4);

                    // Now, m_buf contains checksum result.
                    uint8_t* mBufUInt8 = reinterpret_cast<uint8_t*>(m_buf);
                    struct MD5::digest digest;
                    for (size_t i = 0; i < 16; ++i)
                        digest.data[i] = mBufUInt8[i];

                    return digest;
                }
            };

            context _ctx;

        public:
            MD5() = default;
            ~MD5() = default;

            inline void feed(const void* data, size_t size) noexcept
            {
                _ctx.feed(data, size);
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


        // Source: https://opensource.apple.com/source/WTF/WTF-7603.1.30.1.33/wtf/SHA1.cpp.auto.html
        class SHA1
        {
        public:
            struct digest
            {
                uint8_t data[20];
            };

        private:
            struct context
            {
                uint8_t  data[64] = {0};
                size_t   blocklen = 0;
                uint64_t totallen = 0;
                uint32_t state[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

                static inline uint32_t f(int t, uint32_t b, uint32_t c, uint32_t d) noexcept
                {
                    if (t < 20) return (b & c) | ((~b) & d);
                    if (t < 40) return b ^ c ^ d;
                    if (t < 60) return (b & c) | (b & d) | (c & d);
                    return b ^ c ^ d;
                }

                static inline uint32_t k(int t) noexcept
                {
                    if (t < 20) return 0x5a827999;
                    if (t < 40) return 0x6ed9eba1;
                    if (t < 60) return 0x8f1bbcdc;
                    return 0xca62c1d6;
                }

                static inline uint32_t rotate_left(int n, uint32_t x) noexcept { return (x << n) | (x >> (32 - n)); }

                inline void transform() noexcept
                {
                    uint32_t w[80] = { 0 };
                    for (int t = 0; t < 16; ++t)
                        w[t] = (data[t * 4] << 24) | (data[t * 4 + 1] << 16) | (data[t * 4 + 2] << 8) | data[t * 4 + 3];
                    for (int t = 16; t < 80; ++t)
                        w[t] = rotate_left(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);

                    uint32_t a = state[0];
                    uint32_t b = state[1];
                    uint32_t c = state[2];
                    uint32_t d = state[3];
                    uint32_t e = state[4];

                    for (int t = 0; t < 80; ++t)
                    {
                        uint32_t temp = rotate_left(5, a) + f(t, b, c, d) + e + w[t] + k(t);
                        e = d;
                        d = c;
                        c = rotate_left(30, b);
                        b = a;
                        a = temp;
                    }

                    state[0] += a;
                    state[1] += b;
                    state[2] += c;
                    state[3] += d;
                    state[4] += e;
                }

                inline void feed(const void* data, size_t size) noexcept
                {
                    auto d = reinterpret_cast<const uint8_t*>(data);
                    for (size_t i = 0; i < size; ++i, ++totallen)
                    {
                        this->data[blocklen++] = *d++;
                        if (blocklen == 64)
                        {
                            transform();
                            blocklen = 0;
                        }
                    }
                }

                inline SHA1::digest finalize() noexcept
                {
                    // padding
                    data[blocklen++] = 0x80;
                    if (blocklen > 56)
                    {
                        // Pad out to next block.
                        while (blocklen < 64)
                            data[blocklen++] = 0x00;
                        transform();
                        blocklen = 0;
                    }
                    for (size_t i = blocklen; i < 56; ++i)
                        data[i] = 0x00;


                    // Write the length as a big-endian 64-bit value.
                    uint64_t bits = totallen * 8;
                    for (int i = 0; i < 8; ++i)
                    {
                        data[56 + (7 - i)] = bits & 0xFF;
                        bits >>= 8;
                    }
                    blocklen = 64;
                    transform();
                    blocklen = 0;

                    // Write to digest big-endian
                    struct SHA1::digest digest;
                    for (size_t i = 0; i < 5; ++i)
                    {
                        uint32_t hashValue = state[i];
                        for (size_t j = 0; j < 4; ++j)
                        {
                            digest.data[4 * i + (3 - j)] = hashValue & 0xFF;
                            hashValue >>= 8;
                        }
                    }
                    return digest;
                }
            };

            context _ctx;

        public:
            SHA1() = default;
            ~SHA1() = default;

            inline void feed(const void* data, size_t size) noexcept
            {
                _ctx.feed(data, size);
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

                inline void feed(const void* data, size_t size) noexcept
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
                _ctx.feed(data, size);
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