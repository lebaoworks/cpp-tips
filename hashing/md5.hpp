#include <cstdint>
#include <cstring>

namespace hashing
{
    // Source: https://opensource.apple.com/source/WTF/WTF-7605.3.8/wtf/MD5.cpp.auto.html
    class MD5
    {
    public:
        struct digest { uint8_t data[16]; };

    private:
        uint32_t buffer[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
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
        
    public:
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
                transform(buffer, reinterpret_cast<uint32_t*>(m_in)); // m_in is 4-byte aligned.
                d += t;
                size -= t;
            }

            // Process data in 64-byte chunks

            while (size >= 64)
            {
                memcpy(m_in, d, 64);
                to_little_endian_4bytes(m_in, 16);
                transform(buffer, reinterpret_cast<uint32_t*>(m_in)); // m_in is 4-byte aligned.
                d += 64;
                size -= 64;
            }

            // Handle any remaining bytes of data.
            memcpy(m_in, d, size);
        }

        inline digest finalize() noexcept
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
                transform(buffer, reinterpret_cast<uint32_t*>(m_in)); // m_in is 4-byte aligned.

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

            transform(buffer, reinterpret_cast<uint32_t*>(m_in));
            to_little_endian_4bytes(reinterpret_cast<uint8_t*>(buffer), 4);

            // Now, m_buf contains checksum result.
            uint8_t* mBufUInt8 = reinterpret_cast<uint8_t*>(buffer);
                
            digest digest;
            for (size_t i = 0; i < 16; ++i)
                digest.data[i] = mBufUInt8[i];

            return digest;
        }
    };
}