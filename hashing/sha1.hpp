#include <cstdint>
#include <cstring>

namespace hashing
{
    // Source: https://opensource.apple.com/source/WTF/WTF-7603.1.30.1.33/wtf/SHA1.cpp.auto.html
    class SHA1
    {
    public:
        struct digest { uint8_t data[20]; };

    private:
        uint8_t  data[64] = { 0 };
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
    
    public:
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

        inline digest finalize() noexcept
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
}
