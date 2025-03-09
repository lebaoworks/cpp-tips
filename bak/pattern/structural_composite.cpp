#include <list>

#include "../utest.h"

namespace pattern
{
    namespace structural
    {
        /// Composite is a structural design pattern
        ///     that lets you compose objects into tree structures
        ///     and then work with these structures as if they were individual objects.
        namespace composite
        {
            struct file_base
            {
                virtual ~file_base() = default;
                virtual size_t size() = 0;
            };

            struct file : public file_base
            {
            private:
                size_t _size;
            public:
                file(size_t s) : _size(s) {}
                size_t size() override { return this->_size; }
            };

            struct directory : public file_base
            {
            private:
                std::list<file_base*> list;
            public:
                size_t size() override
                {
                    size_t ret = 0;
                    for (auto& f : list)
                        ret += f->size();
                    return ret;
                }

                void add(file_base* f) { list.push_back(f); }
            };
        }
    }
}

using namespace pattern::structural::composite;

UTEST(pattern_structural, composite)
{
    file f1(10), f2(20), f3(30);
    directory d1, d2, d3;
    d1.add(&f1);
    d1.add(&f2);
    d2.add(&f3);
    d2.add(&d1);
    d3.add(&d1);
    d3.add(&d2);

    EXPECT_EQ(10, f1.size());
    EXPECT_EQ(20, f2.size());
    EXPECT_EQ(30, f3.size());
    EXPECT_EQ(30, d1.size());
    EXPECT_EQ(60, d2.size());
    EXPECT_EQ(90, d3.size());
}