#include <vector>

#include "../utest.h"

namespace pattern
{
    namespace behavior
    {
        /// Iterator is a behavioral design pattern
        ///     that lets you traverse elements of a collection
        ///     without exposing its underlying representation.
        namespace iterator
        {
            struct iterator
            {
                virtual ~iterator() = default;
                virtual void next() = 0;
                virtual bool is_done() = 0;
                virtual int current() = 0;
            };

            struct aggregate
            {
                virtual ~aggregate() = default;
                virtual iterator* create_iterator() = 0;
            };

            struct collection : public aggregate
            {
            private:
                std::vector<int> v;

            public:
                struct iterator : public behavior::iterator::iterator
                {
                private:
                    collection& _collection;
                    int index;
                public:
                    iterator(collection& collection) : _collection(collection), index(0) { }
                    void next() override { ++index; }
                    bool is_done() override { return index >= _collection.v.size(); }
                    int current() override { return _collection.v.at(index); }
                };

            public:
                collection(size_t size) : v(size) {}

                iterator* create_iterator() override { return new iterator(*this); }

                void set(size_t index, int value) { v.at(index) = value; }
            };
            
        }
    }
}

using namespace pattern::behavior::iterator;

UTEST(pattern_behavior, iterator)
{
    collection c(3);
    c.create_iterator();
    c.set(0, 1);
    c.set(1, 2);
    c.set(2, 3);

    auto it = c.create_iterator();
    int i = 1;
    while (!it->is_done())
    {
        ASSERT_EQ(i, it->current());
        it->next();
        i++;
    }
    ASSERT_EQ(4, i);

}

