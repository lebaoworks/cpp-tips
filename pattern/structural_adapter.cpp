#include "../utest.h"

namespace pattern
{
    namespace structural
    {
        /// Adapter is a structural design pattern
        ///     that allows objects with incompatible interfaces to collaborate.
        namespace adapter
        {
            struct old_class
            {
                int old_method() { return 1; }
            };

            struct new_class
            {
                int new_method() { return 2; }
            };

            struct object
            {
                virtual int get() const = 0;
                virtual int operator+(const object& other) = 0;
            };

            struct old_adapter : public object
            {
            private:
                old_class* _old_class;
            public:
                old_adapter(old_class* old_class) : _old_class(old_class) {}

                int get() const override { return _old_class->old_method(); }
                int operator+(const object& other) override { return get() + other.get(); }
            };

            struct new_adapter : public object
            {
            private:
                new_class* _new_class;
            public:
                new_adapter(new_class* new_class) : _new_class(new_class) {}

                int get() const override { return _new_class->new_method(); }
                int operator+(const object& other) override { return get() + other.get(); }
            };
        }
    }
}

using namespace pattern::structural::adapter;

UTEST(pattern_structural, adapter)
{
    auto old_object = new old_class();
    auto new_object = new new_class();

    old_adapter old_compatible(old_object);
    new_adapter new_compatible(new_object);

    EXPECT_EQ(old_compatible + new_compatible, 3);
}
