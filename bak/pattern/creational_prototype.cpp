#include <string>

#include "../nstd.hpp"
#include "../utest.h"

namespace pattern
{
    namespace creational
    {
        /// Prototype is a creational design pattern
        ///     that lets you copy existing objects
        ///     without making your code dependent on their classes.
        namespace prototype
        {
            struct prototype
            {
                virtual prototype* clone() const = 0;

                virtual void change() = 0;

                virtual int get() const = 0;
            };

            struct concrete: public prototype
            {
                int internal = 0;

                prototype* clone() const override { return new concrete(*this); }

                void change() override { ++internal; }

                int get() const override { return internal; }
            };

        }
    }
}

using namespace pattern::creational::prototype;

UTEST(pattern_creational, prototype)
{
    prototype* original = new concrete();
    defer{ delete original; };

    // Don't care whatever the original is, clone make exact copy of it
    prototype* clone = original->clone();
    defer{ delete clone; };

    ASSERT_EQ(original->get(), clone->get());

    original->change();
    ASSERT_NE(original->get(), clone->get());
}