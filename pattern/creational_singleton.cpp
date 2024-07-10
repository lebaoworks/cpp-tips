#include "../utest.h"

namespace pattern
{
    namespace creational
    {
        class singleton
        {
        public:
            static singleton& instance()
            {
                static singleton instance;
                return instance;
            }

        private:
            singleton() {}
            singleton(const singleton&) = delete;
            singleton& operator=(const singleton&) = delete;
        };
    }
}

using namespace pattern::creational;

UTEST(pattern_creational, singleton)
{
    auto& s1 = singleton::instance();
    auto& s2 = singleton::instance();
    EXPECT_EQ(&s1, &s2);
}
