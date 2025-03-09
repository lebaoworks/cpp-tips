#include <list>

#include "../utest.h"

namespace pattern
{
    namespace structural
    {
        /// Proxy is a structural design pattern
        ///     that lets you provide a substitute or placeholder for another object.
        /// A proxy controls access to the original object,
        ///     allowing you to perform something either before or after the request gets through to the original object.
        namespace proxy
        {
            struct subject
            {
                virtual ~subject() = default;
                virtual int request(int x) = 0;
            };

            struct real_subject : public subject
            {
                int request(int x) override { return x << 1; }
            };

            struct proxy : public subject
            {
            private:
                subject* real;
                std::list<std::pair<int, int>> list;
            public:
                proxy(subject* real) : real(real) {}

                int request(int x) override
                {
                    auto ret = real->request(x);
                    list.push_back({ x, ret });
                    return ret;
                }

                std::list<std::pair<int, int>> access_history() { return list; }
            };

        }
    }
}

using namespace pattern::structural::proxy;

UTEST(pattern_structural, proxy)
{
    subject* o = new real_subject();
    subject* p = new struct proxy(o);

    EXPECT_EQ(2, p->request(1));
    EXPECT_EQ(4, p->request(2));
    EXPECT_EQ(8, p->request(4));

    for (auto& history : reinterpret_cast<proxy*>(p)->access_history())
        EXPECT_EQ(history.first << 1, history.second);
}
