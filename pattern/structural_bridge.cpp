#include "../utest.h"

#include <string>
#include <list>

namespace pattern
{
    namespace structural
    {
        /// Bridge is a structural design pattern
        ///     that lets you split a large class or a set of closely related classes into two separate hierarchies
        ///     abstraction and implementation
        ///     which can be developed independently of each other.
        namespace bridge
        {

            ///
            /// Abstraction
            ///
            ///

            struct account
            {
                virtual std::string get_type() = 0;
            };

            struct bank
            {
            protected:
                account* _account;
            public:
                bank(account* account) : _account(account) {}

                virtual std::list<std::string> get_privileges() const = 0;
            };

            ///
            /// Implementation
            /// 

            struct normal_account : public account
            {
                std::string get_type() override { return "normal"; }
            };

            struct premium_account : public account
            {
                std::string get_type() override { return "premium"; }
            };

            struct a_bank : public bank
            {
                a_bank(account* account) : bank(account) {}

                std::list<std::string> get_privileges() const override
                {
                    if (_account->get_type() == "premium")
                        return {
                            "loan",
                            "credit card",
                            "insurance",
                            "investment"
                        };
                    else
                        return {
                            "loan",
                            "credit card",
                        };

                }
            };

            struct b_bank : public bank
            {
                b_bank(account* account) : bank(account) {}

                std::list<std::string> get_privileges() const override
                {
                    if (_account->get_type() == "premium")
                        return {
                            "loan",
                            "credit card",
                            "investment",
                            "concierge service"
                    };
                    else
                        return {
                            "loan",
                            "credit card",
                    };
                }
            };
        }
    }
}

using namespace pattern::structural::bridge;

UTEST(pattern_structural, bridge)
{
    bank* acc_at_bank_1 = new a_bank(new normal_account());

    bank* acc_at_bank_2 = new b_bank(new premium_account());

    for (auto& privilege : acc_at_bank_1->get_privileges())
        ASSERT_NE(privilege, "insurance");

    for (auto& privilege : acc_at_bank_2->get_privileges())
        ASSERT_NE(privilege, "insurance");
}
