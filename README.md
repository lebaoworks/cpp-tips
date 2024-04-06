# cpp-tips

## Introduction  <!-- omit in toc -->
This is the collection of snippets I found on internet or made by me.  

## Contents: <!-- omit in toc -->
- [Defer function](#defer)
- [Format like printf](#format-like-printf)
- [Runtime exception with format](#runtime-exception-with-format)

## Defer
- Requirement: C++11 or later.
- Source: [pmttavaras's answer](https://stackoverflow.com/a/42060129) on stackoverflow.
- Modified to use move-semantic for true zero-overhead by me.

Deferred functions will be called at the end of the scope where they were declared, in last-in-first-out order. 

Snippet:
```cpp
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
```

Sample:
```cpp
int main()
{
    defer{ printf("4\n"); };
    defer{ printf("3\n"); };

    {
        defer{ printf("1\n"); };
    }
    
    defer{ printf("2\n"); };
}
```

## Format like printf
- Source: [ifreilicht's answer](https://stackoverflow.com/a/26221725) on stackoverflow.

Snippet:
```cpp
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>

namespace nstd
{
    template<typename... Args>
    std::string format(const std::string& format, const Args&... args)
    {
        int size_s = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
        if (size_s <= 0) throw std::runtime_error("Error during formatting.");
        auto size = static_cast<size_t>(size_s);
        auto buf = std::make_unique<char[]>(size);
        std::snprintf(buf.get(), size, format.c_str(), args...);
        return std::string(buf.get(), buf.get() + size - 1);
    }
}
```

Sample:
```cpp
int main()
{
    std::cout << nstd::format("hello %s!\n", "lebaoworks");
}
```

## Runtime exception with format
- Source: Me.
- Requirement: [format](#format-like-printf)

Snippet:
```cpp
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
}
```

Sample:
```cpp
int main()
{
    try
    {
        throw nstd::runtime_error("test except by %s", "lebaoworks");
    }
    catch (std::exception& e)
    {
        printf("Got exception: %s", e.what());
    }
}
```
