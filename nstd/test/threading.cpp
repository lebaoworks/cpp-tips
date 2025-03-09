#include <atomic>
#include <thread>

#include <gtest/gtest.h>
#include <nstd/threading.hpp>
#include <nstd/utility.hpp>

TEST(nstd_threading, thread_pool_submit_ret)
{
    nstd::thread_pool pool(2);
    auto future = pool.submit([] { return 1340; });
    ASSERT_EQ(future.get(), 1340);
}

TEST(nstd_threading, thread_pool_submit_no_ret)
{
    nstd::thread_pool pool(2);
    int counter = 0;
    auto future = pool.submit([&] { counter = 1340; });
    future.wait();
    ASSERT_EQ(counter, 1340);
}

TEST(nstd_threading, thread_pool_task_exception)
{
    nstd::thread_pool pool(2);
    auto future = pool.submit([&] { throw std::runtime_error("test"); });
    ASSERT_THROW(future.get(), std::runtime_error);
}

TEST(nstd_threading, thread_pool_teardown)
{
    std::atomic<int> counter(0);
    {
        nstd::thread_pool pool(4);
        for (int i = 0; i < 100; ++i)
            pool.submit([&] { counter++; });
    }
    ASSERT_EQ(counter, 100);
}

TEST(nstd_threading, thread_pool_parallel)
{
    nstd::time_counter counter;
    {
        nstd::thread_pool pool(4);
        counter.reset();
        for (int i = 0; i < 4; ++i)
            pool.submit([] { std::this_thread::sleep_for(std::chrono::milliseconds(500)); });
    }
    ASSERT_LT(counter.elapsed<std::chrono::milliseconds>(), 700);
}