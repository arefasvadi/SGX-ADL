#include <foonathan/memory/container.hpp>    // vector, list, list_node_size,...
#include <foonathan/memory/memory_pool.hpp>  // memory_pool
#include <foonathan/memory/namespace_alias.hpp>
#include <foonathan/memory/smart_ptr.hpp>  // allocate_unique
#include <foonathan/memory/static_allocator.hpp>  // static_allocator_storage, static_block_allocator
#include <foonathan/memory/temporary_allocator.hpp>  // temporary_allocator
#include <iostream>
#include <vector>
#include "gtest/gtest.h"

namespace {

  constexpr int repeat     = 200;
  constexpr int test_sizes = 7;
  const size_t  vec_lens[7]
      = {1000, 10000, 100000, 1000000, 10000000, 100000000, 500000000};

  TEST(StandardAllocator, VectorSum) {
    for (int i = 0; i < repeat; ++i) {
      std::vector<float> a(1000000, 1);
      std::vector<float> b(1000000, 1);
      // std::vector<float> res(vec_lens[i],1);
      std::vector<float> res;
      for (int j = 0; j < 1000000; ++j) {
        res.push_back(a[j] + b[j]);
      }
      for (int j = 0; j < 1000000; ++j) {
        ASSERT_EQ(res[j], 2);
      }
    }
  }

  TEST(Foonathan, VectorSum) {
    namespace memory = foonathan::memory;
    memory::memory_pool<
        memory::array_pool
        // memory::growing_block_allocator<memory::default_allocator,
        // 2, 1>
        >
        pool(sizeof(float), 1024 * 32 * 1024);
    // std::cerr << pool.node_size() << "\n";
    // std::cerr << pool.capacity_left() << "\n";
    // std::cerr << pool.next_capacity() << "\n";

    for (int i = 0; i < repeat; ++i) {
      memory::vector<float, decltype(pool)> a(1000000, 1, pool);
      memory::vector<float, decltype(pool)> b(1000000, 1, pool);
      memory::vector<float, decltype(pool)> res(pool);
      for (int j = 0; j < 1000000; ++j) {
        res.push_back(a[j] + b[j]);
      }
      for (int j = 0; j < 1000000; ++j) {
        ASSERT_EQ(res[j], 2);
      }
    }
  }
}  // namespace