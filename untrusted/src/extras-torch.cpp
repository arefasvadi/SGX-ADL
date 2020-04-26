#include "extras-torch.h"
#include <torch/torch.h>
#include <iostream>

void test_torch_cxx() {
    torch::Tensor tensor = torch::rand({2, 3});
    std::cout << tensor << std::endl;
}

void torch_create_tensor_from_buffer() {
    
}