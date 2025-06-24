#pragma once

#include <iostream>

#define LOG(A)                                                                                                         \
    do {                                                                                                               \
        std::cerr << "[I] " << A << std::endl;                                                                         \
    } while (false)

#define ERR(A)                                                                                                         \
    do {                                                                                                               \
        std::cerr << "[E] " << A << std::endl;                                                                         \
    } while (false)
