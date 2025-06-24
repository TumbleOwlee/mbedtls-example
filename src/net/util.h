#pragma once

#include <iostream>

/*!
 * Simple logging macro
 */
#define LOG(A)                                                                                                         \
    do {                                                                                                               \
        std::cerr << "[I] " << A << std::endl;                                                                         \
    } while (false)

/*!
 * Simple error logging macro
 */
#define ERR(A)                                                                                                         \
    do {                                                                                                               \
        std::cerr << "[E] " << A << std::endl;                                                                         \
    } while (false)
