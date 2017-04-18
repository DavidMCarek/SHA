// EECS 4980:805 Inside Cryptography
// SHA512 Project
// David Carek

// this file acts as the interface for the SHA512.cpp file and exposes the hash function for
// other sections of the program that need it
#pragma once
#include <cstdint>

void hash(uint64_t inputHash[8], uint64_t plaintext[16]);