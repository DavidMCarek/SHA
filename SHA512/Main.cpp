// EECS 4980:805 Inside Cryptography
// SHA512 Project
// David Carek

// This file is the main control for running SHA512. It reads and validates input params, keeps track of the hash, takes
// care of the padding for the final block, prints the output hash, and prints the elapsed time while hashing.

#include <iostream>
#include <fstream>
#include <chrono>
#include "SHA.h"

// this is used as the initial state of the hash
static const uint64_t iv[8] = {
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179
};

int main(int argc, char * argv[]) {

	// check arguments for input and notify user
	if (argc > 2) {
		std::cout << "Invalid arguments. Please use SHA512 <File>" << std::endl;
		return 1;
	}

	// try to open the file listed in the command
	std::ifstream inputStream;
	inputStream.open(argv[1], std::ios::binary);

	// if file could not open notify user
	if (inputStream.fail()) {
		std::cout << "Could not open input file" << std::endl;
		return 1;
	}

	// get the file length by going to the end of the file
	inputStream.seekg(0, inputStream.end);
	uint64_t fileSize = inputStream.tellg();
	uint64_t remainingSize = fileSize;
	inputStream.seekg(0, inputStream.beg); // reset to the beginning of the file

	char buffer[128]; // holds the text read in from the file
	uint64_t plaintext[16]; // holds the file input as 16 64 bit values

	uint64_t hashValue[8]; // holds the current hash state

	// the hashValue starts as the iv
	std::memcpy(hashValue, iv, sizeof(iv));

	std::chrono::time_point<std::chrono::system_clock> start, end;
	start = std::chrono::system_clock::now();

	// read through the file until there is not a full block to read in
	while (remainingSize > 127) {
		inputStream.read(buffer, sizeof(buffer)); // read a block from the file
		remainingSize -= sizeof(buffer); // correct the remaining size of the file after the read
		std::memcpy(plaintext, buffer, sizeof(buffer)); // move the buffer into the array of 64 bit values
		// use the byteswap to fix the byte positions in the array
		for (int i = 0; i < 16; i++) {
			plaintext[i] = _byteswap_uint64(plaintext[i]);
		}

		// hash the plaintext with the previous hash
		hash(hashValue, plaintext);
	}

	inputStream.read(buffer, remainingSize); // read in what's left in the file
	buffer[remainingSize] = 0x80; // start the padding for the last or second to last block
	// fill the rest of the block with zeros
	for (int i = remainingSize + 1; i < 128; i++) {
		buffer[i] = 0x00;
	}

	std::memcpy(plaintext, buffer, sizeof(buffer)); // move the buffer into the array of 64 bit values
	// use the byteswap to fix the byte positions in the array
	for (int i = 0; i < 15; i++) {
		plaintext[i] = _byteswap_uint64(plaintext[i]);
	}

	// if the remaining size is greater than 110 then we do not have room for the file size section
	// of the padding. So, we need to hash the current block and fill the next block with zeros except
	// for the last section which will contain the file length
	if (remainingSize > 110) {
		hash(hashValue, plaintext);

		for (int i = 0; i < 15; i++) {
			plaintext[i] = 0;
		}
	}

	plaintext[15] = fileSize * 8; // set the last 64 bits to the file size

	hash(hashValue, plaintext); // and hash the final block

	end = std::chrono::system_clock::now();

	// print the hash
	printf("%llX %llX %llX %llX %llX %llX %llX %llX\n", hashValue[0], hashValue[1], hashValue[2], hashValue[3], hashValue[4], hashValue[5], hashValue[6], hashValue[7]);
	// print elapsed time
	std::chrono::duration<double> elapsedTime = end - start;
	printf("Elapsed Time: %.3f Seconds\n", elapsedTime.count());
	return 0;
}