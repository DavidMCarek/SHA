// EECS 4980:805 Inside Cryptography
// SHA512 Project
// David Carek

// this file contains the internal components required to hash a 16 byte block with an 8 byte block to 
// produce an 8 byte block.

#include "SHA.h"
#include <stdlib.h>
#include <iostream>

// these are the round constants used in the round function for hashing
static const uint64_t roundConstants[80] = {
	0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538,
	0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242, 0x12835B0145706FBE,
	0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,	0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
	0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5, 0x983E5152EE66DFAB,
	0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
	0x06CA6351E003826F, 0x142929670A0E6E70,	0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED,
	0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
	0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
	0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8, 0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
	0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,	0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373,
	0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
	0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B, 0xCA273ECEEA26619C,
	0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
	0x113F9804BEF90DAE, 0x1B710B35131C471B,	0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
	0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};

// used to generate the wi required for each round of the hashing
static void wordGen(uint64_t words[80]) {
	// we already have 0 to 15 wi generated so we just need to compute w16 to w79
	for (int i = 16; i < 80; i++) {
		// this function is a little hard to look at but is given in the slides
		words[i] = words[i - 16] + (_rotr64(words[i - 15], 1) ^ _rotr64(words[i - 15], 8) ^ (words[i - 15] >> 7)) +
			words[i - 7] + (_rotr64(words[i - 2], 19) ^ _rotr64(words[i - 2], 61) ^ (words[i - 2] >> 6));
	}
}

// this function runs one round of hashing and stores the result in hash[8]
static void round(uint64_t word, uint64_t roundConstant, uint64_t hash[8]) {
	// calculate all of the needed components needed for hash[4] and hash[0]

	// does a best 2 out of 3 at the bit level
	uint64_t majority = (hash[0] & hash[1]) | (hash[0] & hash[2]) | (hash[1] & hash[2]);
	// if hash[4] then hash[5] else hash[6] at the bit level
	uint64_t conditional = (hash[4] & hash[5]) | (~hash[4] & hash[6]);
	// xor rotated versions of A(hash[0]) with eachother
	uint64_t aRot = _rotr64(hash[0], 28) ^ _rotr64(hash[0], 34) ^ _rotr64(hash[0], 39);
	// same as above but with E(hash[4])
	uint64_t eRot = _rotr64(hash[4], 14) ^ _rotr64(hash[4], 18) ^ _rotr64(hash[4], 41);
	// output of mixer 2 from the slides
	uint64_t mix = hash[7] + conditional + eRot + word + roundConstant;

	hash[7] = hash[6];
	hash[6] = hash[5];
	hash[5] = hash[4];
	hash[4] = mix + hash[3]; // mixer 2 + D(hash[3])
	hash[3] = hash[2];
	hash[2] = hash[1];
	hash[1] = hash[0];
	// majority + aRot = output of mixer 1. so A(hash[0]) = mixer 1 output + mixer 2 output
	hash[0] = majority + aRot + mix;
};

// this function controls the internals of the hashing function by running the input hash and plaintext 
// through the 80 rounds of hashing
void hash(uint64_t inputHash[8], uint64_t plaintext[16]) {

	uint64_t words[80];
	// copy the first 16 wi(plaintext) into the array for all 80 wi(words)
	std::memcpy(words, plaintext, sizeof(uint64_t) * 16);
	// generate the remaining wi(16 to 79)
	wordGen(words);

	uint64_t outputHash[8];
	// copy the input hash into the output hash so we can hold on to the original hash for the 
	// addition in a couple lines
	std::memcpy(outputHash, inputHash, sizeof(uint64_t) * 8);

	// run the 80 rounds for the hashing
	for (int i = 0; i < 80; i++) {
		round(words[i], roundConstants[i], outputHash);
	}

	// add the output hash to the input hash for the final step
	outputHash[0] += inputHash[0];
	outputHash[1] += inputHash[1];
	outputHash[2] += inputHash[2];
	outputHash[3] += inputHash[3];
	outputHash[4] += inputHash[4];
	outputHash[5] += inputHash[5];
	outputHash[6] += inputHash[6];
	outputHash[7] += inputHash[7];

	// store the output hash in the input hash so that the hash passed in holds the new hash value
	std::memcpy(inputHash, outputHash, sizeof(uint64_t) * 8);
}