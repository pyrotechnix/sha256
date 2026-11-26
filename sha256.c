#include "sha256.h"

const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Modulo but positive
int positive_modulo(int i, int n) {
    return (i % n + n) % n;
}

// Calculates the number of 512 byte blocks required to store a message including padding
uint64_t get_num_blocks(char *message) {
    uint64_t l = strlen(message) * 8;
    return (l + 72) / 512 + ((l + 72) % 512 != 0);
}

// Pads the original message according to the specification
uint8_t *pad_message(char *message, uint64_t num_blocks) {
    uint64_t l = strlen(message) * 8;
    int num_zeros_to_add = positive_modulo(440 - l, 512);
    uint8_t *processed_string = malloc(sizeof(uint8_t) * num_blocks * 64);
    int idx;
    for (idx = 0; idx < strlen(message); idx++) {
        processed_string[idx] = message[idx];
    }
    processed_string[idx] = 0b10000000;
    idx++;
    // Adding 0s
    for (int i = 0; i < num_zeros_to_add / 8; i++) {
        processed_string[idx] = 0b00000000;
        idx++;
    }
    // Adding length
    for (int i = 0; i < 8; i++) {
        processed_string[idx] = (l >> ((7 - i) * 8)) & 0b11111111;
        idx++;
    }
    return processed_string;
}

uint32_t *convert_string_to_words(uint8_t *string, uint64_t num_blocks) {
    uint32_t *words = malloc(sizeof(uint32_t) * num_blocks * 16);
    for (int i = 0; i < num_blocks * 16; i++) {
        words[i] = 0;
        words[i] |= string[i * 4] << 24;
        words[i] |= string[i * 4 + 1] << 16;
        words[i] |= string[i * 4 + 2] << 8;
        words[i] |= string[i * 4 + 3];
    }
    free(string);
    return words;
}

// Choose function (From the spec I don't really know what it does)
uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

// Majority function (Returns bits which are true in at least 2 of the 3 numbers)
uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// Rotate right
uint32_t rotr(uint32_t num, int n) {
    return num >> n | num << (32 - n);
}

// As far as I am aware, these are just arbitrarily messing up the data
uint32_t sigma0(uint32_t num) {
    return rotr(num, 7) ^ rotr(num, 18) ^ (num >> 3); 
}

uint32_t sigma1(uint32_t num) {
    return rotr(num, 17) ^ rotr(num, 19) ^ (num >> 10); 
}

uint32_t bigma0(uint32_t num) {
    return rotr(num, 2) ^ rotr(num, 13) ^ rotr(num, 22);
}

uint32_t bigma1(uint32_t num) {
    return rotr(num, 6) ^ rotr(num, 11) ^ rotr(num, 25);
}

// Set the message schedule
void set_message_schedule(uint64_t block_num, uint32_t *words, uint32_t w[64]) {
    for (int i = 0; i < 16; i++) {
        w[i] = words[block_num * 16 + i];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }
}

char char_to_hex(uint8_t input) {
    if (input < 0xa) {
        return input + '0';
    } else {
        return input - 10 + 'a';
    }
}

// Convert the output into a null-terminated string
char *convert_words_to_str(uint32_t words[8]) {
    char *ret = malloc(sizeof(char) * 65);
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            ret[i * 8 + j] = char_to_hex((words[i] >> ((7 - j) * 4)) & 0b1111);
        }
    }
    return ret;
}

// Apply SHA256 to a message and returns it as a null-terminated hex string
char *sha256(char *message) {
    uint64_t num_blocks = get_num_blocks(message);
    uint8_t *preprocessed_string = pad_message(message, num_blocks);
    uint32_t *words = convert_string_to_words(preprocessed_string, num_blocks);
    // Setting initial hashes as detailed in spec
    uint32_t hashes[8] = {
        0x6a09e667, 0xbb67ae85, 
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    };
    // Message schedule
    uint32_t w[64];
    // Working variables
    uint32_t vars[8];
    // Temporary variables
    uint32_t t1;
    uint32_t t2;
    for (int i = 0; i < num_blocks; i++) {
        set_message_schedule(i, words, w);
        memcpy(vars, hashes, sizeof(hashes));
        for (int t = 0; t < 64; t++) {
            t1 = vars[7] + bigma1(vars[4]) + ch(vars[4], vars[5], vars[6]) + k[t] + w[t];
            t2 = bigma0(vars[0]) + maj(vars[0], vars[1], vars[2]);
            vars[7] = vars[6];
            vars[6] = vars[5];
            vars[5] = vars[4];
            vars[4] = vars[3] + t1;
            vars[3] = vars[2];
            vars[2] = vars[1];
            vars[1] = vars[0];
            vars[0] = t1 + t2;
        }
        for (int j = 0; j < 8; j++) {
            hashes[j] = vars[j] + hashes[j];
        }
    }
    char *output = convert_words_to_str(hashes);
    return output;
}
