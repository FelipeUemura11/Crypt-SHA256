#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Constantes da especificação SHA-256
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Funções auxiliares
#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define SHR(x, n) (x >> n)
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// Estrutura para armazenar o estado do hash
typedef struct {
    uint32_t h[8]; // variaveis de estado do SHA-256
    uint8_t buffer[64]; // chunk expandido de 512 bits
    uint64_t bitlen; // contador que rastreia o numero total de bits processados
} SHA256_HashState;

// Inicializa o estado do SHA-256
void sha256_inicio(SHA256_HashState *hash_state) {
    // h[i] são os valores iniciais constantes do SHA-256
    hash_state->h[0] = 0x6a09e667; // a
    hash_state->h[1] = 0xbb67ae85; // b
    hash_state->h[2] = 0x3c6ef372; // c
    hash_state->h[3] = 0xa54ff53a; // d
    hash_state->h[4] = 0x510e527f; // e
    hash_state->h[5] = 0x9b05688c; // f
    hash_state->h[6] = 0x1f83d9ab; // g
    hash_state->h[7] = 0x5be0cd19; // h
    hash_state->bitlen = 0; // rastreia o numero total de bits processados
    // Buffer eh uma arrays de 64 bytes para armazenar os dados
    memset(hash_state->buffer, 0, 64); // inicializado com zeros
}

// Processa um bloco de 512 bits
void sha256_transformar(SHA256_HashState *hash_state, const uint8_t *data) {
    uint32_t m[64], w[8], temp1, temp2;
    for (int i = 0; i < 16; ++i) {
        m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
    }

    for (int i = 0; i < 8; ++i) {
        w[i] = hash_state->h[i];
    }

    for (int i = 0; i < 64; ++i) {
        temp1 = w[7] + SIGMA1(w[4]) + CH(w[4], w[5], w[6]) + k[i] + m[i];
        temp2 = SIGMA0(w[0]) + MAJ(w[0], w[1], w[2]);
        w[7] = w[6];
        w[6] = w[5];
        w[5] = w[4];
        w[4] = w[3] + temp1;
        w[3] = w[2];
        w[2] = w[1];
        w[1] = w[0];
        w[0] = temp1 + temp2;
    }

    for (int i = 0; i < 8; ++i) {
        hash_state->h[i] += w[i];
    }
}

// Atualiza o hash com novos dados
void sha256_atualizar(SHA256_HashState *hash_state, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // dados adicionados ao buffer
        hash_state->buffer[hash_state->bitlen / 8 % 64] = data[i];
        hash_state->bitlen += 8;
        // se o buffer estiver cheio, processa o bloco e atualiza em bitlen
        if (hash_state->bitlen % 512 == 0) {
            sha256_transformar(hash_state, hash_state->buffer);
        }
    }
}

// Finaliza o hash e gera o digest
void sha256_final(SHA256_HashState *hash_state, uint8_t *hash) {
    size_t i = hash_state->bitlen / 8 % 64;

    hash_state->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) {
            hash_state->buffer[i++] = 0x00;
        }
        sha256_transformar(hash_state, hash_state->buffer);
        i = 0;
    }
    while (i < 56) {
        hash_state->buffer[i++] = 0x00;
    }

    uint64_t bitlen_be = hash_state->bitlen;
    for (int j = 0; j < 8; ++j) {
        hash_state->buffer[63 - j] = bitlen_be & 0xFF;
        bitlen_be >>= 8;
    }
    sha256_transformar(hash_state, hash_state->buffer);

    for (i = 0; i < 8; ++i) {
        hash[i * 4] = (hash_state->h[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (hash_state->h[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (hash_state->h[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = hash_state->h[i] & 0xFF;
    }
}

// Função principal para testar o SHA-256
int main() {
    SHA256_HashState hash_state;
    uint8_t hash[32];
    char *input = "senha";
    
    sha256_inicio(&hash_state); // Estado inicial do SHA-256
    sha256_atualizar(&hash_state, (uint8_t *)input, strlen(input));
    sha256_final(&hash_state, hash);

    printf("Input: %s\n", input);
    printf("Hash SHA-256: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}