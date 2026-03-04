#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <numeric>
#include <vector>

#include <pbc/pbc.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


inline void SHA256_hash(const uint8_t *src, size_t slen, uint8_t *dest)
{
    const EVP_MD *md = EVP_sha3_256();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int dlen = SHA256_DIGEST_LENGTH;
    if (!ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1
             || EVP_DigestUpdate(ctx, src, slen) != 1
             || EVP_DigestFinal_ex(ctx, dest, &dlen) != 1)
    {
        std::cerr << "SHA256_hash failed" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ctx);
}

inline void SHA512_hash(const uint8_t *src, size_t slen, uint8_t *dest)
{
    const EVP_MD *md = EVP_sha3_512();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int dlen = SHA512_DIGEST_LENGTH;
    if (!ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1
             || EVP_DigestUpdate(ctx, src, slen) != 1
             || EVP_DigestFinal_ex(ctx, dest, &dlen) != 1)
    {
        std::cerr << "SHA512_hash failed" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ctx);
}

inline void poly_from_roots(element_t *coeffs,
                             const element_t *roots,
                             size_t n,
                             pairing_t pairing)
{
    for (size_t i = 0; i <= n; i++)
        element_set0(coeffs[i]);
    element_set1(coeffs[0]);

    element_t tmp;
    element_init_Zr(tmp, pairing);

    for (size_t i = 0; i < n; i++)
    {
        for (size_t k = i + 1; k >= 1; k--)
        {
            element_mul(tmp, const_cast<element_t &>(roots[i]), coeffs[k]);
            element_sub(coeffs[k], coeffs[k - 1], tmp);
        }
        element_mul(tmp, const_cast<element_t &>(roots[i]), coeffs[0]);
        element_neg(coeffs[0], tmp);
    }

    element_clear(tmp);
}

inline void poly_eval(element_t val,
                      element_t *coeffs,
                      size_t deg,
                      element_t x,
                      pairing_t pairing)
{
    element_set(val, coeffs[deg]);

    element_t tmp;
    element_init_Zr(tmp, pairing);

    for (int k = (int)deg - 1; k >= 0; k--)
    {
        element_mul(tmp, val, x);
        element_add(val, tmp, coeffs[k]);
    }

    element_clear(tmp);
}


inline double avg(const std::vector<double> &v)
{
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
}