#pragma once

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdlib>
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

inline void SHAKE256_hash(const uint8_t *src, size_t slen, uint8_t *dest, size_t dlen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1
             || EVP_DigestUpdate(ctx, src, slen) != 1
             || EVP_DigestFinalXOF(ctx, dest, dlen) != 1)
    {
        std::cerr << "SHAKE256_hash failed" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ctx);
}

inline void random_Zpstar(element_t x)
{
    do element_random(x); while (element_is0(x));
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


inline void poly_interpolate(element_t *coeffs,
                             const element_t *xs,
                             const element_t *ys,
                             size_t n,
                             pairing_t pairing)
{
    assert(n >= 1);

    for (size_t i = 0; i < n; i++)
        element_set0(coeffs[i]);

    element_t *master = new element_t[n + 1];
    for (size_t i = 0; i <= n; i++) element_init_Zr(master[i], pairing);
    poly_from_roots(master, xs, n, pairing);

    element_t *basis = new element_t[n];
    for (size_t i = 0; i < n; i++) element_init_Zr(basis[i], pairing);

    element_t denom, scale, tmp;
    element_init_Zr(denom, pairing);
    element_init_Zr(scale, pairing);
    element_init_Zr(tmp,   pairing);

    for (size_t k = 0; k < n; k++)
    {
        element_set(basis[n - 1], master[n]);
        for (int i = (int)n - 2; i >= 0; i--)
        {
            element_mul(tmp, basis[i + 1], const_cast<element_t &>(xs[k]));
            element_add(basis[i], master[i + 1], tmp);
        }

        poly_eval(denom, basis, n - 1, const_cast<element_t &>(xs[k]), pairing);
        assert(!element_is0(denom));
        element_div(scale, const_cast<element_t &>(ys[k]), denom);

        for (size_t i = 0; i < n; i++)
        {
            element_mul(tmp, basis[i], scale);
            element_add(coeffs[i], coeffs[i], tmp);
        }
    }

    element_clear(denom); element_clear(scale); element_clear(tmp);
    for (size_t i = 0; i < n; i++)  element_clear(basis[i]);
    for (size_t i = 0; i <= n; i++) element_clear(master[i]);
    delete[] basis;
    delete[] master;
}

inline double avg(const std::vector<double> &v)
{
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
}

inline double median(std::vector<double> v)
{
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t m = v.size() / 2;
    return (v.size() % 2) ? v[m] : 0.5 * (v[m - 1] + v[m]);
}

inline double stddev(const std::vector<double> &v)
{
    if (v.size() < 2) return 0.0;
    const double m = avg(v);
    double acc = 0.0;
    for (double x : v) acc += (x - m) * (x - m);
    return std::sqrt(acc / (v.size() - 1));
}