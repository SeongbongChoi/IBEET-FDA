#pragma once

#include <string>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <cstdlib>

#include <pbc/pbc.h>
#include "utils.h"

namespace LLH24
{

static constexpr int MSG_BYTES = 32;
static constexpr int ALPHA_BYTES = 32;
static constexpr int C4_BYTES = MSG_BYTES + ALPHA_BYTES;

struct MasterSecretKey
{
    element_t s1;
    element_t s2;
};

struct DecryptionKey
{
    element_t dk1; // G1: H1(ID)^s1
    element_t dk2; // G1: H1(ID)^s2
};

struct Ciphertext
{
    element_t c1;        // G1: g^alpha
    element_t c2;        // G1: g^beta
    element_t c3;        // G1: g^(alpha * H4(M) * H2(E1 || c1))
    uint8_t   c4[C4_BYTES]; // {0,1}^(tau+log p): H3(...) XOR (M || alpha_bytes)
};

struct Trapdoor
{
    element_t td; // Zr: H5(E2) / H2(E1 || c1)
};

class LLH24Scheme
{
public:
    pairing_t pairing;
    element_t g;
    element_t mpk1; // g^s1
    element_t mpk2; // g^s2

    int lenG1, lenGT, lenZr;

    LLH24Scheme(const std::string &param_str);
    ~LLH24Scheme();

    void setup(MasterSecretKey &msk);

    void extract(const std::string &id,
                 MasterSecretKey &msk,
                 DecryptionKey &dk);

    void encrypt(const std::string &id_s,
                 const std::string &id_r,
                 DecryptionKey &dk_s,
                 const uint8_t *M,
                 Ciphertext &C);

    bool decrypt(const std::string &id_s,
                 DecryptionKey &dk_r,
                 Ciphertext &C,
                 uint8_t *M);

    void auth(const std::string &id_s,
              const std::string &id_r_prime,
              DecryptionKey &dk_r,
              Ciphertext &C,
              Trapdoor &td);

    bool test(Ciphertext &C,  Trapdoor &td,
              Ciphertext &Cp, Trapdoor &tdp);

private:
    void H1(const std::string &id, element_t out);          // {0,1}* -> G1
    void H2(element_t eVal, element_t c1, element_t out);   // GT x G1 -> Zr
    void H3(element_t eVal, element_t c1, element_t c2,
            element_t c3, uint8_t *out);                    // GT x G1^3 -> {0,1}^C4_BYTES
    void H4(const uint8_t *M, element_t out);               // {0,1}* -> Zr
    void H5(element_t eVal, element_t out);                 // GT -> Zr
};

} // namespace LLH24