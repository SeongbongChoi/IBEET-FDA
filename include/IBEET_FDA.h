#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

#include <pbc/pbc.h>
#include "utils.h"

namespace IBEET
{

    static constexpr int L1 = 32;
    static constexpr int L2 = 32;
    static constexpr int L12 = L1 + L2;

    struct MasterSecretKey
    {
        element_t s1;
        element_t s2;
    };

    struct DecryptionKey
    {
        element_t dk1;
        element_t dk2;
    };

    struct Ciphertext
    {
        element_t C1;
        element_t C2;
        element_t C3;
        uint8_t C4[L12];
    };

    struct Trapdoor1
    {
        element_t td1; // G1
    };

    struct Trapdoor2
    {
        element_t td2; // Zr
    };

    struct Trapdoor3i
    {
        element_t td3;
    };
    struct Trapdoor3j
    {
        element_t td3;
    };


    struct Trapdoor4
    {
        element_t TD1;
        element_t TD2;
    };

    struct TrapdoorFDA
    {
        element_t td1;
        element_t *td2;
        size_t n; 
    };

    class IBEET_FDA
    {
    public:
        pairing_t pairing;
        element_t g;
        element_t mpk1;
        element_t mpk2;

        int lenG1, lenGT, lenZr;

        IBEET_FDA(const std::string &param_str);
        ~IBEET_FDA();

        void setup(MasterSecretKey &msk);

        void extract(const std::string &id,
                     MasterSecretKey &msk,
                     DecryptionKey &dk);

        void encrypt(const std::string &id,
                     const uint8_t *M,
                     Ciphertext &C);

        bool decrypt(DecryptionKey &dk,
                     Ciphertext &C,
                     uint8_t *M);

        void auth1(DecryptionKey &dk, Trapdoor1 &td);
        bool test1(Ciphertext &Ci, Trapdoor1 &tdi,
                   Ciphertext &Cj, Trapdoor1 &tdj);

        void auth2(DecryptionKey &dk, Ciphertext &C, Trapdoor2 &td);
        bool test2(Ciphertext &Ci, Trapdoor2 &tdi,
                   Ciphertext &Cj, Trapdoor2 &tdj);

        void auth3i(DecryptionKey &dk, Ciphertext &C, Trapdoor3i &td);
        void auth3j(DecryptionKey &dk, Trapdoor3j &td);
        bool test3(Ciphertext &Ci, Trapdoor3i &tdi,
                   Ciphertext &Cj, Trapdoor3j &tdj);

        void auth4(DecryptionKey &dk, Ciphertext &Ci, Ciphertext &Cj,
                   element_t gamma, Trapdoor4 &td);
        bool test4(Ciphertext &Ci, Trapdoor4 &tdi,
                   Ciphertext &Cj, Trapdoor4 &tdj);

        void authFDA(Ciphertext &C,
                     DecryptionKey &dk,
                     const std::vector<std::string> &testerIds,
                     TrapdoorFDA &td);
        bool testFDA(Ciphertext &Ci, TrapdoorFDA &tdi,
                     Ciphertext &Cj, TrapdoorFDA &tdj,
                     DecryptionKey &dkt);

    private:
        void H1(const std::string &id, element_t out);
        void H2(element_t t, element_t out);
        void H3(element_t t, element_t k, uint8_t *out);
        void H4(const uint8_t *M, element_t out);
    };

} // namespace IBEET