#pragma once

#include <vector>
#include <cstdint>
#include <cstring>

#include <pbc/pbc.h>
#include "utils.h"

namespace PKEET
{

static constexpr int MSG_BYTES = 32;

struct ServerKeyPair
{
    element_t Xc;
    element_t xc;
};

struct UserKeyPair
{
    element_t X;
    element_t Y;
    element_t x;
    element_t y;
};

struct TesterKeyPair
{
    element_t Xt;
    element_t xt;
};

struct Ciphertext
{
    element_t c1;
    element_t c2;
    uint8_t  *c3;
    element_t c4;
    uint8_t   c5[32];
};

struct Trapdoor
{
    element_t *td1;
    element_t  td2;
    size_t     n;
};

class PKEET_FDA
{
public:
    pairing_t pairing;
    element_t g;

    int lenG1, lenZr;

    PKEET_FDA(const std::string &param_str);
    ~PKEET_FDA();

    void setup();

    void userGen  (UserKeyPair   &ukp);
    void serverGen(ServerKeyPair &skp);
    void testerGen(TesterKeyPair &tkp);

    void encrypt(const uint8_t *m,
                 UserKeyPair   &ukp,
                 ServerKeyPair &skp,
                 Ciphertext    &CT);

    bool decrypt(Ciphertext  &CT,
                 UserKeyPair &ukp,
                 uint8_t     *m);

    void auth(Ciphertext               &CT,
              UserKeyPair              &ukp,
              ServerKeyPair            &skp,
              std::vector<TesterKeyPair> &testers,
              Trapdoor                 &td);

    bool test(Ciphertext    &CTi, Trapdoor &TDi,
              Ciphertext    &CTj, Trapdoor &TDj,
              TesterKeyPair &tkp,
              ServerKeyPair &skp);

private:
    void H1(const uint8_t *in, size_t inlen, uint8_t *out);
    void H2(const uint8_t *in, size_t inlen, element_t out);
    void H3(const uint8_t *in, size_t inlen, uint8_t *out);
};

} // namespace PKEET