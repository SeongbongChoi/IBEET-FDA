#include "LLH24.h"

namespace LLH24
{

LLH24Scheme::LLH24Scheme(const std::string &param_str)
{
    if (pairing_init_set_str(pairing, param_str.c_str()) != 0)
    {
        std::cerr << "LLH24Scheme: pairing_init_set_str failed\n";
        std::exit(EXIT_FAILURE);
    }

    element_init_G1(g,    pairing);
    element_init_G1(mpk1, pairing);
    element_init_G1(mpk2, pairing);

    lenG1 = pairing_length_in_bytes_G1(pairing);
    lenGT = pairing_length_in_bytes_GT(pairing);
    lenZr = pairing_length_in_bytes_Zr(pairing);
}

LLH24Scheme::~LLH24Scheme()
{
    element_clear(g);
    element_clear(mpk1);
    element_clear(mpk2);
    pairing_clear(pairing);
}

void LLH24Scheme::H1(const std::string &id, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash((const uint8_t *)id.data(), id.size(), digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

void LLH24Scheme::H2(element_t eVal, element_t c1, element_t out)
{
    uint8_t *buf = new uint8_t[lenGT + lenG1];
    element_to_bytes(buf,          eVal);
    element_to_bytes(buf + lenGT,  c1);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(buf, lenGT + lenG1, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
    delete[] buf;
}

void LLH24Scheme::H3(element_t eVal, element_t c1, element_t c2, element_t c3, uint8_t *out)
{
    uint8_t *buf = new uint8_t[lenGT + 3 * lenG1];
    element_to_bytes(buf,                    eVal);
    element_to_bytes(buf + lenGT,            c1);
    element_to_bytes(buf + lenGT + lenG1,    c2);
    element_to_bytes(buf + lenGT + 2*lenG1,  c3);
    uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512_hash(buf, lenGT + 3 * lenG1, digest);
    memcpy(out, digest, C4_BYTES);
    delete[] buf;
}

void LLH24Scheme::H4(const uint8_t *M, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(M, MSG_BYTES, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

void LLH24Scheme::H5(element_t eVal, element_t out)
{
    uint8_t *buf = new uint8_t[lenGT];
    element_to_bytes(buf, eVal);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(buf, lenGT, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
    delete[] buf;
}

void LLH24Scheme::setup(MasterSecretKey &msk)
{
    element_random(g);

    element_init_Zr(msk.s1, pairing);
    element_init_Zr(msk.s2, pairing);
    element_random(msk.s1);
    element_random(msk.s2);

    element_pow_zn(mpk1, g, msk.s1);
    element_pow_zn(mpk2, g, msk.s2);
}

void LLH24Scheme::extract(const std::string &id,
                    MasterSecretKey &msk,
                    DecryptionKey &dk)
{
    element_t hID;
    element_init_G1(hID, pairing);
    H1(id, hID);

    element_init_G1(dk.dk1, pairing);
    element_init_G1(dk.dk2, pairing);
    element_pow_zn(dk.dk1, hID, msk.s1);
    element_pow_zn(dk.dk2, hID, msk.s2);

    element_clear(hID);
}

void LLH24Scheme::encrypt(const std::string &id_s,
                    const std::string &id_r,
                    DecryptionKey &dk_s,
                    const uint8_t *M,
                    Ciphertext &C)
{
    element_t hID_r;
    element_init_G1(hID_r, pairing);
    H1(id_r, hID_r);

    element_t alpha, beta;
    element_init_Zr(alpha, pairing); element_random(alpha);
    element_init_Zr(beta,  pairing); element_random(beta);

    element_init_G1(C.c1, pairing); element_pow_zn(C.c1, g, alpha);
    element_init_G1(C.c2, pairing); element_pow_zn(C.c2, g, beta);

    // E1 = e(dk_s1, H1(ID_r))  (symmetric pairing: e(G1,G1)->GT)
    element_t E1;
    element_init_GT(E1, pairing);
    element_pairing(E1, dk_s.dk1, hID_r);

    // H2(E1 || c1)
    element_t h2val;
    element_init_Zr(h2val, pairing);
    H2(E1, C.c1, h2val);

    // H4(M)
    element_t h4val;
    element_init_Zr(h4val, pairing);
    H4(M, h4val);

    // c3 = g^(alpha * H4(M) * H2(E1||c1))
    element_t exp;
    element_init_Zr(exp, pairing);
    element_mul(exp, alpha, h4val);
    element_mul(exp, exp, h2val);
    element_init_G1(C.c3, pairing);
    element_pow_zn(C.c3, g, exp);

    // E_for_c4 = e(mpk2, H1(ID_r))^beta
    element_t eBase;
    element_init_GT(eBase, pairing);
    element_pairing(eBase, mpk2, hID_r);
    element_t eBeta;
    element_init_GT(eBeta, pairing);
    element_pow_zn(eBeta, eBase, beta);

    // H3(e(mpk2,H1(ID_r))^beta || c1 || c2 || c3)
    uint8_t h3buf[C4_BYTES];
    H3(eBeta, C.c1, C.c2, C.c3, h3buf);

    // c4 = H3(...) XOR (M || alpha_bytes)
    uint8_t plain[C4_BYTES] = {};
    memcpy(plain, M, MSG_BYTES);
    uint8_t alpha_buf[ALPHA_BYTES] = {};
    element_to_bytes(alpha_buf, alpha);
    memcpy(plain + MSG_BYTES, alpha_buf, ALPHA_BYTES);
    for (int i = 0; i < C4_BYTES; i++)
        C.c4[i] = plain[i] ^ h3buf[i];

    element_clear(hID_r);
    element_clear(alpha); element_clear(beta);
    element_clear(E1);    element_clear(h2val);
    element_clear(h4val); element_clear(exp);
    element_clear(eBase); element_clear(eBeta);
}

bool LLH24Scheme::decrypt(const std::string &id_s,
                    DecryptionKey &dk_r,
                    Ciphertext &C,
                    uint8_t *M)
{
    // Recover (M || alpha) = c4 XOR H3(e(dk_r2, c2) || c1 || c2 || c3)
    element_t eDkr2c2;
    element_init_GT(eDkr2c2, pairing);
    element_pairing(eDkr2c2, dk_r.dk2, C.c2);

    uint8_t h3buf[C4_BYTES];
    H3(eDkr2c2, C.c1, C.c2, C.c3, h3buf);

    uint8_t plain[C4_BYTES];
    for (int i = 0; i < C4_BYTES; i++)
        plain[i] = C.c4[i] ^ h3buf[i];

    uint8_t *M_dec     = plain;
    uint8_t *alpha_buf = plain + MSG_BYTES;

    element_t alpha;
    element_init_Zr(alpha, pairing);
    element_from_bytes(alpha, alpha_buf);

    // Check c1 = g^alpha
    element_t check1;
    element_init_G1(check1, pairing);
    element_pow_zn(check1, g, alpha);
    if (element_cmp(C.c1, check1))
    {
        element_clear(eDkr2c2); element_clear(alpha); element_clear(check1);
        return false;
    }

    // E1 = e(dk_r1, H1(ID_s))
    element_t hID_s;
    element_init_G1(hID_s, pairing);
    H1(id_s, hID_s);

    element_t E1;
    element_init_GT(E1, pairing);
    element_pairing(E1, dk_r.dk1, hID_s);

    element_t h2val;
    element_init_Zr(h2val, pairing);
    H2(E1, C.c1, h2val);

    element_t h4val;
    element_init_Zr(h4val, pairing);
    H4(M_dec, h4val);

    // Check c3 = g^(alpha * H4(M) * H2(E1||c1))
    element_t exp;
    element_init_Zr(exp, pairing);
    element_mul(exp, alpha, h4val);
    element_mul(exp, exp, h2val);
    element_t check3;
    element_init_G1(check3, pairing);
    element_pow_zn(check3, g, exp);
    if (element_cmp(C.c3, check3))
    {
        element_clear(eDkr2c2); element_clear(alpha); element_clear(check1);
        element_clear(hID_s);   element_clear(E1);    element_clear(h2val);
        element_clear(h4val);   element_clear(exp);   element_clear(check3);
        return false;
    }

    memcpy(M, M_dec, MSG_BYTES);

    element_clear(eDkr2c2); element_clear(alpha); element_clear(check1);
    element_clear(hID_s);   element_clear(E1);    element_clear(h2val);
    element_clear(h4val);   element_clear(exp);   element_clear(check3);
    return true;
}

void LLH24Scheme::auth(const std::string &id_s,
                 const std::string &id_r_prime,
                 DecryptionKey &dk_r,
                 Ciphertext &C,
                 Trapdoor &td)
{
    element_t hID_s, hID_rp;
    element_init_G1(hID_s,  pairing);
    element_init_G1(hID_rp, pairing);
    H1(id_s,       hID_s);
    H1(id_r_prime, hID_rp);

    // E1 = e(dk_r1, H1(ID_s))
    element_t E1;
    element_init_GT(E1, pairing);
    element_pairing(E1, dk_r.dk1, hID_s);

    // E2 = e(dk_r1, H1(ID_r'))
    element_t E2;
    element_init_GT(E2, pairing);
    element_pairing(E2, dk_r.dk1, hID_rp);

    // H2(E1 || c1)
    element_t h2val;
    element_init_Zr(h2val, pairing);
    H2(E1, C.c1, h2val);

    // H5(E2)
    element_t h5val;
    element_init_Zr(h5val, pairing);
    H5(E2, h5val);

    // td = H5(E2) / H2(E1 || c1)
    element_init_Zr(td.td, pairing);
    element_div(td.td, h5val, h2val);

    element_clear(hID_s); element_clear(hID_rp);
    element_clear(E1);    element_clear(E2);
    element_clear(h2val); element_clear(h5val);
}

bool LLH24Scheme::test(Ciphertext &C,  Trapdoor &td,
                 Ciphertext &Cp, Trapdoor &tdp)
{
    // Check e(c1, c'3)^td' = e(c'1, c3)^td
    element_t lhs_base, rhs_base;
    element_init_GT(lhs_base, pairing);
    element_init_GT(rhs_base, pairing);
    element_pairing(lhs_base, C.c1,  Cp.c3);
    element_pairing(rhs_base, Cp.c1, C.c3);

    element_t lhs, rhs;
    element_init_GT(lhs, pairing);
    element_init_GT(rhs, pairing);
    element_pow_zn(lhs, lhs_base, tdp.td);
    element_pow_zn(rhs, rhs_base, td.td);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(lhs_base); element_clear(rhs_base);
    element_clear(lhs);      element_clear(rhs);
    return result;
}

} // namespace LLH24