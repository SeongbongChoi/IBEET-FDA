#include "IBEET_FDA.h"

namespace IBEET
{

IBEET_FDA::IBEET_FDA(const std::string &param_str)
{
    if (pairing_init_set_str(pairing, param_str.c_str()) != 0)
    {
        std::cerr << "IBEET_FDA: pairing_init_set_str failed\n";
        std::exit(EXIT_FAILURE);
    }

    element_init_G1(g,    pairing);
    element_init_G1(mpk1, pairing);
    element_init_G1(mpk2, pairing);

    lenG1 = pairing_length_in_bytes_G1(pairing);
    lenGT = pairing_length_in_bytes_GT(pairing);
    lenZr = pairing_length_in_bytes_Zr(pairing);
}

IBEET_FDA::~IBEET_FDA()
{
    element_clear(g);
    element_clear(mpk1);
    element_clear(mpk2);
    pairing_clear(pairing);
}

void IBEET_FDA::H1(const std::string &id, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash((const uint8_t *)id.data(), id.size(), digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

void IBEET_FDA::H2(element_t t, element_t out)
{
    uint8_t *buf = new uint8_t[lenGT];
    element_to_bytes(buf, t);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(buf, lenGT, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
    delete[] buf;
}

void IBEET_FDA::H3(element_t t, element_t k, uint8_t *out)
{
    uint8_t *buf = new uint8_t[lenGT + lenZr];
    element_to_bytes(buf,         t);
    element_to_bytes(buf + lenGT, k);
    uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512_hash(buf, lenGT + lenZr, digest);
    memcpy(out, digest, L12);
    delete[] buf;
}

void IBEET_FDA::H4(const uint8_t *M, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(M, L1, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

void IBEET_FDA::setup(MasterSecretKey &msk)
{
    element_random(g);

    element_init_Zr(msk.s1, pairing);
    element_init_Zr(msk.s2, pairing);
    element_random(msk.s1);
    element_random(msk.s2);

    element_pow_zn(mpk1, g, msk.s1);
    element_pow_zn(mpk2, g, msk.s2);
}

void IBEET_FDA::extract(const std::string &id,
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

void IBEET_FDA::encrypt(const std::string &id,
                        const uint8_t *M,
                        Ciphertext &C)
{
    element_t hID;
    element_init_G1(hID, pairing);
    H1(id, hID);

    element_t r1, r2;
    element_init_Zr(r1, pairing); element_random(r1);
    element_init_Zr(r2, pairing); element_random(r2);

    element_init_G1(C.C1, pairing); element_pow_zn(C.C1, g, r1);
    element_init_G1(C.C2, pairing); element_pow_zn(C.C2, g, r2);

    element_t m;
    element_init_Zr(m, pairing);
    H4(M, m);

    element_t hID_r1;
    element_init_G1(hID_r1, pairing);
    element_pow_zn(hID_r1, hID, r1);

    element_t e1;
    element_init_GT(e1, pairing);
    element_pairing(e1, hID_r1, mpk1);

    element_t h3val;
    element_init_Zr(h3val, pairing);
    H2(e1, h3val);

    element_t mr1;
    element_init_Zr(mr1, pairing);
    element_mul(mr1, m, r1);

    element_init_Zr(C.C3, pairing);
    element_mul(C.C3, mr1, h3val);

    element_t hID_r2;
    element_init_G1(hID_r2, pairing);
    element_pow_zn(hID_r2, hID, r2);

    element_t e2;
    element_init_GT(e2, pairing);
    element_pairing(e2, hID_r2, mpk2);

    uint8_t h4buf[L12];
    H3(e2, mr1, h4buf);

    uint8_t mr1_buf[L12] = {};
    memcpy(mr1_buf, M, L1);
    element_to_bytes(mr1_buf + L1, r1);

    for (int i = 0; i < L12; i++)
        C.C4[i] = mr1_buf[i] ^ h4buf[i];

    element_clear(hID);
    element_clear(r1);     element_clear(r2);
    element_clear(m);      element_clear(mr1);
    element_clear(hID_r1); element_clear(hID_r2);
    element_clear(e1);     element_clear(e2);
    element_clear(h3val);
}

bool IBEET_FDA::decrypt(DecryptionKey &dk,
                        Ciphertext &C,
                        uint8_t *M)
{
    element_t e1;
    element_init_GT(e1, pairing);
    element_pairing(e1, dk.dk1, C.C1);

    element_t h3val;
    element_init_Zr(h3val, pairing);
    H2(e1, h3val);

    element_t k;
    element_init_Zr(k, pairing);
    element_div(k, C.C3, h3val);

    element_t e2;
    element_init_GT(e2, pairing);
    element_pairing(e2, dk.dk2, C.C2);

    uint8_t h4buf[L12];
    H3(e2, k, h4buf);

    uint8_t mr1_buf[L12];
    for (int i = 0; i < L12; i++)
        mr1_buf[i] = C.C4[i] ^ h4buf[i];

    uint8_t *M_dec  = mr1_buf;
    uint8_t *r1_buf = mr1_buf + L1;

    element_t r1;
    element_init_Zr(r1, pairing);
    element_from_bytes(r1, r1_buf);

    element_t check;
    element_init_G1(check, pairing);
    element_pow_zn(check, g, r1);
    if (element_cmp(C.C1, check))
    {
        element_clear(e1); element_clear(e2);
        element_clear(h3val); element_clear(k);
        element_clear(r1); element_clear(check);
        return false;
    }

    element_t m, mr1_check;
    element_init_Zr(m, pairing);
    element_init_Zr(mr1_check, pairing);
    H4(M_dec, m);
    element_mul(mr1_check, m, r1);

    if (element_cmp(k, mr1_check))
    {
        element_clear(e1); element_clear(e2);
        element_clear(h3val); element_clear(k);
        element_clear(r1); element_clear(check);
        element_clear(m); element_clear(mr1_check);
        return false;
    }

    memcpy(M, M_dec, L1);

    element_clear(e1); element_clear(e2);
    element_clear(h3val); element_clear(k);
    element_clear(r1); element_clear(check);
    element_clear(m); element_clear(mr1_check);
    return true;
}

// ── Type-1 ──────────────────────────────────────────────────────────────────

void IBEET_FDA::auth1(DecryptionKey &dk, Trapdoor1 &td)
{
    element_init_G1(td.td1, pairing);
    element_set(td.td1, dk.dk1);
}

bool IBEET_FDA::test1(Ciphertext &Ci, Trapdoor1 &tdi,
                      Ciphertext &Cj, Trapdoor1 &tdj)
{
    element_t ei, ej;
    element_init_GT(ei, pairing);
    element_init_GT(ej, pairing);
    element_pairing(ei, tdi.td1, Ci.C1);
    element_pairing(ej, tdj.td1, Cj.C1);

    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);
    H2(ei, vi);
    H2(ej, vj);

    element_div(vi, Ci.C3, vi);
    element_div(vj, Cj.C3, vj);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, vj);
    element_pow_zn(rhs, Cj.C1, vi);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(ei); element_clear(ej);
    element_clear(vi); element_clear(vj);
    element_clear(lhs); element_clear(rhs);
    return result;
}

// ── Type-2 ──────────────────────────────────────────────────────────────────

void IBEET_FDA::auth2(DecryptionKey &dk, Ciphertext &C, Trapdoor2 &td)
{
    element_t e;
    element_init_GT(e, pairing);
    element_pairing(e, dk.dk1, C.C1);

    element_init_Zr(td.td2, pairing);
    H2(e, td.td2);

    element_clear(e);
}

bool IBEET_FDA::test2(Ciphertext &Ci, Trapdoor2 &tdi,
                      Ciphertext &Cj, Trapdoor2 &tdj)
{
    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);
    element_div(vi, Ci.C3, tdi.td2);
    element_div(vj, Cj.C3, tdj.td2);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, vj);
    element_pow_zn(rhs, Cj.C1, vi);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(vi); element_clear(vj);
    element_clear(lhs); element_clear(rhs);
    return result;
}

// ── Type-3 ──────────────────────────────────────────────────────────────────

void IBEET_FDA::auth3i(DecryptionKey &dk, Ciphertext &C, Trapdoor3i &td)
{
    element_t e;
    element_init_GT(e, pairing);
    element_pairing(e, dk.dk1, C.C1);

    element_init_Zr(td.td3, pairing);
    H2(e, td.td3);

    element_clear(e);
}

void IBEET_FDA::auth3j(DecryptionKey &dk, Trapdoor3j &td)
{
    element_init_G1(td.td3, pairing);
    element_set(td.td3, dk.dk1);
}

bool IBEET_FDA::test3(Ciphertext &Ci, Trapdoor3i &tdi,
                      Ciphertext &Cj, Trapdoor3j &tdj)
{
    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);

    element_div(vi, Ci.C3, tdi.td3);

    element_t ej;
    element_init_GT(ej, pairing);
    element_pairing(ej, tdj.td3, Cj.C1);
    element_t h2ej;
    element_init_Zr(h2ej, pairing);
    H2(ej, h2ej);
    element_div(vj, Cj.C3, h2ej);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, vj);
    element_pow_zn(rhs, Cj.C1, vi);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(vi);  element_clear(vj);
    element_clear(ej);  element_clear(h2ej);
    element_clear(lhs); element_clear(rhs);
    return result;
}

// ── Type-4 ──────────────────────────────────────────────────────────────────

void IBEET_FDA::auth4(DecryptionKey &dk, Ciphertext &Ci, Ciphertext &Cj,
                      element_t gamma, Trapdoor4 &td)
{
    element_t e;
    element_init_GT(e, pairing);
    element_pairing(e, dk.dk1, Ci.C1);

    element_t h2e;
    element_init_Zr(h2e, pairing);
    H2(e, h2e);

    element_init_Zr(td.TD1, pairing);
    element_div(td.TD1, gamma, h2e);

    element_init_G1(td.TD2, pairing);
    element_pow_zn(td.TD2, Cj.C1, gamma);

    element_clear(e);
    element_clear(h2e);
}

bool IBEET_FDA::test4(Ciphertext &Ci, Trapdoor4 &tdi,
                      Ciphertext &Cj, Trapdoor4 &tdj)
{
    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);
    element_mul(vi, Ci.C3, tdi.TD1);
    element_mul(vj, Cj.C3, tdj.TD1);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, tdi.TD2, vi);
    element_pow_zn(rhs, tdj.TD2, vj);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(vi); element_clear(vj);
    element_clear(lhs); element_clear(rhs);
    return result;
}

// ── FDA ─────────────────────────────────────────────────────────────────────

void IBEET_FDA::authFDA(Ciphertext &C,
                        DecryptionKey &dk,
                        const std::vector<std::string> &testerIds,
                        TrapdoorFDA &td)
{
    size_t n = testerIds.size();

    element_t r_bar;
    element_init_Zr(r_bar, pairing);
    element_random(r_bar);

    element_t mpk1_rbar;
    element_init_G1(mpk1_rbar, pairing);
    element_pow_zn(mpk1_rbar, mpk1, r_bar);

    element_init_G1(td.td1, pairing);
    element_pow_zn(td.td1, g, r_bar);

    element_t *roots = new element_t[n];
    for (size_t i = 0; i < n; i++)
    {
        element_t hti;
        element_init_G1(hti, pairing);
        H1(testerIds[i], hti);

        element_t et;
        element_init_GT(et, pairing);
        element_pairing(et, hti, mpk1_rbar);

        element_init_Zr(roots[i], pairing);
        H2(et, roots[i]);

        element_clear(hti);
        element_clear(et);
    }

    td.td2 = new element_t[n + 1];
    for (size_t i = 0; i <= n; i++)
        element_init_Zr(td.td2[i], pairing);
    td.n = n;

    poly_from_roots(td.td2, roots, n, pairing);

    element_t edk, h2dk;
    element_init_GT(edk, pairing);
    element_init_Zr(h2dk, pairing);
    element_pairing(edk, dk.dk1, C.C1);
    H2(edk, h2dk);

    element_add(td.td2[0], td.td2[0], h2dk);

    for (size_t i = 0; i < n; i++) element_clear(roots[i]);
    delete[] roots;
    element_clear(mpk1_rbar);
    element_clear(r_bar);
    element_clear(edk);
    element_clear(h2dk);
}

bool IBEET_FDA::testFDA(Ciphertext &Ci, TrapdoorFDA &tdi,
                        Ciphertext &Cj, TrapdoorFDA &tdj,
                        DecryptionKey &dkt)
{
    element_t ei, ej;
    element_init_GT(ei, pairing);
    element_init_GT(ej, pairing);
    element_pairing(ei, dkt.dk1, tdi.td1);
    element_pairing(ej, dkt.dk1, tdj.td1);

    element_t xi, xj;
    element_init_Zr(xi, pairing);
    element_init_Zr(xj, pairing);
    H2(ei, xi);
    H2(ej, xj);

    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);
    poly_eval(vi, tdi.td2, tdi.n, xi, pairing);
    poly_eval(vj, tdj.td2, tdj.n, xj, pairing);

    element_t exp_lhs, exp_rhs;
    element_init_Zr(exp_lhs, pairing);
    element_init_Zr(exp_rhs, pairing);
    element_div(exp_lhs, Cj.C3, vj);
    element_div(exp_rhs, Ci.C3, vi);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, exp_lhs);
    element_pow_zn(rhs, Cj.C1, exp_rhs);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(ei);      element_clear(ej);
    element_clear(xi);      element_clear(xj);
    element_clear(vi);      element_clear(vj);
    element_clear(exp_lhs); element_clear(exp_rhs);
    element_clear(lhs);     element_clear(rhs);

    return result;
}

} // namespace IBEET