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
    if (mpz_sizeinbase(pairing->r, 2) > 8 * L2)
    {
        std::cerr << "IBEET_FDA: group order exceeds L2 bytes\n";
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

// SHAKE256(tag || ctr || in), |p| + 64 bits reduced mod p; ctr is bumped until nonzero
void IBEET_FDA::hash_to_Zpstar(uint8_t tag, const uint8_t *in, size_t len, element_t out)
{
    const size_t olen = lenZr + 8;
    uint8_t *buf = new uint8_t[2 + len];
    uint8_t *dig = new uint8_t[olen];
    buf[0] = tag;
    memcpy(buf + 2, in, len);

    mpz_t z;
    mpz_init(z);
    for (uint8_t ctr = 0;; ctr++)
    {
        buf[1] = ctr;
        SHAKE256_hash(buf, 2 + len, dig, olen);
        mpz_import(z, olen, 1, 1, 1, 0, dig);
        mpz_mod(z, z, pairing->r);
        if (mpz_sgn(z) != 0) break;
    }
    element_set_mpz(out, z);

    mpz_clear(z);
    delete[] buf;
    delete[] dig;
}

// fixed-length big-endian encoding of a Zr element in L2 bytes
void IBEET_FDA::Zr_to_bytes(uint8_t *out, element_t x)
{
    mpz_t z;
    mpz_init(z);
    element_to_mpz(z, x);
    memset(out, 0, L2);
    size_t n = (mpz_sizeinbase(z, 2) + 7) / 8;
    mpz_export(out + L2 - n, nullptr, 1, 1, 1, 0, z);
    mpz_clear(z);
}

// accepts only canonical encodings of values in [1, p-1]
bool IBEET_FDA::Zpstar_from_bytes(element_t x, const uint8_t *in)
{
    mpz_t z;
    mpz_init(z);
    mpz_import(z, L2, 1, 1, 1, 0, in);
    bool ok = mpz_sgn(z) != 0 && mpz_cmp(z, pairing->r) < 0;
    if (ok) element_set_mpz(x, z);
    mpz_clear(z);
    return ok;
}

void IBEET_FDA::H1(const std::string &id, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash((const uint8_t *)id.data(), id.size(), digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

void IBEET_FDA::H2(const uint8_t *M, element_t out)
{
    hash_to_Zpstar(0x02, M, L1, out);
}

void IBEET_FDA::H3(element_t t, element_t out)
{
    uint8_t *buf = new uint8_t[lenGT];
    element_to_bytes(buf, t);
    hash_to_Zpstar(0x03, buf, lenGT, out);
    delete[] buf;
}

void IBEET_FDA::H4(element_t t, element_t k,
                   element_t c1, element_t c2, element_t c3, uint8_t *out)
{
    const size_t len = 1 + lenGT + 2 * lenZr + 2 * lenG1;
    uint8_t *buf = new uint8_t[len];
    uint8_t *p = buf;
    *p++ = 0x04;
    p += element_to_bytes(p, t);
    p += element_to_bytes(p, k);
    p += element_to_bytes(p, c1);
    p += element_to_bytes(p, c2);
    p += element_to_bytes(p, c3);
    SHAKE256_hash(buf, len, out, L4);
    delete[] buf;
}

void IBEET_FDA::H5(element_t t, element_t out)
{
    uint8_t *buf = new uint8_t[lenGT];
    element_to_bytes(buf, t);
    hash_to_Zpstar(0x05, buf, lenGT, out);
    delete[] buf;
}

void IBEET_FDA::setup(MasterSecretKey &msk)
{
    element_random(g);

    element_init_Zr(msk.s1, pairing);
    element_init_Zr(msk.s2, pairing);
    random_Zpstar(msk.s1);
    random_Zpstar(msk.s2);

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
    element_t r1, r2;
    element_init_Zr(r1, pairing); random_Zpstar(r1);
    element_init_Zr(r2, pairing); random_Zpstar(r2);

    encrypt(id, M, r1, r2, C);

    element_clear(r1); element_clear(r2);
}

void IBEET_FDA::encrypt(const std::string &id,
                        const uint8_t *M,
                        element_t r1, element_t r2,
                        Ciphertext &C)
{
    element_t hID;
    element_init_G1(hID, pairing);
    H1(id, hID);

    element_init_G1(C.C1, pairing); element_pow_zn(C.C1, g, r1);
    element_init_G1(C.C2, pairing); element_pow_zn(C.C2, g, r2);

    element_t m;
    element_init_Zr(m, pairing);
    H2(M, m);

    element_t e1;
    element_init_GT(e1, pairing);
    element_pairing(e1, hID, mpk1);
    element_pow_zn(e1, e1, r1);

    element_t h3val;
    element_init_Zr(h3val, pairing);
    H3(e1, h3val);

    element_t mr1;
    element_init_Zr(mr1, pairing);
    element_mul(mr1, m, r1);

    element_init_Zr(C.C3, pairing);
    element_mul(C.C3, mr1, h3val);

    element_t e2;
    element_init_GT(e2, pairing);
    element_pairing(e2, hID, mpk2);
    element_pow_zn(e2, e2, r2);

    uint8_t h4buf[L4];
    H4(e2, mr1, C.C1, C.C2, C.C3, h4buf);

    uint8_t pt[L4];
    memcpy(pt, M, L1);
    Zr_to_bytes(pt + L1,      r1);
    Zr_to_bytes(pt + L1 + L2, r2);

    for (int i = 0; i < L4; i++)
        C.C4[i] = pt[i] ^ h4buf[i];

    element_clear(hID);
    element_clear(m);  element_clear(mr1);
    element_clear(e1); element_clear(e2);
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
    H3(e1, h3val);

    element_t k;
    element_init_Zr(k, pairing);
    element_div(k, C.C3, h3val);

    element_t e2;
    element_init_GT(e2, pairing);
    element_pairing(e2, dk.dk2, C.C2);

    uint8_t h4buf[L4];
    H4(e2, k, C.C1, C.C2, C.C3, h4buf);

    uint8_t pt[L4];
    for (int i = 0; i < L4; i++)
        pt[i] = C.C4[i] ^ h4buf[i];

    element_t r1, r2, check, m;
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_init_G1(check, pairing);
    element_init_Zr(m, pairing);

    bool ok = Zpstar_from_bytes(r1, pt + L1)
           && Zpstar_from_bytes(r2, pt + L1 + L2);
    if (ok)
    {
        element_pow_zn(check, g, r1);
        ok = element_cmp(C.C1, check) == 0;
    }
    if (ok)
    {
        element_pow_zn(check, g, r2);
        ok = element_cmp(C.C2, check) == 0;
    }
    if (ok)
    {
        H2(pt, m);
        element_mul(m, m, r1);
        ok = element_cmp(k, m) == 0;
    }
    if (ok)
        memcpy(M, pt, L1);

    element_clear(e1); element_clear(e2);
    element_clear(h3val); element_clear(k);
    element_clear(r1); element_clear(r2);
    element_clear(check); element_clear(m);
    return ok;
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
    H3(ei, vi);
    H3(ej, vj);

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
    H3(e, td.td2);

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
    H3(e, td.td3);

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
    
    element_t h3ej;
    element_init_Zr(h3ej, pairing);
    H3(ej, h3ej);
    element_div(vj, Cj.C3, h3ej);

    element_t lhs, rhs;
    element_init_G1(lhs, pairing);
    element_init_G1(rhs, pairing);
    element_pow_zn(lhs, Ci.C1, vj);
    element_pow_zn(rhs, Cj.C1, vi);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(vi);  element_clear(vj);
    element_clear(ej);  element_clear(h3ej);
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

    element_t h3e;
    element_init_Zr(h3e, pairing);
    H3(e, h3e);

    element_init_Zr(td.TD1, pairing);
    element_div(td.TD1, gamma, h3e);

    element_init_G1(td.TD2, pairing);
    element_pow_zn(td.TD2, Cj.C1, gamma);

    element_clear(e);
    element_clear(h3e);
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
    assert(n >= 1);

    element_t edk, ti;
    element_init_GT(edk, pairing);
    element_init_Zr(ti, pairing);
    element_pairing(edk, dk.dk1, C.C1);
    H3(edk, ti);

    element_t r_bar, mpk2_rbar;
    element_init_Zr(r_bar, pairing);
    element_init_G1(mpk2_rbar, pairing);

    element_t *ys = new element_t[n];
    element_t *zs = new element_t[n];
    for (size_t i = 0; i < n; i++)
    {
        element_init_Zr(ys[i], pairing);
        element_init_Zr(zs[i], pairing);
    }

    element_t hti, w, h5w;
    element_init_G1(hti, pairing);
    element_init_GT(w, pairing);
    element_init_Zr(h5w, pairing);

    bool distinct;
    do
    {
        random_Zpstar(r_bar);
        element_pow_zn(mpk2_rbar, mpk2, r_bar);

        for (size_t i = 0; i < n; i++)
        {
            H1(testerIds[i], hti);
            element_pairing(w, hti, mpk2_rbar);
            H3(w, ys[i]);
            H5(w, h5w);
            element_mul(zs[i], ti, h5w);
        }

        distinct = true;
        for (size_t i = 0; i < n && distinct; i++)
            for (size_t j = i + 1; j < n && distinct; j++)
                if (element_cmp(ys[i], ys[j]) == 0)
                    distinct = false;
    } while (!distinct);

    element_init_G1(td.td1, pairing);
    element_pow_zn(td.td1, g, r_bar);

    td.td2 = new element_t[n];
    for (size_t i = 0; i < n; i++)
        element_init_Zr(td.td2[i], pairing);
    td.n = n;

    poly_interpolate(td.td2, ys, zs, n, pairing);

    for (size_t i = 0; i < n; i++)
    {
        element_clear(ys[i]);
        element_clear(zs[i]);
    }
    delete[] ys;
    delete[] zs;
    element_clear(hti);
    element_clear(w);
    element_clear(h5w);
    element_clear(mpk2_rbar);
    element_clear(r_bar);
    element_clear(edk);
    element_clear(ti);
}

void IBEET_FDA::recoverFDA(TrapdoorFDA &td, DecryptionKey &dkt, element_t v)
{
    element_t w;
    element_init_GT(w, pairing);
    element_pairing(w, dkt.dk2, td.td1);

    element_t x, h5w;
    element_init_Zr(x, pairing);
    element_init_Zr(h5w, pairing);
    H3(w, x);
    H5(w, h5w);

    poly_eval(v, td.td2, td.n - 1, x, pairing);
    element_div(v, v, h5w);

    element_clear(w);
    element_clear(x);
    element_clear(h5w);
}

bool IBEET_FDA::testFDA(Ciphertext &Ci, TrapdoorFDA &tdi,
                        Ciphertext &Cj, TrapdoorFDA &tdj,
                        DecryptionKey &dkt)
{
    element_t vi, vj;
    element_init_Zr(vi, pairing);
    element_init_Zr(vj, pairing);
    recoverFDA(tdi, dkt, vi);
    recoverFDA(tdj, dkt, vj);

    if (element_is0(vi) || element_is0(vj))
    {
        element_clear(vi); element_clear(vj);
        return false;
    }

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

    element_clear(vi);      element_clear(vj);
    element_clear(exp_lhs); element_clear(exp_rhs);
    element_clear(lhs);     element_clear(rhs);

    return result;
}

} // namespace IBEET
