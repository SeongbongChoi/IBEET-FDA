#include "PKEET_FDA.h"

namespace PKEET
{

PKEET_FDA::PKEET_FDA(const std::string &param_str)
{
    if (pairing_init_set_str(pairing, param_str.c_str()) != 0)
    {
        std::cerr << "PKEET_FDA: pairing_init_set_str failed\n";
        std::exit(EXIT_FAILURE);
    }

    element_init_G1(g, pairing);

    lenG1 = pairing_length_in_bytes_G1(pairing);
    lenZr = pairing_length_in_bytes_Zr(pairing);
}

PKEET_FDA::~PKEET_FDA()
{
    element_clear(g);
    pairing_clear(pairing);
}

void PKEET_FDA::H1(const uint8_t *in, size_t inlen, uint8_t *out)
{
    uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512_hash(in, inlen, digest);
    memcpy(out, digest, MSG_BYTES + lenZr);
}

void PKEET_FDA::H2(const uint8_t *in, size_t inlen, element_t out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(in, inlen, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}

void PKEET_FDA::H3(const uint8_t *in, size_t inlen, uint8_t *out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_hash(in, inlen, digest);
    memcpy(out, digest, 32);
}

void PKEET_FDA::setup()
{
    element_random(g);
}

void PKEET_FDA::serverGen(ServerKeyPair &skp)
{
    element_init_Zr(skp.xc, pairing); element_random(skp.xc);
    element_init_G1(skp.Xc, pairing);
    element_pow_zn(skp.Xc, g, skp.xc);
}

void PKEET_FDA::userGen(UserKeyPair &ukp)
{
    element_init_Zr(ukp.x, pairing); element_random(ukp.x);
    element_init_Zr(ukp.y, pairing); element_random(ukp.y);
    element_init_G1(ukp.X, pairing); element_pow_zn(ukp.X, g, ukp.x);
    element_init_G1(ukp.Y, pairing); element_pow_zn(ukp.Y, g, ukp.y);
}

void PKEET_FDA::testerGen(TesterKeyPair &tkp)
{
    element_init_Zr(tkp.xt, pairing); element_random(tkp.xt);
    element_init_G1(tkp.Xt, pairing); element_pow_zn(tkp.Xt, g, tkp.xt);
}

void PKEET_FDA::encrypt(const uint8_t *m,
                        UserKeyPair   &ukp,
                        ServerKeyPair &skp,
                        Ciphertext    &CT)
{
    // mu = m || u_bytes  총 크기: MSG_BYTES + lenZr
    int mulen = MSG_BYTES + lenZr;

    element_t u, v;
    element_init_Zr(u, pairing); element_random(u);
    element_init_Zr(v, pairing); element_random(v);

    element_init_G1(CT.c1, pairing); element_pow_zn(CT.c1, g, u);
    element_init_G1(CT.c2, pairing); element_pow_zn(CT.c2, g, v);
    CT.c3 = new uint8_t[mulen]();

    element_t Xu;
    element_init_G1(Xu, pairing);
    element_pow_zn(Xu, ukp.X, u);

    uint8_t *Xu_buf = new uint8_t[lenG1];
    element_to_bytes(Xu_buf, Xu);

    uint8_t *h1 = new uint8_t[mulen];
    H1(Xu_buf, lenG1, h1);

    uint8_t *u_bytes = new uint8_t[lenZr];
    element_to_bytes(u_bytes, u);

    uint8_t *mu = new uint8_t[mulen]();
    memcpy(mu,            m,       MSG_BYTES);
    memcpy(mu + MSG_BYTES, u_bytes, lenZr);

    for (int i = 0; i < mulen; i++)
        CT.c3[i] = mu[i] ^ h1[i];

    element_t Xcv;
    element_init_G1(Xcv, pairing);
    element_pow_zn(Xcv, skp.Xc, v);

    uint8_t *Xcv_buf = new uint8_t[lenG1];
    element_to_bytes(Xcv_buf, Xcv);

    element_t h2val;
    element_init_Zr(h2val, pairing);
    H2(Xcv_buf, lenG1, h2val);

    element_t m_zr;
    element_init_Zr(m_zr, pairing);
    element_from_hash(m_zr, const_cast<uint8_t *>(m), MSG_BYTES);

    element_t exp;
    element_init_Zr(exp, pairing);
    element_add(exp, h2val, m_zr);

    element_t Yv, gexp;
    element_init_G1(Yv,   pairing); element_pow_zn(Yv,   ukp.Y, v);
    element_init_G1(gexp, pairing); element_pow_zn(gexp, g, exp);

    element_init_G1(CT.c4, pairing);
    element_mul(CT.c4, Yv, gexp);

    uint8_t *c1_buf = new uint8_t[lenG1];
    uint8_t *c2_buf = new uint8_t[lenG1];
    uint8_t *c4_buf = new uint8_t[lenG1];
    element_to_bytes(c1_buf, CT.c1);
    element_to_bytes(c2_buf, CT.c2);
    element_to_bytes(c4_buf, CT.c4);

    size_t hlen = 3 * lenG1 + 2 * mulen;
    uint8_t *hbuf = new uint8_t[hlen]();
    size_t off = 0;
    memcpy(hbuf + off, c1_buf, lenG1); off += lenG1;
    memcpy(hbuf + off, c2_buf, lenG1); off += lenG1;
    memcpy(hbuf + off, CT.c3,  mulen); off += mulen;
    memcpy(hbuf + off, c4_buf, lenG1); off += lenG1;
    memcpy(hbuf + off, mu,     mulen);
    H3(hbuf, hlen, CT.c5);

    element_clear(u);    element_clear(v);
    element_clear(Xu);   element_clear(Xcv);
    element_clear(Yv);   element_clear(gexp);
    element_clear(h2val);element_clear(m_zr); element_clear(exp);
    delete[] Xu_buf; delete[] h1; delete[] u_bytes;
    delete[] mu; delete[] Xcv_buf;
    delete[] c1_buf; delete[] c2_buf; delete[] c4_buf; delete[] hbuf;
}

bool PKEET_FDA::decrypt(Ciphertext  &CT,
                        UserKeyPair &ukp,
                        uint8_t     *m)
{
    int mulen = MSG_BYTES + lenZr;

    element_t c1x;
    element_init_G1(c1x, pairing);
    element_pow_zn(c1x, CT.c1, ukp.x);

    uint8_t *c1x_buf = new uint8_t[lenG1];
    element_to_bytes(c1x_buf, c1x);

    uint8_t *h1 = new uint8_t[mulen];
    H1(c1x_buf, lenG1, h1);

    uint8_t *mu = new uint8_t[mulen]();
    for (int i = 0; i < mulen; i++)
        mu[i] = CT.c3[i] ^ h1[i];

    uint8_t *m_rec   = mu;
    uint8_t *u_bytes = mu + MSG_BYTES;

    element_t u;
    element_init_Zr(u, pairing);
    element_from_bytes(u, u_bytes);

    element_t check;
    element_init_G1(check, pairing);
    element_pow_zn(check, g, u);
    if (element_cmp(CT.c1, check))
    {
        element_clear(c1x); element_clear(u); element_clear(check);
        delete[] c1x_buf; delete[] h1; delete[] mu;
        return false;
    }

    uint8_t *c1_buf = new uint8_t[lenG1];
    uint8_t *c2_buf = new uint8_t[lenG1];
    uint8_t *c4_buf = new uint8_t[lenG1];
    element_to_bytes(c1_buf, CT.c1);
    element_to_bytes(c2_buf, CT.c2);
    element_to_bytes(c4_buf, CT.c4);

    size_t hlen = 3 * lenG1 + 2 * mulen;
    uint8_t *hbuf = new uint8_t[hlen]();
    size_t off = 0;
    memcpy(hbuf + off, c1_buf, lenG1); off += lenG1;
    memcpy(hbuf + off, c2_buf, lenG1); off += lenG1;
    memcpy(hbuf + off, CT.c3,  mulen); off += mulen;
    memcpy(hbuf + off, c4_buf, lenG1); off += lenG1;
    memcpy(hbuf + off, mu,     mulen);

    uint8_t c5_check[32];
    H3(hbuf, hlen, c5_check);

    if (memcmp(CT.c5, c5_check, 32))
    {
        element_clear(c1x); element_clear(u); element_clear(check);
        delete[] c1x_buf; delete[] h1; delete[] mu;
        delete[] c1_buf; delete[] c2_buf; delete[] c4_buf; delete[] hbuf;
        return false;
    }

    memcpy(m, m_rec, MSG_BYTES);

    element_clear(c1x); element_clear(u); element_clear(check);
    delete[] c1x_buf; delete[] h1; delete[] mu;
    delete[] c1_buf; delete[] c2_buf; delete[] c4_buf; delete[] hbuf;
    return true;
}

void PKEET_FDA::auth(Ciphertext               &CT,
                     UserKeyPair              &ukp,
                     ServerKeyPair            &skp,
                     std::vector<TesterKeyPair> &testers,
                     Trapdoor                 &td)
{
    size_t n = testers.size();

    element_t *roots = new element_t[n];
    for (size_t k = 0; k < n; k++)
    {
        element_t Xtxc;
        element_init_G1(Xtxc, pairing);
        element_pow_zn(Xtxc, testers[k].Xt, skp.xc);

        uint8_t *buf = new uint8_t[lenG1];
        element_to_bytes(buf, Xtxc);

        element_init_Zr(roots[k], pairing);
        H2(buf, lenG1, roots[k]);

        element_clear(Xtxc);
        delete[] buf;
    }

    element_t *A = new element_t[n + 1];
    for (size_t i = 0; i <= n; i++)
        element_init_Zr(A[i], pairing);

    poly_from_roots(A, roots, n, pairing);

    element_t c2xc;
    element_init_G1(c2xc, pairing);
    element_pow_zn(c2xc, CT.c2, skp.xc);

    uint8_t *c2xc_buf = new uint8_t[lenG1];
    element_to_bytes(c2xc_buf, c2xc);

    element_t h2c2xc;
    element_init_Zr(h2c2xc, pairing);
    H2(c2xc_buf, lenG1, h2c2xc);

    element_add(A[0], A[0], h2c2xc);

    td.n   = n;
    td.td1 = new element_t[n + 1];
    for (size_t i = 0; i <= n; i++)
    {
        element_init_G1(td.td1[i], pairing);
        element_pow_zn(td.td1[i], g, A[i]);
    }

    element_init_Zr(td.td2, pairing);
    element_set(td.td2, ukp.y);

    for (size_t k = 0; k < n; k++) element_clear(roots[k]);
    for (size_t i = 0; i <= n; i++) element_clear(A[i]);
    delete[] roots; delete[] A;
    element_clear(c2xc); element_clear(h2c2xc);
    delete[] c2xc_buf;
}

bool PKEET_FDA::test(Ciphertext    &CTi, Trapdoor &TDi,
                     Ciphertext    &CTj, Trapdoor &TDj,
                     TesterKeyPair &tkp,
                     ServerKeyPair &skp)
{
    element_t Xcxt;
    element_init_G1(Xcxt, pairing);
    element_pow_zn(Xcxt, skp.Xc, tkp.xt);

    uint8_t *Xcxt_buf = new uint8_t[lenG1];
    element_to_bytes(Xcxt_buf, Xcxt);

    element_t xi;
    element_init_Zr(xi, pairing);
    H2(Xcxt_buf, lenG1, xi);

    auto evalPoly = [&](Trapdoor &TD, element_t x, element_t res)
    {
        element_set0(res);
        element_t xpow;
        element_init_Zr(xpow, pairing);
        element_set1(xpow);

        for (size_t k = 0; k <= TD.n; k++)
        {
            element_t tmp;
            element_init_G1(tmp, pairing);
            element_pow_zn(tmp, TD.td1[k], xpow);
            element_add(res, res, tmp);
            element_clear(tmp);

            element_t xpow_next;
            element_init_Zr(xpow_next, pairing);
            element_mul(xpow_next, xpow, x);
            element_set(xpow, xpow_next);
            element_clear(xpow_next);
        }
        element_clear(xpow);
    };

    element_t eval_i, eval_j;
    element_init_G1(eval_i, pairing);
    element_init_G1(eval_j, pairing);
    evalPoly(TDi, xi, eval_i);
    evalPoly(TDj, xi, eval_j);

    element_t yi_c2i, lhs;
    element_init_G1(yi_c2i, pairing);
    element_init_G1(lhs,    pairing);
    element_pow_zn(yi_c2i, CTi.c2, TDi.td2);
    element_add(lhs, yi_c2i, eval_i);
    element_neg(lhs, lhs);
    element_add(lhs, CTi.c4, lhs);

    element_t yj_c2j, rhs;
    element_init_G1(yj_c2j, pairing);
    element_init_G1(rhs,    pairing);
    element_pow_zn(yj_c2j, CTj.c2, TDj.td2);
    element_add(rhs, yj_c2j, eval_j);
    element_neg(rhs, rhs);
    element_add(rhs, CTj.c4, rhs);

    bool result = (element_cmp(lhs, rhs) == 0);

    element_clear(Xcxt);
    element_clear(xi);
    element_clear(eval_i); element_clear(eval_j);
    element_clear(yi_c2i); element_clear(lhs);
    element_clear(yj_c2j); element_clear(rhs);
    delete[] Xcxt_buf;

    return result;
}

} // namespace PKEET