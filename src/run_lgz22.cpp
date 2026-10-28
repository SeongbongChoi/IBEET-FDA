#include <algorithm>
#include <cstring>

#include "LGZ22.h"
#include "runners.h"

using namespace std::chrono;

void run_lgz22(int N, int M, const std::string &param_str)
{
    using namespace PKEET;

    auto clrCT = [](Ciphertext &C) {
        element_clear(C.c1); element_clear(C.c2); element_clear(C.c4);
        delete[] C.c3;
    };
    auto clrTD = [](Trapdoor &T) {
        element_clear(T.td2);
        for (size_t i = 0; i <= T.n; i++) element_clear(T.td1[i]);
        delete[] T.td1;
    };
    auto clrUKP = [](UserKeyPair &ukp) {
        element_clear(ukp.X); element_clear(ukp.Y);
        element_clear(ukp.x); element_clear(ukp.y);
    };

    std::cout << "\n=== [LGZ22] Correctness Verification ===\n";

    LGZ22Scheme scheme(param_str);
    scheme.setup();

    ServerKeyPair skp;
    scheme.serverGen(skp);

    UserKeyPair ukp_alice, ukp_bob;
    scheme.userGen(ukp_alice);
    scheme.userGen(ukp_bob);

    uint8_t msg_orig[MSG_BYTES]; memset(msg_orig, 0xAB, MSG_BYTES);
    uint8_t msg_diff[MSG_BYTES]; memset(msg_diff, 0xCD, MSG_BYTES);

    // ---- Encrypt / Decrypt ----
    {
        Ciphertext CT;
        scheme.encrypt(msg_orig, ukp_alice, skp, CT);

        uint8_t msg_dec[MSG_BYTES] = {};
        bool ok = scheme.decrypt(CT, ukp_alice, msg_dec);
        check(ok && memcmp(msg_orig, msg_dec, MSG_BYTES) == 0, "Encrypt -> Decrypt (correct key)");

        uint8_t msg_bad[MSG_BYTES] = {};
        bool bad = scheme.decrypt(CT, ukp_bob, msg_bad);
        check(!bad, "Decrypt with wrong key returns false");

        clrCT(CT);
    }

    std::vector<TesterKeyPair> testers(M);
    for (int i = 0; i < M; i++) scheme.testerGen(testers[i]);

    // ---- Auth / Test ----
    {
        Ciphertext CTi, CTj, CTk;
        scheme.encrypt(msg_orig, ukp_alice, skp, CTi);
        scheme.encrypt(msg_orig, ukp_alice, skp, CTj);
        scheme.encrypt(msg_diff, ukp_alice, skp, CTk);

        Trapdoor TDi, TDj, TDk;
        scheme.auth(CTi, ukp_alice, skp, testers, TDi);
        scheme.auth(CTj, ukp_alice, skp, testers, TDj);
        scheme.auth(CTk, ukp_alice, skp, testers, TDk);

        check( scheme.test(CTi, TDi, CTj, TDj, testers[0], skp), "Test returns true for same plaintext");
        check(!scheme.test(CTi, TDi, CTk, TDk, testers[0], skp), "Test returns false for different plaintext");

        TesterKeyPair unauth_tester;
        scheme.testerGen(unauth_tester);
        std::vector<TesterKeyPair> unauth_set = {unauth_tester};
        Trapdoor TDj_unauth;
        scheme.auth(CTj, ukp_alice, skp, unauth_set, TDj_unauth);
        check(!scheme.test(CTi, TDi, CTj, TDj_unauth, unauth_tester, skp), "Test returns false for unauthorized tester");

        clrCT(CTi); clrCT(CTj); clrCT(CTk);
        clrTD(TDi); clrTD(TDj); clrTD(TDk);
        clrTD(TDj_unauth);
        element_clear(unauth_tester.Xt); element_clear(unauth_tester.xt);
    }

    // ---- Benchmark ----
    std::cout << "\n=== [LGZ22] Benchmark: N=" << N << " M=" << M << " ===\n";

    std::vector<double> t_keygen, t_encrypt, t_decrypt, t_auth, t_test;

    for (int i = 0; i < N; i++) {
        UserKeyPair tmp;
        auto t0 = steady_clock::now();
        scheme.userGen(tmp);
        t_keygen.push_back(elapsed_ms(t0));
        clrUKP(tmp);
    }

    // N+1 ciphertexts/trapdoors: N are benchmarked, one extra for pairwise tests
    std::vector<Ciphertext> ctxts(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = steady_clock::now();
        scheme.encrypt(msg_orig, ukp_alice, skp, ctxts[i]);
        t_encrypt.push_back(elapsed_ms(t0));
    }
    scheme.encrypt(msg_orig, ukp_alice, skp, ctxts[N]);

    for (int i = 0; i < N; i++) {
        uint8_t dec[MSG_BYTES] = {};
        auto t0 = steady_clock::now();
        scheme.decrypt(ctxts[i], ukp_alice, dec);
        t_decrypt.push_back(elapsed_ms(t0));
    }

    std::vector<Trapdoor> tds(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = steady_clock::now();
        scheme.auth(ctxts[i], ukp_alice, skp, testers, tds[i]);
        t_auth.push_back(elapsed_ms(t0));
    }
    scheme.auth(ctxts[N], ukp_alice, skp, testers, tds[N]);

    for (int i = 0; i < N; i++) {
        auto t0 = steady_clock::now();
        scheme.test(ctxts[i], tds[i], ctxts[i + 1], tds[i + 1], testers[0], skp);
        t_test.push_back(elapsed_ms(t0));
    }

    std::cout << "KeyGen  : " << avg(t_keygen)  << " ms\n";
    std::cout << "Encrypt : " << avg(t_encrypt) << " ms\n";
    std::cout << "Decrypt : " << avg(t_decrypt) << " ms\n";
    std::cout << "Auth    : " << avg(t_auth)    << " ms\n";
    std::cout << "Test    : " << avg(t_test)    << " ms\n";

    clrUKP(ukp_alice);
    clrUKP(ukp_bob);
    element_clear(skp.Xc); element_clear(skp.xc);
    for (int i = 0; i < M; i++) {
        element_clear(testers[i].Xt);
        element_clear(testers[i].xt);
    }
    for (int i = 0; i <= N; i++) { clrCT(ctxts[i]); clrTD(tds[i]); }
}
