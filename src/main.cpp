#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <chrono>
#include <vector>
#include <cstdlib>
#include <string>

#include "IBEET_FDA.h"
#include "LGZ22.h"
#include "LLH24.h"

using namespace std::chrono;

static void print_pass(const char *label) { std::cout << "  [PASS] " << label << "\n"; }
static void print_fail(const char *label) { std::cerr << "  [FAIL] " << label << "\n"; std::exit(1); }
static void check(bool ok, const char *label) { ok ? print_pass(label) : print_fail(label); }

static double elapsed_ms(high_resolution_clock::time_point t0)
{
    return duration<double, std::milli>(high_resolution_clock::now() - t0).count();
}

static void run_ibeet(int N, int M, const std::string &param_str)
{
    using namespace IBEET;

    auto clrCT  = [](Ciphertext &C)     { element_clear(C.C1); element_clear(C.C2); element_clear(C.C3); };
    auto clrDK  = [](DecryptionKey &dk) { element_clear(dk.dk1); element_clear(dk.dk2); };
    auto clrFDA = [](TrapdoorFDA &td)   {
        element_clear(td.td1);
        for (size_t i = 0; i <= td.n; i++) element_clear(td.td2[i]);
        delete[] td.td2;
    };

    std::cout << "\n=== [IBEET-FDA] Correctness Verification ===\n";

    IBEET_FDA scheme(param_str);
    MasterSecretKey msk;
    scheme.setup(msk);

    const std::string id_alice = "alice@example.com";
    const std::string id_bob   = "bob@example.com";

    uint8_t msg_orig[L1]; memset(msg_orig, 0xAB, L1);
    uint8_t msg_diff[L1]; memset(msg_diff, 0xCD, L1);

    DecryptionKey dk_alice, dk_bob;
    scheme.extract(id_alice, msk, dk_alice);
    scheme.extract(id_bob,   msk, dk_bob);

    // ---- Encrypt / Decrypt ----
    {
        Ciphertext C;
        scheme.encrypt(id_alice, msg_orig, C);

        uint8_t msg_dec[L1] = {};
        bool ok = scheme.decrypt(dk_alice, C, msg_dec);
        check(ok && memcmp(msg_orig, msg_dec, L1) == 0, "Encrypt -> Decrypt (correct key)");

        uint8_t msg_bad[L1] = {};
        bool bad = scheme.decrypt(dk_bob, C, msg_bad);
        check(!bad, "Decrypt with wrong key returns false");

        clrCT(C);
    }

    std::vector<std::string> tester_ids;
    std::vector<DecryptionKey> dk_testers(M);
    for (int i = 0; i < M; i++) {
        tester_ids.push_back("tester" + std::to_string(i) + "@example.com");
        scheme.extract(tester_ids[i], msk, dk_testers[i]);
    }

    // ---- Type-1 ----
    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        scheme.encrypt(id_alice, msg_diff, Ck);

        Trapdoor1 tdi, tdj, tdk;
        scheme.auth1(dk_alice, tdi);
        scheme.auth1(dk_alice, tdj);
        scheme.auth1(dk_alice, tdk);

        check( scheme.test1(Ci, tdi, Cj, tdj), "Type-1: same plaintext -> true");
        check(!scheme.test1(Ci, tdi, Ck, tdk), "Type-1: diff plaintext -> false");

        clrCT(Ci); clrCT(Cj); clrCT(Ck);
        element_clear(tdi.td1); element_clear(tdj.td1); element_clear(tdk.td1);
    }

    // ---- Type-2 ----
    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        scheme.encrypt(id_alice, msg_diff, Ck);

        Trapdoor2 tdi, tdj, tdk;
        scheme.auth2(dk_alice, Ci, tdi);
        scheme.auth2(dk_alice, Cj, tdj);
        scheme.auth2(dk_alice, Ck, tdk);

        check( scheme.test2(Ci, tdi, Cj, tdj), "Type-2: same plaintext -> true");
        check(!scheme.test2(Ci, tdi, Ck, tdk), "Type-2: diff plaintext -> false");

        clrCT(Ci); clrCT(Cj); clrCT(Ck);
        element_clear(tdi.td2); element_clear(tdj.td2); element_clear(tdk.td2);
    }

    // ---- Type-3 ----
    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        scheme.encrypt(id_alice, msg_diff, Ck);

        Trapdoor3i tdi, tdk;
        Trapdoor3j tdj, tdl;
        scheme.auth3i(dk_alice, Ci, tdi);
        scheme.auth3j(dk_alice,     tdj);
        scheme.auth3i(dk_alice, Ck, tdk);
        scheme.auth3j(dk_alice,     tdl);

        check( scheme.test3(Ci, tdi, Cj, tdj), "Type-3: same plaintext -> true");
        check(!scheme.test3(Ci, tdi, Ck, tdl), "Type-3: diff plaintext -> false");

        clrCT(Ci); clrCT(Cj); clrCT(Ck);
        element_clear(tdi.td3); element_clear(tdj.td3);
        element_clear(tdk.td3); element_clear(tdl.td3);
    }

    // ---- Type-4 ----
    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        scheme.encrypt(id_alice, msg_diff, Ck);

        element_t gamma;
        element_init_Zr(gamma, scheme.pairing);
        element_random(gamma);

        Trapdoor4 tdi, tdj, tdk, tdl;
        scheme.auth4(dk_alice, Ci, Cj, gamma, tdi);
        scheme.auth4(dk_alice, Cj, Ci, gamma, tdj);
        scheme.auth4(dk_alice, Ci, Ck, gamma, tdk);
        scheme.auth4(dk_alice, Ck, Ci, gamma, tdl);

        check( scheme.test4(Ci, tdi, Cj, tdj), "Type-4: same plaintext -> true");
        check(!scheme.test4(Ci, tdk, Ck, tdl), "Type-4: diff plaintext -> false");

        clrCT(Ci); clrCT(Cj); clrCT(Ck);
        element_clear(tdi.TD1); element_clear(tdi.TD2);
        element_clear(tdj.TD1); element_clear(tdj.TD2);
        element_clear(tdk.TD1); element_clear(tdk.TD2);
        element_clear(tdl.TD1); element_clear(tdl.TD2);
        element_clear(gamma);
    }

    // ---- FDA ----
    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, msg_orig, Cj);
        scheme.encrypt(id_alice, msg_diff, Ck);

        TrapdoorFDA tdi, tdj, tdk;
        scheme.authFDA(Ci, dk_alice, tester_ids, tdi);
        scheme.authFDA(Cj, dk_alice, tester_ids, tdj);
        scheme.authFDA(Ck, dk_alice, tester_ids, tdk);

        check( scheme.testFDA(Ci, tdi, Cj, tdj, dk_testers[0]), "FDA: same plaintext -> true");
        check(!scheme.testFDA(Ci, tdi, Ck, tdk, dk_testers[0]), "FDA: diff plaintext -> false");

        DecryptionKey dk_unauth;
        scheme.extract("unauthorized@example.com", msk, dk_unauth);
        check(!scheme.testFDA(Ci, tdi, Cj, tdj, dk_unauth), "FDA: unauthorized tester -> false");

        clrCT(Ci); clrCT(Cj); clrCT(Ck);
        clrFDA(tdi); clrFDA(tdj); clrFDA(tdk);
        clrDK(dk_unauth);
    }

    // ---- Benchmark ----
    std::cout << "\n=== [IBEET-FDA] Benchmark: N=" << N << " M=" << M << " ===\n";

    std::vector<double> t_setup, t_extract, t_encrypt, t_decrypt;
    std::vector<double> t_auth1, t_test1;
    std::vector<double> t_auth2, t_test2;
    std::vector<double> t_auth3i, t_auth3j, t_test3;
    std::vector<double> t_auth4, t_test4;
    std::vector<double> t_authFDA, t_testFDA;

    for (int i = 0; i < N; i++) {
        MasterSecretKey tmp;
        auto t0 = high_resolution_clock::now();
        scheme.setup(tmp);
        t_setup.push_back(elapsed_ms(t0));
        element_clear(tmp.s1); element_clear(tmp.s2);
    }

    for (int i = 0; i < N; i++) {
        DecryptionKey dk;
        auto t0 = high_resolution_clock::now();
        scheme.extract(id_alice, msk, dk);
        t_extract.push_back(elapsed_ms(t0));
        clrDK(dk);
    }

    // N+1 ciphertexts/trapdoors: N are benchmarked, one extra for pairwise tests
    std::vector<Ciphertext> ctxts(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.encrypt(id_alice, msg_orig, ctxts[i]);
        t_encrypt.push_back(elapsed_ms(t0));
    }
    scheme.encrypt(id_alice, msg_orig, ctxts[N]);

    for (int i = 0; i < N; i++) {
        uint8_t dec[L1] = {};
        auto t0 = high_resolution_clock::now();
        scheme.decrypt(dk_alice, ctxts[i], dec);
        t_decrypt.push_back(elapsed_ms(t0));
    }

    // Type-1
    {
        std::vector<Trapdoor1> td1s(N + 1);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.auth1(dk_alice, td1s[i]);
            t_auth1.push_back(elapsed_ms(t0));
        }
        scheme.auth1(dk_alice, td1s[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.test1(ctxts[i], td1s[i], ctxts[i + 1], td1s[i + 1]);
            t_test1.push_back(elapsed_ms(t0));
        }
        for (int i = 0; i <= N; i++) element_clear(td1s[i].td1);
    }

    // Type-2
    {
        std::vector<Trapdoor2> td2s(N + 1);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.auth2(dk_alice, ctxts[i], td2s[i]);
            t_auth2.push_back(elapsed_ms(t0));
        }
        scheme.auth2(dk_alice, ctxts[N], td2s[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.test2(ctxts[i], td2s[i], ctxts[i + 1], td2s[i + 1]);
            t_test2.push_back(elapsed_ms(t0));
        }
        for (int i = 0; i <= N; i++) element_clear(td2s[i].td2);
    }

    // Type-3
    {
        std::vector<Trapdoor3i> td3is(N + 1);
        std::vector<Trapdoor3j> td3js(N + 1);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.auth3i(dk_alice, ctxts[i], td3is[i]);
            t_auth3i.push_back(elapsed_ms(t0));
        }
        scheme.auth3i(dk_alice, ctxts[N], td3is[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.auth3j(dk_alice, td3js[i]);
            t_auth3j.push_back(elapsed_ms(t0));
        }
        scheme.auth3j(dk_alice, td3js[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.test3(ctxts[i], td3is[i], ctxts[i + 1], td3js[i + 1]);
            t_test3.push_back(elapsed_ms(t0));
        }
        for (int i = 0; i <= N; i++) {
            element_clear(td3is[i].td3);
            element_clear(td3js[i].td3);
        }
    }

    // Type-4
    {
        element_t gamma;
        element_init_Zr(gamma, scheme.pairing);
        element_random(gamma);

        std::vector<Trapdoor4> td4s(N + 1);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.auth4(dk_alice, ctxts[i], ctxts[(i + 1) % (N + 1)], gamma, td4s[i]);
            t_auth4.push_back(elapsed_ms(t0));
        }
        scheme.auth4(dk_alice, ctxts[N], ctxts[0], gamma, td4s[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = high_resolution_clock::now();
            scheme.test4(ctxts[i], td4s[i], ctxts[i + 1], td4s[i + 1]);
            t_test4.push_back(elapsed_ms(t0));
        }
        for (int i = 0; i <= N; i++) {
            element_clear(td4s[i].TD1);
            element_clear(td4s[i].TD2);
        }
        element_clear(gamma);
    }

    // FDA
    std::vector<TrapdoorFDA> tds(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.authFDA(ctxts[i], dk_alice, tester_ids, tds[i]);
        t_authFDA.push_back(elapsed_ms(t0));
    }
    scheme.authFDA(ctxts[N], dk_alice, tester_ids, tds[N]);
    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.testFDA(ctxts[i], tds[i], ctxts[i + 1], tds[i + 1], dk_testers[0]);
        t_testFDA.push_back(elapsed_ms(t0));
    }

    std::cout << "Setup      : " << avg(t_setup)   << " ms\n";
    std::cout << "Extract    : " << avg(t_extract) << " ms\n";
    std::cout << "Encrypt    : " << avg(t_encrypt) << " ms\n";
    std::cout << "Decrypt    : " << avg(t_decrypt) << " ms\n";
    std::cout << "Auth1      : " << avg(t_auth1)   << " ms\n";
    std::cout << "Test1      : " << avg(t_test1)   << " ms\n";
    std::cout << "Auth2      : " << avg(t_auth2)   << " ms\n";
    std::cout << "Test2      : " << avg(t_test2)   << " ms\n";
    std::cout << "Auth3i     : " << avg(t_auth3i)  << " ms\n";
    std::cout << "Auth3j     : " << avg(t_auth3j)  << " ms\n";
    std::cout << "Test3      : " << avg(t_test3)   << " ms\n";
    std::cout << "Auth4      : " << avg(t_auth4)   << " ms\n";
    std::cout << "Test4      : " << avg(t_test4)   << " ms\n";
    std::cout << "Auth(FDA)  : " << avg(t_authFDA) << " ms\n";
    std::cout << "Test(FDA)  : " << avg(t_testFDA) << " ms\n";

    clrDK(dk_alice);
    clrDK(dk_bob);
    for (int i = 0; i < M; i++) clrDK(dk_testers[i]);
    for (int i = 0; i <= N; i++) { clrCT(ctxts[i]); clrFDA(tds[i]); }
    element_clear(msk.s1); element_clear(msk.s2);
}

static void run_lgz22(int N, int M, const std::string &param_str)
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
        auto t0 = high_resolution_clock::now();
        scheme.userGen(tmp);
        t_keygen.push_back(elapsed_ms(t0));
        clrUKP(tmp);
    }

    // N+1 ciphertexts/trapdoors: N are benchmarked, one extra for pairwise tests
    std::vector<Ciphertext> ctxts(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.encrypt(msg_orig, ukp_alice, skp, ctxts[i]);
        t_encrypt.push_back(elapsed_ms(t0));
    }
    scheme.encrypt(msg_orig, ukp_alice, skp, ctxts[N]);

    for (int i = 0; i < N; i++) {
        uint8_t dec[MSG_BYTES] = {};
        auto t0 = high_resolution_clock::now();
        scheme.decrypt(ctxts[i], ukp_alice, dec);
        t_decrypt.push_back(elapsed_ms(t0));
    }

    std::vector<Trapdoor> tds(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.auth(ctxts[i], ukp_alice, skp, testers, tds[i]);
        t_auth.push_back(elapsed_ms(t0));
    }
    scheme.auth(ctxts[N], ukp_alice, skp, testers, tds[N]);

    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
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

static void run_llh24(int N, const std::string &param_str)
{
    using namespace LLH24;

    auto clrCT = [](Ciphertext &C)     { element_clear(C.c1); element_clear(C.c2); element_clear(C.c3); };
    auto clrDK = [](DecryptionKey &dk) { element_clear(dk.dk1); element_clear(dk.dk2); };

    std::cout << "\n=== [LLH24] Correctness Verification ===\n";

    LLH24Scheme scheme(param_str);
    MasterSecretKey msk;
    scheme.setup(msk);

    const std::string id_alice = "alice@example.com";
    const std::string id_bob   = "bob@example.com";
    const std::string id_carol = "carol@example.com";

    uint8_t msg_orig[MSG_BYTES]; memset(msg_orig, 0xAB, MSG_BYTES);
    uint8_t msg_diff[MSG_BYTES]; memset(msg_diff, 0xCD, MSG_BYTES);

    DecryptionKey dk_alice, dk_bob, dk_carol;
    scheme.extract(id_alice, msk, dk_alice);
    scheme.extract(id_bob,   msk, dk_bob);
    scheme.extract(id_carol, msk, dk_carol);

    // ---- Encrypt / Decrypt ----
    {
        Ciphertext C;
        scheme.encrypt(id_alice, id_bob, dk_alice, msg_orig, C);

        uint8_t msg_dec[MSG_BYTES] = {};
        bool ok = scheme.decrypt(id_alice, dk_bob, C, msg_dec);
        check(ok && memcmp(msg_orig, msg_dec, MSG_BYTES) == 0, "Encrypt -> Decrypt (correct key)");

        uint8_t msg_bad[MSG_BYTES] = {};
        bool bad = scheme.decrypt(id_alice, dk_carol, C, msg_bad);
        check(!bad, "Decrypt with wrong key returns false");

        clrCT(C);
    }

    // ---- Auth / Test ----
    {
        Ciphertext Ci, Cj, Ck;
        scheme.encrypt(id_alice, id_bob,   dk_alice, msg_orig, Ci);
        scheme.encrypt(id_alice, id_carol, dk_alice, msg_orig, Cj);
        scheme.encrypt(id_alice, id_bob,   dk_alice, msg_diff, Ck);

        Trapdoor tdi, tdj, tdk;
        scheme.auth(id_alice, id_carol, dk_bob,   Ci, tdi);
        scheme.auth(id_alice, id_bob,   dk_carol, Cj, tdj);
        scheme.auth(id_alice, id_carol, dk_bob,   Ck, tdk);

        check( scheme.test(Ci, tdi, Cj, tdj), "Auth/Test: same plaintext -> true");
        check(!scheme.test(Ci, tdi, Ck, tdk), "Auth/Test: diff plaintext -> false");

        clrCT(Ci); clrCT(Cj); clrCT(Ck);
        element_clear(tdi.td); element_clear(tdj.td); element_clear(tdk.td);
    }

    // ---- Benchmark ----
    std::cout << "\n=== [LLH24] Benchmark: N=" << N << " ===\n";

    std::vector<double> t_setup, t_extract, t_encrypt, t_decrypt, t_auth, t_test;

    for (int i = 0; i < N; i++) {
        MasterSecretKey tmp;
        auto t0 = high_resolution_clock::now();
        scheme.setup(tmp);
        t_setup.push_back(elapsed_ms(t0));
        element_clear(tmp.s1); element_clear(tmp.s2);
    }

    for (int i = 0; i < N; i++) {
        DecryptionKey dk;
        auto t0 = high_resolution_clock::now();
        scheme.extract(id_alice, msk, dk);
        t_extract.push_back(elapsed_ms(t0));
        clrDK(dk);
    }

    // N+1 ciphertexts/trapdoors: N are benchmarked, one extra for pairwise tests
    std::vector<Ciphertext> ctxts(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.encrypt(id_alice, id_bob, dk_alice, msg_orig, ctxts[i]);
        t_encrypt.push_back(elapsed_ms(t0));
    }
    scheme.encrypt(id_alice, id_bob, dk_alice, msg_orig, ctxts[N]);

    for (int i = 0; i < N; i++) {
        uint8_t dec[MSG_BYTES] = {};
        auto t0 = high_resolution_clock::now();
        scheme.decrypt(id_alice, dk_bob, ctxts[i], dec);
        t_decrypt.push_back(elapsed_ms(t0));
    }

    std::vector<Trapdoor> tds(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.auth(id_alice, id_carol, dk_bob, ctxts[i], tds[i]);
        t_auth.push_back(elapsed_ms(t0));
    }
    scheme.auth(id_alice, id_carol, dk_bob, ctxts[N], tds[N]);

    for (int i = 0; i < N; i++) {
        auto t0 = high_resolution_clock::now();
        scheme.test(ctxts[i], tds[i], ctxts[i + 1], tds[i + 1]);
        t_test.push_back(elapsed_ms(t0));
    }

    std::cout << "Setup   : " << avg(t_setup)   << " ms\n";
    std::cout << "Extract : " << avg(t_extract) << " ms\n";
    std::cout << "Encrypt : " << avg(t_encrypt) << " ms\n";
    std::cout << "Decrypt : " << avg(t_decrypt) << " ms\n";
    std::cout << "Auth    : " << avg(t_auth)    << " ms\n";
    std::cout << "Test    : " << avg(t_test)    << " ms\n";

    clrDK(dk_alice);
    clrDK(dk_bob);
    clrDK(dk_carol);
    for (int i = 0; i <= N; i++) { clrCT(ctxts[i]); element_clear(tds[i].td); }
    element_clear(msk.s1); element_clear(msk.s2);
}

static void print_usage(const char *prog)
{
    std::cerr << "Usage: " << prog
              << " -p <param_file> [-n iterations] [-m testers] [-s ibeet|lgz22|llh24|all]\n"
              << "  -p  PBC pairing parameter file (required)\n"
              << "  -n  number of benchmark iterations (default: 10)\n"
              << "  -m  number of testers            (default: 1)\n"
              << "  -s  scheme to run                (default: all)\n";
}

int main(int argc, char *argv[])
{
    int N = 10;
    int M = 1;
    std::string mode       = "all";
    std::string param_file = "";

    for (int i = 1; i < argc; i++)
    {
        std::string a(argv[i]);
        if      (a == "-n" && i + 1 < argc) { N          = std::atoi(argv[++i]); }
        else if (a == "-m" && i + 1 < argc) { M          = std::atoi(argv[++i]); }
        else if (a == "-s" && i + 1 < argc) { mode       = argv[++i]; }
        else if (a == "-p" && i + 1 < argc) { param_file = argv[++i]; }
        else { print_usage(argv[0]); return 1; }
    }

    if (param_file.empty())
    {
        std::cerr << "Error: -p <param_file> is required.\n\n";
        print_usage(argv[0]);
        return 1;
    }

    std::ifstream ifs(param_file);
    if (!ifs.is_open())
    {
        std::cerr << "Error: cannot open parameter file: " << param_file << "\n";
        return 1;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    const std::string param_str = oss.str();

    if (mode == "ibeet" || mode == "all") run_ibeet(N, M, param_str);
    if (mode == "lgz22" || mode == "all") run_lgz22(N, M, param_str);
    if (mode == "llh24" || mode == "all") run_llh24(N, param_str);

    return 0;
}
