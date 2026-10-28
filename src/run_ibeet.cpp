#include <algorithm>
#include <cstring>

#include "IBEET_FDA.h"
#include "runners.h"

using namespace std::chrono;

void run_ibeet(int N, const std::vector<size_t> &Ms, const std::string &param_str)
{
    using namespace IBEET;

    const size_t max_n = *std::max_element(Ms.begin(), Ms.end());

    auto clrCT  = [](Ciphertext &C)     { element_clear(C.C1); element_clear(C.C2); element_clear(C.C3); };
    auto clrDK  = [](DecryptionKey &dk) { element_clear(dk.dk1); element_clear(dk.dk2); };
    auto clrFDA = [](TrapdoorFDA &td)   {
        element_clear(td.td1);
        for (size_t i = 0; i < td.n; i++) element_clear(td.td2[i]);
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

        C.C4[0] ^= 0x01;
        check(!scheme.decrypt(dk_alice, C, msg_bad), "Decrypt with CT4 bit flipped returns false");

        clrCT(C);
    }

    {
        element_t r1, r2;
        element_init_Zr(r1, scheme.pairing); element_set0(r1);
        element_init_Zr(r2, scheme.pairing); random_Zpstar(r2);

        Ciphertext C;
        scheme.encrypt(id_alice, msg_orig, r1, r2, C);

        uint8_t msg_bad[L1] = {};
        check(!scheme.decrypt(dk_alice, C, msg_bad), "Decrypt rejects r1 = 0");

        clrCT(C);
        element_clear(r1); element_clear(r2);
    }

    std::vector<std::string> tester_ids;
    std::vector<DecryptionKey> dk_testers(max_n);
    for (size_t i = 0; i < max_n; i++) {
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
        random_Zpstar(gamma);

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

    // ---- Benchmark ----
    std::cout << "\n=== [IBEET-FDA] Benchmark: N=" << N << " ===\n";

    std::vector<double> t_setup, t_extract, t_encrypt, t_decrypt;
    std::vector<double> t_auth1, t_test1;
    std::vector<double> t_auth2, t_test2;
    std::vector<double> t_auth3i, t_auth3j, t_test3;
    std::vector<double> t_auth4, t_test4;

    {
        IBEET_FDA sink(param_str);
        for (int i = 0; i < N; i++) {
            MasterSecretKey tmp;
            auto t0 = steady_clock::now();
            sink.setup(tmp);
            t_setup.push_back(elapsed_ms(t0));
            element_clear(tmp.s1); element_clear(tmp.s2);
        }
    }

    for (int i = 0; i < N; i++) {
        DecryptionKey dk;
        auto t0 = steady_clock::now();
        scheme.extract(id_alice, msk, dk);
        t_extract.push_back(elapsed_ms(t0));
        clrDK(dk);
    }

    // N+1 ciphertexts/trapdoors: N are benchmarked, one extra for pairwise tests
    std::vector<Ciphertext> ctxts(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = steady_clock::now();
        scheme.encrypt(id_alice, msg_orig, ctxts[i]);
        t_encrypt.push_back(elapsed_ms(t0));
    }
    scheme.encrypt(id_alice, msg_orig, ctxts[N]);

    for (int i = 0; i < N; i++) {
        uint8_t dec[L1] = {};
        auto t0 = steady_clock::now();
        scheme.decrypt(dk_alice, ctxts[i], dec);
        t_decrypt.push_back(elapsed_ms(t0));
    }

    // Type-1
    {
        std::vector<Trapdoor1> td1s(N + 1);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            scheme.auth1(dk_alice, td1s[i]);
            t_auth1.push_back(elapsed_ms(t0));
        }
        scheme.auth1(dk_alice, td1s[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            scheme.test1(ctxts[i], td1s[i], ctxts[i + 1], td1s[i + 1]);
            t_test1.push_back(elapsed_ms(t0));
        }
        for (int i = 0; i <= N; i++) element_clear(td1s[i].td1);
    }

    // Type-2
    {
        std::vector<Trapdoor2> td2s(N + 1);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            scheme.auth2(dk_alice, ctxts[i], td2s[i]);
            t_auth2.push_back(elapsed_ms(t0));
        }
        scheme.auth2(dk_alice, ctxts[N], td2s[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
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
            auto t0 = steady_clock::now();
            scheme.auth3i(dk_alice, ctxts[i], td3is[i]);
            t_auth3i.push_back(elapsed_ms(t0));
        }
        scheme.auth3i(dk_alice, ctxts[N], td3is[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            scheme.auth3j(dk_alice, td3js[i]);
            t_auth3j.push_back(elapsed_ms(t0));
        }
        scheme.auth3j(dk_alice, td3js[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
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
        random_Zpstar(gamma);

        std::vector<Trapdoor4> td4s(N + 1);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            scheme.auth4(dk_alice, ctxts[i], ctxts[(i + 1) % (N + 1)], gamma, td4s[i]);
            t_auth4.push_back(elapsed_ms(t0));
        }
        scheme.auth4(dk_alice, ctxts[N], ctxts[0], gamma, td4s[N]);
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            scheme.test4(ctxts[i], td4s[i], ctxts[i + 1], td4s[i + 1]);
            t_test4.push_back(elapsed_ms(t0));
        }
        for (int i = 0; i <= N; i++) {
            element_clear(td4s[i].TD1);
            element_clear(td4s[i].TD2);
        }
        element_clear(gamma);
    }

    std::cout << "Setup      : " << avg(t_setup)   << " ms (med " << median(t_setup) << ", sd " << stddev(t_setup) << ")\n";
    std::cout << "Extract    : " << avg(t_extract) << " ms (med " << median(t_extract) << ", sd " << stddev(t_extract) << ")\n";
    std::cout << "Encrypt    : " << avg(t_encrypt) << " ms (med " << median(t_encrypt) << ", sd " << stddev(t_encrypt) << ")\n";
    std::cout << "Decrypt    : " << avg(t_decrypt) << " ms (med " << median(t_decrypt) << ", sd " << stddev(t_decrypt) << ")\n";
    std::cout << "Auth1      : " << avg(t_auth1)   << " ms (med " << median(t_auth1) << ", sd " << stddev(t_auth1) << ")\n";
    std::cout << "Test1      : " << avg(t_test1)   << " ms (med " << median(t_test1) << ", sd " << stddev(t_test1) << ")\n";
    std::cout << "Auth2      : " << avg(t_auth2)   << " ms (med " << median(t_auth2) << ", sd " << stddev(t_auth2) << ")\n";
    std::cout << "Test2      : " << avg(t_test2)   << " ms (med " << median(t_test2) << ", sd " << stddev(t_test2) << ")\n";
    std::cout << "Auth3i     : " << avg(t_auth3i)  << " ms (med " << median(t_auth3i) << ", sd " << stddev(t_auth3i) << ")\n";
    std::cout << "Auth3j     : " << avg(t_auth3j)  << " ms (med " << median(t_auth3j) << ", sd " << stddev(t_auth3j) << ")\n";
    std::cout << "Test3      : " << avg(t_test3)   << " ms (med " << median(t_test3) << ", sd " << stddev(t_test3) << ")\n";
    std::cout << "Auth4      : " << avg(t_auth4)   << " ms (med " << median(t_auth4) << ", sd " << stddev(t_auth4) << ")\n";
    std::cout << "Test4      : " << avg(t_test4)   << " ms (med " << median(t_test4) << ", sd " << stddev(t_test4) << ")\n";

    DecryptionKey dk_unauth;
    scheme.extract("unauthorized@example.com", msk, dk_unauth);

    Ciphertext C_diff;
    scheme.encrypt(id_alice, msg_diff, C_diff);

    Trapdoor2 t_token;
    scheme.auth2(dk_alice, ctxts[0], t_token);

    for (size_t n : Ms) {
        const std::vector<std::string> ids(tester_ids.begin(), tester_ids.begin() + n);

        std::vector<double> t_authFDA, t_testFDA;
        std::vector<TrapdoorFDA> tds(N + 1);

        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            scheme.authFDA(ctxts[i], dk_alice, ids, tds[i]);
            t_authFDA.push_back(elapsed_ms(t0));
        }
        scheme.authFDA(ctxts[N], dk_alice, ids, tds[N]);

        bool same_ok = true;
        for (int i = 0; i < N; i++) {
            auto t0 = steady_clock::now();
            bool eq = scheme.testFDA(ctxts[i], tds[i], ctxts[i + 1], tds[i + 1], dk_testers[n - 1]);
            t_testFDA.push_back(elapsed_ms(t0));
            if (!eq) same_ok = false;
        }

        std::cout << "\n--- FDA: n=" << n << " ---\n";

        bool token_ok = true;
        for (size_t k = 0; k < n; k++) {
            element_t v;
            element_init_Zr(v, scheme.pairing);
            scheme.recoverFDA(tds[0], dk_testers[k], v);
            if (element_cmp(v, t_token.td2) != 0) token_ok = false;
            element_clear(v);
        }
        check(token_ok, "designated testers recover t_i");

        element_t v_unauth;
        element_init_Zr(v_unauth, scheme.pairing);
        scheme.recoverFDA(tds[0], dk_unauth, v_unauth);
        check(element_cmp(v_unauth, t_token.td2) != 0, "unauthorized tester recovers wrong t_i");
        element_clear(v_unauth);

        check(same_ok, "same plaintext -> true");

        TrapdoorFDA td_diff;
        scheme.authFDA(C_diff, dk_alice, ids, td_diff);
        check(!scheme.testFDA(ctxts[0], tds[0], C_diff, td_diff, dk_testers[n - 1]),
              "diff plaintext -> false");
        clrFDA(td_diff);

        check(!scheme.testFDA(ctxts[0], tds[0], ctxts[1], tds[1], dk_unauth),
              "unauthorized tester -> false");

        std::cout << "Auth(FDA)  : " << avg(t_authFDA) << " ms (med "
                  << median(t_authFDA) << ", sd " << stddev(t_authFDA) << ")\n";
        std::cout << "Test(FDA)  : " << avg(t_testFDA) << " ms (med "
                  << median(t_testFDA) << ", sd " << stddev(t_testFDA) << ")\n";

        for (int i = 0; i <= N; i++) clrFDA(tds[i]);
    }

    clrDK(dk_alice);
    clrDK(dk_bob);
    clrDK(dk_unauth);
    clrCT(C_diff);
    element_clear(t_token.td2);
    for (size_t i = 0; i < max_n; i++) clrDK(dk_testers[i]);
    for (int i = 0; i <= N; i++) clrCT(ctxts[i]);
    element_clear(msk.s1); element_clear(msk.s2);
}
