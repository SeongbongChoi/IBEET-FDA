#include <algorithm>
#include <cstring>

#include "LLH24.h"
#include "runners.h"

using namespace std::chrono;

void run_llh24(int N, const std::string &param_str)
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

    {
        LLH24Scheme sink(param_str);
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
        scheme.encrypt(id_alice, id_bob, dk_alice, msg_orig, ctxts[i]);
        t_encrypt.push_back(elapsed_ms(t0));
    }
    scheme.encrypt(id_alice, id_bob, dk_alice, msg_orig, ctxts[N]);

    for (int i = 0; i < N; i++) {
        uint8_t dec[MSG_BYTES] = {};
        auto t0 = steady_clock::now();
        scheme.decrypt(id_alice, dk_bob, ctxts[i], dec);
        t_decrypt.push_back(elapsed_ms(t0));
    }

    std::vector<Trapdoor> tds(N + 1);
    for (int i = 0; i < N; i++) {
        auto t0 = steady_clock::now();
        scheme.auth(id_alice, id_carol, dk_bob, ctxts[i], tds[i]);
        t_auth.push_back(elapsed_ms(t0));
    }
    scheme.auth(id_alice, id_carol, dk_bob, ctxts[N], tds[N]);

    for (int i = 0; i < N; i++) {
        auto t0 = steady_clock::now();
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
