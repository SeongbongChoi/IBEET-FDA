#pragma once

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

inline void print_pass(const char *label) { std::cout << "  [PASS] " << label << "\n"; }
inline void print_fail(const char *label) { std::cerr << "  [FAIL] " << label << "\n"; std::exit(1); }
inline void check(bool ok, const char *label) { ok ? print_pass(label) : print_fail(label); }

inline double elapsed_ms(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

void run_ibeet(int N, const std::vector<size_t> &Ms, const std::string &param_str);
void run_lgz22(int N, int M, const std::string &param_str);
void run_llh24(int N, const std::string &param_str);
