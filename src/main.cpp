#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "runners.h"

static void print_usage(const char *prog)
{
    std::cerr << "Usage: " << prog
              << " -p <param_file> [-n iterations] [-m testers] [-s ibeet|lgz22|llh24|all]\n"
              << "  -p  PBC pairing parameter file     (required)\n"
              << "  -n  number of benchmark iterations (default: 10)\n"
              << "  -m  tester counts, comma-separated (default: 1, e.g. 1,5,10,50,100)\n"
              << "      IBEET-FDA sweeps every value; LGZ22 uses the largest\n"
              << "  -s  scheme to run                  (default: all)\n";
}

static bool parse_tester_counts(const std::string &s, std::vector<size_t> &out)
{
    std::stringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        const long v = std::strtol(tok.c_str(), nullptr, 10);
        if (v < 1) return false;
        out.push_back((size_t)v);
    }
    return !out.empty();
}

int main(int argc, char *argv[])
{
    int N = 10;
    std::vector<size_t> Ms;
    std::string mode       = "all";
    std::string param_file = "";
    std::string testers    = "1";

    for (int i = 1; i < argc; i++)
    {
        std::string a(argv[i]);
        if      (a == "-n" && i + 1 < argc) { N          = std::atoi(argv[++i]); }
        else if (a == "-m" && i + 1 < argc) { testers    = argv[++i]; }
        else if (a == "-s" && i + 1 < argc) { mode       = argv[++i]; }
        else if (a == "-p" && i + 1 < argc) { param_file = argv[++i]; }
        else { print_usage(argv[0]); return 1; }
    }

    if (N < 1)
    {
        std::cerr << "Error: -n expects a positive integer.\n\n";
        print_usage(argv[0]);
        return 1;
    }

    if (!parse_tester_counts(testers, Ms))
    {
        std::cerr << "Error: -m expects comma-separated positive integers.\n\n";
        print_usage(argv[0]);
        return 1;
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

    if (mode == "ibeet" || mode == "all") run_ibeet(N, Ms, param_str);
    if (mode == "lgz22" || mode == "all")
        run_lgz22(N, (int)*std::max_element(Ms.begin(), Ms.end()), param_str);
    if (mode == "llh24" || mode == "all") run_llh24(N, param_str);

    return 0;
}
