# IBEET-FDA
Identity-based encryption with equality test supporting flexible designated authorization

## Required Libraries
1. GMP library
2. PBC library
3. OpenSSL


## Build the Project

Tested on Ubuntu 20.04.6 LTS

The library can be cloned and built with networking support as
```
git clone https://github.com/SeongbongChoi/IBEET-FDA.git
cd IBEET-FDA
mkdir build
cd build
cmake ..
make
```


## Running the Code
- `-p`: PBC pairing parameter file
- `-n`: the number of iteration
- `-m`: the number of tester
- `-s`: scheme (ibeet, lgz22, llh24, all)

Example usage:
```
./bin/frontend -p params/e256.param -n 10 -m 5 -s ibeet
./bin/frontend -p params/e256.param -n 10 -m 5 -s lgz22
./bin/frontend -p params/e256.param -n 10 -s llh24
```
