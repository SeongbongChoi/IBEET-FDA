# IBEET-FDA
Identity-based encryption with equality test supporting flexible designated authorization

### Build

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
- `-n`: the number of iteration
- `-m`: the number of tester
- `-s`: mode (ibeet, pkeet, both)

Example usage:
```
./bin/frontend -n 10 -m 5 -s ibeet
./bin/frontend -n 10 -m 5 -s pkeet
```
