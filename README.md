# Fast Recursive SHA256

A fast recursive [SHA-256](https://en.wikipedia.org/wiki/SHA-2#Pseudocode) (SHA256) implementation in C++ intrinsics with [Intel SHA Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html) and extra source code [optimizations](OPTIMIZE.md).

Created as a contribution to optimize the VDF (verifiable delay function) creation part by TimeLord in [MMX blockchain](https://github.com/madMAx43v3r/mmx-node).

The SHA256 algorithm used recursively can be a method for securing that an amount of sequential computation time has passed (VDF). Once created, easy to verify with checkpoints and parallel SHA256 processing. A valid, but niche way of using SHA256.

Here the recursive SHA256 implementation is presented in its isolated form.

## TLDR;

I just want free fast recursive SHA256:
* Use at own responsibility ([LICENSE](LICENSE))
* Copy [rec_sha256_fast.cxx](rec_sha256_fast.cxx) into project
* Call `rec_sha256_fast()` function

Recommended:
* Make checks/fallback if SHA Extensions not available

## Requirement

**CPU:** Intel/AMD x64 (w/ SHA Extensions).\
**Model:** Intel 11th-gen (Rocket Lake), AMD Zen, or later (a few exceptions).

**Windows:** CPU-Z (Instructions) or HWiNFO64 (Features), look for `SHA`.\
**Linux:** `grep -o 'sha_ni' /proc/cpuinfo`, empty if not available.

## Usage

To use it in your own project. Copy the [rec_sha256_fast.cxx](rec_sha256_fast.cxx) file (only one needed). Remaining files are to illustrate optimizations done and perform benchmark. Function call:
```c++
void rec_sha256_fast(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 32bytes hash/data SHA256 value
const uint64_t num_iters) //-- number of times to SHA256 32bytes given in *hash
```

## Benchmark

Intel 13th-gen CPU P-core at **6.0 GHz** (Windows/VS2022): **42.48 MH/s**

![Console output Windows/VS2022](/media/benchmark.png "Console output Windows/VS2022 benchmark")

Look [BENCHMARK.md](BENCHMARK.md) for more information, and results.

## Optimization

Look [OPTIMIZE.md](OPTIMIZE.md) for more information, and [CHANGES.md](CHANGES.md) for revisions.

## Donation

If you find implementation useful, donations are welcome:

`BTC:` `bc1qtl00g8lctmuud72rv5eqr6kkpt85ws0t2u9s8d`\
`ETH:` `0x5fA8c257b502947A65D399906999D4FC373510B5`\
`MMX:` `mmx1pk95pv4lj5k3y9cwxzuuyznjsgdkqsu7wkxz029nqnenjathtv7suf9qgc`\
`XCH:` `xch1rk473wu3yqlxyyap4f4fhs8knzf4jt6aagtzka0g24hjgskmlv7qcme9gt`\
`KAS:` `kaspa:qqjrwh00du33v4f78re4x3u50420fcvemuu3ye3wy2dhllxtjlhagf04g97hj`

<!-- eof -->
