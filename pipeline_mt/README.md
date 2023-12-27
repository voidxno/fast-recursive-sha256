# Fast Recursive SHA256 - pipelined

For context, read main [README.md](../README.md).

Pipelined editions of fast recursive [SHA-256](https://en.wikipedia.org/wiki/SHA-2#Pseudocode) (SHA256) implementation in C++ intrinsics with [Intel SHA Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html).

Created to optimize **verification of VDF's** (verifiable delay function) created by TimeLord in [MMX blockchain](https://github.com/madMAx43v3r/mmx-node).

Depending on architecture of a CPU core, [instruction pipelining](https://en.wikipedia.org/wiki/Instruction_pipelining) can be used to get more throughput. **Can not help VDF creation.** Where each new SHA256 iteration is dependent on previous result. In contrast. VDF verification has checkpoints, and can be processed in parallel.

For observed effects of pipelining, look at [RESULTS.md](RESULTS.md).

## TLDR;

I just want free fast recursive SHA256 - pipelined:
* Use at own responsibility ([LICENSE](LICENSE))
* Copy [rec_sha256_fast_pl.cxx](rec_sha256_fast_pl.cxx) into project
* Call `rec_sha256_fast_x1()` function, identical to `_fast()`
* Call `rec_sha256_fast_x2()` function
* Call `rec_sha256_fast_x3()` function
* Call `rec_sha256_fast_x4()` function

## Usage

To use in your own project. Copy the [rec_sha256_fast_pl.cxx](rec_sha256_fast_pl.cxx) file (only one needed). Remaining file is for benchmark. Function calls:
```c++
void rec_sha256_fast_x1(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 32 bytes, 1x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 1x 32bytes given in *hash
```

```c++
void rec_sha256_fast_x2(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 64 bytes, 2x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 2x 32bytes given in *hash
```

```c++
void rec_sha256_fast_x3(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 96 bytes, 3x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 3x 32bytes given in *hash
```

```c++
void rec_sha256_fast_x4(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 128 bytes, 4x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 4x 32bytes given in *hash
```
## Benchmark (mt)

Intel 13th-gen CPU **P-core** (Raptor Cove) at **6.0 GHz** (Linux/Clang15): **57.19 MH/s** (1 thread, `_x2`):

![Console output Linux/Clang15 P-core](/pipeline_mt/media/benchmark_mt_p.png "Console output Linux/Clang15 P-core benchmark")

Intel 13th-gen CPU **E-core** (Gracemont) at **4.3 GHz** (Linux/Clang15): **78.40 MH/s** (1 thread, `_x2`):

![Console output Linux/Clang15 E-core](/pipeline_mt/media/benchmark_mt_e.png "Console output Linux/Clang15 E-core benchmark")

AMD 7040-series CPU **Zen4-core** (Phoenix) at **5.1 GHz** (Linux/Clang15): **72.83 MH/s** (1 thread, `_x2`):

![Console output Linux/Clang15 Zen4-core](/pipeline_mt/media/benchmark_mt_z4.png "Console output Linux/Clang15 Zen4-core benchmark")

Look [BENCHMARK.md](BENCHMARK.md) for more information, pipelining, threads and results.

## Optimization (mt)

Look [OPTIMIZE.md](OPTIMIZE.md) for more information.

<!-- eof -->
