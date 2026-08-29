# Fast Recursive SHA256 - pipelined

For context, read main [README.md](../README.md).

Pipelined editions of fast recursive [SHA-256](https://en.wikipedia.org/wiki/SHA-2#Pseudocode) (SHA256) implementation in C++ intrinsics with [Intel SHA Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html) or [ARM Cryptography Extensions](https://developer.arm.com/architectures/instruction-sets/intrinsics/#q=sha256).

Written to optimize **verification of VDF's** (verifiable delay function) created by TimeLord in [MMX blockchain](https://github.com/madMAx43v3r/mmx-node).

Depending on architecture of a CPU core, [instruction pipelining](https://en.wikipedia.org/wiki/Instruction_pipelining) can be used to get more throughput. **Can not help VDF creation**. Where each new SHA256 iteration is dependent on previous result. In contrast. VDF verification has checkpoints, and can be processed in parallel.

For observed effects of pipelining, look at [RESULTS.md](RESULTS.md).

## TLDR;

I just want free fast recursive SHA256 - pipelined:
* Use at own responsibility ([LICENSE](LICENSE))
* Copy [rsha256pl_fast_x64.cxx](rsha256pl_fast_x64.cxx) into project (Intel)
* Copy [rsha256pl_fast_arm.cxx](rsha256pl_fast_arm.cxx) into project (ARM)
* Call `rsha256_fast_x1()` function, identical to `_fast()`
* Call `rsha256_fast_x2()` function
* Call `rsha256_fast_x3()` function
* Call `rsha256_fast_x4()` function

## Usage

To use in your own project. Copy the [rsha256pl_fast_x64.cxx](rsha256pl_fast_x64.cxx) or [rsha256pl_fast_arm.cxx](rsha256pl_fast_arm.cxx) file (only one needed). Remaining files are to illustrate optimizations and perform benchmark. Function calls:

```c++
void rsha256_fast_x1(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 32 bytes, 1x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 1x 32bytes given in *hash
```

```c++
void rsha256_fast_x2(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 64 bytes, 2x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 2x 32bytes given in *hash
```

```c++
void rsha256_fast_x3(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 96 bytes, 3x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 3x 32bytes given in *hash
```

```c++
void rsha256_fast_x4(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 128 bytes, 4x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 4x 32bytes given in *hash
```
## Benchmark (mt)

Intel 15th-gen CPU **E-core** (Skymont) at **4.6 GHz** (Linux/gcc15): **100.76 MH/s** (1 thread, `_x2`):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 4.60 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>62.18</b> MH/s ( <b>1.352</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:  <b>100.76</b> MH/s ( <b>2.191</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:  <b>100.48</b> MH/s ( <b>2.184</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:   <b>93.07</b> MH/s ( <b>2.023</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

Intel 15th-gen CPU **P-core** (Lion Cove) at **5.7 GHz** (Linux/gcc15): **92.75 MH/s** (1 thread, `_x2`):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 5.70 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>52.08</b> MH/s ( <b>0.914</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:   <b>92.75</b> MH/s ( <b>1.627</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:  <b>110.88</b> MH/s ( <b>1.945</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:  <b>106.41</b> MH/s ( <b>1.867</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

AMD 7040-series CPU **Zen4-core** (Phoenix) at **5.1 GHz** (Linux/gcc15): **72.21 MH/s** (1 thread, `_x2`):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 5.10 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>38.25</b> MH/s ( <b>0.750</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:   <b>72.21</b> MH/s ( <b>1.416</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:   <b>81.39</b> MH/s ( <b>1.596</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:   <b>76.55</b> MH/s ( <b>1.501</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

ARM Cortex-A76 CPU **A76-core** (Enyo) at **2.4 GHz** (Linux/gcc15): **33.65 MH/s** (1 thread, `_x2`):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 2.40 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>18.41</b> MH/s ( <b>0.767</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:   <b>33.65</b> MH/s ( <b>1.402</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:   <b>36.12</b> MH/s ( <b>1.505</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:   <b>36.92</b> MH/s ( <b>1.538</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

Look [BENCHMARK.md](BENCHMARK.md) for more information, pipelining, threads and results.

## Optimization (mt)

Look [OPTIMIZE.md](OPTIMIZE.md) for more information, and [CHANGES.md](../CHANGES.md) for history.

<!-- eof -->
