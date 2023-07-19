# Benchmark (Fast Recursive SHA256)

To benchmark, copy all (3x) .cxx files. Compile in your development environment. Run resulting benchmark binary. Compilers tested are Visual Studio 2022, GCC 12 (GNU Compiler Collection) and Clang 15 (LLVM).

Here are samples of benchmark performed on an Intel 13th-gen CPU, locked at 6.0 GHz. Commands used for compile and run of benchmark shown below (VS2022, Clang15, gcc12):

```batchfile
cl.exe /O2 /arch:AVX benchmark.cxx rec_sha256_fast.cxx rec_sha256_reference.cxx
benchmark.exe -i 100M -s 6.0
```

```sh
clang++ benchmark.cxx rec_sha256_fast.cxx rec_sha256_reference.cxx -o benchmark -z noexecstack -mavx -msha -O2
./benchmark -i 100M -s 6.0
```

```sh
gcc benchmark.cxx rec_sha256_fast.cxx rec_sha256_reference.cxx -o benchmark -z noexecstack -mavx -msha -O2
./benchmark -i 100M -s 6.0
```

Program call for benchmark:
```
benchmark -i <iters> -s <cpuspeed>

-i <iter>: Number of SHA256 iterations to perform (optional)
           Valid values: 10M, 50M, 100M (default), 200M, 500M

-s <ghz>: x.x GHz speed of CPU when run (optional)
          If set, calculates and shows MH/s/0.1GHz for result
          Only calculates, cannot set real CPU speed of machine
```
Console output for Windows/VS2022:

![Console output Windows/VS2022](/media/benchmark.png "Console output Windows/VS2022 benchmark")

Results:

| Environment <sup>[1]</sup> | Fast | P/U <sup>[2]</sup> | Reference <sup>[3]</sup> | P/U <sup>[2]</sup> |
| :--- | :--- | :--- | :--- | :--- |
| Windows/VS2022 | 42.48 MH/s | **0.708** | 31.17 MH/s | **0.520** |
| Linux/Clang15 | 42.47 MH/s | **0.708** | 41.37 MH/s | **0.689** |
| Linux/gcc12 | 42.13 MH/s | **0.702** | 35.56 MH/s | **0.593** |

_<sup>[1]</sup> Compiler versions, VS2022 v19.36.32532, Clang15 v15.0.7, gcc12 v12.2.0._\
_<sup>[2]</sup> P/U, per unit, **MH/s/0.1GHz** speed from measured MH/s and **6.0 GHz** CPU._\
_<sup>[3]</sup> Reference numbers are only to illustrate source code optimization effect._

All testing indicates a linear MH/s increase, given CPU GHz speed. Locking CPU speed, using MH/s/0.1GHz unit, is an easy way to measure optimization effect. Or compare IPC (instructions per clock) for SHA Extensions between CPU generations (for this specific use-case).

Elements surrounding raw GHz of CPU do not look to affect results (RAM, HyperThreading, CPU cache, more). Seems logical, since the recursive SHA256 implementation is not much more than a few instructions repeated in a CPU core.

<!-- eof -->
