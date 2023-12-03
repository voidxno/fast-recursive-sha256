# Benchmark (Fast Recursive SHA256)

To benchmark, copy all (3x) .cxx files. Compile in your development environment. Run resulting benchmark binary. Compilers tested are Visual Studio 2022, GCC 12 (GNU Compiler Collection) and Clang 15 (LLVM).

Here are samples of benchmark performed on an **Intel 13th-gen** CPU, locked at **6.0 GHz** (**P-cores**) and **4.3 GHz** (**E-cores**). Commands used for compile and run of benchmark shown below (VS2022, Clang15, gcc12):

```batchfile
cl.exe /O2 /arch:AVX benchmark.cxx rec_sha256_fast.cxx rec_sha256_reference.cxx
benchmark.exe -i 100M -s 6.0 -m MH
benchmark.exe -i 100M -s 4.3 -m MH
```

```sh
clang++ benchmark.cxx rec_sha256_fast.cxx rec_sha256_reference.cxx -o benchmark -z noexecstack -mavx -msha -O2
./benchmark -i 100M -s 6.0 -m MH
./benchmark -i 100M -s 4.3 -m MH
```

```sh
g++ benchmark.cxx rec_sha256_fast.cxx rec_sha256_reference.cxx -o benchmark -z noexecstack -mavx -msha -O2
./benchmark -i 100M -s 6.0 -m MH
./benchmark -i 100M -s 4.3 -m MH
```

Lock CPU speed for benchmark:

To measure capabilities of a CPU core architecture, benchmark needs to run with locked CPU GHz speed. Not max, but locked. Can be possible through BIOS. If not, look for OS utilities. In Linux, maybe [`cpupower`](https://manpages.ubuntu.com/manpages/en/man1/cpupower.1.html) ([`--frequency-set`](https://manpages.ubuntu.com/manpages/man1/cpupower-frequency-set.1.html)).

Lock benchmark to specific CPU core:

If heterogeneous cores on a CPU, like Intel P- and E-cores. Need to lock run of benchmark to specific core. In Linux, look at [`taskset`](https://manpages.ubuntu.com/manpages/en/man1/taskset.1.html) (`--cpu-list`). On Windows, look at `AFFINITY` parameter for `START` batch command.

Program call for benchmark:
```
benchmark -i <iters> -s <cpuspeed> -m <unit>

-i <iter>: Number of SHA256 iterations to perform (optional)
           Valid values: 10M, 50M, 100M (default), 200M, 500M

-s <ghz>: x.x GHz speed of CPU when run (optional)
          If set, calculates and shows MH/s/0.1GHz for result
          Only calculates, cannot set real CPU speed of machine

- m <unit>: Measure unit to calculate (optional)
            Valid values: MH (default), MB, MiB, cpb
```
Console output for Windows/VS2022 (**P-core**, **6.0 GHz**):

![Console output Windows/VS2022](/media/benchmark.png "Console output Windows/VS2022 benchmark")

Results (**P-core**, **6.0 GHz**):

| Environment <sup>[1]</sup> | Fast | P/U <sup>[2]</sup> | Reference <sup>[3]</sup> | P/U <sup>[2]</sup> |
| :--- | :--- | :--- | :--- | :--- |
| Windows/VS2022 | 42.48 MH/s | **0.708** | 31.17 MH/s | **0.520** |
| Linux/Clang15 | 42.47 MH/s | **0.708** | 41.37 MH/s | **0.689** |
| Linux/gcc12 | 42.13 MH/s | **0.702** | 35.56 MH/s | **0.593** |

Results (**E-core**, **4.3 GHz**):

| Environment <sup>[1]</sup> | Fast | P/U <sup>[2]</sup> | Reference <sup>[3]</sup> | P/U <sup>[2]</sup> |
| :--- | :--- | :--- | :--- | :--- |
| Windows/VS2022 | 42.02 MH/s | **0.977** | 29.29 MH/s | **0.681** |
| Linux/Clang15 | 42.09 MH/s | **0.979** | 40.91 MH/s | **0.951** |
| Linux/gcc12 | 42.07 MH/s | **0.978** | 33.43 MH/s | **0.777** |

_<sup>[1]</sup> Compiler versions, VS2022 v19.36.32532, Clang15 v15.0.7, gcc12 v12.2.0._\
_<sup>[2]</sup> P/U, per unit, MH/s/0.1GHz speed from measured MH/s and CPU speed._\
_<sup>[3]</sup> Reference numbers are only to illustrate source code optimization effect._

All testing indicates a linear MH/s increase, given CPU GHz speed. Locking CPU speed, using MH/s/0.1GHz unit, is an easy way to measure optimization effect. Or compare IPC (instructions per clock) for SHA Extensions between CPU generations (for this specific use-case).

Elements surrounding raw GHz of CPU do not look to affect results (RAM, HyperThreading, CPU cache, more). Seems logical, since the recursive SHA256 implementation is not much more than a few instructions repeated in a CPU core.

Intel's E-cores are much more efficient per 0.1 GHz than P-cores. Cannot run with as high clock. Still manages to get work done. In the end, a race of who can clock highest (GHz).

<!-- eof -->
