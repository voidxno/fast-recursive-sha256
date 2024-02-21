# Benchmark (Fast Recursive SHA256) - pipelined

To benchmark, copy all (3x) .cxx files. Compile in your development environment. Run resulting benchmark binary. Compilers tested are Visual Studio 2022, GCC 12 (GNU Compiler Collection) and Clang 15 (LLVM).

Here are samples of benchmark performed on 4 types of CPU cores. **Intel 13th-gen** (Raptor Lake), locked at **6.0 GHz** (**P-cores**, Raptor Cove) and **4.3 GHz** (**E-cores**, Gracemont). **AMD 7040-series** (Phoenix), locked at **5.1 GHz** (**Zen4-cores**, Phoenix). **ARM Cortex-A76** (Enyo), locked at **2.4 GHz** (**A76-core**, Enyo). Commands used for compile and run of benchmark shown below (VS2022, Clang15, gcc12):

```batchfile
cl.exe /O2 /arch:AVX /MP /openmp benchmark_mt.cxx rsha256pl_*.cxx
benchmark_mt.exe -i 10M -s 6.0 -m MH -t 1
benchmark_mt.exe -i 10M -s 4.3 -m MH -t 1
benchmark_mt.exe -i 10M -s 5.1 -m MH -t 1
```

```sh
clang++ benchmark_mt.cxx rsha256pl_*.cxx -o benchmark_mt -fopenmp -z noexecstack -mavx -msha -O2
./benchmark_mt -i 10M -s 6.0 -m MH -t 1
./benchmark_mt -i 10M -s 4.3 -m MH -t 1
./benchmark_mt -i 10M -s 5.1 -m MH -t 1
```

```sh
clang++ benchmark_mt.cxx rsha256pl_*.cxx -o benchmark_mt -fopenmp -z noexecstack -march=armv8-a+crypto -mtune=native -O2
./benchmark_mt -i 10M -s 2.4 -m MH -t 1
```

```sh
g++ benchmark_mt.cxx rsha256pl_*.cxx -o benchmark_mt -fopenmp -z noexecstack -mavx -msha -O2
./benchmark_mt -i 10M -s 6.0 -m MH -t 1
./benchmark_mt -i 10M -s 4.3 -m MH -t 1
./benchmark_mt -i 10M -s 5.1 -m MH -t 1
```

```sh
g++ benchmark_mt.cxx rsha256pl_*.cxx -o benchmark_mt -fopenmp -z noexecstack -march=armv8-a+crypto -mtune=native -O2
./benchmark_mt -i 10M -s 2.4 -m MH -t 1
```

Lock CPU speed for benchmark:

To measure capabilities of a CPU core architecture, benchmark needs to run with locked CPU GHz speed. Not max, but locked. Can be possible through BIOS. If not, look for OS utilities. In Linux, maybe [`cpufreq-info`](https://manpages.ubuntu.com/cpufreq-info.html) (available frequency steps), [`cpufreq-set`](https://manpages.ubuntu.com/cpufreq-set.html) (`-u`), [`cpupower`](https://manpages.ubuntu.com/cpupower.html) ([`--frequency-set`](https://manpages.ubuntu.com/cpupower-frequency-set.html), `-u`).

Lock benchmark to specific CPU core:

If heterogeneous cores on a CPU, like Intel P- and E-cores. Need to lock run of benchmark to specific core. In Linux, look at [`taskset`](https://manpages.ubuntu.com/taskset.html) (`--cpu-list`). On Windows, look at `AFFINITY` parameter for `START` batch command.

Be aware of benchmark [limitations](#limitations-mt) when it comes to running multiple threads.

Program call for benchmark:
```
benchmark_mt -i <iters> -s <cpuspeed> -m <unit> -t <threads>

-i <iter>: Number of SHA256 iterations to perform (optional)
           Valid values: 10M (default), 50M, 100M, 200M, 500M

-s <ghz>: x.x GHz speed of CPU when run (optional)
          If set, calculates and shows MH/s/0.1GHz for result
          Only calculates, cannot set real CPU speed of machine

-m <unit>: Measure unit to calculate (optional)
           Valid values: MH (default), MB, MiB, cpb

-t <threads>: Number of threads to run (optional)
              Valid values: 1 (default), 256 (max)
```
Console output for Linux/Clang15 (**P-core**, **6.0 GHz**):

![Console output Linux/Clang15 P-core](/pipeline_mt/media/benchmark_mt_p.png "Console output Linux/Clang15 P-core benchmark")

Console output for Linux/Clang15 (**E-core**, **4.3 GHz**):

![Console output Linux/Clang15 E-core](/pipeline_mt/media/benchmark_mt_e.png "Console output Linux/Clang15 E-core benchmark")

Console output for Linux/Clang15 (**Zen4-core**, **5.1 GHz**):

![Console output Linux/Clang15 Zen4-core](/pipeline_mt/media/benchmark_mt_z4.png "Console output Linux/Clang15 Zen4-core benchmark")

Console output for Linux/Clang15 (**A76-core**, **2.4 GHz**):

![Console output Linux/Clang15 A76-core](/pipeline_mt/media/benchmark_mt_a76.png "Console output Linux/Clang15 A76-core benchmark")

Results (non-pipelined vs pipelined, 1 CPU core, 1 thread):

| | Fast _x1 | Fast _x2 | Uplift |
| :--- | :--- | :--- | :--- |
| **P-core**, **6.0 GHz** | 42.42 MH/s | 57.19 MH/s | **+34.8%** |
| **E-core**, **4.3 GHz** | 42.02 MH/s | 78.40 MH/s | **+86.5%** |
| **Zen4-core**, **5.1 GHz** | 38.36 MH/s | 72.83 MH/s | **+89.8%** |
| **A76-core**, **2.4 GHz** | 18.41 MH/s | 36.89 MH/s | **+100.3%** |

There are nuances. Synthetic results are great. Real-life P-core, not so much. E-core, good. Zen4-core, some reduction. A76-core, good. Look in [RESULTS.md](RESULTS.md).

## Limitations (mt)

Even though this benchmark will measure potential throughput of recursive SHA256 on a CPU core. It is simplistic, and needs to be run in a controlled manner.

Goal here is finding best potential throughput, depending on pipelining and threads. Aiming for that result in real-life implementation.

Factors to control:
- Pipelined edition
- Threads
- Core(s) speed
- Core(s) used

A few guidelines:
- Lock CPU speed on cores measured on
- Lock benchmark to 1 core (usually), or more
- If more cores, do not mix architecture (P/E-core)
- Make sure cores are not used by OS or apps (idle)
- If multiple threads, multiply by cores run on
- Sample: 4 cores, then 4, 8, 12, 16, 20 threads

Usual method to measure pipelined efficiency:
- Lock benchmark to 1 core, run 1, 2, 4, 8 thread(s)
- Look at throughput of `_x1` to `_x4` pipelined editions

<!-- eof -->
