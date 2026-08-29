# Benchmark (Fast Recursive SHA256) - pipelined

To benchmark, copy all (3x) .cxx files. Compile in your development environment. Run resulting benchmark binary. Compilers tested are GCC 15 (GNU Compiler Collection) and Visual Studio 2026.

Here are samples of benchmark performed on 4 types of CPU cores. **Intel 15th-gen** (Arrow Lake), locked at **4.6 GHz** (**E-core**, Skymont) and **5.7 GHz** (**P-core**, Lion Cove). **AMD 7040-series** (Phoenix), locked at **5.1 GHz** (**Zen4-core**, Phoenix). **ARM Cortex-A76** (Enyo), locked at **2.4 GHz** (**A76-core**, Enyo). Commands used for compile and run of benchmark shown below (gcc15, VS2026):

```sh
g++ benchmark_mt.cxx rsha256pl_*.cxx -o benchmark_mt -fopenmp -z noexecstack -mavx -msha -O2
./benchmark_mt -i 10M -s 4.6 -m MH -t 1
./benchmark_mt -i 10M -s 5.7 -m MH -t 1
./benchmark_mt -i 10M -s 5.1 -m MH -t 1
```

```batchfile
cl.exe /O2 /arch:AVX /MP /openmp benchmark_mt.cxx rsha256pl_*.cxx
benchmark_mt.exe -i 10M -s 4.6 -m MH -t 1
benchmark_mt.exe -i 10M -s 5.7 -m MH -t 1
benchmark_mt.exe -i 10M -s 5.1 -m MH -t 1
```

```sh
g++ benchmark_mt.cxx rsha256pl_*.cxx -o benchmark_mt -fopenmp -z noexecstack -march=armv8-a+crypto -mtune=native -O2
./benchmark_mt -i 10M -s 2.4 -m MH -t 1
```

Lock CPU speed for benchmark:

To measure capabilities of a CPU core architecture, benchmark needs to run with locked CPU GHz speed. Not max, but locked. Can be possible through BIOS. If not, look for OS utilities. In Linux, maybe [`cpufreq-info`](https://manpages.ubuntu.com/manpages/lts/man1/cpufreq-info.html) (available frequency steps), [`cpufreq-set`](https://manpages.ubuntu.com/manpages/lts/man1/cpufreq-set.html) (`-u`), [`cpupower`](https://manpages.ubuntu.com/manpages/lts/man1/cpupower.html) ([`--frequency-set`](https://manpages.ubuntu.com/manpages/lts/man1/cpupower-frequency-set.html), `-u`).

Lock benchmark to specific CPU core:

If heterogeneous cores on a CPU, like Intel E- and P-cores. Need to lock run of benchmark to specific core. In Linux, look at [`taskset`](https://manpages.ubuntu.com/manpages/lts/man1/taskset.html) (`--cpu-list`). On Windows, look at `AFFINITY` parameter for `START` batch command.

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
Console output for Linux/gcc15 (**E-core**, **4.6 GHz**):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 4.60 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>62.18</b> MH/s ( <b>1.352</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:  <b>100.75</b> MH/s ( <b>2.190</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:  <b>100.46</b> MH/s ( <b>2.184</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:   <b>93.10</b> MH/s ( <b>2.024</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

Console output for Linux/gcc15 (**P-core**, **5.7 GHz**):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 5.70 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>52.08</b> MH/s ( <b>0.914</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:   <b>92.76</b> MH/s ( <b>1.627</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:  <b>110.88</b> MH/s ( <b>1.945</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:  <b>106.43</b> MH/s ( <b>1.867</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

Console output for Linux/gcc15 (**Zen4-core**, **5.1 GHz**):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 5.10 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>38.25</b> MH/s ( <b>0.750</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:   <b>72.21</b> MH/s ( <b>1.416</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:   <b>81.39</b> MH/s ( <b>1.596</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:   <b>76.55</b> MH/s ( <b>1.501</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

Console output for Linux/gcc15 (**A76-core**, **2.4 GHz**):

<pre><code><b>[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 10 MH (iterations), 2.40 GHz (cpu speed), MH/s (unit), 1 (threads)
- Fast _x1:   <b>18.41</b> MH/s ( <b>0.767</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x2:   <b>33.65</b> MH/s ( <b>1.402</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x3:   <b>36.12</b> MH/s ( <b>1.505</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Fast _x4:   <b>36.92</b> MH/s ( <b>1.538</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

Results (non-pipelined vs pipelined, 1 CPU core, 1 thread):

| | Fast _x1 | Fast _x2 | Uplift |
| :--- | :--- | :--- | :--- |
| **E-core**, **4.6 GHz** | 62.18 MH/s | 100.75 MH/s | **+62.0%** |
| **P-core**, **5.7 GHz** | 52.08 MH/s | 92.76 MH/s | **+78.1%** |
| **Zen4-core**, **5.1 GHz** | 38.25 MH/s | 72.21 MH/s | **+88.7%** |
| **A76-core**, **2.4 GHz** | 18.41 MH/s | 33.65 MH/s | **+82.7%** |

Very positive results with &gt;50% uplift for all CPU core architectures above. More observations in [RESULTS.md](RESULTS.md).

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
