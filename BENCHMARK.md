# Benchmark (Fast Recursive SHA256)

To benchmark, copy all (5x) .cxx files. Compile in your development environment. Run resulting benchmark binary. Compilers tested are GCC 15 (GNU Compiler Collection) and Visual Studio 2026.

Here are samples of benchmark performed on 4 types of CPU cores. **Intel 15th-gen** (Arrow Lake), locked at **4.6 GHz** (**E-core**, Skymont) and **5.7 GHz** (**P-core**, Lion Cove). **AMD 7040-series** (Phoenix), locked at **5.1 GHz** (**Zen4-core**, Phoenix). **ARM Cortex-A76** (Enyo), locked at **2.4 GHz** (**A76-core**, Enyo). Commands used for compile and run of benchmark shown below (gcc15, VS2026):

```sh
g++ benchmark.cxx rsha256_*.cxx -o benchmark -z noexecstack -mavx -msha -O2
./benchmark -i 100M -s 4.6 -m MH
./benchmark -i 100M -s 5.7 -m MH
./benchmark -i 100M -s 5.1 -m MH
```

```batchfile
cl.exe /O2 /arch:AVX benchmark.cxx rsha256_*.cxx
benchmark.exe -i 100M -s 4.6 -m MH
benchmark.exe -i 100M -s 5.7 -m MH
benchmark.exe -i 100M -s 5.1 -m MH
```

```sh
g++ benchmark.cxx rsha256_*.cxx -o benchmark -z noexecstack -march=armv8-a+crypto -mtune=native -O2
./benchmark -i 100M -s 2.4 -m MH
```

Lock CPU speed for benchmark:

To measure capabilities of a CPU core architecture, benchmark needs to run with locked CPU GHz speed. Not max, but locked. Can be possible through BIOS. If not, look for OS utilities. In Linux, maybe [`cpufreq-info`](https://manpages.ubuntu.com/manpages/lts/man1/cpufreq-info.html) (available frequency steps), [`cpufreq-set`](https://manpages.ubuntu.com/manpages/lts/man1/cpufreq-set.html) (`-u`), [`cpupower`](https://manpages.ubuntu.com/manpages/lts/man1/cpupower.html) ([`--frequency-set`](https://manpages.ubuntu.com/manpages/lts/man1/cpupower-frequency-set.html), `-u`).

Lock benchmark to specific CPU core:

If heterogeneous cores on a CPU, like Intel E- and P-cores. Need to lock run of benchmark to specific core. In Linux, look at [`taskset`](https://manpages.ubuntu.com/manpages/lts/man1/taskset.html) (`--cpu-list`). On Windows, look at `AFFINITY` parameter for `START` batch command.

Program call for benchmark:
```
benchmark -i <iters> -s <cpuspeed> -m <unit>

-i <iter>: Number of SHA256 iterations to perform (optional)
           Valid values: 10M, 50M, 100M (default), 200M, 500M

-s <ghz>: x.x GHz speed of CPU when run (optional)
          If set, calculates and shows MH/s/0.1GHz for result
          Only calculates, cannot set real CPU speed of machine

-m <unit>: Measure unit to calculate (optional)
           Valid values: MH (default), MB, MiB, cpb
```
Console output for Linux/gcc15 (**E-core**, **4.6 GHz**):

<pre><code><b>[Benchmark - Fast Recursive SHA256 (w/Intel SHA Extensions)]</b>
- Parameters: 100 MH (iterations), 4.60 GHz (cpu speed), MH/s (unit)
- Fast:       <b>62.19</b> MH/s (<b>1.352</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
- Reference:  <b>43.17</b> MH/s (<b>0.939</b> MH/s/0.1GHz) [verify hash: <b>ok</b>]
</code></pre>

Results (**E-core**, **4.6 GHz**):

| Environment | Fast | P/U <sup>[1]</sup> | Reference <sup>[2]</sup> | P/U <sup>[1]</sup> |
| :--- | :--- | :--- | :--- | :--- |
| Linux/gcc15 | 62.19 MH/s | **1.352** | 43.17 MH/s | **0.939** |
| Windows/VS2026 | 57.64 MH/s | **1.253** | 25.37 MH/s | **0.551** |

Results (**P-core**, **5.7 GHz**):

| Environment | Fast | P/U <sup>[1]</sup> | Reference <sup>[2]</sup> | P/U <sup>[1]</sup> |
| :--- | :--- | :--- | :--- | :--- |
| Linux/gcc15 | 52.08 MH/s | **0.914** | 34.16 MH/s | **0.599** |
| Windows/VS2026 | 51.75 MH/s | **0.908** | 24.05 MH/s | **0.422** |

Results (**Zen4-core**, **5.1 GHz**):

| Environment | Fast | P/U <sup>[1]</sup> | Reference <sup>[2]</sup> | P/U <sup>[1]</sup> |
| :--- | :--- | :--- | :--- | :--- |
| Linux/gcc15 | 38.25 MH/s | **0.750** | 28.05 MH/s | **0.550** |
| Windows/VS2026 | 38.19 MH/s | **0.749** | 19.73 MH/s | **0.387** |

Results (**A76-core**, **2.4 GHz**):

| Environment | Fast | P/U <sup>[1]</sup> | Reference <sup>[2]</sup> | P/U <sup>[1]</sup> |
| :--- | :--- | :--- | :--- | :--- |
| Linux/gcc15 | 18.42 MH/s | **0.767** | 15.59 MH/s | **0.650** |
| Windows/VS2026 | --- | --- | --- | --- |

_<sup>[1]</sup> P/U, per unit, MH/s/0.1GHz speed from measured MH/s and CPU speed._\
_<sup>[2]</sup> Reference numbers are only to illustrate source code optimization effect._

All testing indicates a linear MH/s increase, given CPU GHz speed. Locking CPU speed, using MH/s/0.1GHz unit, is an easy way to measure optimization effect. Or compare IPC (instructions per clock) for SHA Extensions between CPU generations (for this specific use-case).

Elements surrounding raw GHz of CPU do not look to affect results (RAM, HyperThreading, CPU cache, more). Seems logical, since the recursive SHA256 implementation is not much more than a few instructions repeated in a CPU core.

Intel's E-core is much more efficient per 0.1 GHz than P-core. Cannot run with as high clock. Still manages to get work done. AMD's Zen4-core and ARM's A76-core are somewhat below. In the end, a race of who can clock highest (GHz).

<!-- eof -->
