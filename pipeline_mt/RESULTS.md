# Results (Fast Recursive SHA256) - pipelined

Results and observations from using [Benchmark (mt)](BENCHMARK.md) on **Intel 13th-gen** (Raptor Lake), **AMD 7040-series** (Phoenix) and **ARM Cortex-A76** CPUs. Finding pipelined edition that gives best throughput in most scenarios.

Benchmarks below were done locked to 1 core (P-core, E-core, Zen4-core and A76-core). Forcing all threads to run on that core. Speed of core (GHz), also locked. What speed not relevant, only recorded resulting MH/s/0.1GHz.

Goal was looking for possible performance uplift of pipelined (_x2, _x3, _x4) vs non-pipelined (_x1) edition. In this case, compiled with Linux/Clang15. Also tested with Linux/gcc. Minor variations between them. Windows/VS2022 same pattern, but varied more.

Results (1x **P-core**, Intel 13th-gen, **MH/s/0.1GHz**):

| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 0.707 | 0.953 | 0.911 | 0.896 |
| `-t 2` | 0.962 | 1.032 | 0.966 | 0.954 |
| `-t 4` | 0.962 | 1.032 | 0.966 | 0.954 |
| `-t 8` | 0.962 | 1.032 | 0.966 | 0.954 |

Results (1x **E-core**, Intel 13th-gen, **MH/s/0.1GHz**):

| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 0.977 | 1.825 | 1.766 | 1.801 |
| `-t 2` | 0.978 | 1.825 | 1.766 | 1.800 |
| `-t 4` | 0.978 | 1.825 | 1.766 | 1.799 |
| `-t 8` | 0.979 | 1.825 | 1.766 | 1.797 |

Results (1x **Zen4-core**, AMD 7040-series, **MH/s/0.1GHz**):

| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 0.753 | 1.435 | 1.582 | 1.582 |
| `-t 2` | 1.508 | 2.868 | 3.162 | 3.163 |
| `-t 4` | 1.511 | 2.869 | 3.162 | 3.164 |
| `-t 8` | 1.513 | 2.869 | 3.162 | 3.164 |

Results (1x **A76-core**, ARM Cortex-A76, **MH/s/0.1GHz**):


| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 0.767 | 1.537 | 1.703 | 1.741 |
| `-t 2` | 0.768 | 1.537 | 1.703 | 1.741 |
| `-t 4` | 0.768 | 1.537 | 1.703 | 1.741 |
| `-t 8` | 0.768 | 1.537 | 1.703 | 1.741 |

Fast _x2 looks like a good choice. Uplift, with least amount of code complexity.

| | Threads |  Fast _x1 | Fast _x2 | Uplift |
| :--- | :---| :--- | :--- | :--- |
| **P-core** | `-t 1` | 0.707 | 0.953 | **+34.8%** |
| **P-core** | `-t 8` | 0.962 | 1.032 | **+7.2%** |
| **E-core** | `-t 1` | 0.977 | 1.825 | **+86.8%** |
| **E-core** | `-t 8` | 0.979 | 1.825 | **+86.4%** |
| **Zen4-core** | `-t 1` | 0.753 | 1.435 | **+90.6%**  |
| **Zen4-core** | `-t 8` | 1.513 | 2.869 | **+89.6%** <sup>[1]</sup> |
| **A76-core** | `-t 1` | 0.767 | 1.537 | **+100.3%** |
| **A76-core** | `-t 8` | 0.768 | 1.537 | **+100.1%** |

_<sup>[1]</sup> All-core Zen4 CPU might not scale this high. Look section below._

**P-core:** Not impressive uplift in real-life. Nearly all implementations of pipelined editions will be on workloads already done in parallel (multithreaded). In those cases existing non-pipelined (_x1) already saturates P-core pipeline. Still worth it, **+7.2% uplift** with pipelined (_x2).

**E-core:** Impressive real-life uplift. In this case non-pipelined (_x1) is not able to saturate E-core pipeline, at all (multithreaded on 1 core). Using pipelined (_x2) enables E-core to utilize idle execution units inside core. Resulting in real-life **+86.4% uplift**.

**Zen4-core:** Impressive real-life uplift. Even though non-pipelined (_x1) is able to saturate Zen4-core pipeline somewhat (multithreaded). Using pipelined (_x2) enables Zen4-core to utilize even more execution units inside core. Resulting in real-life **+89.6% uplift** (1 core), with a caveat. Tested AMD 7040-series (Phoenix) halves uplift when all 8 cores are used, with >=8 threads (**~45%** vs +89.6% uplift). Not shown in tables above, but easily tested with 8 threads on all cores. Still impressive.

**A76-core:** Impressive real-life uplift. Non-pipelined (_x1) is not able to saturate A76-core pipeline, at all (multithreaded on 1 core). Using pipelined (_x2) enables A76-core to utilize idle execution units inside core. Resulting in real-life **+100.1% uplift**.

## Cycles (cpb)

Another way to look at result is reduced **CPU cycles per block/hash (64 bytes)** processed:

| | Threads | Fast _x1 | Fast _x2 | Decrease (time) |
| :--- | :--- | :--- | :--- | :--- |
| **P-core** | `-t 1` | 141.5 | 105.0 | **-25.7%** |
| **P-core** | `-t 8` | 104.0 | 96.9 | **-6.8%** |
| **E-core** | `-t 1` | 102.4 | 54.8 | **-46.4%** |
| **E-core** | `-t 8` | 102.2 | 54.8 | **-46.3%** |
| **Zen4-core** | `-t 1` | 132.8 | 69.7 | **-47.5%** |
| **Zen4-core** | `-t 8` | 66.1 | 34.9 | **-47.2%** <sup>[1]</sup> |
| **A76-core** | `-t 1` | 130.3 | 65.0 | **-50.1%** |
| **A76-core** | `-t 8` | 130.2 | 65.0 | **-50.0%** |

_<sup>[1]</sup> All-core Zen4 CPU might not scale this high. Look section above._

<!-- eof -->
