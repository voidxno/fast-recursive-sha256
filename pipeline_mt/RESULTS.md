# Results (Fast Recursive SHA256) - pipelined

Results and observations from using [Benchmark (mt)](BENCHMARK.md) on an **Intel 13th-gen** CPU. Finding pipelined edition that gives best throughput in most scenarios.

Benchmarks below were done locked to 1 core (P-core or E-core). Forcing all threads to run on that core. Speed of core (GHz), also locked. What speed not relevant, only recorded resulting MH/s/0.1GHz.

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

Fast _x2 looks like a good choice. Get uplift, with least amount of code complexity.

| | Fast _x1 | Fast _x2 | Uplift |
| :--- | :--- | :--- | :--- |
| **P-core** (`-t 1`) | 0.707 | 0.953 | **+34.8%** |
| **P-core** (`-t 8`) | 0.962 | 1.032 | **+7.2%** |
| **E-core** (`-t 1`) | 0.977 | 1.825 | **+86.8%** |
| **E-core** (`-t 8`) | 0.979 | 1.825 | **+86.4%** |

**P-core:** Not impressive uplift in real-life. Nearly all implementations of pipelined editions will be on workloads already done in parallel (multithreaded). In those cases existing non-pipelined (_x1) already saturates P-core pipeline. Still worth it, **+7.2% uplift** with pipelined (_x2).

**E-core:** Impressive real-life uplift. In this case non-pipelined (_x1) is not able to saturate E-core pipeline, at all (multithreaded on 1 core). Using pipelined (_x2) enables E-core to utilize idle execution units inside core. Resulting in real-life **+86.4% uplift**.

## Cycles (cpb)

Another way to look at result is reduced **CPU cycles per block/hash (64 bytes)** processed:

| | Fast _x1 | Fast _x2 | Decrease (time) |
| :--- | :--- | :--- | :--- |
| **P-core** (`-t 1`) | 141.5 | 105.0 | **-25.7%** |
| **P-core** (`-t 8`) | 104.0 | 96.9 | **-6.8%** |
| **E-core** (`-t 1`) | 102.4 | 54.8 | **-46.4%** |
| **E-core** (`-t 8`) | 102.2 | 54.8 | **-46.3%** |

<!-- eof -->
