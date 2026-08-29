# Results (Fast Recursive SHA256) - pipelined

Results and observations from using [Benchmark (mt)](BENCHMARK.md) on **Intel 15th-gen** (Arrow Lake), **AMD 7040-series** (Phoenix) and **ARM Cortex-A76** CPUs. Finding pipelined edition that gives best throughput in most scenarios.

Benchmarks below were done locked to 1 core (E-core, P-core, Zen4-core and A76-core). Forcing all threads to run on that core. Speed of core (GHz), also locked. What speed not relevant, only recorded resulting MH/s/0.1GHz.

Goal was looking for possible performance uplift of pipelined (_x2, _x3, _x4) vs non-pipelined (_x1) edition. In this case, compiled with Linux/gcc15.

Results (1x **E-core**, Intel 15th-gen, **MH/s/0.1GHz**):

| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 1.352 | 2.191 | 2.184 | 2.023 |
| `-t 2` | 1.352 | 2.191 | 2.184 | 2.023 |
| `-t 4` | 1.352 | 2.191 | 2.184 | 2.023 |
| `-t 8` | 1.352 | 2.191 | 2.184 | 2.023 |

Results (1x **P-core**, Intel 15th-gen, **MH/s/0.1GHz**):

| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 0.914 | 1.627 | 1.945 | 1.867 |
| `-t 2` | 0.914 | 1.627 | 1.945 | 1.867 |
| `-t 4` | 0.914 | 1.627 | 1.945 | 1.867 |
| `-t 8` | 0.914 | 1.627 | 1.945 | 1.867 |

Results (1x **Zen4-core**, AMD 7040-series, **MH/s/0.1GHz**):

| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 0.750 | 1.416 | 1.596 | 1.501 |
| `-t 2` | 1.396 | 1.999 | 1.956 | 1.647 |
| `-t 4` | 1.396 | 1.999 | 1.956 | 1.647 |
| `-t 8` | 1.396 | 1.999 | 1.956 | 1.647 |

Results (1x **A76-core**, ARM Cortex-A76, **MH/s/0.1GHz**):

| Threads | Fast _x1 | Fast _x2 | Fast _x3 | Fast _x4 |
| :--- | :--- | :--- | :--- | :--- |
| `-t 1` | 0.767 | 1.402 | 1.505 | 1.538 |
| `-t 2` | 0.767 | 1.402 | 1.505 | 1.538 |
| `-t 4` | 0.767 | 1.402 | 1.505 | 1.538 |
| `-t 8` | 0.767 | 1.402 | 1.505 | 1.538 |

Fast _x2 looks like a good choice. Uplift, with least amount of code complexity.

| | Threads | Fast _x1 | Fast _x2 | Uplift |
| :--- | :---| :--- | :--- | :--- |
| **E-core** | `-t 1` | 1.352 | 2.191 | **+62.0%** |
| **E-core** | `-t 8` | 1.352 | 2.191 | **+62.0%** |
| **P-core** | `-t 1` | 0.914 | 1.627 | **+78.0%** |
| **P-core** | `-t 8` | 0.914 | 1.627 | **+78.0%** |
| **Zen4-core** | `-t 1` | 0.750 | 1.416 | **+88.8%** |
| **Zen4-core** | `-t 8` | 1.396 | 1.999 | **+43.1%**|
| **A76-core** | `-t 1` | 0.767 | 1.402 | **+82.7%** |
| **A76-core** | `-t 8` | 0.767 | 1.402 | **+82.7%** |

**E-core:** Nice uplift. Non-pipelined (_x1) is not able to saturate E-core pipeline, at all (multithreaded on 1 core). Using pipelined (_x2) enables E-core to utilize idle execution units inside core. Resulting in **+62.0% uplift**.

**P-core:** Very nice uplift. Non-pipelined (_x1) is not able to saturate P-core pipeline, at all (multithreaded on 1 core). Using pipelined (_x2) enables P-core to utilize idle execution units inside core. Resulting in **+78.0% uplift**.

**Zen4-core:** Very nice uplift. More nuanced though. Because of HyperThreading, non-pipelined (_x1) is able to saturate Zen4-core pipeline pretty good (multithreaded on 1 core). Using pipelined (_x2) in addition, taps a few more idle execution units inside core. Basically multithreaded non-pipelined (_x1) alone gives **+86.1% uplift** (0.750 to 1.396). Then pipelined (_x2) adds **+43.1%** (0.1396 to 0.1999), on top of that. Not quite correct, but could say result was **+166.5% uplift** (0.750 to 1.999).

**A76-core:** Very nice uplift. Non-pipelined (_x1) is not able to saturate A76-core pipeline, at all (multithreaded on 1 core). Using pipelined (_x2) enables A76-core to utilize idle execution units inside core. Resulting in **+82.7% uplift**.

## Cycles (cpb)

Another way to look at result is reduced **CPU cycles per block/hash (64 bytes)** processed:

| | Threads | Fast _x1 | Fast _x2 | Decrease (time) |
| :--- | :--- | :--- | :--- | :--- |
| **E-core** | `-t 1` | 74.0 | 45.7 | **-38.2%** |
| **E-core** | `-t 8` | 74.0 | 45.7 | **-38.2%** |
| **P-core** | `-t 1` | 109.4 | 61.4 | **-43.8%** |
| **P-core** | `-t 8` | 109.4 | 61.4 | **-43.8%** |
| **Zen4-core** | `-t 1` | 133.4 | 70.6 | **-47.0%** |
| **Zen4-core** | `-t 8` | 71.7 | 50.0 | **-30.2%** |
| **A76-core** | `-t 1` | 130.4 | 71.3 | **-45.3%** |
| **A76-core** | `-t 8` | 130.4 | 71.3 | **-45.3%** |

<!-- eof -->
