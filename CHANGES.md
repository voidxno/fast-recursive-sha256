# Revisions

**2024.02.21** - Added ARM
- Implemented [ARM Cryptography Extensions](https://developer.arm.com/architectures/instruction-sets/intrinsics/#q=sha256).
- Added separate _arm.cxx files (existing _x64.cxx).
- Renamed rec_sha256 files and functions to rsha256.
- Several cosmetic changes to code, no logic change.
- Added results for ARM Cortex-A76, A76-core (Enyo).

**2023.12.27** - Added Zen4
- Added results for AMD 7040-series, Zen4-core (Phoenix).

**2023.12.11** - Renum Benchmark
- Recoded [benchmark.cxx](benchmark.cxx) in [benchmark_mt.cxx](./pipeline_mt/benchmark_mt.cxx) style.

**2023.12.10** - Pipelined
- Added new [pipelined/multithreaded](./pipeline_mt/) section.
- New _x2, _x3, _x4 (pipelined) vs _x1 (non-pipelined).
- Added new [rec_sha256_fast_pl.cxx](./pipeline_mt/rsha256pl_fast_x64.cxx) file.
- Added new [benchmark_mt.cxx](./pipeline_mt/benchmark_mt.cxx) file.

**2023.12.03** - Measure Units
- Replaced middle rounds with macro in [rec_sha256_fast.cxx](rsha256_fast_x64.cxx) (no change of logic).
- Added [benchmark.cxx](benchmark.cxx) measure unit option `-m`, default `MH` (MH/s), valid options:
- `MH` (megahashes, 1.000.000)
- `MB` (megabyte, 1.000.000, 1.000 x 1.000)
- `MiB` (mebibyte, 1.048.576, 1.024 x 1.024)
- `cpb` (cycles per block/hash 64bytes, and per byte)
- Differentiated P/E-core for Intel 13th-gen CPU.
- Switched to `g++` vs `gcc` for Linux/gcc12 compile.
- Added tips for locking benchmark to CPU cores.

**2023.07.19** - AVX vs SSE4.2
- Changed baseline compile architecture to [Intel AVX](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions) (not AVX2) vs SSE4.2.
- Effect varies depending on CPU architecture. About +1% on Intel 13th-Gen.
- In general a positive effect. Some older CPUs might work better with SSE4.2.
- Restructured [rec_sha256_reference.cxx](rsha256_ref_x64.cxx) with inner inline function.
- Prevents major performance degradation when compiled with AVX vs SSE4.2.

**2023.06.12** - Initial version
- First upload.

<!-- eof -->
