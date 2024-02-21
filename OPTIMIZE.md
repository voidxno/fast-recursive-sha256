# Optimization (Fast Recursive SHA256)

Walkthrough of optimizations realized in source code of [rsha256_fast_x64.cxx](rsha256_fast_x64.cxx) (Intel).

First looked at different implementations of SHA-256 (SHA256). [Pseudocode](https://en.wikipedia.org/wiki/SHA-2#Pseudocode),
Intel [SHA Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html),
[Linux ASM](https://github.com/torvalds/linux/blob/master/arch/x86/crypto/sha256_ni_asm.S), and more. Candidate for fastest recursive SHA256 quickly became an Intel/AMD CPU with SHA Extensions.

Below are steps from generic implementation to final result.

In reality there was an assembler (ASM) source code edition before C++ intrinsics. Look [background](#background) section.

Methodology is nearly identical for [rsha256_fast_arm.cxx](rsha256_fast_arm.cxx) (ARM). Except a few nuances because of differences between accelerated instructions.

## Step 1 - Generic SHA256

Write a generic SHA256 implementation from scratch, in C++ intrinsics. Verify it works, ready for use:
```c++
void sha256(uint8_t* out, const uint8_t* in, const uint64_t length){ ... }
```

Add recursive usage:
```c++
void rsha256(uint8_t* hash, const uint64_t num_iters)
{
 for(uint64_t i = 0; i < num_iters; ++i)
   sha256(hash,hash,32);
}
```
Not included in repository. Reference file in step 2 better suited to illustrate optimizations.

## Step 2 - Loop & length of 32

Two very obvious elements stand out when you look at step 1:
- Always looping
- Always calling `sha256()` with static length of 32 bytes

Move all `sha256()` source code into `rsha256()` function. Walkthrough and rewrite with static prerequisite of 32 bytes length. Several elements are eliminated, some simplified.

Resulting source code is what the [rsha256_ref_x64.cxx](rsha256_ref_x64.cxx) file represents.

A file where generic SHA256 elements still come in usual order, but simplified by 32 bytes prerequisite. Helps most compilers to optimize with good, but varying results.

## Step 3 - Extra tuning

Last step is seeing loop for what it is:
- Just source code performing some logic
- Variables in use, dependencies between them
- Exploit SHA256 padding logic, 64 bytes block, 32 bytes data
- Try/find elements that fit in __m128i data type (xmm0-xmm15)
- See how they can be organized with focus on speed
- While still maintaining consistency in logic performed

Elements adjusted:
- Realize static nature of 3rd/4th 16 bytes of 1x block (64 bytes)
- Convert/move/pre-shuffle into 2x static __m128i (HPAD0_CACHE, HPAD1_CACHE)
- Move/pre-shuffle round init values into 2x static __mm128i (ABEF_INIT, CDGH_INIT)
- Eliminate SHUF_MASK usage inside loop, only outside
- Contain hash value through loops in 2x __mm128i (HASH0_SAVE, HASH1_SAVE)
- Perform init/finish input/output hash values outside loop

Result was the [rsha256_fast_x64.cxx](rsha256_fast_x64.cxx) file.

At this point. Very clean C++ intrinsics implementation. Looks to translate by most compilers to similarly fast binary code.

## Compilers

One goal of optimization was writing common source code that produced similar speed, independent of compiler. Not having to tune source code for each.

Been a learning experience to see how compilers react wildly differently to how source code is written and organized. Look at reference results in [benchmark](BENCHMARK.md).

Now the fast version of source code is fine tuned to be optimal in itself. Helping and forcing most compilers to produce similar results.
Look at fast results in [benchmark](BENCHMARK.md).

## Result

A fast recursive SHA256 implementation, open and free.

Possible others have already done similar, or even faster. Always someone smarter out there. Tried to search, not found it (yet).

It is a very niche use-case. But important for [MMX blockchain](https://github.com/madMAx43v3r/mmx-node) to establish fastest possible recursive SHA256 speed on today's hardware. Securing the VDF (verifiable delay function) logic.

More optimization possible? Maybe, hopefully not by much. Leaving implementation as is for now. Need to focus on other areas.

Could also be other hardware contenders. Not observed anything beating a high-GHz CPU with SHA Extensions (optimized silicon circuits inside CPU). Too low speed (GHz) on FPGA, work not parallelizable. Prohibitive cost to produce a high-GHz ASIC that beats Intel/AMD optimized silicon.

For a single SHA256 calculation, SHA Extensions looks to win the recursive/serial/single-thread race.

## Background

Started by having fun running a TimeLord on [MMX blockchain](https://github.com/madMAx43v3r/mmx-node). One thing is overclocking hardware, equally fun trying to optimize speed/efficiency through source code optimization.

Have some programming background. Manage to navigate most areas, but not my daily work. Good at looking at stuff logically, identify patterns, problemsolve.

Real timeline was working step-by-step (there were many) to a final assembler (ASM) source code edition. Got to a point where the result was 0.702 MH/s/0.1GHz (Intel 13th-Gen CPU, P-core, Raptor Cove).

Shifted at some point to try contributing by optimizing public C++ source code for SHA256 creation in TimeLord. Already a good SHA256 implementation written by [Max](https://github.com/madMAx43v3r) in C++ intrinsics, using SHA Extensions. Had my private 0.702 (ASM) reference point, knowing it was technically possible.

Grew increasingly frustrated over extreme differences in TimeLord speed, depending on arrangement of source code and compiler used (VS2022, Clang15, gcc12). Wanted parity between platforms, if possible.

Tried to understand C++ intrinsics. Wrote my own generic recursive SHA256 edition. Ported all optimizations from my private 0.702 (ASM) edition. Now at 0.708 (VS2022), 0.708 (Clang15), 0.702 (gcc12), look [benchmark](BENCHMARK.md).

Ended up here, open sourcing the result.

Better for MMX to have best possible implementation. Making it easier going forward, improving surrounding aspect.

My thanks to the MMX project, making me explore optimizations, learning new stuff in the process.

<!-- eof -->
