# Optimization (Fast Recursive SHA256) - pipelined

Pipelined (_x2, _x3, _x4) editions are just non-pipelined (_x1, _fast) instructions repeated in same order, with separate variables. Both Linux/Clang15 and Linux/gcc12 looks to produce good results. Keeping CPU core pipeline fed. Windows/VS2022 vary more, still ok.

Looking at compilers assembler (ASM) output of pipelined (_x2, _x3, _x4) C++ source code. There may be a more optimal way to arrange code. Helping all compilers to produce similar results.

For now, good enough. Pipelined was explored to get free performance left on the table for VDF verification ([MMX blockchain](https://github.com/madMAx43v3r/mmx-node)). Nice to have, but not as important as [non-pipelined optimization](../OPTIMIZE.md) (_x1, _fast) for VDF creation by TimeLord.

<!-- eof -->
