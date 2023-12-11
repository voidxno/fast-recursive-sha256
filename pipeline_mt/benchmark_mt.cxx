/*
 * File: benchmark_mt.cxx
 *
 * Author: voidxno
 * Created: 10 Dec 2023
 *
 * Benchmark of fast recursive SHA256, with intrinsics and Intel SHA Extensions
 * Multithread benchmark, using pipelined editions, from x1 to x4
 *
 * Program call: benchmark_mt -i <iters> -s <cpuspeed> -m <unit> -t <threads>
 *
 * -i <iter>: Number of SHA256 iterations to perform (optional)
 *            Valid values: 10M (default), 50M, 100M, 200M, 500M
 *
 * -s <ghz>: x.x GHz speed of CPU when run (optional)
 *           If set, calculates and shows MH/s/0.1GHz for result
 *           Only calculates, cannot set real CPU speed of machine
 *
 * -m <unit>: Measure unit to calculate (optional)
 *            Valid values: MH (default), MB, MiB, cpb
 *
 * -t <threads>: Number of threads to run (optional)
 *               Valid values: 1 (default), 256 (max)
 *
 * Requirement: Intel/AMD x64 CPU, with SHA extensions
 *
 * LICENSE: Unlicense
 * For more information, please refer to <https://unlicense.org>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include <omp.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

//-- external functions, pipelined recursive SHA256 (rec_sha256_fast_pl.cxx)
void rec_sha256_fast_x1(uint8_t* hash, const uint64_t num_iters);
void rec_sha256_fast_x2(uint8_t* hash, const uint64_t num_iters);
void rec_sha256_fast_x3(uint8_t* hash, const uint64_t num_iters);
void rec_sha256_fast_x4(uint8_t* hash, const uint64_t num_iters);

//-- local functions
void local_ANSISetup(void);
void local_ANSIRestore(void);
void local_InitHashVerify();
void local_ParseParameters(int argc,char* argv[]);
int local_Benchmark(void (*bfunc)(uint8_t*,const uint64_t),const char* bname,uint32_t bpipes);

//-- array (4x), with hash verify values (7x), iterations (0, 1, 10M, 50M, 100M, 200M, 500M)
const uint8_t* local_hashverify[4][7];

//-- local parameter values
uint64_t local_iters;
uint32_t local_itersidx;
bool     local_ghz;
double   local_ghzval;
uint32_t local_unit;
char     local_unitstr[16];
uint32_t local_threads;

//-- main() - entrypoint
int main(int argc, char* argv[])
{

 //-- setup/init ANSI capability
 local_ANSISetup();

 //-- init values for verify hash arrays
 local_InitHashVerify();

 //-- default parameter values, -i 10M, -s <not set>, -m MH, -t 1
 local_iters = 10000000;
 local_itersidx = 2;
 local_ghz = false;
 local_ghzval = 0.0;
 local_unit = 0;
 strcpy(local_unitstr,"MH/s");
 local_threads = 1;

 //-- display header
 setvbuf(stdout,NULL,_IONBF,0);
 printf("\33[1;97m[Benchmark (mt) - Fast Recursive SHA256 (w/Intel SHA Extensions)]\33[0m\n");

 //-- parse parameters
 local_ParseParameters(argc,argv);

 //-- display benchmark parameters
 if(!local_ghz){ printf("- Parameters: %" PRIu64 " MH (iterations), n/a GHz (cpu speed), %s (unit), %d (threads)\n",local_iters / 1000000,local_unitstr,local_threads); }
 else          { printf("- Parameters: %" PRIu64 " MH (iterations), %.2f GHz (cpu speed), %s (unit), %d (threads)\n",local_iters / 1000000,local_ghzval,local_unitstr,local_threads); }

 //-- benchmark - pipeline x1, x2, x3, x4 (rec_sha256_fast_pl.cxx)
 if(local_Benchmark(&rec_sha256_fast_x1,"Fast _x1:",1)){ return 1; };
 if(local_Benchmark(&rec_sha256_fast_x2,"Fast _x2:",2)){ return 1; };
 if(local_Benchmark(&rec_sha256_fast_x3,"Fast _x3:",3)){ return 1; };
 if(local_Benchmark(&rec_sha256_fast_x4,"Fast _x4:",4)){ return 1; };

 //-- restore ANSI capability
 local_ANSIRestore();

 return 0;
}

//-- local_ParseParameters() - parse parameters
void local_ParseParameters(int argc,char* argv[])
{
 for(int i = 1, jP = 0; i < argc; ++i){
   if((char)jP == 'i'){
     if     (!strcasecmp(argv[i],"10M"))  { local_iters = 10000000;  local_itersidx = 2; }
     else if(!strcasecmp(argv[i],"50M"))  { local_iters = 50000000;  local_itersidx = 3; }
     else if(!strcasecmp(argv[i],"100M")) { local_iters = 100000000; local_itersidx = 4; }
     else if(!strcasecmp(argv[i],"200M")) { local_iters = 200000000; local_itersidx = 5; }
     else if(!strcasecmp(argv[i],"500M")) { local_iters = 500000000; local_itersidx = 6; }
     jP = 0; continue;
     }

   else if((char)jP == 's'){
     local_ghz = true;
     local_ghzval = strtod(argv[i],NULL);
     if(local_ghzval < 0.1 || local_ghzval > 999.9){ local_ghz = false; local_ghzval = 0.0; }
     local_ghzval = (double)((int)(local_ghzval * 100.0)) / 100.0;
     jP = 0; continue;
     }

   else if((char)jP == 'm'){
     if     (!strcasecmp(argv[i],"MH"))  { local_unit = 0; strcpy(local_unitstr,"MH/s"); }
     else if(!strcasecmp(argv[i],"MB"))  { local_unit = 1; strcpy(local_unitstr,"MB/s"); }
     else if(!strcasecmp(argv[i],"MiB")) { local_unit = 2; strcpy(local_unitstr,"MiB/s"); }
     else if(!strcasecmp(argv[i],"cpb")) { local_unit = 3; strcpy(local_unitstr,"cpb"); }
     jP = 0; continue;
     }

   else if((char)jP == 't'){
     local_threads = atoi(argv[i]);
     if(local_threads < 1 || local_threads > 256){ local_threads = 1; }
     }

   jP = 0;
   if(!strcmp(argv[i],"-i")){ jP = 'i'; continue; }
   if(!strcmp(argv[i],"-s")){ jP = 's'; continue; }
   if(!strcmp(argv[i],"-m")){ jP = 'm'; continue; }
   if(!strcmp(argv[i],"-t")){ jP = 't'; continue; }
   }

 if(local_unit == 3 && local_threads > 1){
   printf("- \33[1;33mINFO: Detected -m cpb and -t <threads> larger than 1. Make sure benchmark locked to 1 CPU core.\33[0m\n");
   printf("- \33[1;33mINFO: Throughput cpb values only valid if 1 thread and/or benchmark locked to 1 CPU core.\33[0m\n");
   }
}

//-- local_Benchmark() - perform benchmark with function pointer given
int local_Benchmark(
void        (*bfunc)(uint8_t*,const uint64_t),
const char* bname,
uint32_t    bpipes)
{
 uint8_t  hashx4[32 * 4];
 double   timestart;
 double   timestop;
 double   timediff;
 uint64_t alliters;
 double   speedMHs;
 double   speedMBs;
 double   speedMiBs;
 double   speedCPBhash;
 double   speedCPBbyte;
 bool     hashok;

 if(bpipes < 1 || bpipes > 4) bpipes = 1;

 printf("- %-10s  Consistency check of 0x and 1x iterations ...",bname);
 for(uint32_t i = 0; i < bpipes; ++i){ memcpy(hashx4 + (32 * i),local_hashverify[i][0],32); }
 bfunc(hashx4,0);
 hashok = true;
 for(uint32_t i = 0; i < bpipes; ++i){ if(memcmp(hashx4 + (32 * i),local_hashverify[i][0],32)) hashok = false; }
 if(!hashok){ fprintf(stderr,"\n\33[1;31mERROR: Resulting hash after 0 iterations do not match reference value !\33[0m\n"); return 1; }
 for(uint32_t i = 0; i < bpipes; ++i){ memcpy(hashx4 + (32 * i),local_hashverify[i][0],32); }
 bfunc(hashx4,1);
 hashok = true;
 for(uint32_t i = 0; i < bpipes; ++i){ if(memcmp(hashx4 + (32 * i),local_hashverify[i][1],32)) hashok = false; }
 if(!hashok){ fprintf(stderr,"\n\33[1;31mERROR: Resulting hash after 1 iterations do not match reference value !\33[0m\n"); return 1; }

 printf("\33[2K\r- %-10s  Spin run of %" PRIu64 "MH iterations ...",bname,local_iters / 1000000);
 for(uint32_t i = 0; i < bpipes; ++i){ memcpy(hashx4 + (32 * i),local_hashverify[i][0],32); }
 bfunc(hashx4,local_iters);

 printf("\33[2K\r- %-10s  Benchmark of %" PRIu64 "MH iterations (pipes x threads: %d times) ...",bname,local_iters / 1000000,bpipes * local_threads);
 hashok = true;
 timestart = omp_get_wtime();

#pragma omp parallel for
 for(int thread = 0; thread < local_threads; ++thread){
   uint8_t loop_hashx4[32 * 4];
   for(uint32_t i = 0; i < bpipes; ++i){ memcpy(loop_hashx4 + (32 * i),local_hashverify[i][0],32); }
   bfunc(loop_hashx4,local_iters);
   for(uint32_t i = 0; i < bpipes; ++i){ if(memcmp(loop_hashx4 + (32 * i),local_hashverify[i][local_itersidx],32)) hashok = false; }
   }

 timestop = omp_get_wtime();
 timediff = timestop - timestart;
 if(timediff <= 0.0){ fprintf(stderr,"\n\33[1;31mERROR: Elapsed time after %" PRIu64 "MH iterations is 0.0 !\33[0m\n",local_iters / 1000000); return 1; }
 alliters = local_iters * (bpipes * local_threads);
 speedMHs = ((double)(alliters) / (double)timediff) / 1000000.0;
 speedMBs = (((double)alliters * 64) / 1000000.0) / (double)timediff;
 speedMiBs = (((double)alliters * 64) / 1048576.0) / (double)timediff;
 speedCPBhash = ((double)local_ghzval * 1000000000.0) / (((double)alliters) / (double)timediff);
 speedCPBbyte = ((double)local_ghzval * 1000000000.0) / (((double)alliters * 64) / (double)timediff);

 //-- unit: MH/s
 if(local_unit == 0){
   if(!local_ghz){ printf("\33[2K\r- %-9s \33[1;32m%7.2f\33[0m MH/s (\33[1;32mn/a\33[0m MH/s/0.1GHz) [verify hash: %s]\n",bname,speedMHs,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-9s \33[1;32m%7.2f\33[0m MH/s (\33[1;32m%6.3f\33[0m MH/s/0.1GHz) [verify hash: %s]\n",bname,speedMHs,speedMHs / (local_ghzval * 10.0),(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: MB/s (MB = megabyte = 1000 x 1000 bytes (8bit) = 1.000.000)
 else if(local_unit == 1){
   if(!local_ghz){ printf("\33[2K\r- %-9s \33[1;32m%9.2f\33[0m MB/s (\33[1;32mn/a\33[0m MB/s/0.1GHz) [verify hash: %s]\n",bname,speedMBs,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-9s \33[1;32m%9.2f\33[0m MB/s (\33[1;32m%7.2f\33[0m MB/s/0.1GHz) [verify hash: %s]\n",bname,speedMBs,speedMBs / (local_ghzval * 10.0),(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: MiB/s (MiB = mebibyte = 1024 x 1024 bytes (8bit) = 1.048.576)
 else if(local_unit == 2){
   if(!local_ghz){ printf("\33[2K\r- %-9s \33[1;32m%9.2f\33[0m MiB/s (\33[1;32mn/a\33[0m MiB/s/0.1GHz) [verify hash: %s]\n",bname,speedMiBs,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-9s \33[1;32m%9.2f\33[0m MiB/s (\33[1;32m%7.2f\33[0m MiB/s/0.1GHz) [verify hash: %s]\n",bname,speedMiBs,speedMiBs / (local_ghzval * 10.0),(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: cpb (cpb = cycles per block, and per byte)
 else if(local_unit == 3){
   if(!local_ghz){ printf("\33[2K\r- %-9s \33[1;32mn/a\33[0m cycles per block (\33[1;32mn/a\33[0m per byte) [verify hash: %s]\n",bname,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-9s \33[1;32m%6.1f\33[0m cycles per block (\33[1;32m%4.2f\33[0m per byte) [verify hash: %s]\n",bname,speedCPBhash,speedCPBbyte,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }

 if(local_unit == 3 && !local_ghz){ printf("- \33[1;33mINFO: Need -s <cpuspeed> parameter to calculate CPU cycles results.\33[0m\n"); }
 if(!hashok){ fprintf(stderr,"\33[1;31mERROR: Resulting hash after %" PRIu64 "MH iterations do not match reference value !\33[0m\n",local_iters / 1000000); return 1; }

 return 0;
}

//-- local_ANSISetup() - setup/init ANSI capability (needed for Windows)
//-- local_ANSIRestore() - restore ANSI capability (needed for Windows)
#ifdef _WIN32
#include <windows.h>
static HANDLE local_win_stdout;
static DWORD  local_win_savemode = 0;
void local_ANSISetup(void)
{
 local_win_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
 if(local_win_stdout == INVALID_HANDLE_VALUE){ return; }
 if(!GetConsoleMode(local_win_stdout,&local_win_savemode)){ local_win_savemode = 0; return; }
 if(!SetConsoleMode(local_win_stdout,(local_win_savemode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))){ local_win_savemode = 0; return; }
}
void local_ANSIRestore(void)
{
 if(!SetConsoleMode(local_win_stdout,local_win_savemode)){ return; }
}
#else
void local_ANSISetup(void) {}
void local_ANSIRestore(void) {}
#endif

//-- local_InitHashVerify() - init values in verify hash arrays
void local_InitHashVerify()
{
 static const uint8_t hashP1_0[32]    = { 0x2E,0xFD,0x64,0xA5,0x54,0x63,0xB5,0xB5,0x54,0xC4,0xA2,0xE2,0x2A,0x47,0x2D,0xA2,0x3B,0xB7,0x6E,0x63,0x75,0x8C,0xE3,0xC8,0x92,0x76,0xAB,0xF0,0xE9,0xAD,0x8B,0x15 };
 static const uint8_t hashP1_1[32]    = { 0x77,0x46,0x1D,0x8E,0xD8,0xA2,0x20,0x6F,0x82,0x36,0x66,0x18,0xD3,0x63,0xBA,0xA2,0xFF,0xDD,0x99,0x1B,0x5D,0x2D,0x80,0x98,0x6D,0xBC,0xF8,0x2F,0x58,0xA4,0xF3,0xF3 };
 static const uint8_t hashP1_10M[32]  = { 0x85,0xDE,0x67,0x64,0x93,0xDB,0x94,0x1B,0xAC,0x9F,0x89,0xB3,0x29,0x32,0x7A,0xF2,0x43,0x36,0x21,0x80,0x07,0x18,0xEB,0xB5,0xD7,0x92,0x6B,0xD4,0xF5,0xFF,0xED,0x97 };
 static const uint8_t hashP1_50M[32]  = { 0x06,0x7D,0x78,0xD9,0x50,0x04,0x4F,0x00,0x2B,0x4C,0xC9,0x89,0x6E,0xDE,0x9C,0xE0,0x5A,0x5C,0xA9,0xFA,0x4A,0x0F,0x6E,0x69,0xBE,0x18,0x8E,0x6C,0x95,0x61,0x6C,0xED };
 static const uint8_t hashP1_100M[32] = { 0x6D,0x9B,0x4C,0x49,0x90,0x28,0x2B,0xF0,0x46,0xC9,0x65,0x7B,0x32,0xCD,0x99,0xEC,0x14,0x35,0x16,0x6A,0xEE,0x6B,0x4C,0x23,0x3C,0xBE,0xAC,0x1F,0x28,0x5A,0x65,0xAA };
 static const uint8_t hashP1_200M[32] = { 0x05,0x90,0x5D,0xA9,0x58,0xD9,0xFC,0x78,0x52,0xAE,0x95,0x4A,0xF9,0xF1,0x31,0xB9,0x5A,0x1F,0xA4,0x07,0x18,0x6E,0x9B,0x68,0x7D,0xE5,0x7D,0x49,0xD4,0x05,0x5B,0xF1 };
 static const uint8_t hashP1_500M[32] = { 0x49,0xC0,0x53,0xE8,0xC3,0x82,0x64,0x77,0xFA,0x52,0xB7,0x7D,0xE2,0x03,0xED,0x9D,0xE0,0xD1,0xCE,0x04,0x5D,0xA0,0x1A,0x45,0xC0,0x56,0xE3,0x65,0x3F,0x9F,0x72,0x9E };

 static const uint8_t hashP2_0[32]    = { 0x73,0xE5,0xC1,0xF5,0x36,0x7E,0x1F,0xAD,0x7D,0x42,0xAA,0xAC,0xAA,0x29,0x5F,0x10,0x7F,0xB9,0xE2,0xC6,0x34,0x17,0x01,0x12,0x6B,0x1D,0x64,0xBB,0xCB,0x17,0x8D,0xA3 };
 static const uint8_t hashP2_1[32]    = { 0x90,0x7C,0x06,0xBE,0x9B,0x50,0x77,0x75,0x27,0xCA,0xCF,0x85,0x79,0xC6,0x0F,0x5D,0xEB,0x31,0xC9,0x7A,0x01,0xE7,0x56,0xD7,0xE9,0x90,0x3E,0x8E,0x07,0xB1,0xE6,0x55 };
 static const uint8_t hashP2_10M[32]  = { 0x91,0x78,0xDD,0x15,0x24,0xB7,0x78,0xB6,0x1F,0xA5,0x98,0x66,0x7E,0x11,0xAD,0x23,0xC8,0xBD,0x1C,0x03,0x61,0x00,0x36,0xE0,0x1E,0xE1,0x67,0xA9,0x4B,0xC7,0xDF,0xFF };
 static const uint8_t hashP2_50M[32]  = { 0x16,0x51,0x10,0x60,0x6C,0x92,0x5C,0x79,0x9E,0xE0,0x1A,0xB8,0xAC,0xF0,0x6C,0x3F,0x06,0x83,0x99,0x44,0xD4,0xF4,0x32,0xA6,0x20,0x8D,0x75,0x39,0x3F,0x0B,0xFB,0x7B };
 static const uint8_t hashP2_100M[32] = { 0x57,0xC5,0x5A,0x3F,0xA0,0x27,0xC3,0x0B,0x0E,0xC9,0x76,0x82,0x28,0x14,0x3B,0x8A,0x62,0xF5,0x34,0x0B,0x7A,0xB6,0xE6,0x1C,0xCF,0x5E,0xFE,0x87,0xA6,0xA9,0x27,0x5D };
 static const uint8_t hashP2_200M[32] = { 0x5C,0x46,0x15,0x2C,0xCA,0x2C,0x71,0x3A,0x46,0x6B,0x05,0xB4,0x57,0x34,0xEE,0x69,0xC5,0x24,0xDF,0x45,0xFD,0x02,0xCA,0x75,0xEC,0x79,0xEF,0xD4,0xD8,0x38,0x2E,0x03 };
 static const uint8_t hashP2_500M[32] = { 0x74,0xC9,0x40,0x27,0x18,0x0D,0x06,0x77,0xA2,0xA7,0x15,0x5E,0x33,0xED,0x3F,0x3B,0x73,0x41,0x5B,0x92,0xFF,0xBB,0x33,0x79,0x7F,0x75,0xC1,0x84,0x47,0x65,0x1F,0x86 };

 static const uint8_t hashP3_0[32]    = { 0x05,0x27,0x51,0x68,0x62,0x10,0xA1,0xDA,0xCE,0x86,0x2D,0x47,0x41,0x46,0xA0,0x03,0x69,0x6E,0x97,0x21,0xDA,0xA8,0x37,0xD9,0x2B,0x20,0x0B,0xC1,0xDB,0x9F,0x14,0xEF };
 static const uint8_t hashP3_1[32]    = { 0x28,0x5A,0xF9,0x6F,0xD4,0x51,0xB5,0x45,0x92,0xB1,0xB0,0xF7,0xAF,0xD9,0xF4,0x8B,0x09,0x93,0xF4,0x30,0xDC,0xD8,0xB4,0xE6,0xDD,0x76,0xAD,0x1C,0x47,0x2D,0x3D,0xB9 };
 static const uint8_t hashP3_10M[32]  = { 0xB3,0x4D,0xAA,0xCC,0xC6,0xA1,0x8C,0x23,0x0A,0xB5,0xAA,0x74,0xB5,0xD8,0x1D,0xF3,0xAD,0x23,0xD4,0x87,0x23,0xB3,0x1C,0x14,0xD1,0xCC,0xB7,0xB1,0xD1,0xE7,0x31,0xA4 };
 static const uint8_t hashP3_50M[32]  = { 0x61,0x0E,0x1E,0xB2,0xBF,0x76,0x91,0xCC,0x83,0xC8,0x8E,0x05,0x5F,0x2C,0x44,0x9D,0xB5,0x9A,0x12,0xFB,0x03,0x00,0xDB,0xE5,0xC9,0x19,0x34,0xC3,0xF3,0x7A,0x4E,0xD6 };
 static const uint8_t hashP3_100M[32] = { 0xB8,0x3A,0x64,0xD1,0xFA,0x96,0x70,0xF5,0xF3,0x3A,0x20,0x05,0xA3,0x44,0x52,0x7B,0x4B,0x65,0x3A,0xB8,0x05,0x2D,0x4E,0xEF,0x35,0x06,0xC6,0xD6,0x14,0xC8,0xDF,0x44 };
 static const uint8_t hashP3_200M[32] = { 0x32,0xDE,0x0D,0x85,0x02,0xD9,0x87,0x52,0x7D,0x00,0xE6,0x5C,0x70,0x35,0xDE,0x38,0xF2,0x71,0xBC,0x85,0xF8,0x43,0x69,0xA0,0x18,0x25,0x5B,0x4B,0x2E,0x1F,0xD9,0xDB };
 static const uint8_t hashP3_500M[32] = { 0x56,0xB2,0x41,0x7E,0x4D,0xD4,0xBB,0x2D,0x83,0x1D,0xB5,0x1D,0x30,0xB5,0x83,0xA3,0x7F,0x1F,0x8C,0xA6,0x07,0xEF,0xFF,0x5B,0x04,0x61,0xEC,0x98,0x76,0x44,0x0D,0xEE };

 static const uint8_t hashP4_0[32]    = { 0xCA,0x6A,0x07,0x79,0xCD,0xA9,0xE1,0x0E,0x39,0x90,0x5A,0x78,0x5D,0x42,0x8D,0x6E,0x3E,0xCE,0x26,0x27,0x53,0xA6,0x40,0x2A,0xB9,0x36,0x3B,0x84,0xCF,0x73,0x6F,0x60 };
 static const uint8_t hashP4_1[32]    = { 0xE5,0x1A,0xDA,0xDA,0xC9,0xC6,0xD9,0x34,0xD0,0x5B,0x0E,0xD0,0x04,0xB4,0x10,0x7F,0xC2,0x96,0x1C,0x99,0x7F,0x62,0x2A,0x15,0xCA,0x8B,0x55,0xB0,0x5F,0xA5,0x8B,0x60 };
 static const uint8_t hashP4_10M[32]  = { 0xB3,0x3F,0xA1,0x71,0xB2,0x8B,0xE6,0x9F,0x3C,0xBD,0xC1,0x7C,0xD7,0xF1,0x72,0x3E,0x20,0x3B,0x85,0xCD,0xEC,0xB2,0xA6,0x90,0xE4,0x61,0x10,0x7D,0xF5,0xEE,0x3E,0x04 };
 static const uint8_t hashP4_50M[32]  = { 0x17,0xB6,0x93,0x8D,0x55,0x6E,0xCF,0x28,0xBE,0x1A,0x67,0x89,0xBE,0x96,0x4D,0x72,0xBF,0xE7,0xFB,0xCC,0xA9,0x57,0x8A,0x42,0x22,0xCD,0x0A,0x61,0xB6,0x34,0x8A,0x4A };
 static const uint8_t hashP4_100M[32] = { 0x62,0xD3,0xE9,0xAF,0x03,0xCC,0x7C,0x26,0x8E,0x26,0xF3,0xC3,0x39,0x63,0x0E,0xF5,0x3A,0x71,0x72,0x68,0x7B,0xD1,0x76,0x6B,0xE1,0x19,0xEA,0x53,0xE2,0x3B,0xAB,0x99 };
 static const uint8_t hashP4_200M[32] = { 0x28,0xC2,0x56,0xA4,0x42,0x89,0xBF,0x7D,0xB0,0x64,0x4B,0x90,0x26,0x6E,0x99,0x31,0x34,0x47,0x90,0x28,0x68,0xB5,0x10,0x99,0xC4,0x0F,0x4C,0x31,0xC1,0x28,0x91,0xA4 };
 static const uint8_t hashP4_500M[32] = { 0x54,0xBC,0x9F,0x8B,0xE4,0x50,0x21,0x71,0x18,0x7C,0x2F,0x06,0x83,0x4E,0xCD,0xB8,0xA6,0xFA,0xBD,0x11,0x43,0xB6,0xF2,0x4B,0x7A,0xEB,0xD7,0x08,0x90,0x85,0x5A,0xDD };

 local_hashverify[0][0] = hashP1_0; local_hashverify[0][1] = hashP1_1; local_hashverify[0][2] = hashP1_10M; local_hashverify[0][3] = hashP1_50M; local_hashverify[0][4] = hashP1_100M; local_hashverify[0][5] = hashP1_200M; local_hashverify[0][6] = hashP1_500M;
 local_hashverify[1][0] = hashP2_0; local_hashverify[1][1] = hashP2_1; local_hashverify[1][2] = hashP2_10M; local_hashverify[1][3] = hashP2_50M; local_hashverify[1][4] = hashP2_100M; local_hashverify[1][5] = hashP2_200M; local_hashverify[1][6] = hashP2_500M;
 local_hashverify[2][0] = hashP3_0; local_hashverify[2][1] = hashP3_1; local_hashverify[2][2] = hashP3_10M; local_hashverify[2][3] = hashP3_50M; local_hashverify[2][4] = hashP3_100M; local_hashverify[2][5] = hashP3_200M; local_hashverify[2][6] = hashP3_500M;
 local_hashverify[3][0] = hashP4_0; local_hashverify[3][1] = hashP4_1; local_hashverify[3][2] = hashP4_10M; local_hashverify[3][3] = hashP4_50M; local_hashverify[3][4] = hashP4_100M; local_hashverify[3][5] = hashP4_200M; local_hashverify[3][6] = hashP4_500M;
}

// <eof>
