/*
 * File: benchmark.cxx
 *
 * Author: voidxno
 * Created: 12 Jun 2023
 *
 * Benchmark of fast recursive SHA256, with intrinsics and
 * Intel SHA Extensions or ARM Cryptography Extensions
 *
 * Program call: benchmark -i <iters> -s <cpuspeed> -m <unit>
 *
 * -i <iter>: Number of SHA256 iterations to perform (optional)
 *            Valid values: 10M, 50M, 100M (default), 200M, 500M
 *
 * -s <ghz>: x.x GHz speed of CPU when run (optional)
 *           If set, calculates and shows MH/s/0.1GHz for result
 *           Only calculates, cannot set real CPU speed of machine
 *
 * -m <unit>: Measure unit to calculate (optional)
 *            Valid values: MH (default), MB, MiB, cpb
 *
 * Requirement: Intel/AMD x64 CPU, with SHA Extensions, or
 *              ARM CPU, with Cryptography Extensions
 *
 * LICENSE: Unlicense
 * For more information, please refer to <https://unlicense.org>
 *
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

//-- external functions, recursive SHA256 (rsha256_fast_*.cxx, rsha256_ref_*.cxx)
void rsha256_fast(uint8_t* hash,const uint64_t num_iters);
void rsha256_ref(uint8_t* hash,const uint64_t num_iters);

//-- local functions
void local_ANSISetup(void);
void local_ANSIRestore(void);
void local_InitHashVerify();
void local_ParseParameters(int argc,char* argv[]);
int local_Benchmark(void (*bfunc)(uint8_t*,const uint64_t),const char* bname);

//-- array with hash verify values (7x), iterations (0, 1, 10M, 50M, 100M, 200M, 500M)
const uint8_t* local_hashverify[7];

//-- local parameter values
uint64_t local_iters;
uint32_t local_itersidx;
bool     local_ghz;
double   local_ghzval;
uint32_t local_unit;
char     local_unitstr[16];

//-- main() - entrypoint
int main(int argc, char* argv[])
{

 //-- setup/init ANSI capability
 local_ANSISetup();

 //-- init values for verify hash arrays
 local_InitHashVerify();

 //-- default parameter values, -i 100M, -s <not set>, -m MH
 local_iters = 100000000;
 local_itersidx = 4;
 local_ghz = false;
 local_ghzval = 0.0;
 local_unit = 0;
 strcpy(local_unitstr,"MH/s");

 //-- display header
 setvbuf(stdout,NULL,_IONBF,0);
#if defined(__amd64__) || defined(_M_AMD64)
 printf("\33[1;97m[Benchmark - Fast Recursive SHA256 (w/Intel SHA Extensions)]\33[0m\n");
#elif defined(__aarch64__) || defined(_M_ARM64)
 printf("\33[1;97m[Benchmark - Fast Recursive SHA256 (w/ARM Cryptography Extensions)]\33[0m\n");
#else
 printf("\33[1;97m[Benchmark - Fast Recursive SHA256 (w/<unknown platform>)]\33[0m\n");
#endif

 //-- parse parameters
 local_ParseParameters(argc,argv);

 //-- display benchmark parameters
 if(!local_ghz){ printf("- Parameters: %" PRIu64 " MH (iterations), n/a GHz (cpu speed), %s (unit)\n",local_iters / 1000000,local_unitstr); }
 else          { printf("- Parameters: %" PRIu64 " MH (iterations), %.2f GHz (cpu speed), %s (unit)\n",local_iters / 1000000,local_ghzval,local_unitstr); }

 //-- benchmark - fast (rsha256_fast_*.cxx)
 if(local_Benchmark(&rsha256_fast,"Fast:")){ return 1; };

 //-- benchmark - reference (rsha256_ref_*.cxx)
 if(local_Benchmark(&rsha256_ref,"Reference:")){ return 1; };

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

   jP = 0;
   if(!strcmp(argv[i],"-i")){ jP = 'i'; continue; }
   if(!strcmp(argv[i],"-s")){ jP = 's'; continue; }
   if(!strcmp(argv[i],"-m")){ jP = 'm'; continue; }
   }
}

//-- local_Benchmark() - perform benchmark with function pointer given
int local_Benchmark(
void        (*bfunc)(uint8_t*,const uint64_t),
const char* bname)
{
 uint8_t  hash[32];
 clock_t  timestart;
 clock_t  timestop;
 clock_t  timediff;
 double   speedMHs;
 double   speedMBs;
 double   speedMiBs;
 double   speedCPBhash;
 double   speedCPBbyte;
 bool     hashok;

 printf("- %-10s  Consistency check of 0x and 1x iterations ...",bname);
 memcpy(hash,local_hashverify[0],32);
 bfunc(hash,0);
 hashok = (memcmp(hash,local_hashverify[0],32)) ? false : true;
 if(!hashok){ fprintf(stderr,"\n\33[1;31mERROR: Resulting hash after 0 iterations do not match reference value !\33[0m\n"); return 1; }
 memcpy(hash,local_hashverify[0],32);
 bfunc(hash,1);
 hashok = (memcmp(hash,local_hashverify[1],32)) ? false : true;
 if(!hashok){ fprintf(stderr,"\n\33[1;31mERROR: Resulting hash after 1 iterations do not match reference value !\33[0m\n"); return 1; }

 printf("\33[2K\r- %-10s  Spin run of %" PRIu64 "MH iterations ...",bname,local_iters / 1000000);
 memcpy(hash,local_hashverify[0],32);
 bfunc(hash,local_iters);

 printf("\33[2K\r- %-10s  Benchmark of %" PRIu64 "MH iterations ...",bname,local_iters / 1000000);
 memcpy(hash,local_hashverify[0],32);
 timestart = clock();
 bfunc(hash,local_iters);
 timestop = clock();
 timediff = timestop - timestart;
 if(timediff <= 0){ fprintf(stderr,"\n\33[1;31mERROR: Elapsed time after %" PRIu64 "MH iterations is 0 !\33[0m\n",local_iters / 1000000); return 1; }
 speedMHs = ((double)local_iters / ((double)timediff / CLOCKS_PER_SEC)) / 1000000.0;
 speedMBs = ((((double)local_iters * 64) / 1000000.0) / ((double)timediff / CLOCKS_PER_SEC));
 speedMiBs = ((((double)local_iters * 64) / 1048576.0) / ((double)timediff / CLOCKS_PER_SEC));
 speedCPBhash = ((double)local_ghzval * 1000000000.0) / (((double)local_iters) / ((double)timediff / CLOCKS_PER_SEC));
 speedCPBbyte = ((double)local_ghzval * 1000000000.0) / (((double)local_iters * 64) / ((double)timediff / CLOCKS_PER_SEC));
 hashok = (memcmp(hash,local_hashverify[local_itersidx],32)) ? false : true;

 //-- unit: MH/s
 if(local_unit == 0){
   if(!local_ghz){ printf("\33[2K\r- %-10s \33[1;32m%6.2f\33[0m MH/s (\33[1;32mn/a\33[0m MH/s/0.1GHz) [verify hash: %s]\n",bname,speedMHs,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-10s \33[1;32m%6.2f\33[0m MH/s (\33[1;32m%5.3f\33[0m MH/s/0.1GHz) [verify hash: %s]\n",bname,speedMHs,speedMHs / (local_ghzval * 10.0),(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: MB/s (MB = megabyte = 1000 x 1000 bytes (8bit) = 1.000.000)
 else if(local_unit == 1){
   if(!local_ghz){ printf("\33[2K\r- %-10s \33[1;32m%8.2f\33[0m MB/s (\33[1;32mn/a\33[0m MB/s/0.1GHz) [verify hash: %s]\n",bname,speedMBs,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-10s \33[1;32m%8.2f\33[0m MB/s (\33[1;32m%6.2f\33[0m MB/s/0.1GHz) [verify hash: %s]\n",bname,speedMBs,speedMBs / (local_ghzval * 10.0),(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: MiB/s (MiB = mebibyte = 1024 x 1024 bytes (8bit) = 1.048.576)
 else if(local_unit == 2){
   if(!local_ghz){ printf("\33[2K\r- %-10s \33[1;32m%8.2f\33[0m MiB/s (\33[1;32mn/a\33[0m MiB/s/0.1GHz) [verify hash: %s]\n",bname,speedMiBs,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-10s \33[1;32m%8.2f\33[0m MiB/s (\33[1;32m%6.2f\33[0m MiB/s/0.1GHz) [verify hash: %s]\n",bname,speedMiBs,speedMiBs / (local_ghzval * 10.0),(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: cpb (cpb = cycles per block, and per byte)
 else if(local_unit == 3){
   if(!local_ghz){ printf("\33[2K\r- %-10s \33[1;32mn/a\33[0m cycles per block (\33[1;32mn/a\33[0m per byte) [verify hash: %s]\n",bname,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else          { printf("\33[2K\r- %-10s \33[1;32m%6.1f\33[0m cycles per block (\33[1;32m%4.2f\33[0m per byte) [verify hash: %s]\n",bname,speedCPBhash,speedCPBbyte,(hashok) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
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
 static const uint8_t hash_0[32]    = { 0x2E,0xFD,0x64,0xA5,0x54,0x63,0xB5,0xB5,0x54,0xC4,0xA2,0xE2,0x2A,0x47,0x2D,0xA2,0x3B,0xB7,0x6E,0x63,0x75,0x8C,0xE3,0xC8,0x92,0x76,0xAB,0xF0,0xE9,0xAD,0x8B,0x15 };
 static const uint8_t hash_1[32]    = { 0x77,0x46,0x1D,0x8E,0xD8,0xA2,0x20,0x6F,0x82,0x36,0x66,0x18,0xD3,0x63,0xBA,0xA2,0xFF,0xDD,0x99,0x1B,0x5D,0x2D,0x80,0x98,0x6D,0xBC,0xF8,0x2F,0x58,0xA4,0xF3,0xF3 };
 static const uint8_t hash_10M[32]  = { 0x85,0xDE,0x67,0x64,0x93,0xDB,0x94,0x1B,0xAC,0x9F,0x89,0xB3,0x29,0x32,0x7A,0xF2,0x43,0x36,0x21,0x80,0x07,0x18,0xEB,0xB5,0xD7,0x92,0x6B,0xD4,0xF5,0xFF,0xED,0x97 };
 static const uint8_t hash_50M[32]  = { 0x06,0x7D,0x78,0xD9,0x50,0x04,0x4F,0x00,0x2B,0x4C,0xC9,0x89,0x6E,0xDE,0x9C,0xE0,0x5A,0x5C,0xA9,0xFA,0x4A,0x0F,0x6E,0x69,0xBE,0x18,0x8E,0x6C,0x95,0x61,0x6C,0xED };
 static const uint8_t hash_100M[32] = { 0x6D,0x9B,0x4C,0x49,0x90,0x28,0x2B,0xF0,0x46,0xC9,0x65,0x7B,0x32,0xCD,0x99,0xEC,0x14,0x35,0x16,0x6A,0xEE,0x6B,0x4C,0x23,0x3C,0xBE,0xAC,0x1F,0x28,0x5A,0x65,0xAA };
 static const uint8_t hash_200M[32] = { 0x05,0x90,0x5D,0xA9,0x58,0xD9,0xFC,0x78,0x52,0xAE,0x95,0x4A,0xF9,0xF1,0x31,0xB9,0x5A,0x1F,0xA4,0x07,0x18,0x6E,0x9B,0x68,0x7D,0xE5,0x7D,0x49,0xD4,0x05,0x5B,0xF1 };
 static const uint8_t hash_500M[32] = { 0x49,0xC0,0x53,0xE8,0xC3,0x82,0x64,0x77,0xFA,0x52,0xB7,0x7D,0xE2,0x03,0xED,0x9D,0xE0,0xD1,0xCE,0x04,0x5D,0xA0,0x1A,0x45,0xC0,0x56,0xE3,0x65,0x3F,0x9F,0x72,0x9E };

 local_hashverify[0] = hash_0; local_hashverify[1] = hash_1; local_hashverify[2] = hash_10M; local_hashverify[3] = hash_50M; local_hashverify[4] = hash_100M; local_hashverify[5] = hash_200M; local_hashverify[6] = hash_500M;
}

// <eof>
