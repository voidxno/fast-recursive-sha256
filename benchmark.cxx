/*
 * File: benchmark.cxx
 *
 * Author: voidxno
 * Created: 12 Jun 2023
 *
 * Benchmark of fast recursive SHA256, with intrinsics and Intel SHA Extensions
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
 * - m <unit>: Measure unit to calculate (optional)
 *             Valid values: MH (default), MB, MiB, cpb
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

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

//-- external functions, recursive SHA256 (rec_sha256_reference.cxx, rec_sha256_fast.cxx)
void rec_sha256_fast(uint8_t* hash,const uint64_t num_iters);
void rec_sha256_reference(uint8_t* hash,const uint64_t num_iters);

//-- local functions
void local_ANSISetup(void);
void local_ANSIRestore(void);
void local_ParseParameters(int argc,char* argv[]);
int local_Benchmark(void (*pfFunc)(uint8_t*,const uint64_t),const char* pcName);

//-- arrays with verify values for <x> iterations of recursive SHA256
static const uint8_t local_hashStart[32]   = { 0x2E,0xFD,0x64,0xA5,0x54,0x63,0xB5,0xB5,0x54,0xC4,0xA2,0xE2,0x2A,0x47,0x2D,0xA2,0x3B,0xB7,0x6E,0x63,0x75,0x8C,0xE3,0xC8,0x92,0x76,0xAB,0xF0,0xE9,0xAD,0x8B,0x15 };
static const uint8_t local_hashEnd1x[32]   = { 0x77,0x46,0x1D,0x8E,0xD8,0xA2,0x20,0x6F,0x82,0x36,0x66,0x18,0xD3,0x63,0xBA,0xA2,0xFF,0xDD,0x99,0x1B,0x5D,0x2D,0x80,0x98,0x6D,0xBC,0xF8,0x2F,0x58,0xA4,0xF3,0xF3 };
static const uint8_t local_hashEnd10M[32]  = { 0x85,0xDE,0x67,0x64,0x93,0xDB,0x94,0x1B,0xAC,0x9F,0x89,0xB3,0x29,0x32,0x7A,0xF2,0x43,0x36,0x21,0x80,0x07,0x18,0xEB,0xB5,0xD7,0x92,0x6B,0xD4,0xF5,0xFF,0xED,0x97 };
static const uint8_t local_hashEnd50M[32]  = { 0x06,0x7D,0x78,0xD9,0x50,0x04,0x4F,0x00,0x2B,0x4C,0xC9,0x89,0x6E,0xDE,0x9C,0xE0,0x5A,0x5C,0xA9,0xFA,0x4A,0x0F,0x6E,0x69,0xBE,0x18,0x8E,0x6C,0x95,0x61,0x6C,0xED };
static const uint8_t local_hashEnd100M[32] = { 0x6D,0x9B,0x4C,0x49,0x90,0x28,0x2B,0xF0,0x46,0xC9,0x65,0x7B,0x32,0xCD,0x99,0xEC,0x14,0x35,0x16,0x6A,0xEE,0x6B,0x4C,0x23,0x3C,0xBE,0xAC,0x1F,0x28,0x5A,0x65,0xAA };
static const uint8_t local_hashEnd200M[32] = { 0x05,0x90,0x5D,0xA9,0x58,0xD9,0xFC,0x78,0x52,0xAE,0x95,0x4A,0xF9,0xF1,0x31,0xB9,0x5A,0x1F,0xA4,0x07,0x18,0x6E,0x9B,0x68,0x7D,0xE5,0x7D,0x49,0xD4,0x05,0x5B,0xF1 };
static const uint8_t local_hashEnd500M[32] = { 0x49,0xC0,0x53,0xE8,0xC3,0x82,0x64,0x77,0xFA,0x52,0xB7,0x7D,0xE2,0x03,0xED,0x9D,0xE0,0xD1,0xCE,0x04,0x5D,0xA0,0x1A,0x45,0xC0,0x56,0xE3,0x65,0x3F,0x9F,0x72,0x9E };

//-- local parameter values
uint64_t local_iIterations;
uint8_t  local_hashEnd[32];
bool     local_bGHz;
double   local_dGHz;
uint64_t local_iUnit;
char     local_strUnit[16];

//-- main() - entrypoint
int main(int argc, char* argv[])
{

 //-- setup/init ANSI capability
 local_ANSISetup();

 //-- default parameter values, -i 100M, -s <not set>, -m MH
 local_iIterations = 100000000;
 memcpy(local_hashEnd,local_hashEnd100M,32);
 local_bGHz = false;
 local_dGHz = 0.0;
 local_iUnit = 0;
 strcpy(local_strUnit,"MH/s");

 //-- parse parameters
 local_ParseParameters(argc,argv);

 //-- display header and benchmark parameters
 setvbuf(stdout,NULL,_IONBF,0);
 printf("\33[1;97m[Benchmark - Fast Recursive SHA256 (w/Intel SHA Extensions)]\33[0m\n");
 if(!local_bGHz){ printf("- Parameters: %" PRIu64 " MH (iterations), n/a GHz (cpu speed), %s (unit)\n",local_iIterations / 1000000,local_strUnit); }
 else           { printf("- Parameters: %" PRIu64 " MH (iterations), %.2f GHz (cpu speed), %s (unit)\n",local_iIterations / 1000000,local_dGHz,local_strUnit); }

 //-- benchmark - fast (rec_sha256_fast.cxx)
 if(local_Benchmark(&rec_sha256_fast,"Fast:")){ return 1; };

 //-- benchmark - reference (rec_sha256_reference.cxx)
 if(local_Benchmark(&rec_sha256_reference,"Reference:")){ return 1; };

 //-- restore ANSI capability
 local_ANSIRestore();

 return 0;
}

//-- local_ParseParameters() - parse parameters
void local_ParseParameters(int argc,char* argv[])
{
 for(int i = 1, iP = 0; i < argc; ++i){
   if((char)iP == 'i'){
     if     (!strcasecmp(argv[i],"10M"))  { local_iIterations = 10000000;  memcpy(local_hashEnd,local_hashEnd10M, 32); }
     else if(!strcasecmp(argv[i],"50M"))  { local_iIterations = 50000000;  memcpy(local_hashEnd,local_hashEnd50M, 32); }
     else if(!strcasecmp(argv[i],"100M")) { local_iIterations = 100000000; memcpy(local_hashEnd,local_hashEnd100M,32); }
     else if(!strcasecmp(argv[i],"200M")) { local_iIterations = 200000000; memcpy(local_hashEnd,local_hashEnd200M,32); }
     else if(!strcasecmp(argv[i],"500M")) { local_iIterations = 500000000; memcpy(local_hashEnd,local_hashEnd500M,32); }
     iP = 0; continue;
     }

   if((char)iP == 's'){
     local_bGHz = true;
     local_dGHz = strtod(argv[i],NULL);
     if(local_dGHz < 0.1 || local_dGHz > 999.9){ local_bGHz = false; local_dGHz = 0.0; }
     local_dGHz = (double)((int)(local_dGHz * 100.0)) / 100.0;
     iP = 0; continue;
     }

   if((char)iP == 'm'){
     if     (!strcasecmp(argv[i],"MH"))  { local_iUnit = 0; strcpy(local_strUnit,"MH/s"); }
     else if(!strcasecmp(argv[i],"MB"))  { local_iUnit = 1; strcpy(local_strUnit,"MB/s"); }
     else if(!strcasecmp(argv[i],"MiB")) { local_iUnit = 2; strcpy(local_strUnit,"MiB/s"); }
     else if(!strcasecmp(argv[i],"cpb")) { local_iUnit = 3; strcpy(local_strUnit,"cpb"); }
     iP = 0; continue;
     }

   iP = 0;
   if(!strcmp(argv[i],"-i")){ iP = 'i'; continue; }
   if(!strcmp(argv[i],"-s")){ iP = 's'; continue; }
   if(!strcmp(argv[i],"-m")){ iP = 'm'; continue; }
   }
}

//-- local_Benchmark() - perform benchmark with function pointer given
int local_Benchmark(
void        (*pfFunc)(uint8_t*,const uint64_t),
const char* pcName)
{
 uint8_t hash[32];
 clock_t timeStart;
 clock_t timeStop;
 clock_t timeElapsed;
 double  dSpeedMHs;
 double  dSpeedMBs;
 double  dSpeedMiBs;
 double  dSpeedCPBhash;
 double  dSpeedCPBbyte;
 bool    bHashOk;

 printf("- %-10s  Consistency check of 0x and 1x iterations ...",pcName);
 memcpy(hash,local_hashStart,32);
 pfFunc(hash,0);
 bHashOk = (memcmp(hash,local_hashStart,32)) ? false : true;
 if(!bHashOk){ fprintf(stderr,"\n\33[1;31mERROR: Resulting hash after 0 iterations do not match reference value !\33[0m\n"); return 1; }
 memcpy(hash,local_hashStart,32);
 pfFunc(hash,1);
 bHashOk = (memcmp(hash,local_hashEnd1x,32)) ? false : true;
 if(!bHashOk){ fprintf(stderr,"\n\33[1;31mERROR: Resulting hash after 1 iterations do not match reference value !\33[0m\n"); return 1; }

 printf("\33[2K\r- %-10s  Spin run of %" PRIu64 "MH iterations ...",pcName,local_iIterations / 1000000);
 memcpy(hash,local_hashStart,32);
 pfFunc(hash,local_iIterations);

 printf("\33[2K\r- %-10s  Benchmark of %" PRIu64 "MH iterations ...",pcName,local_iIterations / 1000000);
 memcpy(hash,local_hashStart,32);
 timeStart = clock();
 pfFunc(hash,local_iIterations);
 timeStop = clock();
 timeElapsed = timeStop - timeStart;
 dSpeedMHs = ((double)local_iIterations / ((double)timeElapsed / CLOCKS_PER_SEC)) / 1000000.0;
 dSpeedMBs = ((((double)local_iIterations * 64) / 1000000.0) / ((double)timeElapsed / CLOCKS_PER_SEC));
 dSpeedMiBs = ((((double)local_iIterations * 64) / 1048576.0) / ((double)timeElapsed / CLOCKS_PER_SEC));
 dSpeedCPBhash = ((double)local_dGHz * 1000000000.0) / (((double)local_iIterations) / ((double)timeElapsed / CLOCKS_PER_SEC));
 dSpeedCPBbyte = ((double)local_dGHz * 1000000000.0) / (((double)local_iIterations * 64) / ((double)timeElapsed / CLOCKS_PER_SEC));
 bHashOk = (memcmp(hash,local_hashEnd,32)) ? false : true;

 //-- unit: MH/s
 if(local_iUnit == 0){
   if(!local_bGHz){ printf("\33[2K\r- %-10s  \33[1;32m%.2f\33[0m MH/s (\33[1;32mn/a\33[0m MH/s/0.1GHz) [verify hash: %s]\n",pcName,dSpeedMHs,(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else           { printf("\33[2K\r- %-10s  \33[1;32m%.2f\33[0m MH/s (\33[1;32m%.3f\33[0m MH/s/0.1GHz) [verify hash: %s]\n",pcName,dSpeedMHs,dSpeedMHs / (local_dGHz * 10.0),(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: MB/s (MB = megabyte = 1000 x 1000 bytes (8bit) = 1.000.000)
 else if(local_iUnit == 1){
   if(!local_bGHz){ printf("\33[2K\r- %-10s  \33[1;32m%.2f\33[0m MB/s (\33[1;32mn/a\33[0m MB/s/0.1GHz) [verify hash: %s]\n",pcName,dSpeedMBs,(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else           { printf("\33[2K\r- %-10s  \33[1;32m%.2f\33[0m MB/s (\33[1;32m%.2f\33[0m MB/s/0.1GHz) [verify hash: %s]\n",pcName,dSpeedMBs,dSpeedMBs / (local_dGHz * 10.0),(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: MiB/s (MiB = mebibyte = 1024 x 1024 bytes (8bit) = 1.048.576)
 else if(local_iUnit == 2){
   if(!local_bGHz){ printf("\33[2K\r- %-10s  \33[1;32m%.2f\33[0m MiB/s (\33[1;32mn/a\33[0m MiB/s/0.1GHz) [verify hash: %s]\n",pcName,dSpeedMiBs,(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else           { printf("\33[2K\r- %-10s  \33[1;32m%.2f\33[0m MiB/s (\33[1;32m%.2f\33[0m MiB/s/0.1GHz) [verify hash: %s]\n",pcName,dSpeedMiBs,dSpeedMiBs / (local_dGHz * 10.0),(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }
 //-- unit: cpb (cpb = cycles per block, and per byte)
 else if(local_iUnit == 3){
   if(!local_bGHz){ printf("\33[2K\r- %-10s  \33[1;32mn/a\33[0m cycles per block (\33[1;32mn/a\33[0m per byte) [verify hash: %s]\n",pcName,(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   else           { printf("\33[2K\r- %-10s  \33[1;32m%.1f\33[0m cycles per block (\33[1;32m%.2f\33[0m per byte) [verify hash: %s]\n",pcName,dSpeedCPBhash,dSpeedCPBbyte,(bHashOk) ? "\33[1;32mok\33[0m" : "\33[1;31mERROR\33[0m"); }
   }

 if(local_iUnit == 3 && !local_bGHz){ printf("\33[1;33mINFO:\33[0m Need -s <cpuspeed> parameter to calculate CPU cycles results.\n"); }
 if(!bHashOk){ fprintf(stderr,"\33[1;31mERROR: Resulting hash after %" PRIu64 "MH iterations do not match reference value !\33[0m\n",local_iIterations / 1000000); return 1; }

 return 0;
}

//-- local_ANSISetup() - setup/init ANSI capability (needed for Windows)
//-- local_ANSIRestore() - restore ANSI capability (needed for Windows)
#ifdef _WIN32
#include <windows.h>
static HANDLE local_hStdOut;
static DWORD  local_dwSaveMode = 0;
void local_ANSISetup(void)
{
 local_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
 if(local_hStdOut == INVALID_HANDLE_VALUE){ return; }
 if(!GetConsoleMode(local_hStdOut,&local_dwSaveMode)){ local_dwSaveMode = 0; return; }
 if(!SetConsoleMode(local_hStdOut,(local_dwSaveMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))){ local_dwSaveMode = 0; return; }
}
void local_ANSIRestore(void)
{
 if(!SetConsoleMode(local_hStdOut,local_dwSaveMode)){ return; }
}
#else
void local_ANSISetup(void) {}
void local_ANSIRestore(void) {}
#endif

// <eof>
