/*
 * File: rsha256_ref_arm.cxx
 *
 * Author: voidxno
 * Created: 17 Feb 2024
 * Source: https://github.com/voidxno/fast-recursive-sha256
 *
 * Reference recursive SHA256 function, with intrinsics and ARM Cryptography Extensions
 *
 * Requirement: ARM CPU, with Cryptography Extensions
 *
 * LICENSE: Unlicense
 * For more information, please refer to <https://unlicense.org>
 *
 */

#include <stdint.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

#ifdef _WIN32
#define bswap_32(x) _byteswap_ulong(x)
#else
#include <byteswap.h>
#endif

#if defined(__aarch64__) || defined(_M_ARM64)

inline void compress_digest(uint32_t* state,const uint8_t* last);

void rsha256_ref(          //-- no return value, result to *hash
uint8_t*       hash,       //-- input/output 32bytes hash/data SHA256 value
const uint64_t num_iters)  //-- number of times to SHA256 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init values for SHA256 rounds, A-H logic
   uint32_t state[8] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};

   //-- pre-process/padding, length=32, hash/data input
   uint8_t last[64];
   memcpy(last,hash,32);
   memset(&last[32],0x00,32);
   memcpy(&last[32],"\x80",1);
   memcpy(&last[56],"\x00\x00\x00\x00\x00\x00\x01\x00",8);

   //-- compress digest, 1x block
   compress_digest(state,last);

   //-- shuffle hash bytes to correct endian
   for(int k = 0; k < 8; ++k){ state[k] = bswap_32(state[k]); }

   //-- copy/save current hash value into *hash
   memcpy(hash,state,32);
   }
}

inline void compress_digest(uint32_t* state,const uint8_t* last)
{

 //-- array of 64x constants for SHA256 rounds
 static const uint32_t K64[64] = {
   0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
   0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
   0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
   0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
   0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
   0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
   0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
   0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
   };

 //-- variables to calculate SHA256 rounds
 uint32x4_t STATE0;
 uint32x4_t STATE1;
 uint32x4_t STATEV;
 uint32x4_t MSGV;
 uint32x4_t MSGTMP0;
 uint32x4_t MSGTMP1;
 uint32x4_t MSGTMP2;
 uint32x4_t MSGTMP3;

 //-- init state value for SHA256 rounds
 STATE0 = vld1q_u32(&state[0]);
 STATE1 = vld1q_u32(&state[4]);

 //-- save current state for usage later
 const uint32x4_t ABCD_SAVE = STATE0;
 const uint32x4_t EFGH_SAVE = STATE1;

 //-- init values with hash/data input
 MSGTMP0 = vld1q_u32((const uint32_t*)(&last[0]));
 MSGTMP1 = vld1q_u32((const uint32_t*)(&last[16]));
 MSGTMP2 = vld1q_u32((const uint32_t*)(&last[32]));
 MSGTMP3 = vld1q_u32((const uint32_t*)(&last[48]));

 //-- shuffle values bytes required by Cryptography Extensions
 MSGTMP0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSGTMP0)));
 MSGTMP1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSGTMP1)));
 MSGTMP2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSGTMP2)));
 MSGTMP3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSGTMP3)));

 //-- rounds 0-3
 MSGV = vaddq_u32(MSGTMP0,vld1q_u32(&K64[0]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP0 = vsha256su0q_u32(MSGTMP0,MSGTMP1);

 //-- rounds 4-7
 MSGV = vaddq_u32(MSGTMP1,vld1q_u32(&K64[4]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP0 = vsha256su1q_u32(MSGTMP0,MSGTMP2,MSGTMP3);
 MSGTMP1 = vsha256su0q_u32(MSGTMP1,MSGTMP2);

 //-- rounds 8-11
 MSGV = vaddq_u32(MSGTMP2,vld1q_u32(&K64[8]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP1 = vsha256su1q_u32(MSGTMP1,MSGTMP3,MSGTMP0);
 MSGTMP2 = vsha256su0q_u32(MSGTMP2,MSGTMP3);

 //-- rounds 12-15
 MSGV = vaddq_u32(MSGTMP3,vld1q_u32(&K64[12]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP2 = vsha256su1q_u32(MSGTMP2,MSGTMP0,MSGTMP1);
 MSGTMP3 = vsha256su0q_u32(MSGTMP3,MSGTMP0);

 //-- rounds 16-19
 MSGV = vaddq_u32(MSGTMP0,vld1q_u32(&K64[16]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP3 = vsha256su1q_u32(MSGTMP3,MSGTMP1,MSGTMP2);
 MSGTMP0 = vsha256su0q_u32(MSGTMP0,MSGTMP1);

 //-- rounds 20-23
 MSGV = vaddq_u32(MSGTMP1,vld1q_u32(&K64[20]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP0 = vsha256su1q_u32(MSGTMP0,MSGTMP2,MSGTMP3);
 MSGTMP1 = vsha256su0q_u32(MSGTMP1,MSGTMP2);

 //-- rounds 24-27
 MSGV = vaddq_u32(MSGTMP2,vld1q_u32(&K64[24]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP1 = vsha256su1q_u32(MSGTMP1,MSGTMP3,MSGTMP0);
 MSGTMP2 = vsha256su0q_u32(MSGTMP2,MSGTMP3);

 //-- rounds 28-31
 MSGV = vaddq_u32(MSGTMP3,vld1q_u32(&K64[28]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP2 = vsha256su1q_u32(MSGTMP2,MSGTMP0,MSGTMP1);
 MSGTMP3 = vsha256su0q_u32(MSGTMP3,MSGTMP0);

 //-- rounds 32-35
 MSGV = vaddq_u32(MSGTMP0,vld1q_u32(&K64[32]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP3 = vsha256su1q_u32(MSGTMP3,MSGTMP1,MSGTMP2);
 MSGTMP0 = vsha256su0q_u32(MSGTMP0,MSGTMP1);

 //-- rounds 36-39
 MSGV = vaddq_u32(MSGTMP1,vld1q_u32(&K64[36]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP0 = vsha256su1q_u32(MSGTMP0,MSGTMP2,MSGTMP3);
 MSGTMP1 = vsha256su0q_u32(MSGTMP1,MSGTMP2);

 //-- rounds 40-43
 MSGV = vaddq_u32(MSGTMP2,vld1q_u32(&K64[40]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP1 = vsha256su1q_u32(MSGTMP1,MSGTMP3,MSGTMP0);
 MSGTMP2 = vsha256su0q_u32(MSGTMP2,MSGTMP3);

 //-- rounds 44-47
 MSGV = vaddq_u32(MSGTMP3,vld1q_u32(&K64[44]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP2 = vsha256su1q_u32(MSGTMP2,MSGTMP0,MSGTMP1);
 MSGTMP3 = vsha256su0q_u32(MSGTMP3,MSGTMP0);

 //-- rounds 48-51
 MSGV = vaddq_u32(MSGTMP0,vld1q_u32(&K64[48]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);
 MSGTMP3 = vsha256su1q_u32(MSGTMP3,MSGTMP1,MSGTMP2);

 //-- rounds 52-55
 MSGV = vaddq_u32(MSGTMP1,vld1q_u32(&K64[52]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);

 //-- rounds 56-59
 MSGV = vaddq_u32(MSGTMP2,vld1q_u32(&K64[56]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);

 //-- rounds 60-63
 MSGV = vaddq_u32(MSGTMP3,vld1q_u32(&K64[60]));
 STATEV = STATE0;
 STATE0 = vsha256hq_u32(STATE0,STATE1,MSGV);
 STATE1 = vsha256h2q_u32(STATE1,STATEV,MSGV);

 //-- add init state to current state
 STATE0 = vaddq_u32(STATE0,ABCD_SAVE);
 STATE1 = vaddq_u32(STATE1,EFGH_SAVE);

 //-- save state for next iteration or final result
 vst1q_u32(&state[0],STATE0);
 vst1q_u32(&state[4],STATE1);
}

#endif

// <eof>
