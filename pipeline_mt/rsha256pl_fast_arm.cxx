/*
 * File: rsha256pl_fast_arm.cxx
 *
 * Author: voidxno
 * Created: 17 Feb 2024
 * Source: https://github.com/voidxno/fast-recursive-sha256
 *
 * Fast recursive SHA256 function, with intrinsics and ARM Cryptography Extensions
 * Pipelined editions, from x1 to x4
 *
 * rsha256_fast_x1() - Identical to rsha256_fast()
 * rsha256_fast_x2() - 64 bytes, 2x 32bytes
 * rsha256_fast_x3() - 96 bytes, 3x 32bytes
 * rsha256_fast_x4() - 128 bytes, 4x 32bytes
 *
 * Requirement: ARM CPU, with Cryptography Extensions
 *
 * LICENSE: Unlicense
 * For more information, please refer to <https://unlicense.org>
 *
 */

#include <stdint.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

#if defined(__aarch64__) || defined(_M_ARM64)

void rsha256_fast_x1(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 32 bytes, 1x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 1x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

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

 //-- init values for SHA256 rounds, A-H logic
 static const uint32_t abcdinit[4] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A};
 static const uint32_t efghinit[4] = {0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
 const uint32x4_t ABCD_INIT = vld1q_u32(&abcdinit[0]);
 const uint32x4_t EFGH_INIT = vld1q_u32(&efghinit[0]);

 //-- pre-arranged values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 static const uint32_t hpad0cache[4] = {0x80000000,0x00000000,0x00000000,0x00000000};
 static const uint32_t hpad1cache[4] = {0x00000000,0x00000000,0x00000000,0x00000100};
 const uint32x4_t HPAD0_CACHE = vld1q_u32(&hpad0cache[0]);
 const uint32x4_t HPAD1_CACHE = vld1q_u32(&hpad1cache[0]);

 //-- variables to calculate SHA256 rounds
 uint32x4_t STATE0_P1; uint32x4_t STATE1_P1; uint32x4_t STATEV_P1; uint32x4_t MSGV_P1; uint32x4_t MSGTMP0_P1; uint32x4_t MSGTMP1_P1; uint32x4_t MSGTMP2_P1; uint32x4_t MSGTMP3_P1;

 //-- variables to init/keep hash value through SHA256 rounds
 uint32x4_t HASH0_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[0]));
 uint32x4_t HASH1_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[16]));

 //-- shuffle hash bytes required by Cryptography Extensions
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state value for SHA256 rounds
   STATE0_P1 = ABCD_INIT;
   STATE1_P1 = EFGH_INIT;

   //-- rounds 0-3
   MSGV_P1 = vaddq_u32(HASH0_SAVE_P1,vld1q_u32(&K64[0]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   MSGTMP0_P1 = vsha256su0q_u32(HASH0_SAVE_P1,HASH1_SAVE_P1);

   //-- rounds 4-7
   MSGV_P1 = vaddq_u32(HASH1_SAVE_P1,vld1q_u32(&K64[4]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   MSGTMP0_P1 = vsha256su1q_u32(MSGTMP0_P1,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP1_P1 = vsha256su0q_u32(HASH1_SAVE_P1,HPAD0_CACHE);

   //-- rounds 8-11
   MSGV_P1 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   MSGTMP1_P1 = vsha256su1q_u32(MSGTMP1_P1,HPAD1_CACHE,MSGTMP0_P1);
   MSGTMP2_P1 = HPAD0_CACHE;

   //-- rounds 12-15
   MSGV_P1 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   MSGTMP2_P1 = vsha256su1q_u32(MSGTMP2_P1,MSGTMP0_P1,MSGTMP1_P1);
   MSGTMP3_P1 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P1);

#define SHA256ROUND_X1( \
msgv_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, statev_p1, state0_p1, state1_p1, kvalue) \
  msgv_p1 = vaddq_u32(msgtmp0_p1,vld1q_u32(kvalue)); \
  statev_p1 = state0_p1; \
  state0_p1 = vsha256hq_u32(state0_p1,state1_p1,msgv_p1); \
  state1_p1 = vsha256h2q_u32(state1_p1,statev_p1,msgv_p1); \
  msgtmp3_p1 = vsha256su1q_u32(msgtmp3_p1,msgtmp1_p1,msgtmp2_p1); \
  msgtmp0_p1 = vsha256su0q_u32(msgtmp0_p1,msgtmp1_p1);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X1(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[16]);
   SHA256ROUND_X1(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[20]);
   SHA256ROUND_X1(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[24]);
   SHA256ROUND_X1(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X1(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[32]);
   SHA256ROUND_X1(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[36]);
   SHA256ROUND_X1(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[40]);
   SHA256ROUND_X1(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,&K64[44]);

   //-- rounds 48-51
   MSGV_P1 = vaddq_u32(MSGTMP0_P1,vld1q_u32(&K64[48]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   MSGTMP3_P1 = vsha256su1q_u32(MSGTMP3_P1,MSGTMP1_P1,MSGTMP2_P1);

   //-- rounds 52-55
   MSGV_P1 = vaddq_u32(MSGTMP1_P1,vld1q_u32(&K64[52]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);

   //-- rounds 56-59
   MSGV_P1 = vaddq_u32(MSGTMP2_P1,vld1q_u32(&K64[56]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);

   //-- rounds 60-63
   MSGV_P1 = vaddq_u32(MSGTMP3_P1,vld1q_u32(&K64[60]));
   STATEV_P1 = STATE0_P1;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);

   //-- add init state to current state
   HASH0_SAVE_P1 = vaddq_u32(STATE0_P1,ABCD_INIT);
   HASH1_SAVE_P1 = vaddq_u32(STATE1_P1,EFGH_INIT);
   }

 //-- shuffle Cryptography Extensions hash value back
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));

 //-- copy/return final hash value into *hash
 vst1q_u32((uint32_t*)(&hash[0]),HASH0_SAVE_P1);
 vst1q_u32((uint32_t*)(&hash[16]),HASH1_SAVE_P1);
}

void rsha256_fast_x2(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 64 bytes, 2x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 2x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

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

 //-- init values for SHA256 rounds, A-H logic
 static const uint32_t abcdinit[4] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A};
 static const uint32_t efghinit[4] = {0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
 const uint32x4_t ABCD_INIT = vld1q_u32(&abcdinit[0]);
 const uint32x4_t EFGH_INIT = vld1q_u32(&efghinit[0]);

 //-- pre-arranged values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 static const uint32_t hpad0cache[4] = {0x80000000,0x00000000,0x00000000,0x00000000};
 static const uint32_t hpad1cache[4] = {0x00000000,0x00000000,0x00000000,0x00000100};
 const uint32x4_t HPAD0_CACHE = vld1q_u32(&hpad0cache[0]);
 const uint32x4_t HPAD1_CACHE = vld1q_u32(&hpad1cache[0]);

 //-- variables to calculate SHA256 rounds
 uint32x4_t STATE0_P1; uint32x4_t STATE1_P1; uint32x4_t STATEV_P1; uint32x4_t MSGV_P1; uint32x4_t MSGTMP0_P1; uint32x4_t MSGTMP1_P1; uint32x4_t MSGTMP2_P1; uint32x4_t MSGTMP3_P1;
 uint32x4_t STATE0_P2; uint32x4_t STATE1_P2; uint32x4_t STATEV_P2; uint32x4_t MSGV_P2; uint32x4_t MSGTMP0_P2; uint32x4_t MSGTMP1_P2; uint32x4_t MSGTMP2_P2; uint32x4_t MSGTMP3_P2;

 //-- variables to init/keep hash value through SHA256 rounds
 uint32x4_t HASH0_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[0]));
 uint32x4_t HASH1_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[16]));
 uint32x4_t HASH0_SAVE_P2 = vld1q_u32((const uint32_t*)(&hash[32]));
 uint32x4_t HASH1_SAVE_P2 = vld1q_u32((const uint32_t*)(&hash[48]));

 //-- shuffle hash bytes required by Cryptography Extensions
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));
 HASH0_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P2)));
 HASH1_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P2)));

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state value for SHA256 rounds
   STATE0_P1 = ABCD_INIT;
   STATE0_P2 = ABCD_INIT;
   STATE1_P1 = EFGH_INIT;
   STATE1_P2 = EFGH_INIT;

   //-- rounds 0-3
   MSGV_P1 = vaddq_u32(HASH0_SAVE_P1,vld1q_u32(&K64[0]));
   MSGV_P2 = vaddq_u32(HASH0_SAVE_P2,vld1q_u32(&K64[0]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   MSGTMP0_P1 = vsha256su0q_u32(HASH0_SAVE_P1,HASH1_SAVE_P1);
   MSGTMP0_P2 = vsha256su0q_u32(HASH0_SAVE_P2,HASH1_SAVE_P2);

   //-- rounds 4-7
   MSGV_P1 = vaddq_u32(HASH1_SAVE_P1,vld1q_u32(&K64[4]));
   MSGV_P2 = vaddq_u32(HASH1_SAVE_P2,vld1q_u32(&K64[4]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   MSGTMP0_P1 = vsha256su1q_u32(MSGTMP0_P1,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP0_P2 = vsha256su1q_u32(MSGTMP0_P2,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP1_P1 = vsha256su0q_u32(HASH1_SAVE_P1,HPAD0_CACHE);
   MSGTMP1_P2 = vsha256su0q_u32(HASH1_SAVE_P2,HPAD0_CACHE);

   //-- rounds 8-11
   MSGV_P1 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   MSGV_P2 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   MSGTMP1_P1 = vsha256su1q_u32(MSGTMP1_P1,HPAD1_CACHE,MSGTMP0_P1);
   MSGTMP1_P2 = vsha256su1q_u32(MSGTMP1_P2,HPAD1_CACHE,MSGTMP0_P2);
   MSGTMP2_P1 = HPAD0_CACHE;
   MSGTMP2_P2 = HPAD0_CACHE;

   //-- rounds 12-15
   MSGV_P1 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   MSGV_P2 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   MSGTMP2_P1 = vsha256su1q_u32(MSGTMP2_P1,MSGTMP0_P1,MSGTMP1_P1);
   MSGTMP2_P2 = vsha256su1q_u32(MSGTMP2_P2,MSGTMP0_P2,MSGTMP1_P2);
   MSGTMP3_P1 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P1);
   MSGTMP3_P2 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P2);

#define SHA256ROUND_X2( \
msgv_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, statev_p1, state0_p1, state1_p1, \
msgv_p2, msgtmp0_p2, msgtmp1_p2, msgtmp2_p2, msgtmp3_p2, statev_p2, state0_p2, state1_p2, kvalue) \
  msgv_p1 = vaddq_u32(msgtmp0_p1,vld1q_u32(kvalue)); \
  msgv_p2 = vaddq_u32(msgtmp0_p2,vld1q_u32(kvalue)); \
  statev_p1 = state0_p1; \
  statev_p2 = state0_p2; \
  state0_p1 = vsha256hq_u32(state0_p1,state1_p1,msgv_p1); \
  state0_p2 = vsha256hq_u32(state0_p2,state1_p2,msgv_p2); \
  state1_p1 = vsha256h2q_u32(state1_p1,statev_p1,msgv_p1); \
  state1_p2 = vsha256h2q_u32(state1_p2,statev_p2,msgv_p2); \
  msgtmp3_p1 = vsha256su1q_u32(msgtmp3_p1,msgtmp1_p1,msgtmp2_p1); \
  msgtmp3_p2 = vsha256su1q_u32(msgtmp3_p2,msgtmp1_p2,msgtmp2_p2); \
  msgtmp0_p1 = vsha256su0q_u32(msgtmp0_p1,msgtmp1_p1); \
  msgtmp0_p2 = vsha256su0q_u32(msgtmp0_p2,msgtmp1_p2);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X2(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[16]);
   SHA256ROUND_X2(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[20]);
   SHA256ROUND_X2(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[24]);
   SHA256ROUND_X2(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X2(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[32]);
   SHA256ROUND_X2(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[36]);
   SHA256ROUND_X2(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[40]);
   SHA256ROUND_X2(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATEV_P2,STATE0_P2,STATE1_P2,&K64[44]);

   //-- rounds 48-51
   MSGV_P1 = vaddq_u32(MSGTMP0_P1,vld1q_u32(&K64[48]));
   MSGV_P2 = vaddq_u32(MSGTMP0_P2,vld1q_u32(&K64[48]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   MSGTMP3_P1 = vsha256su1q_u32(MSGTMP3_P1,MSGTMP1_P1,MSGTMP2_P1);
   MSGTMP3_P2 = vsha256su1q_u32(MSGTMP3_P2,MSGTMP1_P2,MSGTMP2_P2);

   //-- rounds 52-55
   MSGV_P1 = vaddq_u32(MSGTMP1_P1,vld1q_u32(&K64[52]));
   MSGV_P2 = vaddq_u32(MSGTMP1_P2,vld1q_u32(&K64[52]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);

   //-- rounds 56-59
   MSGV_P1 = vaddq_u32(MSGTMP2_P1,vld1q_u32(&K64[56]));
   MSGV_P2 = vaddq_u32(MSGTMP2_P2,vld1q_u32(&K64[56]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);

   //-- rounds 60-63
   MSGV_P1 = vaddq_u32(MSGTMP3_P1,vld1q_u32(&K64[60]));
   MSGV_P2 = vaddq_u32(MSGTMP3_P2,vld1q_u32(&K64[60]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);

   //-- add init state to current state
   HASH0_SAVE_P1 = vaddq_u32(STATE0_P1,ABCD_INIT);
   HASH0_SAVE_P2 = vaddq_u32(STATE0_P2,ABCD_INIT);
   HASH1_SAVE_P1 = vaddq_u32(STATE1_P1,EFGH_INIT);
   HASH1_SAVE_P2 = vaddq_u32(STATE1_P2,EFGH_INIT);
   }

 //-- shuffle Cryptography Extensions hash value back
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));
 HASH0_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P2)));
 HASH1_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P2)));

 //-- copy/return final hash value into *hash
 vst1q_u32((uint32_t*)(&hash[0]),HASH0_SAVE_P1);
 vst1q_u32((uint32_t*)(&hash[16]),HASH1_SAVE_P1);
 vst1q_u32((uint32_t*)(&hash[32]),HASH0_SAVE_P2);
 vst1q_u32((uint32_t*)(&hash[48]),HASH1_SAVE_P2);
}

void rsha256_fast_x3(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 96 bytes, 3x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 3x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

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

 //-- init values for SHA256 rounds, A-H logic
 static const uint32_t abcdinit[4] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A};
 static const uint32_t efghinit[4] = {0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
 const uint32x4_t ABCD_INIT = vld1q_u32(&abcdinit[0]);
 const uint32x4_t EFGH_INIT = vld1q_u32(&efghinit[0]);

 //-- pre-arranged values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 static const uint32_t hpad0cache[4] = {0x80000000,0x00000000,0x00000000,0x00000000};
 static const uint32_t hpad1cache[4] = {0x00000000,0x00000000,0x00000000,0x00000100};
 const uint32x4_t HPAD0_CACHE = vld1q_u32(&hpad0cache[0]);
 const uint32x4_t HPAD1_CACHE = vld1q_u32(&hpad1cache[0]);

 //-- variables to calculate SHA256 rounds
 uint32x4_t STATE0_P1; uint32x4_t STATE1_P1; uint32x4_t STATEV_P1; uint32x4_t MSGV_P1; uint32x4_t MSGTMP0_P1; uint32x4_t MSGTMP1_P1; uint32x4_t MSGTMP2_P1; uint32x4_t MSGTMP3_P1;
 uint32x4_t STATE0_P2; uint32x4_t STATE1_P2; uint32x4_t STATEV_P2; uint32x4_t MSGV_P2; uint32x4_t MSGTMP0_P2; uint32x4_t MSGTMP1_P2; uint32x4_t MSGTMP2_P2; uint32x4_t MSGTMP3_P2;
 uint32x4_t STATE0_P3; uint32x4_t STATE1_P3; uint32x4_t STATEV_P3; uint32x4_t MSGV_P3; uint32x4_t MSGTMP0_P3; uint32x4_t MSGTMP1_P3; uint32x4_t MSGTMP2_P3; uint32x4_t MSGTMP3_P3;

 //-- variables to init/keep hash value through SHA256 rounds
 uint32x4_t HASH0_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[0]));
 uint32x4_t HASH1_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[16]));
 uint32x4_t HASH0_SAVE_P2 = vld1q_u32((const uint32_t*)(&hash[32]));
 uint32x4_t HASH1_SAVE_P2 = vld1q_u32((const uint32_t*)(&hash[48]));
 uint32x4_t HASH0_SAVE_P3 = vld1q_u32((const uint32_t*)(&hash[64]));
 uint32x4_t HASH1_SAVE_P3 = vld1q_u32((const uint32_t*)(&hash[80]));

 //-- shuffle hash bytes required by Cryptography Extensions
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));
 HASH0_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P2)));
 HASH1_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P2)));
 HASH0_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P3)));
 HASH1_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P3)));

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state value for SHA256 rounds
   STATE0_P1 = ABCD_INIT;
   STATE0_P2 = ABCD_INIT;
   STATE0_P3 = ABCD_INIT;
   STATE1_P1 = EFGH_INIT;
   STATE1_P2 = EFGH_INIT;
   STATE1_P3 = EFGH_INIT;

   //-- rounds 0-3
   MSGV_P1 = vaddq_u32(HASH0_SAVE_P1,vld1q_u32(&K64[0]));
   MSGV_P2 = vaddq_u32(HASH0_SAVE_P2,vld1q_u32(&K64[0]));
   MSGV_P3 = vaddq_u32(HASH0_SAVE_P3,vld1q_u32(&K64[0]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   MSGTMP0_P1 = vsha256su0q_u32(HASH0_SAVE_P1,HASH1_SAVE_P1);
   MSGTMP0_P2 = vsha256su0q_u32(HASH0_SAVE_P2,HASH1_SAVE_P2);
   MSGTMP0_P3 = vsha256su0q_u32(HASH0_SAVE_P3,HASH1_SAVE_P3);

   //-- rounds 4-7
   MSGV_P1 = vaddq_u32(HASH1_SAVE_P1,vld1q_u32(&K64[4]));
   MSGV_P2 = vaddq_u32(HASH1_SAVE_P2,vld1q_u32(&K64[4]));
   MSGV_P3 = vaddq_u32(HASH1_SAVE_P3,vld1q_u32(&K64[4]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   MSGTMP0_P1 = vsha256su1q_u32(MSGTMP0_P1,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP0_P2 = vsha256su1q_u32(MSGTMP0_P2,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP0_P3 = vsha256su1q_u32(MSGTMP0_P3,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP1_P1 = vsha256su0q_u32(HASH1_SAVE_P1,HPAD0_CACHE);
   MSGTMP1_P2 = vsha256su0q_u32(HASH1_SAVE_P2,HPAD0_CACHE);
   MSGTMP1_P3 = vsha256su0q_u32(HASH1_SAVE_P3,HPAD0_CACHE);

   //-- rounds 8-11
   MSGV_P1 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   MSGV_P2 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   MSGV_P3 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   MSGTMP1_P1 = vsha256su1q_u32(MSGTMP1_P1,HPAD1_CACHE,MSGTMP0_P1);
   MSGTMP1_P2 = vsha256su1q_u32(MSGTMP1_P2,HPAD1_CACHE,MSGTMP0_P2);
   MSGTMP1_P3 = vsha256su1q_u32(MSGTMP1_P3,HPAD1_CACHE,MSGTMP0_P3);
   MSGTMP2_P1 = HPAD0_CACHE;
   MSGTMP2_P2 = HPAD0_CACHE;
   MSGTMP2_P3 = HPAD0_CACHE;

   //-- rounds 12-15
   MSGV_P1 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   MSGV_P2 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   MSGV_P3 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   MSGTMP2_P1 = vsha256su1q_u32(MSGTMP2_P1,MSGTMP0_P1,MSGTMP1_P1);
   MSGTMP2_P2 = vsha256su1q_u32(MSGTMP2_P2,MSGTMP0_P2,MSGTMP1_P2);
   MSGTMP2_P3 = vsha256su1q_u32(MSGTMP2_P3,MSGTMP0_P3,MSGTMP1_P3);
   MSGTMP3_P1 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P1);
   MSGTMP3_P2 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P2);
   MSGTMP3_P3 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P3);

#define SHA256ROUND_X3( \
msgv_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, statev_p1, state0_p1, state1_p1, \
msgv_p2, msgtmp0_p2, msgtmp1_p2, msgtmp2_p2, msgtmp3_p2, statev_p2, state0_p2, state1_p2, \
msgv_p3, msgtmp0_p3, msgtmp1_p3, msgtmp2_p3, msgtmp3_p3, statev_p3, state0_p3, state1_p3, kvalue) \
  msgv_p1 = vaddq_u32(msgtmp0_p1,vld1q_u32(kvalue)); \
  msgv_p2 = vaddq_u32(msgtmp0_p2,vld1q_u32(kvalue)); \
  msgv_p3 = vaddq_u32(msgtmp0_p3,vld1q_u32(kvalue)); \
  statev_p1 = state0_p1; \
  statev_p2 = state0_p2; \
  statev_p3 = state0_p3; \
  state0_p1 = vsha256hq_u32(state0_p1,state1_p1,msgv_p1); \
  state0_p2 = vsha256hq_u32(state0_p2,state1_p2,msgv_p2); \
  state0_p3 = vsha256hq_u32(state0_p3,state1_p3,msgv_p3); \
  state1_p1 = vsha256h2q_u32(state1_p1,statev_p1,msgv_p1); \
  state1_p2 = vsha256h2q_u32(state1_p2,statev_p2,msgv_p2); \
  state1_p3 = vsha256h2q_u32(state1_p3,statev_p3,msgv_p3); \
  msgtmp3_p1 = vsha256su1q_u32(msgtmp3_p1,msgtmp1_p1,msgtmp2_p1); \
  msgtmp3_p2 = vsha256su1q_u32(msgtmp3_p2,msgtmp1_p2,msgtmp2_p2); \
  msgtmp3_p3 = vsha256su1q_u32(msgtmp3_p3,msgtmp1_p3,msgtmp2_p3); \
  msgtmp0_p1 = vsha256su0q_u32(msgtmp0_p1,msgtmp1_p1); \
  msgtmp0_p2 = vsha256su0q_u32(msgtmp0_p2,msgtmp1_p2); \
  msgtmp0_p3 = vsha256su0q_u32(msgtmp0_p3,msgtmp1_p3);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X3(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[16]);
   SHA256ROUND_X3(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[20]);
   SHA256ROUND_X3(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[24]);
   SHA256ROUND_X3(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X3(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[32]);
   SHA256ROUND_X3(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[36]);
   SHA256ROUND_X3(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[40]);
   SHA256ROUND_X3(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATEV_P3,STATE0_P3,STATE1_P3,&K64[44]);

   //-- rounds 48-51
   MSGV_P1 = vaddq_u32(MSGTMP0_P1,vld1q_u32(&K64[48]));
   MSGV_P2 = vaddq_u32(MSGTMP0_P2,vld1q_u32(&K64[48]));
   MSGV_P3 = vaddq_u32(MSGTMP0_P3,vld1q_u32(&K64[48]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   MSGTMP3_P1 = vsha256su1q_u32(MSGTMP3_P1,MSGTMP1_P1,MSGTMP2_P1);
   MSGTMP3_P2 = vsha256su1q_u32(MSGTMP3_P2,MSGTMP1_P2,MSGTMP2_P2);
   MSGTMP3_P3 = vsha256su1q_u32(MSGTMP3_P3,MSGTMP1_P3,MSGTMP2_P3);

   //-- rounds 52-55
   MSGV_P1 = vaddq_u32(MSGTMP1_P1,vld1q_u32(&K64[52]));
   MSGV_P2 = vaddq_u32(MSGTMP1_P2,vld1q_u32(&K64[52]));
   MSGV_P3 = vaddq_u32(MSGTMP1_P3,vld1q_u32(&K64[52]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);

   //-- rounds 56-59
   MSGV_P1 = vaddq_u32(MSGTMP2_P1,vld1q_u32(&K64[56]));
   MSGV_P2 = vaddq_u32(MSGTMP2_P2,vld1q_u32(&K64[56]));
   MSGV_P3 = vaddq_u32(MSGTMP2_P3,vld1q_u32(&K64[56]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);

   //-- rounds 60-63
   MSGV_P1 = vaddq_u32(MSGTMP3_P1,vld1q_u32(&K64[60]));
   MSGV_P2 = vaddq_u32(MSGTMP3_P2,vld1q_u32(&K64[60]));
   MSGV_P3 = vaddq_u32(MSGTMP3_P3,vld1q_u32(&K64[60]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);

   //-- add init state to current state
   HASH0_SAVE_P1 = vaddq_u32(STATE0_P1,ABCD_INIT);
   HASH0_SAVE_P2 = vaddq_u32(STATE0_P2,ABCD_INIT);
   HASH0_SAVE_P3 = vaddq_u32(STATE0_P3,ABCD_INIT);
   HASH1_SAVE_P1 = vaddq_u32(STATE1_P1,EFGH_INIT);
   HASH1_SAVE_P2 = vaddq_u32(STATE1_P2,EFGH_INIT);
   HASH1_SAVE_P3 = vaddq_u32(STATE1_P3,EFGH_INIT);
   }

 //-- shuffle Cryptography Extensions hash value back
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));
 HASH0_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P2)));
 HASH1_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P2)));
 HASH0_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P3)));
 HASH1_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P3)));

 //-- copy/return final hash value into *hash
 vst1q_u32((uint32_t*)(&hash[0]),HASH0_SAVE_P1);
 vst1q_u32((uint32_t*)(&hash[16]),HASH1_SAVE_P1);
 vst1q_u32((uint32_t*)(&hash[32]),HASH0_SAVE_P2);
 vst1q_u32((uint32_t*)(&hash[48]),HASH1_SAVE_P2);
 vst1q_u32((uint32_t*)(&hash[64]),HASH0_SAVE_P3);
 vst1q_u32((uint32_t*)(&hash[80]),HASH1_SAVE_P3);
}

void rsha256_fast_x4(     //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 128 bytes, 4x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 4x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

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

 //-- init values for SHA256 rounds, A-H logic
 static const uint32_t abcdinit[4] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A};
 static const uint32_t efghinit[4] = {0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
 const uint32x4_t ABCD_INIT = vld1q_u32(&abcdinit[0]);
 const uint32x4_t EFGH_INIT = vld1q_u32(&efghinit[0]);

 //-- pre-arranged values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 static const uint32_t hpad0cache[4] = {0x80000000,0x00000000,0x00000000,0x00000000};
 static const uint32_t hpad1cache[4] = {0x00000000,0x00000000,0x00000000,0x00000100};
 const uint32x4_t HPAD0_CACHE = vld1q_u32(&hpad0cache[0]);
 const uint32x4_t HPAD1_CACHE = vld1q_u32(&hpad1cache[0]);

 //-- variables to calculate SHA256 rounds
 uint32x4_t STATE0_P1; uint32x4_t STATE1_P1; uint32x4_t STATEV_P1; uint32x4_t MSGV_P1; uint32x4_t MSGTMP0_P1; uint32x4_t MSGTMP1_P1; uint32x4_t MSGTMP2_P1; uint32x4_t MSGTMP3_P1;
 uint32x4_t STATE0_P2; uint32x4_t STATE1_P2; uint32x4_t STATEV_P2; uint32x4_t MSGV_P2; uint32x4_t MSGTMP0_P2; uint32x4_t MSGTMP1_P2; uint32x4_t MSGTMP2_P2; uint32x4_t MSGTMP3_P2;
 uint32x4_t STATE0_P3; uint32x4_t STATE1_P3; uint32x4_t STATEV_P3; uint32x4_t MSGV_P3; uint32x4_t MSGTMP0_P3; uint32x4_t MSGTMP1_P3; uint32x4_t MSGTMP2_P3; uint32x4_t MSGTMP3_P3;
 uint32x4_t STATE0_P4; uint32x4_t STATE1_P4; uint32x4_t STATEV_P4; uint32x4_t MSGV_P4; uint32x4_t MSGTMP0_P4; uint32x4_t MSGTMP1_P4; uint32x4_t MSGTMP2_P4; uint32x4_t MSGTMP3_P4;

 //-- variables to init/keep hash value through SHA256 rounds
 uint32x4_t HASH0_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[0]));
 uint32x4_t HASH1_SAVE_P1 = vld1q_u32((const uint32_t*)(&hash[16]));
 uint32x4_t HASH0_SAVE_P2 = vld1q_u32((const uint32_t*)(&hash[32]));
 uint32x4_t HASH1_SAVE_P2 = vld1q_u32((const uint32_t*)(&hash[48]));
 uint32x4_t HASH0_SAVE_P3 = vld1q_u32((const uint32_t*)(&hash[64]));
 uint32x4_t HASH1_SAVE_P3 = vld1q_u32((const uint32_t*)(&hash[80]));
 uint32x4_t HASH0_SAVE_P4 = vld1q_u32((const uint32_t*)(&hash[96]));
 uint32x4_t HASH1_SAVE_P4 = vld1q_u32((const uint32_t*)(&hash[112]));

 //-- shuffle hash bytes required by Cryptography Extensions
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));
 HASH0_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P2)));
 HASH1_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P2)));
 HASH0_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P3)));
 HASH1_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P3)));
 HASH0_SAVE_P4 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P4)));
 HASH1_SAVE_P4 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P4)));

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state value for SHA256 rounds
   STATE0_P1 = ABCD_INIT;
   STATE0_P2 = ABCD_INIT;
   STATE0_P3 = ABCD_INIT;
   STATE0_P4 = ABCD_INIT;
   STATE1_P1 = EFGH_INIT;
   STATE1_P2 = EFGH_INIT;
   STATE1_P3 = EFGH_INIT;
   STATE1_P4 = EFGH_INIT;

   //-- rounds 0-3
   MSGV_P1 = vaddq_u32(HASH0_SAVE_P1,vld1q_u32(&K64[0]));
   MSGV_P2 = vaddq_u32(HASH0_SAVE_P2,vld1q_u32(&K64[0]));
   MSGV_P3 = vaddq_u32(HASH0_SAVE_P3,vld1q_u32(&K64[0]));
   MSGV_P4 = vaddq_u32(HASH0_SAVE_P4,vld1q_u32(&K64[0]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);
   MSGTMP0_P1 = vsha256su0q_u32(HASH0_SAVE_P1,HASH1_SAVE_P1);
   MSGTMP0_P2 = vsha256su0q_u32(HASH0_SAVE_P2,HASH1_SAVE_P2);
   MSGTMP0_P3 = vsha256su0q_u32(HASH0_SAVE_P3,HASH1_SAVE_P3);
   MSGTMP0_P4 = vsha256su0q_u32(HASH0_SAVE_P4,HASH1_SAVE_P4);

   //-- rounds 4-7
   MSGV_P1 = vaddq_u32(HASH1_SAVE_P1,vld1q_u32(&K64[4]));
   MSGV_P2 = vaddq_u32(HASH1_SAVE_P2,vld1q_u32(&K64[4]));
   MSGV_P3 = vaddq_u32(HASH1_SAVE_P3,vld1q_u32(&K64[4]));
   MSGV_P4 = vaddq_u32(HASH1_SAVE_P4,vld1q_u32(&K64[4]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);
   MSGTMP0_P1 = vsha256su1q_u32(MSGTMP0_P1,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP0_P2 = vsha256su1q_u32(MSGTMP0_P2,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP0_P3 = vsha256su1q_u32(MSGTMP0_P3,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP0_P4 = vsha256su1q_u32(MSGTMP0_P4,HPAD0_CACHE,HPAD1_CACHE);
   MSGTMP1_P1 = vsha256su0q_u32(HASH1_SAVE_P1,HPAD0_CACHE);
   MSGTMP1_P2 = vsha256su0q_u32(HASH1_SAVE_P2,HPAD0_CACHE);
   MSGTMP1_P3 = vsha256su0q_u32(HASH1_SAVE_P3,HPAD0_CACHE);
   MSGTMP1_P4 = vsha256su0q_u32(HASH1_SAVE_P4,HPAD0_CACHE);

   //-- rounds 8-11
   MSGV_P1 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   MSGV_P2 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   MSGV_P3 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   MSGV_P4 = vaddq_u32(HPAD0_CACHE,vld1q_u32(&K64[8]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);
   MSGTMP1_P1 = vsha256su1q_u32(MSGTMP1_P1,HPAD1_CACHE,MSGTMP0_P1);
   MSGTMP1_P2 = vsha256su1q_u32(MSGTMP1_P2,HPAD1_CACHE,MSGTMP0_P2);
   MSGTMP1_P3 = vsha256su1q_u32(MSGTMP1_P3,HPAD1_CACHE,MSGTMP0_P3);
   MSGTMP1_P4 = vsha256su1q_u32(MSGTMP1_P4,HPAD1_CACHE,MSGTMP0_P4);
   MSGTMP2_P1 = HPAD0_CACHE;
   MSGTMP2_P2 = HPAD0_CACHE;
   MSGTMP2_P3 = HPAD0_CACHE;
   MSGTMP2_P4 = HPAD0_CACHE;

   //-- rounds 12-15
   MSGV_P1 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   MSGV_P2 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   MSGV_P3 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   MSGV_P4 = vaddq_u32(HPAD1_CACHE,vld1q_u32(&K64[12]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);
   MSGTMP2_P1 = vsha256su1q_u32(MSGTMP2_P1,MSGTMP0_P1,MSGTMP1_P1);
   MSGTMP2_P2 = vsha256su1q_u32(MSGTMP2_P2,MSGTMP0_P2,MSGTMP1_P2);
   MSGTMP2_P3 = vsha256su1q_u32(MSGTMP2_P3,MSGTMP0_P3,MSGTMP1_P3);
   MSGTMP2_P4 = vsha256su1q_u32(MSGTMP2_P4,MSGTMP0_P4,MSGTMP1_P4);
   MSGTMP3_P1 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P1);
   MSGTMP3_P2 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P2);
   MSGTMP3_P3 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P3);
   MSGTMP3_P4 = vsha256su0q_u32(HPAD1_CACHE,MSGTMP0_P4);

#define SHA256ROUND_X4( \
msgv_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, statev_p1, state0_p1, state1_p1, \
msgv_p2, msgtmp0_p2, msgtmp1_p2, msgtmp2_p2, msgtmp3_p2, statev_p2, state0_p2, state1_p2, \
msgv_p3, msgtmp0_p3, msgtmp1_p3, msgtmp2_p3, msgtmp3_p3, statev_p3, state0_p3, state1_p3, \
msgv_p4, msgtmp0_p4, msgtmp1_p4, msgtmp2_p4, msgtmp3_p4, statev_p4, state0_p4, state1_p4, kvalue) \
  msgv_p1 = vaddq_u32(msgtmp0_p1,vld1q_u32(kvalue)); \
  msgv_p2 = vaddq_u32(msgtmp0_p2,vld1q_u32(kvalue)); \
  msgv_p3 = vaddq_u32(msgtmp0_p3,vld1q_u32(kvalue)); \
  msgv_p4 = vaddq_u32(msgtmp0_p4,vld1q_u32(kvalue)); \
  statev_p1 = state0_p1; \
  statev_p2 = state0_p2; \
  statev_p3 = state0_p3; \
  statev_p4 = state0_p4; \
  state0_p1 = vsha256hq_u32(state0_p1,state1_p1,msgv_p1); \
  state0_p2 = vsha256hq_u32(state0_p2,state1_p2,msgv_p2); \
  state0_p3 = vsha256hq_u32(state0_p3,state1_p3,msgv_p3); \
  state0_p4 = vsha256hq_u32(state0_p4,state1_p4,msgv_p4); \
  state1_p1 = vsha256h2q_u32(state1_p1,statev_p1,msgv_p1); \
  state1_p2 = vsha256h2q_u32(state1_p2,statev_p2,msgv_p2); \
  state1_p3 = vsha256h2q_u32(state1_p3,statev_p3,msgv_p3); \
  state1_p4 = vsha256h2q_u32(state1_p4,statev_p4,msgv_p4); \
  msgtmp3_p1 = vsha256su1q_u32(msgtmp3_p1,msgtmp1_p1,msgtmp2_p1); \
  msgtmp3_p2 = vsha256su1q_u32(msgtmp3_p2,msgtmp1_p2,msgtmp2_p2); \
  msgtmp3_p3 = vsha256su1q_u32(msgtmp3_p3,msgtmp1_p3,msgtmp2_p3); \
  msgtmp3_p4 = vsha256su1q_u32(msgtmp3_p4,msgtmp1_p4,msgtmp2_p4); \
  msgtmp0_p1 = vsha256su0q_u32(msgtmp0_p1,msgtmp1_p1); \
  msgtmp0_p2 = vsha256su0q_u32(msgtmp0_p2,msgtmp1_p2); \
  msgtmp0_p3 = vsha256su0q_u32(msgtmp0_p3,msgtmp1_p3); \
  msgtmp0_p4 = vsha256su0q_u32(msgtmp0_p4,msgtmp1_p4);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X4(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[16]);
   SHA256ROUND_X4(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[20]);
   SHA256ROUND_X4(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[24]);
   SHA256ROUND_X4(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X4(MSGV_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[32]);
   SHA256ROUND_X4(MSGV_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[36]);
   SHA256ROUND_X4(MSGV_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[40]);
   SHA256ROUND_X4(MSGV_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATEV_P1,STATE0_P1,STATE1_P1,
                  MSGV_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATEV_P2,STATE0_P2,STATE1_P2,
                  MSGV_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATEV_P3,STATE0_P3,STATE1_P3,
                  MSGV_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,STATEV_P4,STATE0_P4,STATE1_P4,&K64[44]);

   //-- rounds 48-51
   MSGV_P1 = vaddq_u32(MSGTMP0_P1,vld1q_u32(&K64[48]));
   MSGV_P2 = vaddq_u32(MSGTMP0_P2,vld1q_u32(&K64[48]));
   MSGV_P3 = vaddq_u32(MSGTMP0_P3,vld1q_u32(&K64[48]));
   MSGV_P4 = vaddq_u32(MSGTMP0_P4,vld1q_u32(&K64[48]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);
   MSGTMP3_P1 = vsha256su1q_u32(MSGTMP3_P1,MSGTMP1_P1,MSGTMP2_P1);
   MSGTMP3_P2 = vsha256su1q_u32(MSGTMP3_P2,MSGTMP1_P2,MSGTMP2_P2);
   MSGTMP3_P3 = vsha256su1q_u32(MSGTMP3_P3,MSGTMP1_P3,MSGTMP2_P3);
   MSGTMP3_P4 = vsha256su1q_u32(MSGTMP3_P4,MSGTMP1_P4,MSGTMP2_P4);

   //-- rounds 52-55
   MSGV_P1 = vaddq_u32(MSGTMP1_P1,vld1q_u32(&K64[52]));
   MSGV_P2 = vaddq_u32(MSGTMP1_P2,vld1q_u32(&K64[52]));
   MSGV_P3 = vaddq_u32(MSGTMP1_P3,vld1q_u32(&K64[52]));
   MSGV_P4 = vaddq_u32(MSGTMP1_P4,vld1q_u32(&K64[52]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);

   //-- rounds 56-59
   MSGV_P1 = vaddq_u32(MSGTMP2_P1,vld1q_u32(&K64[56]));
   MSGV_P2 = vaddq_u32(MSGTMP2_P2,vld1q_u32(&K64[56]));
   MSGV_P3 = vaddq_u32(MSGTMP2_P3,vld1q_u32(&K64[56]));
   MSGV_P4 = vaddq_u32(MSGTMP2_P4,vld1q_u32(&K64[56]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);

   //-- rounds 60-63
   MSGV_P1 = vaddq_u32(MSGTMP3_P1,vld1q_u32(&K64[60]));
   MSGV_P2 = vaddq_u32(MSGTMP3_P2,vld1q_u32(&K64[60]));
   MSGV_P3 = vaddq_u32(MSGTMP3_P3,vld1q_u32(&K64[60]));
   MSGV_P4 = vaddq_u32(MSGTMP3_P4,vld1q_u32(&K64[60]));
   STATEV_P1 = STATE0_P1;
   STATEV_P2 = STATE0_P2;
   STATEV_P3 = STATE0_P3;
   STATEV_P4 = STATE0_P4;
   STATE0_P1 = vsha256hq_u32(STATE0_P1,STATE1_P1,MSGV_P1);
   STATE0_P2 = vsha256hq_u32(STATE0_P2,STATE1_P2,MSGV_P2);
   STATE0_P3 = vsha256hq_u32(STATE0_P3,STATE1_P3,MSGV_P3);
   STATE0_P4 = vsha256hq_u32(STATE0_P4,STATE1_P4,MSGV_P4);
   STATE1_P1 = vsha256h2q_u32(STATE1_P1,STATEV_P1,MSGV_P1);
   STATE1_P2 = vsha256h2q_u32(STATE1_P2,STATEV_P2,MSGV_P2);
   STATE1_P3 = vsha256h2q_u32(STATE1_P3,STATEV_P3,MSGV_P3);
   STATE1_P4 = vsha256h2q_u32(STATE1_P4,STATEV_P4,MSGV_P4);

   //-- add init state to current state
   HASH0_SAVE_P1 = vaddq_u32(STATE0_P1,ABCD_INIT);
   HASH0_SAVE_P2 = vaddq_u32(STATE0_P2,ABCD_INIT);
   HASH0_SAVE_P3 = vaddq_u32(STATE0_P3,ABCD_INIT);
   HASH0_SAVE_P4 = vaddq_u32(STATE0_P4,ABCD_INIT);
   HASH1_SAVE_P1 = vaddq_u32(STATE1_P1,EFGH_INIT);
   HASH1_SAVE_P2 = vaddq_u32(STATE1_P2,EFGH_INIT);
   HASH1_SAVE_P3 = vaddq_u32(STATE1_P3,EFGH_INIT);
   HASH1_SAVE_P4 = vaddq_u32(STATE1_P4,EFGH_INIT);
   }

 //-- shuffle Cryptography Extensions hash value back
 HASH0_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P1)));
 HASH1_SAVE_P1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P1)));
 HASH0_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P2)));
 HASH1_SAVE_P2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P2)));
 HASH0_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P3)));
 HASH1_SAVE_P3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P3)));
 HASH0_SAVE_P4 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH0_SAVE_P4)));
 HASH1_SAVE_P4 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(HASH1_SAVE_P4)));

 //-- copy/return final hash value into *hash
 vst1q_u32((uint32_t*)(&hash[0]),HASH0_SAVE_P1);
 vst1q_u32((uint32_t*)(&hash[16]),HASH1_SAVE_P1);
 vst1q_u32((uint32_t*)(&hash[32]),HASH0_SAVE_P2);
 vst1q_u32((uint32_t*)(&hash[48]),HASH1_SAVE_P2);
 vst1q_u32((uint32_t*)(&hash[64]),HASH0_SAVE_P3);
 vst1q_u32((uint32_t*)(&hash[80]),HASH1_SAVE_P3);
 vst1q_u32((uint32_t*)(&hash[96]),HASH0_SAVE_P4);
 vst1q_u32((uint32_t*)(&hash[112]),HASH1_SAVE_P4);
}

#endif

// <eof>
