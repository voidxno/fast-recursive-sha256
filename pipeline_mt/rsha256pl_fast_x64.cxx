/*
 * File: rec_sha256_fast_pl.cxx
 *
 * Author: voidxno
 * Created: 10 Dec 2023
 * Source: https://github.com/voidxno/fast-recursive-sha256
 *
 * Fast recursive SHA256 function, with intrinsics and Intel SHA Extensions
 * Pipelined editions, from x1 to x4
 *
 * rec_sha256_fast_x1() - Identical to rec_sha256_fast()
 * rec_sha256_fast_x2() - 64 bytes, 2x 32bytes
 * rec_sha256_fast_x3() - 96 bytes, 3x 32bytes
 * rec_sha256_fast_x4() - 128 bytes, 4x 32bytes
 *
 * Requirement: Intel/AMD x64 CPU, with SHA extensions
 *
 * LICENSE: Unlicense
 * For more information, please refer to <https://unlicense.org>
 *
 */

#include <stdint.h>

#include <immintrin.h>

#ifdef _WIN32
#include <intrin.h>
#endif

void rec_sha256_fast_x1(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 32 bytes, 1x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 1x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

 //-- array of 64x constants for SHA256 rounds
 alignas(64) static const uint32_t K64[64] = {
   0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
   0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
   0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
   0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
   0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
   0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
   0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
   0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
   };

 //-- shuffle mask for byte order required by SHA Extensions
 const __m128i SHUF_MASK = _mm_set_epi64x(0x0C0D0E0F08090A0B,0x0405060700010203);

 //-- pre-arranged/rotated init values for SHA256 rounds, 8x A-H logic
 const __m128i ABEF_INIT = _mm_set_epi64x(0x6A09E667BB67AE85,0x510E527F9B05688C);
 const __m128i CDGH_INIT = _mm_set_epi64x(0x3C6EF372A54FF53A,0x1F83D9AB5BE0CD19);

 //-- pre-arranged/rotated values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 const __m128i HPAD0_CACHE = _mm_set_epi64x(0x0000000000000000,0x0000000080000000);
 const __m128i HPAD1_CACHE = _mm_set_epi64x(0x0000010000000000,0x0000000000000000);

 //-- variables to calculate SHA256 rounds
 __m128i STATE0_P1; __m128i STATE1_P1; __m128i MSG_P1; __m128i MSGTMP0_P1; __m128i MSGTMP1_P1; __m128i MSGTMP2_P1; __m128i MSGTMP3_P1;

 //-- variables to init/keep hash value through SHA256 rounds
 __m128i HASH0_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[0]));
 __m128i HASH1_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[16]));

 //-- shuffle 32bytes hash/data given required by SHA Extensions
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state values for SHA256 rounds
   STATE0_P1 = ABEF_INIT;
   STATE1_P1 = CDGH_INIT;

   //-- rounds 0-3
   MSG_P1 = HASH0_SAVE_P1;
   MSGTMP0_P1 = MSG_P1;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[0])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);

   //-- rounds 4-7
   MSG_P1 = HASH1_SAVE_P1;
   MSGTMP1_P1 = MSG_P1;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[4])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   MSGTMP0_P1 = _mm_sha256msg1_epu32(MSGTMP0_P1,MSGTMP1_P1);

   //-- rounds 8-11
   MSG_P1 = HPAD0_CACHE;
   MSGTMP2_P1 = MSG_P1;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[8])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   MSGTMP1_P1 = _mm_sha256msg1_epu32(MSGTMP1_P1,MSGTMP2_P1);

   //-- rounds 12-15
   MSG_P1 = HPAD1_CACHE;
   MSGTMP3_P1 = MSG_P1;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[12])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   MSGTMP0_P1 = _mm_add_epi32(MSGTMP0_P1,_mm_alignr_epi8(MSGTMP3_P1,MSGTMP2_P1,4));
   MSGTMP0_P1 = _mm_sha256msg2_epu32(MSGTMP0_P1,MSGTMP3_P1);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   MSGTMP2_P1 = _mm_sha256msg1_epu32(MSGTMP2_P1,MSGTMP3_P1);

#define SHA256ROUND_X1( \
msg_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, state0_p1, state1_p1, kvalue) \
  msg_p1 = msgtmp0_p1; \
  msg_p1 = _mm_add_epi32(msg_p1,_mm_load_si128((__m128i*)(kvalue))); \
  state1_p1 = _mm_sha256rnds2_epu32(state1_p1,state0_p1,msg_p1); \
  msgtmp1_p1 = _mm_add_epi32(msgtmp1_p1,_mm_alignr_epi8(msgtmp0_p1,msgtmp3_p1,4)); \
  msgtmp1_p1 = _mm_sha256msg2_epu32(msgtmp1_p1,msgtmp0_p1); \
  msg_p1 = _mm_shuffle_epi32(msg_p1,0x0E); \
  state0_p1 = _mm_sha256rnds2_epu32(state0_p1,state1_p1,msg_p1); \
  msgtmp3_p1 = _mm_sha256msg1_epu32(msgtmp3_p1,msgtmp0_p1);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X1(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,&K64[16]);
   SHA256ROUND_X1(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,&K64[20]);
   SHA256ROUND_X1(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,&K64[24]);
   SHA256ROUND_X1(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X1(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,&K64[32]);
   SHA256ROUND_X1(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,&K64[36]);
   SHA256ROUND_X1(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,&K64[40]);
   SHA256ROUND_X1(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,&K64[44]);

   //-- rounds 48-51
   SHA256ROUND_X1(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,&K64[48]);

   //-- rounds 52-55
   MSG_P1 = MSGTMP1_P1;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[52])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   MSGTMP2_P1 = _mm_add_epi32(MSGTMP2_P1,_mm_alignr_epi8(MSGTMP1_P1,MSGTMP0_P1,4));
   MSGTMP2_P1 = _mm_sha256msg2_epu32(MSGTMP2_P1,MSGTMP1_P1);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);

   //-- rounds 56-59
   MSG_P1 = MSGTMP2_P1;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[56])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   MSGTMP3_P1 = _mm_add_epi32(MSGTMP3_P1,_mm_alignr_epi8(MSGTMP2_P1,MSGTMP1_P1,4));
   MSGTMP3_P1 = _mm_sha256msg2_epu32(MSGTMP3_P1,MSGTMP2_P1);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);

   //-- rounds 60-63
   MSG_P1 = MSGTMP3_P1;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[60])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);

   //-- add previous/init hash values to current state
   STATE0_P1 = _mm_add_epi32(STATE0_P1,ABEF_INIT);
   STATE1_P1 = _mm_add_epi32(STATE1_P1,CDGH_INIT);

   //-- reorder hash correctly, save for next iteration or final result
   STATE0_P1 = _mm_shuffle_epi32(STATE0_P1,0x1B); // FEBA
   STATE1_P1 = _mm_shuffle_epi32(STATE1_P1,0xB1); // DCHG
   HASH0_SAVE_P1 = _mm_blend_epi16(STATE0_P1,STATE1_P1,0xF0); // DCBA
   HASH1_SAVE_P1 = _mm_alignr_epi8(STATE1_P1,STATE0_P1,8);    // HGFE
   }

 //-- shuffle SHA Extensions hash value back to normal
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);

 //-- copy/return final hash value into *hash
 _mm_storeu_si128((__m128i*)(&hash[0]),HASH0_SAVE_P1);
 _mm_storeu_si128((__m128i*)(&hash[16]),HASH1_SAVE_P1);
}

void rec_sha256_fast_x2(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 64 bytes, 2x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 2x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

 //-- array of 64x constants for SHA256 rounds
 alignas(64) static const uint32_t K64[64] = {
   0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
   0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
   0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
   0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
   0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
   0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
   0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
   0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
   };

 //-- shuffle mask for byte order required by SHA Extensions
 const __m128i SHUF_MASK = _mm_set_epi64x(0x0C0D0E0F08090A0B,0x0405060700010203);

 //-- pre-arranged/rotated init values for SHA256 rounds, 8x A-H logic
 const __m128i ABEF_INIT = _mm_set_epi64x(0x6A09E667BB67AE85,0x510E527F9B05688C);
 const __m128i CDGH_INIT = _mm_set_epi64x(0x3C6EF372A54FF53A,0x1F83D9AB5BE0CD19);

 //-- pre-arranged/rotated values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 const __m128i HPAD0_CACHE = _mm_set_epi64x(0x0000000000000000,0x0000000080000000);
 const __m128i HPAD1_CACHE = _mm_set_epi64x(0x0000010000000000,0x0000000000000000);

 //-- variables to calculate SHA256 rounds
 __m128i STATE0_P1; __m128i STATE1_P1; __m128i MSG_P1; __m128i MSGTMP0_P1; __m128i MSGTMP1_P1; __m128i MSGTMP2_P1; __m128i MSGTMP3_P1;
 __m128i STATE0_P2; __m128i STATE1_P2; __m128i MSG_P2; __m128i MSGTMP0_P2; __m128i MSGTMP1_P2; __m128i MSGTMP2_P2; __m128i MSGTMP3_P2;

 //-- variables to init/keep hash value through SHA256 rounds
 __m128i HASH0_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[0]));
 __m128i HASH1_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[16]));
 __m128i HASH0_SAVE_P2 = _mm_loadu_si128((__m128i*)(&hash[32]));
 __m128i HASH1_SAVE_P2 = _mm_loadu_si128((__m128i*)(&hash[48]));

 //-- shuffle 32bytes hash/data given required by SHA Extensions
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);
 HASH0_SAVE_P2 = _mm_shuffle_epi8(HASH0_SAVE_P2,SHUF_MASK);
 HASH1_SAVE_P2 = _mm_shuffle_epi8(HASH1_SAVE_P2,SHUF_MASK);

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state values for SHA256 rounds
   STATE0_P1 = ABEF_INIT;
   STATE1_P1 = CDGH_INIT;
   STATE0_P2 = ABEF_INIT;
   STATE1_P2 = CDGH_INIT;

   //-- rounds 0-3
   MSG_P1 = HASH0_SAVE_P1;
   MSG_P2 = HASH0_SAVE_P2;
   MSGTMP0_P1 = MSG_P1;
   MSGTMP0_P2 = MSG_P2;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[0])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[0])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);

   //-- rounds 4-7
   MSG_P1 = HASH1_SAVE_P1;
   MSG_P2 = HASH1_SAVE_P2;
   MSGTMP1_P1 = MSG_P1;
   MSGTMP1_P2 = MSG_P2;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[4])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[4])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   MSGTMP0_P1 = _mm_sha256msg1_epu32(MSGTMP0_P1,MSGTMP1_P1);
   MSGTMP0_P2 = _mm_sha256msg1_epu32(MSGTMP0_P2,MSGTMP1_P2);

   //-- rounds 8-11
   MSG_P1 = HPAD0_CACHE;
   MSG_P2 = HPAD0_CACHE;
   MSGTMP2_P1 = MSG_P1;
   MSGTMP2_P2 = MSG_P2;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[8])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[8])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   MSGTMP1_P1 = _mm_sha256msg1_epu32(MSGTMP1_P1,MSGTMP2_P1);
   MSGTMP1_P2 = _mm_sha256msg1_epu32(MSGTMP1_P2,MSGTMP2_P2);

   //-- rounds 12-15
   MSG_P1 = HPAD1_CACHE;
   MSG_P2 = HPAD1_CACHE;
   MSGTMP3_P1 = MSG_P1;
   MSGTMP3_P2 = MSG_P2;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[12])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[12])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   MSGTMP0_P1 = _mm_add_epi32(MSGTMP0_P1,_mm_alignr_epi8(MSGTMP3_P1,MSGTMP2_P1,4));
   MSGTMP0_P2 = _mm_add_epi32(MSGTMP0_P2,_mm_alignr_epi8(MSGTMP3_P2,MSGTMP2_P2,4));
   MSGTMP0_P1 = _mm_sha256msg2_epu32(MSGTMP0_P1,MSGTMP3_P1);
   MSGTMP0_P2 = _mm_sha256msg2_epu32(MSGTMP0_P2,MSGTMP3_P2);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   MSGTMP2_P1 = _mm_sha256msg1_epu32(MSGTMP2_P1,MSGTMP3_P1);
   MSGTMP2_P2 = _mm_sha256msg1_epu32(MSGTMP2_P2,MSGTMP3_P2);

#define SHA256ROUND_X2( \
msg_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, state0_p1, state1_p1, \
msg_p2, msgtmp0_p2, msgtmp1_p2, msgtmp2_p2, msgtmp3_p2, state0_p2, state1_p2, kvalue) \
  msg_p1 = msgtmp0_p1; \
  msg_p2 = msgtmp0_p2; \
  msg_p1 = _mm_add_epi32(msg_p1,_mm_load_si128((__m128i*)(kvalue))); \
  msg_p2 = _mm_add_epi32(msg_p2,_mm_load_si128((__m128i*)(kvalue))); \
  state1_p1 = _mm_sha256rnds2_epu32(state1_p1,state0_p1,msg_p1); \
  state1_p2 = _mm_sha256rnds2_epu32(state1_p2,state0_p2,msg_p2); \
  msgtmp1_p1 = _mm_add_epi32(msgtmp1_p1,_mm_alignr_epi8(msgtmp0_p1,msgtmp3_p1,4)); \
  msgtmp1_p2 = _mm_add_epi32(msgtmp1_p2,_mm_alignr_epi8(msgtmp0_p2,msgtmp3_p2,4)); \
  msgtmp1_p1 = _mm_sha256msg2_epu32(msgtmp1_p1,msgtmp0_p1); \
  msgtmp1_p2 = _mm_sha256msg2_epu32(msgtmp1_p2,msgtmp0_p2); \
  msg_p1 = _mm_shuffle_epi32(msg_p1,0x0E); \
  msg_p2 = _mm_shuffle_epi32(msg_p2,0x0E); \
  state0_p1 = _mm_sha256rnds2_epu32(state0_p1,state1_p1,msg_p1); \
  state0_p2 = _mm_sha256rnds2_epu32(state0_p2,state1_p2,msg_p2); \
  msgtmp3_p1 = _mm_sha256msg1_epu32(msgtmp3_p1,msgtmp0_p1); \
  msgtmp3_p2 = _mm_sha256msg1_epu32(msgtmp3_p2,msgtmp0_p2);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X2(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,&K64[16]);
   SHA256ROUND_X2(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATE0_P2,STATE1_P2,&K64[20]);
   SHA256ROUND_X2(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATE0_P2,STATE1_P2,&K64[24]);
   SHA256ROUND_X2(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATE0_P2,STATE1_P2,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X2(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,&K64[32]);
   SHA256ROUND_X2(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATE0_P2,STATE1_P2,&K64[36]);
   SHA256ROUND_X2(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATE0_P2,STATE1_P2,&K64[40]);
   SHA256ROUND_X2(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATE0_P2,STATE1_P2,&K64[44]);

   //-- rounds 48-51
   SHA256ROUND_X2(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,&K64[48]);

   //-- rounds 52-55
   MSG_P1 = MSGTMP1_P1;
   MSG_P2 = MSGTMP1_P2;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[52])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[52])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   MSGTMP2_P1 = _mm_add_epi32(MSGTMP2_P1,_mm_alignr_epi8(MSGTMP1_P1,MSGTMP0_P1,4));
   MSGTMP2_P2 = _mm_add_epi32(MSGTMP2_P2,_mm_alignr_epi8(MSGTMP1_P2,MSGTMP0_P2,4));
   MSGTMP2_P1 = _mm_sha256msg2_epu32(MSGTMP2_P1,MSGTMP1_P1);
   MSGTMP2_P2 = _mm_sha256msg2_epu32(MSGTMP2_P2,MSGTMP1_P2);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);

   //-- rounds 56-59
   MSG_P1 = MSGTMP2_P1;
   MSG_P2 = MSGTMP2_P2;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[56])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[56])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   MSGTMP3_P1 = _mm_add_epi32(MSGTMP3_P1,_mm_alignr_epi8(MSGTMP2_P1,MSGTMP1_P1,4));
   MSGTMP3_P2 = _mm_add_epi32(MSGTMP3_P2,_mm_alignr_epi8(MSGTMP2_P2,MSGTMP1_P2,4));
   MSGTMP3_P1 = _mm_sha256msg2_epu32(MSGTMP3_P1,MSGTMP2_P1);
   MSGTMP3_P2 = _mm_sha256msg2_epu32(MSGTMP3_P2,MSGTMP2_P2);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);

   //-- rounds 60-63
   MSG_P1 = MSGTMP3_P1;
   MSG_P2 = MSGTMP3_P2;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[60])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[60])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);

   //-- add previous/init hash values to current state
   STATE0_P1 = _mm_add_epi32(STATE0_P1,ABEF_INIT);
   STATE0_P2 = _mm_add_epi32(STATE0_P2,ABEF_INIT);
   STATE1_P1 = _mm_add_epi32(STATE1_P1,CDGH_INIT);
   STATE1_P2 = _mm_add_epi32(STATE1_P2,CDGH_INIT);

   //-- reorder hash correctly, save for next iteration or final result
   STATE0_P1 = _mm_shuffle_epi32(STATE0_P1,0x1B); // FEBA
   STATE1_P1 = _mm_shuffle_epi32(STATE1_P1,0xB1); // DCHG
   STATE0_P2 = _mm_shuffle_epi32(STATE0_P2,0x1B); // FEBA
   STATE1_P2 = _mm_shuffle_epi32(STATE1_P2,0xB1); // DCHG
   HASH0_SAVE_P1 = _mm_blend_epi16(STATE0_P1,STATE1_P1,0xF0); // DCBA
   HASH1_SAVE_P1 = _mm_alignr_epi8(STATE1_P1,STATE0_P1,8);    // HGFE
   HASH0_SAVE_P2 = _mm_blend_epi16(STATE0_P2,STATE1_P2,0xF0); // DCBA
   HASH1_SAVE_P2 = _mm_alignr_epi8(STATE1_P2,STATE0_P2,8);    // HGFE
   }

 //-- shuffle SHA Extensions hash value back to normal
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);
 HASH0_SAVE_P2 = _mm_shuffle_epi8(HASH0_SAVE_P2,SHUF_MASK);
 HASH1_SAVE_P2 = _mm_shuffle_epi8(HASH1_SAVE_P2,SHUF_MASK);

 //-- copy/return final hash value into *hash
 _mm_storeu_si128((__m128i*)(&hash[0]),HASH0_SAVE_P1);
 _mm_storeu_si128((__m128i*)(&hash[16]),HASH1_SAVE_P1);
 _mm_storeu_si128((__m128i*)(&hash[32]),HASH0_SAVE_P2);
 _mm_storeu_si128((__m128i*)(&hash[48]),HASH1_SAVE_P2);
}

void rec_sha256_fast_x3(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 96 bytes, 3x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 3x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

 //-- array of 64x constants for SHA256 rounds
 alignas(64) static const uint32_t K64[64] = {
   0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
   0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
   0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
   0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
   0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
   0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
   0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
   0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
   };

 //-- shuffle mask for byte order required by SHA Extensions
 const __m128i SHUF_MASK = _mm_set_epi64x(0x0C0D0E0F08090A0B,0x0405060700010203);

 //-- pre-arranged/rotated init values for SHA256 rounds, 8x A-H logic
 const __m128i ABEF_INIT = _mm_set_epi64x(0x6A09E667BB67AE85,0x510E527F9B05688C);
 const __m128i CDGH_INIT = _mm_set_epi64x(0x3C6EF372A54FF53A,0x1F83D9AB5BE0CD19);

 //-- pre-arranged/rotated values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 const __m128i HPAD0_CACHE = _mm_set_epi64x(0x0000000000000000,0x0000000080000000);
 const __m128i HPAD1_CACHE = _mm_set_epi64x(0x0000010000000000,0x0000000000000000);

 //-- variables to calculate SHA256 rounds
 __m128i STATE0_P1; __m128i STATE1_P1; __m128i MSG_P1; __m128i MSGTMP0_P1; __m128i MSGTMP1_P1; __m128i MSGTMP2_P1; __m128i MSGTMP3_P1;
 __m128i STATE0_P2; __m128i STATE1_P2; __m128i MSG_P2; __m128i MSGTMP0_P2; __m128i MSGTMP1_P2; __m128i MSGTMP2_P2; __m128i MSGTMP3_P2;
 __m128i STATE0_P3; __m128i STATE1_P3; __m128i MSG_P3; __m128i MSGTMP0_P3; __m128i MSGTMP1_P3; __m128i MSGTMP2_P3; __m128i MSGTMP3_P3;

 //-- variables to init/keep hash value through SHA256 rounds
 __m128i HASH0_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[0]));
 __m128i HASH1_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[16]));
 __m128i HASH0_SAVE_P2 = _mm_loadu_si128((__m128i*)(&hash[32]));
 __m128i HASH1_SAVE_P2 = _mm_loadu_si128((__m128i*)(&hash[48]));
 __m128i HASH0_SAVE_P3 = _mm_loadu_si128((__m128i*)(&hash[64]));
 __m128i HASH1_SAVE_P3 = _mm_loadu_si128((__m128i*)(&hash[80]));

 //-- shuffle 32bytes hash/data given required by SHA Extensions
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);
 HASH0_SAVE_P2 = _mm_shuffle_epi8(HASH0_SAVE_P2,SHUF_MASK);
 HASH1_SAVE_P2 = _mm_shuffle_epi8(HASH1_SAVE_P2,SHUF_MASK);
 HASH0_SAVE_P3 = _mm_shuffle_epi8(HASH0_SAVE_P3,SHUF_MASK);
 HASH1_SAVE_P3 = _mm_shuffle_epi8(HASH1_SAVE_P3,SHUF_MASK);

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state values for SHA256 rounds
   STATE0_P1 = ABEF_INIT;
   STATE1_P1 = CDGH_INIT;
   STATE0_P2 = ABEF_INIT;
   STATE1_P2 = CDGH_INIT;
   STATE0_P3 = ABEF_INIT;
   STATE1_P3 = CDGH_INIT;

   //-- rounds 0-3
   MSG_P1 = HASH0_SAVE_P1;
   MSG_P2 = HASH0_SAVE_P2;
   MSG_P3 = HASH0_SAVE_P3;
   MSGTMP0_P1 = MSG_P1;
   MSGTMP0_P2 = MSG_P2;
   MSGTMP0_P3 = MSG_P3;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[0])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[0])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[0])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);

   //-- rounds 4-7
   MSG_P1 = HASH1_SAVE_P1;
   MSG_P2 = HASH1_SAVE_P2;
   MSG_P3 = HASH1_SAVE_P3;
   MSGTMP1_P1 = MSG_P1;
   MSGTMP1_P2 = MSG_P2;
   MSGTMP1_P3 = MSG_P3;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[4])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[4])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[4])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   MSGTMP0_P1 = _mm_sha256msg1_epu32(MSGTMP0_P1,MSGTMP1_P1);
   MSGTMP0_P2 = _mm_sha256msg1_epu32(MSGTMP0_P2,MSGTMP1_P2);
   MSGTMP0_P3 = _mm_sha256msg1_epu32(MSGTMP0_P3,MSGTMP1_P3);

   //-- rounds 8-11
   MSG_P1 = HPAD0_CACHE;
   MSG_P2 = HPAD0_CACHE;
   MSG_P3 = HPAD0_CACHE;
   MSGTMP2_P1 = MSG_P1;
   MSGTMP2_P2 = MSG_P2;
   MSGTMP2_P3 = MSG_P3;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[8])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[8])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[8])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   MSGTMP1_P1 = _mm_sha256msg1_epu32(MSGTMP1_P1,MSGTMP2_P1);
   MSGTMP1_P2 = _mm_sha256msg1_epu32(MSGTMP1_P2,MSGTMP2_P2);
   MSGTMP1_P3 = _mm_sha256msg1_epu32(MSGTMP1_P3,MSGTMP2_P3);

   //-- rounds 12-15
   MSG_P1 = HPAD1_CACHE;
   MSG_P2 = HPAD1_CACHE;
   MSG_P3 = HPAD1_CACHE;
   MSGTMP3_P1 = MSG_P1;
   MSGTMP3_P2 = MSG_P2;
   MSGTMP3_P3 = MSG_P3;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[12])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[12])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[12])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   MSGTMP0_P1 = _mm_add_epi32(MSGTMP0_P1,_mm_alignr_epi8(MSGTMP3_P1,MSGTMP2_P1,4));
   MSGTMP0_P2 = _mm_add_epi32(MSGTMP0_P2,_mm_alignr_epi8(MSGTMP3_P2,MSGTMP2_P2,4));
   MSGTMP0_P3 = _mm_add_epi32(MSGTMP0_P3,_mm_alignr_epi8(MSGTMP3_P3,MSGTMP2_P3,4));
   MSGTMP0_P1 = _mm_sha256msg2_epu32(MSGTMP0_P1,MSGTMP3_P1);
   MSGTMP0_P2 = _mm_sha256msg2_epu32(MSGTMP0_P2,MSGTMP3_P2);
   MSGTMP0_P3 = _mm_sha256msg2_epu32(MSGTMP0_P3,MSGTMP3_P3);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   MSGTMP2_P1 = _mm_sha256msg1_epu32(MSGTMP2_P1,MSGTMP3_P1);
   MSGTMP2_P2 = _mm_sha256msg1_epu32(MSGTMP2_P2,MSGTMP3_P2);
   MSGTMP2_P3 = _mm_sha256msg1_epu32(MSGTMP2_P3,MSGTMP3_P3);

#define SHA256ROUND_X3( \
msg_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, state0_p1, state1_p1, \
msg_p2, msgtmp0_p2, msgtmp1_p2, msgtmp2_p2, msgtmp3_p2, state0_p2, state1_p2, \
msg_p3, msgtmp0_p3, msgtmp1_p3, msgtmp2_p3, msgtmp3_p3, state0_p3, state1_p3, kvalue) \
  msg_p1 = msgtmp0_p1; \
  msg_p2 = msgtmp0_p2; \
  msg_p3 = msgtmp0_p3; \
  msg_p1 = _mm_add_epi32(msg_p1,_mm_load_si128((__m128i*)(kvalue))); \
  msg_p2 = _mm_add_epi32(msg_p2,_mm_load_si128((__m128i*)(kvalue))); \
  msg_p3 = _mm_add_epi32(msg_p3,_mm_load_si128((__m128i*)(kvalue))); \
  state1_p1 = _mm_sha256rnds2_epu32(state1_p1,state0_p1,msg_p1); \
  state1_p2 = _mm_sha256rnds2_epu32(state1_p2,state0_p2,msg_p2); \
  state1_p3 = _mm_sha256rnds2_epu32(state1_p3,state0_p3,msg_p3); \
  msgtmp1_p1 = _mm_add_epi32(msgtmp1_p1,_mm_alignr_epi8(msgtmp0_p1,msgtmp3_p1,4)); \
  msgtmp1_p2 = _mm_add_epi32(msgtmp1_p2,_mm_alignr_epi8(msgtmp0_p2,msgtmp3_p2,4)); \
  msgtmp1_p3 = _mm_add_epi32(msgtmp1_p3,_mm_alignr_epi8(msgtmp0_p3,msgtmp3_p3,4)); \
  msgtmp1_p1 = _mm_sha256msg2_epu32(msgtmp1_p1,msgtmp0_p1); \
  msgtmp1_p2 = _mm_sha256msg2_epu32(msgtmp1_p2,msgtmp0_p2); \
  msgtmp1_p3 = _mm_sha256msg2_epu32(msgtmp1_p3,msgtmp0_p3); \
  msg_p1 = _mm_shuffle_epi32(msg_p1,0x0E); \
  msg_p2 = _mm_shuffle_epi32(msg_p2,0x0E); \
  msg_p3 = _mm_shuffle_epi32(msg_p3,0x0E); \
  state0_p1 = _mm_sha256rnds2_epu32(state0_p1,state1_p1,msg_p1); \
  state0_p2 = _mm_sha256rnds2_epu32(state0_p2,state1_p2,msg_p2); \
  state0_p3 = _mm_sha256rnds2_epu32(state0_p3,state1_p3,msg_p3); \
  msgtmp3_p1 = _mm_sha256msg1_epu32(msgtmp3_p1,msgtmp0_p1); \
  msgtmp3_p2 = _mm_sha256msg1_epu32(msgtmp3_p2,msgtmp0_p2); \
  msgtmp3_p3 = _mm_sha256msg1_epu32(msgtmp3_p3,msgtmp0_p3);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X3(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATE0_P3,STATE1_P3,&K64[16]);
   SHA256ROUND_X3(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATE0_P3,STATE1_P3,&K64[20]);
   SHA256ROUND_X3(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATE0_P3,STATE1_P3,&K64[24]);
   SHA256ROUND_X3(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATE0_P3,STATE1_P3,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X3(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATE0_P3,STATE1_P3,&K64[32]);
   SHA256ROUND_X3(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATE0_P3,STATE1_P3,&K64[36]);
   SHA256ROUND_X3(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATE0_P3,STATE1_P3,&K64[40]);
   SHA256ROUND_X3(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATE0_P3,STATE1_P3,&K64[44]);

   //-- rounds 48-51
   SHA256ROUND_X3(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATE0_P3,STATE1_P3,&K64[48]);

   //-- rounds 52-55
   MSG_P1 = MSGTMP1_P1;
   MSG_P2 = MSGTMP1_P2;
   MSG_P3 = MSGTMP1_P3;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[52])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[52])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[52])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   MSGTMP2_P1 = _mm_add_epi32(MSGTMP2_P1,_mm_alignr_epi8(MSGTMP1_P1,MSGTMP0_P1,4));
   MSGTMP2_P2 = _mm_add_epi32(MSGTMP2_P2,_mm_alignr_epi8(MSGTMP1_P2,MSGTMP0_P2,4));
   MSGTMP2_P3 = _mm_add_epi32(MSGTMP2_P3,_mm_alignr_epi8(MSGTMP1_P3,MSGTMP0_P3,4));
   MSGTMP2_P1 = _mm_sha256msg2_epu32(MSGTMP2_P1,MSGTMP1_P1);
   MSGTMP2_P2 = _mm_sha256msg2_epu32(MSGTMP2_P2,MSGTMP1_P2);
   MSGTMP2_P3 = _mm_sha256msg2_epu32(MSGTMP2_P3,MSGTMP1_P3);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);

   //-- rounds 56-59
   MSG_P1 = MSGTMP2_P1;
   MSG_P2 = MSGTMP2_P2;
   MSG_P3 = MSGTMP2_P3;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[56])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[56])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[56])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   MSGTMP3_P1 = _mm_add_epi32(MSGTMP3_P1,_mm_alignr_epi8(MSGTMP2_P1,MSGTMP1_P1,4));
   MSGTMP3_P2 = _mm_add_epi32(MSGTMP3_P2,_mm_alignr_epi8(MSGTMP2_P2,MSGTMP1_P2,4));
   MSGTMP3_P3 = _mm_add_epi32(MSGTMP3_P3,_mm_alignr_epi8(MSGTMP2_P3,MSGTMP1_P3,4));
   MSGTMP3_P1 = _mm_sha256msg2_epu32(MSGTMP3_P1,MSGTMP2_P1);
   MSGTMP3_P2 = _mm_sha256msg2_epu32(MSGTMP3_P2,MSGTMP2_P2);
   MSGTMP3_P3 = _mm_sha256msg2_epu32(MSGTMP3_P3,MSGTMP2_P3);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);

   //-- rounds 60-63
   MSG_P1 = MSGTMP3_P1;
   MSG_P2 = MSGTMP3_P2;
   MSG_P3 = MSGTMP3_P3;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[60])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[60])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[60])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);

   //-- add previous/init hash values to current state
   STATE0_P1 = _mm_add_epi32(STATE0_P1,ABEF_INIT);
   STATE0_P2 = _mm_add_epi32(STATE0_P2,ABEF_INIT);
   STATE0_P3 = _mm_add_epi32(STATE0_P3,ABEF_INIT);
   STATE1_P1 = _mm_add_epi32(STATE1_P1,CDGH_INIT);
   STATE1_P2 = _mm_add_epi32(STATE1_P2,CDGH_INIT);
   STATE1_P3 = _mm_add_epi32(STATE1_P3,CDGH_INIT);

   //-- reorder hash correctly, save for next iteration or final result
   STATE0_P1 = _mm_shuffle_epi32(STATE0_P1,0x1B); // FEBA
   STATE1_P1 = _mm_shuffle_epi32(STATE1_P1,0xB1); // DCHG
   STATE0_P2 = _mm_shuffle_epi32(STATE0_P2,0x1B); // FEBA
   STATE1_P2 = _mm_shuffle_epi32(STATE1_P2,0xB1); // DCHG
   STATE0_P3 = _mm_shuffle_epi32(STATE0_P3,0x1B); // FEBA
   STATE1_P3 = _mm_shuffle_epi32(STATE1_P3,0xB1); // DCHG
   HASH0_SAVE_P1 = _mm_blend_epi16(STATE0_P1,STATE1_P1,0xF0); // DCBA
   HASH1_SAVE_P1 = _mm_alignr_epi8(STATE1_P1,STATE0_P1,8);    // HGFE
   HASH0_SAVE_P2 = _mm_blend_epi16(STATE0_P2,STATE1_P2,0xF0); // DCBA
   HASH1_SAVE_P2 = _mm_alignr_epi8(STATE1_P2,STATE0_P2,8);    // HGFE
   HASH0_SAVE_P3 = _mm_blend_epi16(STATE0_P3,STATE1_P3,0xF0); // DCBA
   HASH1_SAVE_P3 = _mm_alignr_epi8(STATE1_P3,STATE0_P3,8);    // HGFE
   }

 //-- shuffle SHA Extensions hash value back to normal
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);
 HASH0_SAVE_P2 = _mm_shuffle_epi8(HASH0_SAVE_P2,SHUF_MASK);
 HASH1_SAVE_P2 = _mm_shuffle_epi8(HASH1_SAVE_P2,SHUF_MASK);
 HASH0_SAVE_P3 = _mm_shuffle_epi8(HASH0_SAVE_P3,SHUF_MASK);
 HASH1_SAVE_P3 = _mm_shuffle_epi8(HASH1_SAVE_P3,SHUF_MASK);

 //-- copy/return final hash value into *hash
 _mm_storeu_si128((__m128i*)(&hash[0]),HASH0_SAVE_P1);
 _mm_storeu_si128((__m128i*)(&hash[16]),HASH1_SAVE_P1);
 _mm_storeu_si128((__m128i*)(&hash[32]),HASH0_SAVE_P2);
 _mm_storeu_si128((__m128i*)(&hash[48]),HASH1_SAVE_P2);
 _mm_storeu_si128((__m128i*)(&hash[64]),HASH0_SAVE_P3);
 _mm_storeu_si128((__m128i*)(&hash[80]),HASH1_SAVE_P3);
}

void rec_sha256_fast_x4(  //-- no return value, result to *hash
uint8_t*       hash,      //-- input/output 128 bytes, 4x 32bytes hash/data SHA256 values
const uint64_t num_iters) //-- number of times to SHA256 4x 32bytes given in *hash
{

 //-- if 0 iterations, result is input hash/data
 if(num_iters <= 0) return;

 //-- array of 64x constants for SHA256 rounds
 alignas(64) static const uint32_t K64[64] = {
   0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
   0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
   0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
   0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
   0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
   0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
   0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
   0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
   };

 //-- shuffle mask for byte order required by SHA Extensions
 const __m128i SHUF_MASK = _mm_set_epi64x(0x0C0D0E0F08090A0B,0x0405060700010203);

 //-- pre-arranged/rotated init values for SHA256 rounds, 8x A-H logic
 const __m128i ABEF_INIT = _mm_set_epi64x(0x6A09E667BB67AE85,0x510E527F9B05688C);
 const __m128i CDGH_INIT = _mm_set_epi64x(0x3C6EF372A54FF53A,0x1F83D9AB5BE0CD19);

 //-- pre-arranged/rotated values for 3rd/4th 16bytes of 1x block, SHA256 padding logic
 const __m128i HPAD0_CACHE = _mm_set_epi64x(0x0000000000000000,0x0000000080000000);
 const __m128i HPAD1_CACHE = _mm_set_epi64x(0x0000010000000000,0x0000000000000000);

 //-- variables to calculate SHA256 rounds
 __m128i STATE0_P1; __m128i STATE1_P1; __m128i MSG_P1; __m128i MSGTMP0_P1; __m128i MSGTMP1_P1; __m128i MSGTMP2_P1; __m128i MSGTMP3_P1;
 __m128i STATE0_P2; __m128i STATE1_P2; __m128i MSG_P2; __m128i MSGTMP0_P2; __m128i MSGTMP1_P2; __m128i MSGTMP2_P2; __m128i MSGTMP3_P2;
 __m128i STATE0_P3; __m128i STATE1_P3; __m128i MSG_P3; __m128i MSGTMP0_P3; __m128i MSGTMP1_P3; __m128i MSGTMP2_P3; __m128i MSGTMP3_P3;
 __m128i STATE0_P4; __m128i STATE1_P4; __m128i MSG_P4; __m128i MSGTMP0_P4; __m128i MSGTMP1_P4; __m128i MSGTMP2_P4; __m128i MSGTMP3_P4;

 //-- variables to init/keep hash value through SHA256 rounds
 __m128i HASH0_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[0]));
 __m128i HASH1_SAVE_P1 = _mm_loadu_si128((__m128i*)(&hash[16]));
 __m128i HASH0_SAVE_P2 = _mm_loadu_si128((__m128i*)(&hash[32]));
 __m128i HASH1_SAVE_P2 = _mm_loadu_si128((__m128i*)(&hash[48]));
 __m128i HASH0_SAVE_P3 = _mm_loadu_si128((__m128i*)(&hash[64]));
 __m128i HASH1_SAVE_P3 = _mm_loadu_si128((__m128i*)(&hash[80]));
 __m128i HASH0_SAVE_P4 = _mm_loadu_si128((__m128i*)(&hash[96]));
 __m128i HASH1_SAVE_P4 = _mm_loadu_si128((__m128i*)(&hash[112]));

 //-- shuffle 32bytes hash/data given required by SHA Extensions
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);
 HASH0_SAVE_P2 = _mm_shuffle_epi8(HASH0_SAVE_P2,SHUF_MASK);
 HASH1_SAVE_P2 = _mm_shuffle_epi8(HASH1_SAVE_P2,SHUF_MASK);
 HASH0_SAVE_P3 = _mm_shuffle_epi8(HASH0_SAVE_P3,SHUF_MASK);
 HASH1_SAVE_P3 = _mm_shuffle_epi8(HASH1_SAVE_P3,SHUF_MASK);
 HASH0_SAVE_P4 = _mm_shuffle_epi8(HASH0_SAVE_P4,SHUF_MASK);
 HASH1_SAVE_P4 = _mm_shuffle_epi8(HASH1_SAVE_P4,SHUF_MASK);

 //-- repeat SHA256 operation number of iterations
 for(uint64_t i = 0; i < num_iters; ++i){

   //-- init state values for SHA256 rounds
   STATE0_P1 = ABEF_INIT;
   STATE1_P1 = CDGH_INIT;
   STATE0_P2 = ABEF_INIT;
   STATE1_P2 = CDGH_INIT;
   STATE0_P3 = ABEF_INIT;
   STATE1_P3 = CDGH_INIT;
   STATE0_P4 = ABEF_INIT;
   STATE1_P4 = CDGH_INIT;

   //-- rounds 0-3
   MSG_P1 = HASH0_SAVE_P1;
   MSG_P2 = HASH0_SAVE_P2;
   MSG_P3 = HASH0_SAVE_P3;
   MSG_P4 = HASH0_SAVE_P4;
   MSGTMP0_P1 = MSG_P1;
   MSGTMP0_P2 = MSG_P2;
   MSGTMP0_P3 = MSG_P3;
   MSGTMP0_P4 = MSG_P4;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[0])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[0])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[0])));
   MSG_P4 = _mm_add_epi32(MSG_P4,_mm_load_si128((__m128i*)(&K64[0])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   STATE1_P4 = _mm_sha256rnds2_epu32(STATE1_P4,STATE0_P4,MSG_P4);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   MSG_P4 = _mm_shuffle_epi32(MSG_P4,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   STATE0_P4 = _mm_sha256rnds2_epu32(STATE0_P4,STATE1_P4,MSG_P4);

   //-- rounds 4-7
   MSG_P1 = HASH1_SAVE_P1;
   MSG_P2 = HASH1_SAVE_P2;
   MSG_P3 = HASH1_SAVE_P3;
   MSG_P4 = HASH1_SAVE_P4;
   MSGTMP1_P1 = MSG_P1;
   MSGTMP1_P2 = MSG_P2;
   MSGTMP1_P3 = MSG_P3;
   MSGTMP1_P4 = MSG_P4;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[4])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[4])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[4])));
   MSG_P4 = _mm_add_epi32(MSG_P4,_mm_load_si128((__m128i*)(&K64[4])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   STATE1_P4 = _mm_sha256rnds2_epu32(STATE1_P4,STATE0_P4,MSG_P4);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   MSG_P4 = _mm_shuffle_epi32(MSG_P4,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   STATE0_P4 = _mm_sha256rnds2_epu32(STATE0_P4,STATE1_P4,MSG_P4);
   MSGTMP0_P1 = _mm_sha256msg1_epu32(MSGTMP0_P1,MSGTMP1_P1);
   MSGTMP0_P2 = _mm_sha256msg1_epu32(MSGTMP0_P2,MSGTMP1_P2);
   MSGTMP0_P3 = _mm_sha256msg1_epu32(MSGTMP0_P3,MSGTMP1_P3);
   MSGTMP0_P4 = _mm_sha256msg1_epu32(MSGTMP0_P4,MSGTMP1_P4);

   //-- rounds 8-11
   MSG_P1 = HPAD0_CACHE;
   MSG_P2 = HPAD0_CACHE;
   MSG_P3 = HPAD0_CACHE;
   MSG_P4 = HPAD0_CACHE;
   MSGTMP2_P1 = MSG_P1;
   MSGTMP2_P2 = MSG_P2;
   MSGTMP2_P3 = MSG_P3;
   MSGTMP2_P4 = MSG_P4;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[8])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[8])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[8])));
   MSG_P4 = _mm_add_epi32(MSG_P4,_mm_load_si128((__m128i*)(&K64[8])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   STATE1_P4 = _mm_sha256rnds2_epu32(STATE1_P4,STATE0_P4,MSG_P4);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   MSG_P4 = _mm_shuffle_epi32(MSG_P4,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   STATE0_P4 = _mm_sha256rnds2_epu32(STATE0_P4,STATE1_P4,MSG_P4);
   MSGTMP1_P1 = _mm_sha256msg1_epu32(MSGTMP1_P1,MSGTMP2_P1);
   MSGTMP1_P2 = _mm_sha256msg1_epu32(MSGTMP1_P2,MSGTMP2_P2);
   MSGTMP1_P3 = _mm_sha256msg1_epu32(MSGTMP1_P3,MSGTMP2_P3);
   MSGTMP1_P4 = _mm_sha256msg1_epu32(MSGTMP1_P4,MSGTMP2_P4);

   //-- rounds 12-15
   MSG_P1 = HPAD1_CACHE;
   MSG_P2 = HPAD1_CACHE;
   MSG_P3 = HPAD1_CACHE;
   MSG_P4 = HPAD1_CACHE;
   MSGTMP3_P1 = MSG_P1;
   MSGTMP3_P2 = MSG_P2;
   MSGTMP3_P3 = MSG_P3;
   MSGTMP3_P4 = MSG_P4;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[12])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[12])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[12])));
   MSG_P4 = _mm_add_epi32(MSG_P4,_mm_load_si128((__m128i*)(&K64[12])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   STATE1_P4 = _mm_sha256rnds2_epu32(STATE1_P4,STATE0_P4,MSG_P4);
   MSGTMP0_P1 = _mm_add_epi32(MSGTMP0_P1,_mm_alignr_epi8(MSGTMP3_P1,MSGTMP2_P1,4));
   MSGTMP0_P2 = _mm_add_epi32(MSGTMP0_P2,_mm_alignr_epi8(MSGTMP3_P2,MSGTMP2_P2,4));
   MSGTMP0_P3 = _mm_add_epi32(MSGTMP0_P3,_mm_alignr_epi8(MSGTMP3_P3,MSGTMP2_P3,4));
   MSGTMP0_P4 = _mm_add_epi32(MSGTMP0_P4,_mm_alignr_epi8(MSGTMP3_P4,MSGTMP2_P4,4));
   MSGTMP0_P1 = _mm_sha256msg2_epu32(MSGTMP0_P1,MSGTMP3_P1);
   MSGTMP0_P2 = _mm_sha256msg2_epu32(MSGTMP0_P2,MSGTMP3_P2);
   MSGTMP0_P3 = _mm_sha256msg2_epu32(MSGTMP0_P3,MSGTMP3_P3);
   MSGTMP0_P4 = _mm_sha256msg2_epu32(MSGTMP0_P4,MSGTMP3_P4);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   MSG_P4 = _mm_shuffle_epi32(MSG_P4,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   STATE0_P4 = _mm_sha256rnds2_epu32(STATE0_P4,STATE1_P4,MSG_P4);
   MSGTMP2_P1 = _mm_sha256msg1_epu32(MSGTMP2_P1,MSGTMP3_P1);
   MSGTMP2_P2 = _mm_sha256msg1_epu32(MSGTMP2_P2,MSGTMP3_P2);
   MSGTMP2_P3 = _mm_sha256msg1_epu32(MSGTMP2_P3,MSGTMP3_P3);
   MSGTMP2_P4 = _mm_sha256msg1_epu32(MSGTMP2_P4,MSGTMP3_P4);

#define SHA256ROUND_X4( \
msg_p1, msgtmp0_p1, msgtmp1_p1, msgtmp2_p1, msgtmp3_p1, state0_p1, state1_p1, \
msg_p2, msgtmp0_p2, msgtmp1_p2, msgtmp2_p2, msgtmp3_p2, state0_p2, state1_p2, \
msg_p3, msgtmp0_p3, msgtmp1_p3, msgtmp2_p3, msgtmp3_p3, state0_p3, state1_p3, \
msg_p4, msgtmp0_p4, msgtmp1_p4, msgtmp2_p4, msgtmp3_p4, state0_p4, state1_p4, kvalue) \
  msg_p1 = msgtmp0_p1; \
  msg_p2 = msgtmp0_p2; \
  msg_p3 = msgtmp0_p3; \
  msg_p4 = msgtmp0_p4; \
  msg_p1 = _mm_add_epi32(msg_p1,_mm_load_si128((__m128i*)(kvalue))); \
  msg_p2 = _mm_add_epi32(msg_p2,_mm_load_si128((__m128i*)(kvalue))); \
  msg_p3 = _mm_add_epi32(msg_p3,_mm_load_si128((__m128i*)(kvalue))); \
  msg_p4 = _mm_add_epi32(msg_p4,_mm_load_si128((__m128i*)(kvalue))); \
  state1_p1 = _mm_sha256rnds2_epu32(state1_p1,state0_p1,msg_p1); \
  state1_p2 = _mm_sha256rnds2_epu32(state1_p2,state0_p2,msg_p2); \
  state1_p3 = _mm_sha256rnds2_epu32(state1_p3,state0_p3,msg_p3); \
  state1_p4 = _mm_sha256rnds2_epu32(state1_p4,state0_p4,msg_p4); \
  msgtmp1_p1 = _mm_add_epi32(msgtmp1_p1,_mm_alignr_epi8(msgtmp0_p1,msgtmp3_p1,4)); \
  msgtmp1_p2 = _mm_add_epi32(msgtmp1_p2,_mm_alignr_epi8(msgtmp0_p2,msgtmp3_p2,4)); \
  msgtmp1_p3 = _mm_add_epi32(msgtmp1_p3,_mm_alignr_epi8(msgtmp0_p3,msgtmp3_p3,4)); \
  msgtmp1_p4 = _mm_add_epi32(msgtmp1_p4,_mm_alignr_epi8(msgtmp0_p4,msgtmp3_p4,4)); \
  msgtmp1_p1 = _mm_sha256msg2_epu32(msgtmp1_p1,msgtmp0_p1); \
  msgtmp1_p2 = _mm_sha256msg2_epu32(msgtmp1_p2,msgtmp0_p2); \
  msgtmp1_p3 = _mm_sha256msg2_epu32(msgtmp1_p3,msgtmp0_p3); \
  msgtmp1_p4 = _mm_sha256msg2_epu32(msgtmp1_p4,msgtmp0_p4); \
  msg_p1 = _mm_shuffle_epi32(msg_p1,0x0E); \
  msg_p2 = _mm_shuffle_epi32(msg_p2,0x0E); \
  msg_p3 = _mm_shuffle_epi32(msg_p3,0x0E); \
  msg_p4 = _mm_shuffle_epi32(msg_p4,0x0E); \
  state0_p1 = _mm_sha256rnds2_epu32(state0_p1,state1_p1,msg_p1); \
  state0_p2 = _mm_sha256rnds2_epu32(state0_p2,state1_p2,msg_p2); \
  state0_p3 = _mm_sha256rnds2_epu32(state0_p3,state1_p3,msg_p3); \
  state0_p4 = _mm_sha256rnds2_epu32(state0_p4,state1_p4,msg_p4); \
  msgtmp3_p1 = _mm_sha256msg1_epu32(msgtmp3_p1,msgtmp0_p1); \
  msgtmp3_p2 = _mm_sha256msg1_epu32(msgtmp3_p2,msgtmp0_p2); \
  msgtmp3_p3 = _mm_sha256msg1_epu32(msgtmp3_p3,msgtmp0_p3); \
  msgtmp3_p4 = _mm_sha256msg1_epu32(msgtmp3_p4,msgtmp0_p4);

   //-- rounds 16-19, 20-23, 24-27, 28-31
   SHA256ROUND_X4(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,STATE0_P4,STATE1_P4,&K64[16]);
   SHA256ROUND_X4(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,STATE0_P4,STATE1_P4,&K64[20]);
   SHA256ROUND_X4(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,STATE0_P4,STATE1_P4,&K64[24]);
   SHA256ROUND_X4(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,STATE0_P4,STATE1_P4,&K64[28]);

   //-- rounds 32-35, 36-39, 40-43, 44-47
   SHA256ROUND_X4(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,STATE0_P4,STATE1_P4,&K64[32]);
   SHA256ROUND_X4(MSG_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,STATE0_P4,STATE1_P4,&K64[36]);
   SHA256ROUND_X4(MSG_P1,MSGTMP2_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP2_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP2_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP2_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,STATE0_P4,STATE1_P4,&K64[40]);
   SHA256ROUND_X4(MSG_P1,MSGTMP3_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP3_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP3_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP3_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,STATE0_P4,STATE1_P4,&K64[44]);

   //-- rounds 48-51
   SHA256ROUND_X4(MSG_P1,MSGTMP0_P1,MSGTMP1_P1,MSGTMP2_P1,MSGTMP3_P1,STATE0_P1,STATE1_P1,
                  MSG_P2,MSGTMP0_P2,MSGTMP1_P2,MSGTMP2_P2,MSGTMP3_P2,STATE0_P2,STATE1_P2,
                  MSG_P3,MSGTMP0_P3,MSGTMP1_P3,MSGTMP2_P3,MSGTMP3_P3,STATE0_P3,STATE1_P3,
                  MSG_P4,MSGTMP0_P4,MSGTMP1_P4,MSGTMP2_P4,MSGTMP3_P4,STATE0_P4,STATE1_P4,&K64[48]);

   //-- rounds 52-55
   MSG_P1 = MSGTMP1_P1;
   MSG_P2 = MSGTMP1_P2;
   MSG_P3 = MSGTMP1_P3;
   MSG_P4 = MSGTMP1_P4;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[52])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[52])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[52])));
   MSG_P4 = _mm_add_epi32(MSG_P4,_mm_load_si128((__m128i*)(&K64[52])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   STATE1_P4 = _mm_sha256rnds2_epu32(STATE1_P4,STATE0_P4,MSG_P4);
   MSGTMP2_P1 = _mm_add_epi32(MSGTMP2_P1,_mm_alignr_epi8(MSGTMP1_P1,MSGTMP0_P1,4));
   MSGTMP2_P2 = _mm_add_epi32(MSGTMP2_P2,_mm_alignr_epi8(MSGTMP1_P2,MSGTMP0_P2,4));
   MSGTMP2_P3 = _mm_add_epi32(MSGTMP2_P3,_mm_alignr_epi8(MSGTMP1_P3,MSGTMP0_P3,4));
   MSGTMP2_P4 = _mm_add_epi32(MSGTMP2_P4,_mm_alignr_epi8(MSGTMP1_P4,MSGTMP0_P4,4));
   MSGTMP2_P1 = _mm_sha256msg2_epu32(MSGTMP2_P1,MSGTMP1_P1);
   MSGTMP2_P2 = _mm_sha256msg2_epu32(MSGTMP2_P2,MSGTMP1_P2);
   MSGTMP2_P3 = _mm_sha256msg2_epu32(MSGTMP2_P3,MSGTMP1_P3);
   MSGTMP2_P4 = _mm_sha256msg2_epu32(MSGTMP2_P4,MSGTMP1_P4);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   MSG_P4 = _mm_shuffle_epi32(MSG_P4,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   STATE0_P4 = _mm_sha256rnds2_epu32(STATE0_P4,STATE1_P4,MSG_P4);

   //-- rounds 56-59
   MSG_P1 = MSGTMP2_P1;
   MSG_P2 = MSGTMP2_P2;
   MSG_P3 = MSGTMP2_P3;
   MSG_P4 = MSGTMP2_P4;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[56])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[56])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[56])));
   MSG_P4 = _mm_add_epi32(MSG_P4,_mm_load_si128((__m128i*)(&K64[56])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   STATE1_P4 = _mm_sha256rnds2_epu32(STATE1_P4,STATE0_P4,MSG_P4);
   MSGTMP3_P1 = _mm_add_epi32(MSGTMP3_P1,_mm_alignr_epi8(MSGTMP2_P1,MSGTMP1_P1,4));
   MSGTMP3_P2 = _mm_add_epi32(MSGTMP3_P2,_mm_alignr_epi8(MSGTMP2_P2,MSGTMP1_P2,4));
   MSGTMP3_P3 = _mm_add_epi32(MSGTMP3_P3,_mm_alignr_epi8(MSGTMP2_P3,MSGTMP1_P3,4));
   MSGTMP3_P4 = _mm_add_epi32(MSGTMP3_P4,_mm_alignr_epi8(MSGTMP2_P4,MSGTMP1_P4,4));
   MSGTMP3_P1 = _mm_sha256msg2_epu32(MSGTMP3_P1,MSGTMP2_P1);
   MSGTMP3_P2 = _mm_sha256msg2_epu32(MSGTMP3_P2,MSGTMP2_P2);
   MSGTMP3_P3 = _mm_sha256msg2_epu32(MSGTMP3_P3,MSGTMP2_P3);
   MSGTMP3_P4 = _mm_sha256msg2_epu32(MSGTMP3_P4,MSGTMP2_P4);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   MSG_P4 = _mm_shuffle_epi32(MSG_P4,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   STATE0_P4 = _mm_sha256rnds2_epu32(STATE0_P4,STATE1_P4,MSG_P4);

   //-- rounds 60-63
   MSG_P1 = MSGTMP3_P1;
   MSG_P2 = MSGTMP3_P2;
   MSG_P3 = MSGTMP3_P3;
   MSG_P4 = MSGTMP3_P4;
   MSG_P1 = _mm_add_epi32(MSG_P1,_mm_load_si128((__m128i*)(&K64[60])));
   MSG_P2 = _mm_add_epi32(MSG_P2,_mm_load_si128((__m128i*)(&K64[60])));
   MSG_P3 = _mm_add_epi32(MSG_P3,_mm_load_si128((__m128i*)(&K64[60])));
   MSG_P4 = _mm_add_epi32(MSG_P4,_mm_load_si128((__m128i*)(&K64[60])));
   STATE1_P1 = _mm_sha256rnds2_epu32(STATE1_P1,STATE0_P1,MSG_P1);
   STATE1_P2 = _mm_sha256rnds2_epu32(STATE1_P2,STATE0_P2,MSG_P2);
   STATE1_P3 = _mm_sha256rnds2_epu32(STATE1_P3,STATE0_P3,MSG_P3);
   STATE1_P4 = _mm_sha256rnds2_epu32(STATE1_P4,STATE0_P4,MSG_P4);
   MSG_P1 = _mm_shuffle_epi32(MSG_P1,0x0E);
   MSG_P2 = _mm_shuffle_epi32(MSG_P2,0x0E);
   MSG_P3 = _mm_shuffle_epi32(MSG_P3,0x0E);
   MSG_P4 = _mm_shuffle_epi32(MSG_P4,0x0E);
   STATE0_P1 = _mm_sha256rnds2_epu32(STATE0_P1,STATE1_P1,MSG_P1);
   STATE0_P2 = _mm_sha256rnds2_epu32(STATE0_P2,STATE1_P2,MSG_P2);
   STATE0_P3 = _mm_sha256rnds2_epu32(STATE0_P3,STATE1_P3,MSG_P3);
   STATE0_P4 = _mm_sha256rnds2_epu32(STATE0_P4,STATE1_P4,MSG_P4);

   //-- add previous/init hash values to current state
   STATE0_P1 = _mm_add_epi32(STATE0_P1,ABEF_INIT);
   STATE0_P2 = _mm_add_epi32(STATE0_P2,ABEF_INIT);
   STATE0_P3 = _mm_add_epi32(STATE0_P3,ABEF_INIT);
   STATE0_P4 = _mm_add_epi32(STATE0_P4,ABEF_INIT);
   STATE1_P1 = _mm_add_epi32(STATE1_P1,CDGH_INIT);
   STATE1_P2 = _mm_add_epi32(STATE1_P2,CDGH_INIT);
   STATE1_P3 = _mm_add_epi32(STATE1_P3,CDGH_INIT);
   STATE1_P4 = _mm_add_epi32(STATE1_P4,CDGH_INIT);

   //-- reorder hash correctly, save for next iteration or final result
   STATE0_P1 = _mm_shuffle_epi32(STATE0_P1,0x1B); // FEBA
   STATE1_P1 = _mm_shuffle_epi32(STATE1_P1,0xB1); // DCHG
   STATE0_P2 = _mm_shuffle_epi32(STATE0_P2,0x1B); // FEBA
   STATE1_P2 = _mm_shuffle_epi32(STATE1_P2,0xB1); // DCHG
   STATE0_P3 = _mm_shuffle_epi32(STATE0_P3,0x1B); // FEBA
   STATE1_P3 = _mm_shuffle_epi32(STATE1_P3,0xB1); // DCHG
   STATE0_P4 = _mm_shuffle_epi32(STATE0_P4,0x1B); // FEBA
   STATE1_P4 = _mm_shuffle_epi32(STATE1_P4,0xB1); // DCHG
   HASH0_SAVE_P1 = _mm_blend_epi16(STATE0_P1,STATE1_P1,0xF0); // DCBA
   HASH1_SAVE_P1 = _mm_alignr_epi8(STATE1_P1,STATE0_P1,8);    // HGFE
   HASH0_SAVE_P2 = _mm_blend_epi16(STATE0_P2,STATE1_P2,0xF0); // DCBA
   HASH1_SAVE_P2 = _mm_alignr_epi8(STATE1_P2,STATE0_P2,8);    // HGFE
   HASH0_SAVE_P3 = _mm_blend_epi16(STATE0_P3,STATE1_P3,0xF0); // DCBA
   HASH1_SAVE_P3 = _mm_alignr_epi8(STATE1_P3,STATE0_P3,8);    // HGFE
   HASH0_SAVE_P4 = _mm_blend_epi16(STATE0_P4,STATE1_P4,0xF0); // DCBA
   HASH1_SAVE_P4 = _mm_alignr_epi8(STATE1_P4,STATE0_P4,8);    // HGFE
   }

 //-- shuffle SHA Extensions hash value back to normal
 HASH0_SAVE_P1 = _mm_shuffle_epi8(HASH0_SAVE_P1,SHUF_MASK);
 HASH1_SAVE_P1 = _mm_shuffle_epi8(HASH1_SAVE_P1,SHUF_MASK);
 HASH0_SAVE_P2 = _mm_shuffle_epi8(HASH0_SAVE_P2,SHUF_MASK);
 HASH1_SAVE_P2 = _mm_shuffle_epi8(HASH1_SAVE_P2,SHUF_MASK);
 HASH0_SAVE_P3 = _mm_shuffle_epi8(HASH0_SAVE_P3,SHUF_MASK);
 HASH1_SAVE_P3 = _mm_shuffle_epi8(HASH1_SAVE_P3,SHUF_MASK);
 HASH0_SAVE_P4 = _mm_shuffle_epi8(HASH0_SAVE_P4,SHUF_MASK);
 HASH1_SAVE_P4 = _mm_shuffle_epi8(HASH1_SAVE_P4,SHUF_MASK);

 //-- copy/return final hash value into *hash
 _mm_storeu_si128((__m128i*)(&hash[0]),HASH0_SAVE_P1);
 _mm_storeu_si128((__m128i*)(&hash[16]),HASH1_SAVE_P1);
 _mm_storeu_si128((__m128i*)(&hash[32]),HASH0_SAVE_P2);
 _mm_storeu_si128((__m128i*)(&hash[48]),HASH1_SAVE_P2);
 _mm_storeu_si128((__m128i*)(&hash[64]),HASH0_SAVE_P3);
 _mm_storeu_si128((__m128i*)(&hash[80]),HASH1_SAVE_P3);
 _mm_storeu_si128((__m128i*)(&hash[96]),HASH0_SAVE_P4);
 _mm_storeu_si128((__m128i*)(&hash[112]),HASH1_SAVE_P4);
}

// <eof>
