/*

This is an implementation of the AES128 algorithm, specifically ECB and CBC mode.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97 
    f5d3d58503b9699de785895a96fdbaaf 
    43b1cd7f598ece23881b00e3ed030688 
    7b0c785e27e8ad3f8223207104725dd4 


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include <string.h> // CBC mode, for memset
#include "aes.h"


/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher.
#define Nr 10

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES128-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
static state_t* _state;

// The array that stores the round keys.
static uint8_t RoundKey[176];

// The Key input to the AES Program
static const uint8_t* Key;

#if defined(CBC) && CBC
  // Initial Vector used only for CBC mode
  static uint8_t* Iv;
#endif

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


// The round constant word array, Rcon[i], contains the values given by 
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
static const uint8_t Rcon[255] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

void _SAND(uint8_t p1, uint8_t p2, uint8_t q1, uint8_t q2, uint8_t * zr, uint8_t * zrm)
{
    uint8_t r = 0xff;
    uint8_t n1 = p1 & q1;
    uint8_t n11 = p2 & q2;
    uint8_t n2 = p2 & q1;
    uint8_t n3 = p1 & q2;
    uint8_t n4 = r ^ n1;

    uint8_t m = n2 ^ n11 ^ r;
    uint8_t z = n3 ^ n4;

    *zr = z;
    *zrm = m;
}

typedef uint8_t word_t;
#define SAND(x1,x2,y1,y2,z1,z2) _SAND(x1,x2,y1,y2,z1,z2)
/*#define SAND(x1,x2) _SAND(x1,0,x2,0,0,0)*/
static uint8_t getSBoxValue(uint8_t num)
{
    return sbox[num];
}
static uint8_t getSBoxValuem(uint8_t num, uint8_t * numm)
{
    /*num ^= *numm;*/
    word_t U_0 = (num ) >> 0;
    word_t U_1 = (num ) >> 1;
    word_t U_2 = (num ) >> 2;
    word_t U_3 = (num ) >> 3;
    word_t U_4 = (num ) >> 4;
    word_t U_5 = (num ) >> 5;
    word_t U_6 = (num ) >> 6;
    word_t U_7 = (num ) >> 7;

    word_t U_0m = (*numm ) >> 0;
    word_t U_1m = (*numm ) >> 1;
    word_t U_2m = (*numm ) >> 2;
    word_t U_3m = (*numm ) >> 3;
    word_t U_4m = (*numm ) >> 4;
    word_t U_5m = (*numm ) >> 5;
    word_t U_6m = (*numm ) >> 6;
    word_t U_7m = (*numm ) >> 7;


    /*word_t U_0m = 0;*/
    /*word_t U_1m = 0;*/
    /*word_t U_2m = 0;*/
    /*word_t U_3m = 0;*/
    /*word_t U_4m = 0;*/
    /*word_t U_5m = 0;*/
    /*word_t U_6m = 0;*/
    /*word_t U_7m = 0;*/



    word_t
        T1,T2,T3,T4,T5,T6,T7,T8,
        T9,T10,T11,T12,T13,T14,T15,T16,
        T17,T18,T19,T20,T21,T22,T23,T24,
        T25, T26, T27;


    word_t
        M1,M2,M3,M4,M5,M6,M7,M8,
        M9,M10,M11,M12,M13,M14,M15,
        M16,M17,M18,M19,M20,M21,M22,
        M23,M24,M25,M26,M27,M28,M29,
        M30,M31,M32,M33,M34,M35,M36,
        M37,M38,M39,M40,M41,M42,M43,
        M44,M45,M46,M47,M48,M49,M50,
        M51,M52,M53,M54,M55,M56,M57,
        M58,M59,M60,M61,M62,M63;

    word_t
        L0,L1,L2,L3,L4,L5,L6,L7,L8,
        L9,L10,L11,L12,L13,L14,
        L15,L16,L17,L18,L19,L20,
        L21,L22,L23,L24,L25,L26,
        L27,L28,L29;

    word_t
    T1m,T2m,T3m,T4m,T5m,T6m,T7m,T8m,
        T9m,T10m,T11m,T12m,T13m,T14m,T15m,T16m,
        T17m,T18m,T19m,T20m,T21m,T22m,T23m,T24m,
        T25m, T26m, T27m,
        M1m,M2m,M3m,M4m,M5m,M6m,M7m,M8m,
        M9m,M10m,M11m,M12m,M13m,M14m,M15m,
        M16m,M17m,M18m,M19m,M20m,M21m,M22m,
        M23m,M24m,M25m,M26m,M27m,M28m,M29m,
        M30m,M31m,M32m,M33m,M34m,M35m,M36m,
        M37m,M38m,M39m,M40m,M41m,M42m,M43m,
        M44m,M45m,M46m,M47m,M48m,M49m,M50m,
        M51m,M52m,M53m,M54m,M55m,M56m,M57m,
        M58m,M59m,M60m,M61m,M62m,M63m,
        L0m,L1m,L2m,L3m,L4m,L5m,L6m,L7m,L8m,
        L9m,L10m,L11m,L12m,L13m,L14m,
        L15m,L16m,L17m,L18m,L19m,L20m,
        L21m,L22m,L23m,L24m,L25m,L26m,
        L27m,L28m,L29m;



    T1 = U_7 ^ U_4;
    T1m = U_7m ^ U_4m;
    T2 = U_7 ^ U_2;
    T2m = U_7m ^ U_2m;
    T3 = U_7 ^ U_1;
    T3m = U_7m ^ U_1m;
    T4 = U_4 ^ U_2;
    T4m = U_4m ^ U_2m;
    T5 = U_3 ^ U_1;
    T5m = U_3m ^ U_1m;
    T6 = T1 ^ T5;
    T6m = T1m ^ T5m;
    T7 = U_6 ^ U_5;
    T7m = U_6m ^ U_5m;
    T8 = U_0 ^ T6;
    T8m = U_0m ^ T6m;
    T9 = U_0 ^ T7;
    T9m = U_0m ^ T7m;
    T10 = T6 ^ T7;
    T10m = T6m ^ T7m;
    T11 = U_6 ^ U_2;
    T11m = U_6m ^ U_2m;
    T12 = U_5 ^ U_2;
    T12m = U_5m ^ U_2m;
    T13 = T3 ^ T4;
    T13m = T3m ^ T4m;
    T14 = T6 ^ T11;
    T14m = T6m ^ T11m;
    T15 = T5 ^ T11;
    T15m = T5m ^ T11m;
    T16 = T5 ^ T12;
    T16m = T5m ^ T12m;
    T17 = T9 ^ T16;
    T17m = T9m ^ T16m;
    T18 = U_4 ^ U_0;
    T18m = U_4m ^ U_0m;
    T19 = T7 ^ T18;
    T19m = T7m ^ T18m;
    T20 = T1 ^ T19;
    T20m = T1m ^ T19m;
    T21 = U_1 ^ U_0;
    T21m = U_1m ^ U_0m;
    T22 = T7 ^ T21;
    T22m = T7m ^ T21m;
    T23 = T2 ^ T22;
    T23m = T2m ^ T22m;
    T24 = T2 ^ T10;
    T24m = T2m ^ T10m;
    T25 = T20 ^ T17;
    T25m = T20m ^ T17m;
    T26 = T3 ^ T16;
    T26m = T3m ^ T16m;
    T27 = T1 ^ T12;
    T27m = T1m ^ T12m;

    /*M1 = T13 & T6;*/
    SAND(T13,T13m,T6,T6m,&M1,&M1m);

    /*M2 = T23 & T8;*/
    SAND(T23,T23m,T8,T8m,&M2,&M2m);

    M3 = T14 ^ M1;
    M3m = T14m ^ M1m;

    /*M4 = T19 & U_0];*/
    SAND(T19,T19m,U_0,U_0m,&M4,&M4m);

    M5 = M4 ^ M1;
    M5m = M4m ^ M1m;

    /*M6 = T3 & T16;*/
    SAND(T3,T3m,T16,T16m,&M6,&M6m);
    /*M7 = T22 & T9;*/
    SAND(T22,T22m,T9,T9m,&M7,&M7m);

    M8 = T26 ^ M6;
    M8m = T26m ^ M6m;

    /*M9 = T20 & T17;*/
    SAND(T20,T20m,T17,T17m,&M9,&M9m);

    M10 = M9 ^ M6;
    M10m = M9m ^ M6m;

    /*M11 = T1 & T15;*/
    SAND(T1,T1m,T15,T15m,&M11,&M11m);
    /*M12 = T4 & T27;*/
    SAND(T4,T4m,T27,T27m,&M12,&M12m);

    M13 = M12 ^ M11;
    M13m = M12m ^ M11m;

    /*M14 = T2 & T10;*/
    SAND(T2,T2m,T10,T10m,&M14,&M14m);

    M15 = M14 ^ M11;
    M15m = M14m ^ M11m;
    M16 = M3 ^ M2;
    M16m = M3m ^ M2m;
    M17 = M5 ^ T24;
    M17m = M5m ^ T24m;
    M18 = M8 ^ M7;
    M18m = M8m ^ M7m;
    M19 = M10 ^ M15;
    M19m = M10m ^ M15m;
    M20 = M16 ^ M13;
    M20m = M16m ^ M13m;
    M21 = M17 ^ M15;
    M21m = M17m ^ M15m;
    M22 = M18 ^ M13;
    M22m = M18m ^ M13m;
    M23 = M19 ^ T25;
    M23m = M19m ^ T25m;
    M24 = M22 ^ M23;
    M24m = M22m ^ M23m;

    /*M25 = M22 & M20;*/
    SAND(M22,M22m,M20,M20m,&M25,&M25m);

    M26 = M21 ^ M25;
    M26m = M21m ^ M25m;
    M27 = M20 ^ M21;
    M27m = M20m ^ M21m;
    M28 = M23 ^ M25;
    M28m = M23m ^ M25m;

    /*M29 = M28 & M27;*/
    SAND(M28,M28m,M27,M27m,&M29,&M29m);
    /*M30 = M26 & M24;*/
    SAND(M26,M26m,M24,M24m,&M30,&M30m);
    /*M31 = M20 & M23;*/
    SAND(M20,M20m,M23,M23m,&M31,&M31m);
    /*M32 = M27 & M31;*/
    SAND(M27,M27m,M31,M31m,&M32,&M32m);

    M33 = M27 ^ M25;
    M33m = M27m ^ M25m;

    /*M34 = M21 & M22;*/
    SAND(M21,M21m,M22,M22m,&M34,&M34m);
    /*M35 = M24 & M34;*/
    SAND(M24,M24m,M34,M34m,&M35,&M35m);

    M36 = M24 ^ M25;
    M36m = M24m ^ M25m;
    M37 = M21 ^ M29;
    M37m = M21m ^ M29m;
    M38 = M32 ^ M33;
    M38m = M32m ^ M33m;
    M39 = M23 ^ M30;
    M39m = M23m ^ M30m;
    M40 = M35 ^ M36;
    M40m = M35m ^ M36m;
    M41 = M38 ^ M40;
    M41m = M38m ^ M40m;
    M42 = M37 ^ M39;
    M42m = M37m ^ M39m;
    M43 = M37 ^ M38;
    M43m = M37m ^ M38m;
    M44 = M39 ^ M40;
    M44m = M39m ^ M40m;
    M45 = M42 ^ M41;
    M45m = M42m ^ M41m;

    /*M46 = M44 & T6;*/
    SAND(M44,M44m,T6,T6m,&M46,&M46m);
    /*M47 = M40 & T8;*/
    SAND(M40,M40m,T8,T8m,&M47,&M47m);
    /*M48 = M39 & U_0];*/
    SAND(M39,M39m,U_0,U_0m,&M48,&M48m);
    /*M49 = M43 & T16;*/
    SAND(M43,M43m,T16,T16m,&M49,&M49m);
    /*M50 = M38 & T9;*/
    SAND(M38,M38m,T9,T9m,&M50,&M50m);
    /*M51 = M37 & T17;*/
    SAND(M37,M37m,T17,T17m,&M51,&M51m);
    /*M52 = M42 & T15;*/
    SAND(M42,M42m,T15,T15m,&M52,&M52m);
    /*M53 = M45 & T27;*/
    SAND(M45,M45m,T27,T27m,&M53,&M53m);
    /*M54 = M41 & T10;*/
    SAND(M41,M41m,T10,T10m,&M54,&M54m);
    /*M55 = M44 & T13;*/
    SAND(M44,M44m,T13,T13m,&M55,&M55m);
    /*M56 = M40 & T23;*/
    SAND(M40,M40m,T23,T23m,&M56,&M56m);
    /*M57 = M39 & T19;*/
    SAND(M39,M39m,T19,T19m,&M57,&M57m);
    /*M58 = M43 & T3;*/
    SAND(M43,M43m,T3,T3m,&M58,&M58m);
    /*M59 = M38 & T22;*/
    SAND(M38,M38m,T22,T22m,&M59,&M59m);
    /*M60 = M37 & T20;*/
    SAND(M37,M37m,T20,T20m,&M60,&M60m);
    /*M61 = M42 & T1;*/
    SAND(M42,M42m,T1,T1m,&M61,&M61m);
    /*M62 = M45 & T4;*/
    SAND(M45,M45m,T4,T4m,&M62,&M62m);
    /*M63 = M41 & T2;*/
    SAND(M41,M41m,T2,T2m,&M63,&M63m);

    L0 = M61 ^ M62;
    L0m = M61m ^ M62m;
    L1 = M50 ^ M56;
    L1m = M50m ^ M56m;
    L2 = M46 ^ M48;
    L2m = M46m ^ M48m;
    L3 = M47 ^ M55;
    L3m = M47m ^ M55m;
    L4 = M54 ^ M58;
    L4m = M54m ^ M58m;
    L5 = M49 ^ M61;
    L5m = M49m ^ M61m;
    L6 = M62 ^ L5;
    L6m = M62m ^ L5m;
    L7 = M46 ^ L3;
    L7m = M46m ^ L3m;
    L8 = M51 ^ M59;
    L8m = M51m ^ M59m;
    L9 = M52 ^ M53;
    L9m = M52m ^ M53m;
    L10 = M53 ^ L4;
    L10m = M53m ^ L4m;
    L11 = M60 ^ L2;
    L11m = M60m ^ L2m;
    L12 = M48 ^ M51;
    L12m = M48m ^ M51m;
    L13 = M50 ^ L0;
    L13m = M50m ^ L0m;
    L14 = M52 ^ M61;
    L14m = M52m ^ M61m;
    L15 = M55 ^ L1;
    L15m = M55m ^ L1m;
    L16 = M56 ^ L0;
    L16m = M56m ^ L0m;
    L17 = M57 ^ L1;
    L17m = M57m ^ L1m;
    L18 = M58 ^ L8;
    L18m = M58m ^ L8m;
    L19 = M63 ^ L4;
    L19m = M63m ^ L4m;
    L20 = L0 ^ L1;
    L20m = L0m ^ L1m;
    L21 = L1 ^ L7;
    L21m = L1m ^ L7m;
    L22 = L3 ^ L12;
    L22m = L3m ^ L12m;
    L23 = L18 ^ L2;
    L23m = L18m ^ L2m;
    L24 = L15 ^ L9;
    L24m = L15m ^ L9m;
    L25 = L6 ^ L10;
    L25m = L6m ^ L10m;
    L26 = L7 ^ L9;
    L26m = L7m ^ L9m;
    L27 = L8 ^ L10;
    L27m = L8m ^ L10m;
    L28 = L11 ^ L14;
    L28m = L11m ^ L14m;
    L29 = L11 ^ L17;
    L29m = L11m ^ L17m;
    U_7 = L6 ^ L24;
    U_7m = L6m ^ L24m;
    U_6 = ~(L16 ^ L26);
    U_6m = L16m ^ L26m;
    /*U_6] = 0x55555555 ^ (L16 ^ L26);*/
    U_5 = ~(L19 ^ L28);
    U_5m = L19m ^ L28m;
    /*U_5] = 0x55555555 ^ (L19 ^ L28);*/
    U_4 = L6 ^ L21;
    U_4m = L6m ^ L21m;
    U_3 = L20 ^ L22;
    U_3m = L20m ^ L22m;
    U_2 = L25 ^ L29;
    U_2m = L25m ^ L29m;
    U_1 = ~(L13 ^ L27);
    U_1m = L13m ^ L27m;
    /*U_1] = 0x55555555 ^ (L13 ^ L27);*/
    U_0 = ~(L6 ^ L23);
    U_0m = L6m ^ L23m;
    /*U_0] = 0x55555555 ^ (L6 ^ L23);*/
    uint8_t t = (uint8_t)(
            ((U_0 & 0x01) << 0) |
            ((U_1 & 0x01) << 1) |
            ((U_2 & 0x01) << 2) |
            ((U_3 & 0x01) << 3) |
            ((U_4 & 0x01) << 4) |
            ((U_5 & 0x01) << 5) |
            ((U_6 & 0x01) << 6) |
            ((U_7 ) << 7)
            );
    uint8_t tm = (uint8_t)(
            ((U_0m & 0x01) << 0) |
            ((U_1m & 0x01) << 1) |
            ((U_2m & 0x01) << 2) |
            ((U_3m & 0x01) << 3) |
            ((U_4m & 0x01) << 4) |
            ((U_5m & 0x01) << 5) |
            ((U_6m & 0x01) << 6) |
            ((U_7m ) << 7)
            );

    *numm = tm;
    return t;
}

static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(void)
{
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for(i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(state_t * state, uint8_t round)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytesm(state_t * state, state_t * statem)
{
  uint8_t i, j;
  for(i = 0; i < 4; ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValuem((*state)[j][i], (*statem)[j] + i);
    }
  }
}

static void SubBytes(state_t * state, state_t * statem)
{
  uint8_t i, j;
  for(i = 0; i < 4; ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t * state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp       = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp       = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t * state)
{
  uint8_t i;
  uint8_t Tmp,Tm,t;
  for(i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t * state)
{
  int i;
  uint8_t a,b,c,d;
  for(i=0;i<4;++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t * state)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j=0;j<4;++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t * state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp=(*state)[3][1];
  (*state)[3][1]=(*state)[2][1];
  (*state)[2][1]=(*state)[1][1];
  (*state)[1][1]=(*state)[0][1];
  (*state)[0][1]=temp;

  // Rotate second row 2 columns to right 
  temp=(*state)[0][2];
  (*state)[0][2]=(*state)[2][2];
  (*state)[2][2]=temp;

  temp=(*state)[1][2];
  (*state)[1][2]=(*state)[3][2];
  (*state)[3][2]=temp;

  // Rotate third row 3 columns to right
  temp=(*state)[0][3];
  (*state)[0][3]=(*state)[1][3];
  (*state)[1][3]=(*state)[2][3];
  (*state)[2][3]=(*state)[3][3];
  (*state)[3][3]=temp;
}


// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t * state)
{
  uint8_t round = 0;
  uint8_t rng[] = {0x13,0x05,0x59,0x81,0x49,0xaf,0xb3,0x30,0x29,0x11,0xc4,0xbb,0x91,0xe4,0x98,0x44};

  state_t * statem = (state_t*)rng;

  // add "random" mask
  int i,j;
  for (i=0; i<4; i++)
  {
      for (j=0; j<4; j++)
      {
          /*(*statem)[i][j] = 0;*/
          (*state)[i][j] ^= (*statem)[i][j];
      }
  }

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(state,0); 

  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round = 1; round < Nr; ++round)
  {

    SubBytesm(state,statem);

    ShiftRows(state);
    ShiftRows(statem);

    MixColumns(state);
    MixColumns(statem);

    AddRoundKey(state,round);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytesm(state, statem);

  ShiftRows(state);
  ShiftRows(statem);

  AddRoundKey(state,Nr);

  // remove mask
  for (i=0; i<4; i++)
  {
      for (j=0; j<4; j++)
      {
          (*state)[i][j] ^= (*statem)[i][j];
      }
  }


}

static void InvCipher(state_t * state)
{
  uint8_t round=0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(state,Nr); 

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round=Nr-1;round>0;round--)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state,round);
    InvMixColumns(state);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state,0);
}

static void BlockCopy(uint8_t* output, const uint8_t* input)
{
  uint8_t i;
  for (i=0;i<KEYLEN;++i)
  {
    output[i] = input[i];
  }
}



/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && ECB


void AES128_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output)
{
  // Copy input to output, and work in-memory on output
  BlockCopy(output, input);

  Key = key;
  KeyExpansion();

  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)output);
}

void AES128_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output)
{
  // Copy input to output, and work in-memory on output
  BlockCopy(output, input);

  // The KeyExpansion routine must be called before encryption.
  Key = key;
  KeyExpansion();

  InvCipher((state_t*)output);
}


#endif // #if defined(ECB) && ECB





#if defined(CBC) && CBC


static void XorWithIv(uint8_t* buf)
{
  uint8_t i;
  for(i = 0; i < KEYLEN; ++i)
  {
    buf[i] ^= Iv[i];
  }
}

void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
  uintptr_t i;
  uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */

  BlockCopy(output, input);
  state_t * state = (state_t*)output;

  // Skip the key expansion if key is passed as 0
  if(0 != key)
  {
    Key = key;
    KeyExpansion();
  }

  if(iv != 0)
  {
    Iv = (uint8_t*)iv;
  }

  for(i = 0; i < length; i += KEYLEN)
  {
    XorWithIv(input);
    BlockCopy(output, input);
    state = (state_t*)output;
    Cipher(state);
    Iv = output;
    input += KEYLEN;
    output += KEYLEN;
  }

  if(remainders)
  {
    BlockCopy(output, input);
    memset(output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
    state = (state_t*)output;
    Cipher(state);
  }
}

void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
  uintptr_t i;
  uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */
  
  BlockCopy(output, input);
  state_t * state = (state_t*)output;

  // Skip the key expansion if key is passed as 0
  if(0 != key)
  {
    Key = key;
    KeyExpansion();
  }

  // If iv is passed as 0, we continue to encrypt without re-setting the Iv
  if(iv != 0)
  {
    Iv = (uint8_t*)iv;
  }

  for(i = 0; i < length; i += KEYLEN)
  {
    BlockCopy(output, input);
    state = (state_t*)output;
    InvCipher(state);
    XorWithIv(output);
    Iv = input;
    input += KEYLEN;
    output += KEYLEN;
  }

  if(remainders)
  {
    BlockCopy(output, input);
    memset(output+remainders, 0, KEYLEN - remainders); /* add 0-padding */
    state = (state_t*)output;
    InvCipher(state);
  }
}


#endif // #if defined(CBC) && CBC


