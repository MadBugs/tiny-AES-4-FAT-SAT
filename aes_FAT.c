/*
*NYU* 
*NYU* 
*NYU* PLEASE NOTE: ***************************
*NYU* LOTS FOR CHANGES FOR NY HWSEC CLASSES...
*NYU* ****************************************
*NYU* 
*NYU* 

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128

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
        For AES192/256 the key size is proportionally larger.

*/

/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include <string.h> // CBC mode, for memset
#include "aes_FAT.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define nCols 4		//(was Nb)

#define nWords 4         // (was Nk) The number of 32 bit words in a key.
#define nRounds 10       // (was Nr) The number of rounds in AES Cipher.

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[SBOX_SIZ] = {
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

static const uint8_t rsbox[SBOX_SIZ] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
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
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 * From Wikipedia's article on the Rijndael key schedule 
 * @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 
 * "Only the first some of these constants are actually used – 
 * up to rcon[10] for AES-128 (as 11 round keys are needed), 
 * up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private Macros   :                                                        */
/*****************************************************************************/
#ifdef OPT4_BYPASS_SBOXES
#define  Sbox(num) ((num))
#define getSBoxInvert(num) ((num))
#else
#define  Sbox(num) ( sbox[(num)])
#define getSBoxInvert(num) (rsbox[(num)])
#endif /* OPT4_BYPASS_SBOXES */

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

#include <stdio.h>

static uint64_t SWAP64(uint64_t x){
  x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
  x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
  x = (x & 0x00FF00FF00FF00FF) << 8  | (x & 0xFF00FF00FF00FF00) >> 8;
  return x;
}

inline uint8_t get_sbox(uint8_t in) {return Sbox(in);}

void px128_SWP(const char* pch, void * in_128)
{
   uint64_t *p =(uint64_t *) in_128;
   printf(pch, (llu_t)SWAP64(*p),(llu_t)SWAP64((*(p+1)))); 
}

void px128(const char* pch, void * in_128)
{
   uint64_t *p =(uint64_t *) in_128;
   printf(pch, (llu_t)(*p),(llu_t)((*(p+1)))); 
}

/*static*/ void KeyCompression_from_rk1B(uint8_t RK[2*AES_KEYLEN])
{
  unsigned i, w;
  uint8_t tm[4]; //Used for the column/row operations
  uint8_t u8tmp;

  // Recovering the bytes from 4 to 15 of RK0
  for(i=0; i<4; i++) {RK[4+i]=RK[20+i]^RK[16+i];RK[8+i]=RK[24+i]^RK[20+i];RK[12+i]=RK[28+i]^RK[24+i];}

  //Now RK[12-15] will be forwared into the Sbox
  w = (i - 1)*4;      // w points to the previous Word
  tm[0]=RK[w+0];tm[1]=RK[w+1];tm[2]=RK[w+2];tm[3]=RK[w+3]; //Saves RK[12-15] in temp variables
  u8tmp=tm[0];tm[0]=tm[1];tm[1]=tm[2];tm[2]=tm[3];tm[3]= u8tmp;           //L-1-Rotation
  tm[0]=Sbox(tm[0]);tm[1]=Sbox(tm[1]);tm[2]=Sbox(tm[2]);tm[3]=Sbox(tm[3]);//Sbox Mapping
  tm[0]=tm[0] ^ Rcon[i/nWords];                                           //GF-8 Exp Op
  // Recovering the bytes from 0 to 4 of RK0 (the variable i is poiting ot word 4 now)
  for(i=0; i<4; i++) RK[i]=RK[16+i] ^ tm[i];

  const char* pch="\t!!KeyComp *RK0*:%016llx%016llx ****RECOVERED KEY****HACK****\n";
  PEN_CYAN(); px128_SWP(pch, (void*)&RK[0]); PEN_NC();

} /* End of KeyCompression_from_rk1B() */

// This function produces nCols(nRounds+1) round keys. The round keys are used in each round to decrypt the states. 
/*static*/ void KeyExpansion(uint8_t RK[AES_KEYEXPSIZE], const uint8_t Key[AES_KEYLEN])
{
  unsigned i, j, k, w;
  uint8_t tm[4]; //Used for the column/row operations
  uint8_t u8tmp;
  
  for (i = 0; i < nWords; ++i) // per 4-byte loop: 16 bytes copied total
  {
#ifdef OPT3_
#pragma HLS UNROLL
#endif
    j = i*4;            // j is the index of the RK acess
    RK[j+0]=Key[j+0]; RK[j+1]=Key[j+1]; RK[j+2]=Key[j+2]; RK[j+3]=Key[j+3];
  }

  for (     ; i < nCols * (nRounds + 1); ++i) // per 4-byte loop: 176-16=160 bytes copied total
  {
#ifdef OPT3_
#pragma HLS UNROLL
#endif
    if (i % nWords == 0) // Is this an multiple-of-4 Word?
    {
      w = (i - 1)*4;      // w points to the previous Word
      tm[0]=RK[w+0];tm[1]=RK[w+1];tm[2]=RK[w+2];tm[3]=RK[w+3];

      u8tmp=tm[0];tm[0]=tm[1];tm[1]=tm[2];tm[2]=tm[3];tm[3]= u8tmp;           //L-1-Rotation
      tm[0]=Sbox(tm[0]);tm[1]=Sbox(tm[1]);tm[2]=Sbox(tm[2]);tm[3]=Sbox(tm[3]);//Sbox Mapping
      tm[0]=tm[0] ^ Rcon[i/nWords];                                           //GF-8 Exp Op

      j = i*4;            // j is the index of the RK acess
      k = (i - nWords)*4; // k points to the previous RK
      RK[j+0] = RK[k+0]^tm[0]; RK[j+1] = RK[k+1]^tm[1];
      RK[j+2] = RK[k+2]^tm[2]; RK[j+3] = RK[k+3]^tm[3];
    } 
    else
    {
      j = i*4;            // j is the index of the RK acess
      k = (i - nWords)*4; // k points to the previous RK
      w = (i - 1)*4;      // w points to the previous Word
      // Ex. Let i=5 ::> RK[20]=RK[20-16=4]^RK[20-4=16]
      // RK[16]=SBOX()        --> RK[ 0]=????
      // RK[20]=RK[ 4]^RK[16] --> RK[ 4]=RK[20]^RK[16]
      // RK[24]=RK[ 8]^RK[20] --> RK[ 8]=RK[24]^RK[20]
      // RK[28]=RK[12]^RK[24] --> RK[12]=RK[28]^RK[24]
      RK[j+0] = RK[k+0]^RK[w+0]; RK[j+1] = RK[k+1]^RK[w+1];
      RK[j+2] = RK[k+2]^RK[w+2]; RK[j+3] = RK[k+3]^RK[w+3];
    }
  } /* End of for() */
} /* End of KeyExpansion() */

//Used only in test
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key) { KeyExpansion(ctx->RoundKey, key); }

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(uint8_t round,state_t* state,uint8_t* RoundKey)
{
#ifndef OPT1_
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * nCols * 4) + (i * nCols) + j];
    }
  }
#else

  (*state)[0][0] ^= RoundKey[(round * nCols * 4) + (0 * nCols) + 0];
  (*state)[0][1] ^= RoundKey[(round * nCols * 4) + (0 * nCols) + 1];
  (*state)[0][2] ^= RoundKey[(round * nCols * 4) + (0 * nCols) + 2];
  (*state)[0][3] ^= RoundKey[(round * nCols * 4) + (0 * nCols) + 3];

  (*state)[1][0] ^= RoundKey[(round * nCols * 4) + (1 * nCols) + 0];
  (*state)[1][1] ^= RoundKey[(round * nCols * 4) + (1 * nCols) + 1];
  (*state)[1][2] ^= RoundKey[(round * nCols * 4) + (1 * nCols) + 2];
  (*state)[1][3] ^= RoundKey[(round * nCols * 4) + (1 * nCols) + 3];

  (*state)[2][0] ^= RoundKey[(round * nCols * 4) + (2 * nCols) + 0];
  (*state)[2][1] ^= RoundKey[(round * nCols * 4) + (2 * nCols) + 1];
  (*state)[2][2] ^= RoundKey[(round * nCols * 4) + (2 * nCols) + 2];
  (*state)[2][3] ^= RoundKey[(round * nCols * 4) + (2 * nCols) + 3];

  (*state)[3][0] ^= RoundKey[(round * nCols * 4) + (3 * nCols) + 0];
  (*state)[3][1] ^= RoundKey[(round * nCols * 4) + (3 * nCols) + 1];
  (*state)[3][2] ^= RoundKey[(round * nCols * 4) + (3 * nCols) + 2];
  (*state)[3][3] ^= RoundKey[(round * nCols * 4) + (3 * nCols) + 3];
#endif
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void SubBytes(state_t* state)
{
#ifndef OPT2_
   uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = Sbox((*state)[j][i]);
    }
  } 
#else
   (*state)[0][0] = Sbox((*state)[0][0]);
   (*state)[1][0] = Sbox((*state)[1][0]);
   (*state)[2][0] = Sbox((*state)[2][0]);
   (*state)[3][0] = Sbox((*state)[3][0]);
   
   (*state)[0][1] = Sbox((*state)[0][1]);
   (*state)[1][1] = Sbox((*state)[1][1]);
   (*state)[2][1] = Sbox((*state)[2][1]);
   (*state)[3][1] = Sbox((*state)[3][1]);
   
   (*state)[0][2] = Sbox((*state)[0][2]);
   (*state)[1][2] = Sbox((*state)[1][2]);
   (*state)[2][2] = Sbox((*state)[2][2]);
   (*state)[3][2] = Sbox((*state)[3][2]);
   
   (*state)[0][3] = Sbox((*state)[0][3]);
   (*state)[1][3] = Sbox((*state)[1][3]);
   (*state)[2][3] = Sbox((*state)[2][3]);
   (*state)[3][3] = Sbox((*state)[3][3]);
#endif
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows(state_t* state)
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

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
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
void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#ifdef MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
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
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
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
static void InvSubBytes(state_t* state)
{
#ifndef OPT2_
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
#else

   (*state)[0][0] = getSBoxInvert((*state)[0][0]);
   (*state)[1][0] = getSBoxInvert((*state)[1][0]);
   (*state)[2][0] = getSBoxInvert((*state)[2][0]);
   (*state)[3][0] = getSBoxInvert((*state)[3][0]);
   
   (*state)[0][1] = getSBoxInvert((*state)[0][1]);
   (*state)[1][1] = getSBoxInvert((*state)[1][1]);
   (*state)[2][1] = getSBoxInvert((*state)[2][1]);
   (*state)[3][1] = getSBoxInvert((*state)[3][1]);
   
   (*state)[0][2] = getSBoxInvert((*state)[0][2]);
   (*state)[1][2] = getSBoxInvert((*state)[1][2]);
   (*state)[2][2] = getSBoxInvert((*state)[2][2]);
   (*state)[3][2] = getSBoxInvert((*state)[3][2]);
   
   (*state)[0][3] = getSBoxInvert((*state)[0][3]);
   (*state)[1][3] = getSBoxInvert((*state)[1][3]);
   (*state)[2][3] = getSBoxInvert((*state)[2][3]);
   (*state)[3][3] = getSBoxInvert((*state)[3][3]);
#endif
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}

#ifdef FAULT_ATTACK
static  my_uint128_t FaultRegister[FAULTS_INSERT_POINTS_MAX];
static  int           FaultEnabled[FAULTS_INSERT_POINTS_MAX];
static  int              FaultType[FAULTS_INSERT_POINTS_MAX];
void ClearAllFaults(void)
{
  memset(FaultRegister, 0, sizeof(FaultRegister));
  memset(FaultType    , 0, sizeof    (FaultType));
  memset(FaultEnabled , 0, sizeof (FaultEnabled));
}
void setFaultRegister(llu_t h64, llu_t l64, int fault_type, int at_pos)
{
  FaultRegister[at_pos].h[hH]  =h64; 
  FaultRegister[at_pos].h[hL]  =l64;
  FaultType    [at_pos]        =fault_type;
  FaultEnabled [at_pos]        =1;
}

void faultInsert(state_t* state, enum Fault_Insert_Points_t at_pos)
{
  my_uint128_t tmp_128; my_uint128_t *p2 = &tmp_128;
  copy_8_to_128(&tmp_128, (void *) (*state));
  if      (FFS_STUCK_IN_ZERO == FaultType[at_pos])
  {
     p2->h[hH]&=~FaultRegister[at_pos].h[hH]; // fault!!!
     p2->h[hL]&=~FaultRegister[at_pos].h[hL]; // fault!!!
  }
  else if (FFS_STUCK_IN_ONE  == FaultType[at_pos])
  {
     p2->h[hH]|= FaultRegister[at_pos].h[hH]; // fault!!!
     p2->h[hL]|= FaultRegister[at_pos].h[hL]; // fault!!!
  }
  else if (FFS_FLIPS         == FaultType[at_pos])
  {
     p2->h[hH]^= FaultRegister[at_pos].h[hH]; // fault!!!
     p2->h[hL]^= FaultRegister[at_pos].h[hL]; // fault!!!

//p2->h[hH]&= 0xff00000000ff0000ULL; p2->h[hL]&= 0x0000ff00000000ffULL;
//---------------------------------
//CASE 1:R9 input.....CipherTxt
//-------{0,5,a,f} -> {0,7,a,d}
//R9In:
//............00        05        
//............8899aabbccddeeff
//............  09          0f
//CiOut:
//0011223344556677|8899aabbccddeeff
//00            07|    0a    0d    
//ff000000000000ff|0000ff0000ff0000    
//1d............9c|....58....12....
//---------------------------------
  }
  copy_128_to_8((void*) (*state), &tmp_128);
}

#endif //FAULT_ATTACK

//--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher
//--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher--Cipher
/*static*/ void Cipher(state_t* state, uint8_t RoundKey[AES_KEYEXPSIZE])
{
  uint8_t round = 0;
#ifdef FAULT_ATTACK
  state_t state_no_fault;
#endif

  if(FaultEnabled[R01_IN_ADR]) memcpy(&state_no_fault, (*state), sizeof(state_t));
  if(FaultEnabled[R01_IN_ADR]) faultInsert(state, R01_IN_ADR);

#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
  uint64_t *p =(uint64_t *) (*state);
  const char *pch;
  if(FaultEnabled[R01_IN_ADR])
    {
      printf("R%02d::",round); 
      printf("\t>>>FAUL_R01ADR>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else 
    {
      //uint64_t *p =(uint64_t *) (*state);    
      //const char *pch;
      printf("R%02d::",round); pch="\t>>>Ciph00 >>>>>:%016llx%016llx *** BEFORE...AddRoundKey(       ) <-- state\n";
      px128_SWP(pch, (void*)p); 
    }
#endif 

  // Add the First round key to the state before starting the rounds.
  // 01-------------------------------
  AddRoundKey(0, state, RoundKey);  // Round 0
  // ---------------------------------
#ifdef CIPHER_PRINTS_
  printf("R%02d::",round); pch="\t>>>Ciph01 >>>>>:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- state\n";
  px128_SWP(pch, (void*)p); 
#endif 
  
  // There will be nRounds rounds.
  // The first nRounds-1 rounds are identical.
  // These nRounds-1 rounds are executed in the loop below.
#ifndef ROUND_1_ONLY
  for (round = 1; round < nRounds; ++round)
#else
  round = 1;
#endif 
  {

#ifdef FAULT_ATTACK
    if(8==round) if(FaultEnabled[R08_IN_SUB]) memcpy(&state_no_fault, (*state), sizeof(state_t));
    if(8==round) if(FaultEnabled[R08_IN_SUB]) faultInsert(state, R08_IN_SUB);
    if(9==round) if(FaultEnabled[R09_IN_SUB]) memcpy(&state_no_fault, (*state), sizeof(state_t));
    if(9==round) if(FaultEnabled[R09_IN_SUB]) faultInsert(state, R09_IN_SUB);

#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
    if((8==round) && (FaultEnabled[R08_IN_SUB]))
    {
      printf("R%02d::",round); 
      printf("\t>>>FAUL_R08SUB>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((9==round) && (FaultEnabled[R09_IN_SUB]||FaultEnabled[R08_IN_SUB]))
    {
      printf("R%02d::",round); 
      printf("\t>>>FAUL_R09SUB>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((8==round) || (9==round))
    {
      printf("R%02d::",round); 
      if (1 == round) pch="\t>>>Ciph01 >>>>>:%016llx%016llx *** BEFORE...SubBytes(          ) <-- state\n";
      else            pch="\t>>>Ciph05 >>>>>:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- state\n";
      px128_SWP(pch, (void*)p); 
    }
#endif 
#endif

    // 02-------------------------------
    SubBytes(state);

#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
    if((8==round) && (FaultEnabled[R08_IN_SUB]))
    {
      SubBytes(&state_no_fault);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_080SHI>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((9==round) && (FaultEnabled[R09_IN_SUB]||FaultEnabled[R08_IN_SUB]))
    {
      SubBytes(&state_no_fault);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_090SHI>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((8==round) || (9==round))
    {
      printf("R%02d::",round); pch="\t>>>Ciph02 >>>>>:%016llx%016llx *** AFTER....SubBytes(          ) <-- state\n";
      px128_SWP(pch, (void*)p); 
    }
#endif 
    // ---------------------------------

    // 03-------------------------------
    ShiftRows(state);

#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
    if((8==round) && (FaultEnabled[R08_IN_SUB]))
    {
      ShiftRows(&state_no_fault);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_080MIX>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((9==round) && (FaultEnabled[R09_IN_SUB]||FaultEnabled[R08_IN_SUB]))
    {
      ShiftRows(&state_no_fault);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_090MIX>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((8==round) || (9==round))
    {
      printf("R%02d::",round); pch="\t>>>Ciph03 >>>>>:%016llx%016llx *** AFTER....Shif4Rows(         ) <-- state\n";
      px128_SWP(pch, (void*)p); 
    }
#endif 
    // ---------------------------------

    // 04-------------------------------
    MixColumns(state);

#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
    if((8==round) && (FaultEnabled[R08_IN_SUB]))
    {
      MixColumns(&state_no_fault);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_080ADR>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((9==round) && (FaultEnabled[R09_IN_SUB]||FaultEnabled[R08_IN_SUB]))
    {
      MixColumns(&state_no_fault);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_090ADR>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((8==round) || (9==round))
    {
      printf("R%02d::",round); pch="\t>>>Ciph04 >>>>>:%016llx%016llx *** AFTER....MixColumns(        ) <-- state\n";
      px128_SWP(pch, (void*)p); 
    }
#endif 
    // ---------------------------------
    
    // 05-------------------------------
    AddRoundKey(round, state, RoundKey);

#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
    if((8==round) && (FaultEnabled[R08_IN_SUB]))
    {
      AddRoundKey(round, &state_no_fault, RoundKey);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_090SUB>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if((9==round) && (FaultEnabled[R09_IN_SUB]||FaultEnabled[R08_IN_SUB]))
    {
      AddRoundKey(round, &state_no_fault, RoundKey);
      printf("R%02d::",round); 
      printf("\t>>>FAUL_010SUB>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
      printf(" ***                               <-- state\n");
    }
    else if(9==round)
    {
      printf("R%02d::",round); pch="\t>>>Ciph05 >>>>>:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- state\n";
      px128_SWP(pch, (void*)p); 
    }
#endif 
    // ---------------------------------
  } // for (rounds ...)


#ifdef FAULT_ATTACK
  if (FaultEnabled[R10_IN_SUB]) memcpy(&state_no_fault, (*state), sizeof(state_t));
  if (FaultEnabled[R10_IN_SUB]) faultInsert(state, R10_IN_SUB);

#if defined(FAULT_PRINTS_AESC_1)
  if (FaultEnabled[R10_IN_SUB])
  {
    printf("R%02d::",round); 
    printf("\t>>>FAUL_R10SUB>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
    printf(" ***                               <-- state\n");
  }
#endif 
#endif // FAULT_ATTACK
  
#ifndef ROUND_1_ONLY
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  // 02-------------------------------
  SubBytes(state);
#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
  if (FaultEnabled[R10_IN_SUB] || FaultEnabled[R09_IN_SUB] || FaultEnabled[R08_IN_SUB])
  {
    SubBytes(&state_no_fault);
    printf("R%02d::",round); 
    printf("\t>>>FAUL_R10SHI>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
    printf(" ***                               <-- state\n");
  }
  else
  {
    printf("R%02d::",round); pch="\t>>>Ciph02 >>>>>:%016llx%016llx *** AFTER....SubBytes(          ) <-- state\n";
    px128_SWP(pch, (void*)p); 
  }
#endif 

  // 03-------------------------------
  ShiftRows(state);
#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
  if (FaultEnabled[R10_IN_SUB] || FaultEnabled[R09_IN_SUB] || FaultEnabled[R08_IN_SUB])
  {
    ShiftRows(&state_no_fault);
    printf("R%02d::",round); 
    printf("\t>>>FAUL_R10ADR>:"); phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
    printf(" ***                               <-- state\n");
  }
  else
  {
    printf("R%02d::",round); pch="\t>>>Ciph03 >>>>>:%016llx%016llx *** AFTER....ShiftRows(         ) <-- state\n";
    px128_SWP(pch, (void*)p); 
  }
#endif 
  // 05-------------------------------
  //
#ifdef FAULT_ATTACK
  if (FaultEnabled[R10_IN_ADR]) memcpy(&state_no_fault, (*state), sizeof(state_t));
  if (FaultEnabled[R10_IN_ADR]) faultInsert(state, R10_IN_ADR);
#endif // FAULT_ATTACK

  AddRoundKey(nRounds, state, RoundKey);
#if defined(CIPHER_PRINTS_) || defined(FAULT_PRINTS_AESC_1)
  if (FaultEnabled[R10_IN_ADR] || FaultEnabled[R10_IN_SUB] || FaultEnabled[R09_IN_SUB] || FaultEnabled[R08_IN_SUB])
  {
    AddRoundKey(nRounds, &state_no_fault, RoundKey);
    printf("R%02d::",round); 
    printf("\t>>>FAUL_R10CIP>:");
    phex_n_colored_not_match((void*)p, (void*) &state_no_fault); 
    printf(" ***                               <-- state\n");
  }
  else
  {
    printf("R%02d::",round); pch="\t>>>Ciph05 >>>>>:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- state\n";
    px128_SWP(pch, (void*)p); 
  }
#endif 

#endif //ROUND_1_ONLY
} /* End of Cipher() */


//--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher
//--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher--InvCipher
/*static*/ void InvCipher(state_t* state, uint8_t RoundKey[AES_KEYEXPSIZE])
{
  uint8_t round = nRounds;
#ifdef  INVCIPHER_PRINTS_
  state_t state_0; uint64_t *p0=(uint64_t *) &state_0; uint64_t *p =(uint64_t *) (*state);    
  memcpy(state_0, state, sizeof(state_t));
  const char *pch;
#endif 

#ifdef ROUND_1_ONLY
    round = 1;
#endif

#ifdef  INVCIPHER_PRINTS_
  printf("R%02d::",round); pch="\t<<ICiph04 <<<<<:%016llx%016llx *** BEFORE...AddRoundKey(       ) <-- state\n";
  px128_SWP(pch, (void*)p); 
#endif 

  // 05-------------------------------
  AddRoundKey(round, state, RoundKey);
  // ---------------------------------
  // HWSEC: We want to discover key=RoundKey[0]
  // HWSEC: NOW state{1}=state{0} XOR key=RoundKey[1] (all 128 bits are xored)

#ifdef  INVCIPHER_PRINTS_
  //printf("R%02d::",round); pch="\t!!ICiph04 *RK1*:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- RoundKey(1) **HACK** \n";
  //uint64_t rk1_h=(*p0)^(*p);
  //uint64_t rk1_l=(*(p0+1))^(*(p+1));
  //PEN_YELLOW(); px128_SWP(pch, (void*)rk1); PEN_NC();
  //PEN_YELLOW(); printf(pch, (llu_t)SWAP64(rk1_h),(llu_t)SWAP64(rk1_l)); PEN_NC();
#endif 

#ifdef  INVCIPHER_PRINTS_
  printf("R%02d::",round); pch="\t<<ICiph04 <<<<<:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- state\n";
  px128_SWP(pch, (void*)p); 
#endif 

// xxxxxxxxxxxxxxxxx
#ifdef ROUND_1_ONLY
    // 04-------------------------------
    InvMixColumns(state);
    // ---------------------------------
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph03 <<<<<:%016llx%016llx *** AFTER....InvMixColumns(     ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 

    // 03-------------------------------
    InvShiftRows(state);
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph02 <<<<<:%016llx%016llx *** AFTER....InvShiftRows(      ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 
    // ---------------------------------

    // 02-------------------------------
    InvSubBytes(state);
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph01 <<<<<:%016llx%016llx *** AFTER....InvSubBytes(       ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 
    // ---------------------------------
    round--;

// xxxxxxxxxxxxxxxxx
#else  //else ROUND_1_ONLY

  // There will be nRounds rounds.
  // The first nRounds-1 rounds are identical.
  // These nRounds-1 rounds are executed in the loop below.
  for (round--; round > 0; --round)
  {
    InvShiftRows(state);
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph02 <<<<<:%016llx%016llx *** AFTER....InvShiftRows(      ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 

    InvSubBytes(state);
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph01 <<<<<:%016llx%016llx *** AFTER....InvSubBytes(       ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 

    AddRoundKey(round, state, RoundKey);
#ifdef  INVCIPHER_PRINTS_
  printf("R%02d::",round); pch="\t<<ICiph04 <<<<<:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- state\n";
  px128_SWP(pch, (void*)p); 
#endif 

    InvMixColumns(state);
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph03 <<<<<:%016llx%016llx *** AFTER....InvMixColumns(     ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 
  } // for ()

  // The last round is given below.
  // The MixColumns function is not here in the last round.
 
  InvShiftRows(state);
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph02 <<<<<:%016llx%016llx *** AFTER....InvShiftRows(      ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 

  InvSubBytes(state);
#ifdef  INVCIPHER_PRINTS_
    printf("R%02d::",round); pch="\t<<ICiph01 <<<<<:%016llx%016llx *** AFTER....InvSubBytes(       ) <-- state\n";
    px128_SWP(pch, (void*)p); 
#endif 

#endif //not ROUND_1_ONLY
// xxxxxxxxxxxxxxxxx

  // 01-------------------------------
  AddRoundKey(round, state, RoundKey); // Round 0

#ifdef  INVCIPHER_PRINTS_
  printf("R%02d::",round); pch="\t<<ICiph00 <<<<<:%016llx%016llx *** AFTER....AddRoundKey(       ) <-- state\n";
  px128_SWP(pch, (void*)p); 
#endif 

#if 0
  // TBD
  // HWSEC: Finding the Key now...
  uint8_t RoundKey01[2*AES_KEYLEN]; 
  memset(RoundKey01, 0, sizeof(RoundKey01));
  memcpy(&RoundKey01[1*AES_KEYLEN             ], &rk1_h, sizeof(rk1_h));
  memcpy(&RoundKey01[1*AES_KEYLEN+AES_KEYLEN/2], &rk1_l, sizeof(rk1_l));
  KeyCompression_from_rk1B(RoundKey01);
#endif
  // ---------------------------------
} /* End of InvCipher() */

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
void AES_ECB_encrypt(struct AES_ctx *ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}

