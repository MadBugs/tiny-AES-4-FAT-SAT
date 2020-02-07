/*
*NYU*
*NYU*
*NYU* PLEASE NOTE: ***************************
*NYU* LOTS FOR CHANGES FOR NY HWSEC CLASSES...
*NYU* ****************************************
*NYU*
*NYU*
*/

#ifndef _AES_H_
#define _AES_H_

//------------------------------
// MENU OF OPTIONS... 
//------------------------------
#undef  ROUND_1_ONLY
#undef  OPT4_BYPASS_SBOXES
#define ENABLE_COLOR_OUTPUT
// -----------------------------
#undef  OPT1_
#undef  OPT2_
#undef  OPT3_
#undef  INVCIPHER_PRINTS_
#undef  CIPHER_PRINTS_
#define FAULT_PRINTS_AESC_1
#define FAULT_PRINTS_MAIN_1

#define FAULT_ATTACK
// -----------------------------
#define MULTIPLY_AS_A_FUNCTION 0
// -----------------------------

#include <stdint.h>

#define AES_BLOCKLEN    16 //Block length in bytes AES is 128b block only
#define AES_KEYLEN      16 // Key length in bytes
#define AES_KEYEXPSIZE 176

#define FFS_STUCK_IN_ZERO 0
#define FFS_STUCK_IN_ONE  1
#define FFS_FLIPS         2

// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

enum Fault_Insert_Points_t
{
R01_IN_ADR, // this one really changing the PT
R01_IN_SUB,
R02_IN_SUB,
R03_IN_SUB,
R04_IN_SUB,
R05_IN_SUB,
R06_IN_SUB,
R07_IN_SUB,
R08_IN_SUB,
R09_IN_SUB,
R10_IN_SUB,
R10_IN_ADR, 
FAULTS_INSERT_POINTS_MAX
};
//#define FAULTS_INSERT_POINTS_MAX sizeof(Fault_Insert_Points_t) 

#define SBOX_SIZ  256

struct AES_ctx
{
  uint8_t RoundKey[AES_KEYEXPSIZE];
};

typedef long long unsigned int   llu_t;

#define MAX_SIZE_COLOR_ESC_SEQ  10 // Hope it is big enough
#ifdef  ENABLE_COLOR_OUTPUT
#define PEN_NC()       printf("\e[0m")         // NC - Normal Color
#define PEN_NORMAL()   PEN_NC()                // NC - Normal Color
#define PEN_RED()      printf("\e[1;31m")
#define PEN_GREEN()    printf("\e[1;32m")
#define PEN_YELLOW()   printf("\e[1;33m")
#define PEN_BLUE()     printf("\e[1;34m")
#define PEN_MARGENTA() printf("\e[1;35m")
#define PEN_CYAN()     printf("\e[1;36m")
#define PEN_WHITE()    printf("\e[1;37m")
#else
#define PEN_NC()     
#define PEN_YELLOW() 
#define PEN_RED()    
#define PEN_GREEN()  
#define PEN_BLUE()   
#define PEN_MARGENTA()
#define PEN_CYAN()   
#define PEN_WHITE()
#endif

#if 0
# Define some colors first (you can put this in your .bashrc file):
red='\e[0;31m'
RED='\e[1;31m'
blue='\e[0;34m'
BLUE='\e[1;34m'
cyan='\e[0;36m'
CYAN='\e[1;36m'
green='\e[0;32m'
GREEN='\e[1;32m'
yellow='\e[0;33m'
YELLOW='\e[1;33m'
NC='\e[0m'
#endif

#ifdef MAIN_
uint8_t const hT[2]={0x0,0x1};
#else
extern uint8_t const hT[2];
#endif
#define hH    0x0
#define hL    0x1 
//-----------
#ifdef MAIN_
uint8_t const wT[4]={0x1,0x0,0x3,0x2};
#else
extern uint8_t const wT[4];
#endif
#define wHH   0x1
#define wHL   0x0 
#define wLH   0x3  
#define wLL   0x2  
//-----------
#ifdef MAIN_
uint8_t const bT[16]={0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
	              0xf,0xe,0xd,0xc,0xb,0xa,0x9,0x8};
#else
extern uint8_t const bT[16];
#endif
#define bHHHH 0x7 
#define bHHHL 0x6
#define bHHLH 0x5
#define bHHLL 0x4
#define bHLHH 0x3
#define bHLHL 0x2
#define bHLLH 0x1
#define bHLLL 0x0
#define bLHHH 0xf 
#define bLHHL 0xe
#define bLHLH 0xd
#define bLHLL 0xc
#define bLLHH 0xb
#define bLLHL 0xa
#define bLLLH 0x9
#define bLLLL 0x8
//-----------
typedef union
{
  uint64_t h[ 2];
  uint32_t w[ 4];
  uint8_t  b[16];
  struct 
  {
    uint64_t 
    b008:1, b007:1, b006:1, b005:1, b004:1, b003:1, b002:1, b001:1,
    b016:1, b015:1, b014:1, b013:1, b012:1, b011:1, b010:1, b009:1,
    b024:1, b023:1, b022:1, b021:1, b020:1, b019:1, b018:1, b017:1,
    b032:1, b031:1, b030:1, b029:1, b028:1, b027:1, b026:1, b025:1,
    b040:1, b039:1, b038:1, b037:1, b036:1, b035:1, b034:1, b033:1,
    b048:1, b047:1, b046:1, b045:1, b044:1, b043:1, b042:1, b041:1,
    b056:1, b055:1, b054:1, b053:1, b052:1, b051:1, b050:1, b049:1,
    b064:1, b063:1, b062:1, b061:1, b060:1, b059:1, b058:1, b057:1,
    b072:1, b071:1, b070:1, b069:1, b068:1, b067:1, b066:1, b065:1,
    b080:1, b079:1, b078:1, b077:1, b076:1, b075:1, b074:1, b073:1,
    b088:1, b087:1, b086:1, b085:1, b084:1, b083:1, b082:1, b081:1,
    b096:1, b095:1, b094:1, b093:1, b092:1, b091:1, b090:1, b089:1,
    b104:1, b103:1, b102:1, b101:1, b100:1, b099:1, b098:1, b097:1,
    b112:1, b111:1, b110:1, b109:1, b108:1, b107:1, b106:1, b105:1,
    b120:1, b119:1, b118:1, b117:1, b116:1, b115:1, b114:1, b113:1,
    b128:1, b127:1, b126:1, b125:1, b124:1, b123:1, b122:1, b121:1;
  } bits;
} my_uint128_t;

// PROTOTYPES
void copy_128_to_8(uint8_t *p_out, my_uint128_t *p_in);
void copy_8_to_128(my_uint128_t *p_out, uint8_t *p_in);
void setFaultRegister(llu_t h64, llu_t l64, int fault_type, int register_loc);
void ClearAllFaults(void);
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);

// buffer size is exactly AES_BLOCKLEN bytes; 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(/*const*/ struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(/*const*/ struct AES_ctx* ctx, uint8_t* buf);
void px128(const char* pch, void * in_128);
void px128B(const char* pch, void * in_128);
void phex_128_n(my_uint128_t* in_128);
void phex_128(my_uint128_t* in_128);
void phex_n_colored_not_match(uint8_t* str, uint8_t *p_match);
uint8_t get_sbox(uint8_t in);

void SubBytes   (state_t* state);
void ShiftRows  (state_t* state);
void MixColumns (state_t* state);
void AddRoundKey(uint8_t round,state_t* state, uint8_t* RoundKey);

#endif //_AES_H_

