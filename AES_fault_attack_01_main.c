#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#define MAIN_
#include "aes_FAT.h"
#include "math.h"

#define MAX_TRIES (256*1024)

// --------------------------------------------------
// A BRIEF DESCRITION OF THE APPROACH USED 
// TBD
// --------------------------------------------------

// --------------------------------------------------
// 'Official' valules that are put in Firmware during HW2 - Kept for additional testing
#define TXTSIZ 16
uint8_t key[]              ={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
uint8_t  plain_text[TXTSIZ]={0x6b,0xc0,0xbc,0xe1,0x2a,0x45,0x99,0x91,0xe1,0x34,0x74,0x1a,0x7f,0x9e,0x19,0x25};
#ifndef ROUND_1_ONLY
uint8_t cipher_text[TXTSIZ]={0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d};
#else
# ifdef OPT4_BYPASS_SBOXES
uint8_t cipher_text[TXTSIZ]={0x3b,0x06,0x6b,0x67,0x36,0x0d,0x94,0xdf,0x9f,0x57,0xe5,0x79,0x83,0xf9,0x52,0x5d};
# else
uint8_t cipher_text[TXTSIZ]={0xa9,0xc4,0xbc,0xb9,0xcd,0xdf,0xb4,0x67,0xb5,0x38,0x36,0x75,0x4f,0x92,0x4c,0xce};
# endif
#endif

void copy_128_to_8(uint8_t *p_out, my_uint128_t *p_in)
{ 
  for(int i=0; i<TXTSIZ; i++) p_out[i]=p_in->b[bT[i]]; 
}

void copy_8_to_128(my_uint128_t *p_out, uint8_t *p_in)
{ 
  for(int i=0; i<TXTSIZ; i++) p_out->b[bT[i]]=p_in[i]; 
}


void phex(uint8_t* str) // prints string as hex
{
    uint8_t len = 16; unsigned char i;
    //for (i = 0; i < len; ++i) {printf("0x%.2x,", str[i]);} printf("\n"); // To generate in C format
    for (i = 0; i < len; ++i) {printf("%.2x", str[i]);} printf("\n");
}

void phex_n(uint8_t* str) // prints string as hex
{
    uint8_t len = 16; unsigned char i;
    //for (i = 0; i < len; ++i) {printf("%.2x,", str[i]);} // To generate in C format
    for (i = 0; i < len; ++i) {printf("%.2x", str[i]);} 
    //for (i = 0; i < len; ++i) {str[i] ? printf("%.2x", str[i]) : printf("..");} 
}

void phex_n_colored_not_match(uint8_t* str, uint8_t *p_match)
{
    char out[256];
    char com[256];
    int i, len;

    for (i = 0; i < TXTSIZ; ++i) {sprintf(&com[2*i], "%.2x", p_match[i]);}
    for (i = 0; i < TXTSIZ; ++i) {sprintf(&out[2*i], "%.2x",     str[i]);} 
    len=strlen(out);
    for (i = 0; i < len; i++) 
    {
      if(com[i] != out[i]) PEN_RED();
      printf("%c", out[i]);
      if(com[i] != out[i]) PEN_NC();
    }
}

void phex_128(my_uint128_t* in_128)
{
   uint64_t *p =(uint64_t *) in_128;
   printf("%016llx%016llx\n", (llu_t)(*p),(llu_t)((*(p+1))));
}

void phex_128_n(my_uint128_t* in_128)
{
   uint64_t *p =(uint64_t *) in_128;
   printf("%016llx%016llx", (llu_t)(*p),(llu_t)((*(p+1))));
}

void phex_128_n_dots(my_uint128_t* in_128)
{
    uint8_t str[TXTSIZ];
    unsigned char i;
    copy_128_to_8(str, in_128);
    for (i = 0; i < TXTSIZ; ++i) {str[i] ? printf("%.2x", str[i]) : printf("..");} 
}

void phex_128_n_dots_colored_nibs(my_uint128_t* in_128, char nib)
{
    uint8_t str[TXTSIZ];
    char out[256];
    int i, len, done;
    copy_128_to_8(str, in_128);

    for (i = 0; i < TXTSIZ; ++i) {str[i] ? sprintf(&out[2*i], "%.2x", str[i]) : sprintf(&out[2*i], "..");} 
    len=strlen(out);
    for (done=1, i=0; i < len; i++) if(nib != out[i]) {done=0; break;}
    for (i = 0; i < len; i++) 
    {
      if(nib == out[i]) 
      { 
        if (done) PEN_GREEN(); else PEN_YELLOW(); 
        printf("%c", toupper(out[i]));  PEN_NC();
      } 
      else printf("%c", (out[i]));
    }
}

void phex_128_n_colored_not_match(my_uint128_t* in_128, my_uint128_t *p_match)
{
    uint8_t str[TXTSIZ];
    uint8_t str2[TXTSIZ];
    char out[256];
    char com[256];
    int i, len;
    copy_128_to_8( str, in_128);
    copy_128_to_8(str2, p_match);

    for (i = 0; i < TXTSIZ; ++i) {sprintf(&com[2*i], "%.2x", str2[i]);}
    for (i = 0; i < TXTSIZ; ++i) {sprintf(&out[2*i], "%.2x",  str[i]);} 
    len=strlen(out);
    for (i = 0; i < len; i++) 
    {
      if(com[i] != out[i]) PEN_RED();
      printf("%c", out[i]);
      if(com[i] != out[i]) PEN_NC();
    }
}

void phex_128_n_dots_colored_match(my_uint128_t* in_128, uint8_t *p_match, my_uint128_t *p_mask, char label )
{
    uint8_t str[TXTSIZ];
    uint8_t str2[TXTSIZ];
    char out[256];
    char com[256];
    char mas[256];
    int i, len, done;
    copy_128_to_8( str, in_128);
    copy_128_to_8(str2, p_mask);

    for (i = 0; i < TXTSIZ; ++i) {         sprintf(&com[2*i], "%.2x", p_match[i]);}
    for (i = 0; i < TXTSIZ; ++i) {         sprintf(&mas[2*i], "%.2x", str2[i]);}
    for (i = 0; i < TXTSIZ; ++i) {str[i] ? sprintf(&out[2*i], "%.2x", str[i]) : sprintf(&out[2*i], "..");} 
    len=strlen(out);
    for (done=1, i=0; i < len; i++) if(com[i] != out[i]) {done=0; break;}
    for (i = 0; i < len; i++) 
    {
      if(com[i] == out[i]) 
      { 
        if (done || (mas[i] == label)) PEN_GREEN();
	else                            PEN_BLUE(); 
      }
      printf("%c", out[i]);
      if(com[i] == out[i]) PEN_NC();
    }
}

void print_keys(uint8_t *pk, struct AES_ctx *pctx, int opt)
{
    int i;
    if      ((NULL !=  pk)&&(0==opt))  {printf(  "key  ..................:"); PEN_GREEN(); phex(pk); PEN_NC();}
    else if ( NULL !=  pk)             {printf(  "key  ..................:"); phex(pk);}
    if ( NULL !=pctx) for (i=0; i<(AES_KEYEXPSIZE); i+=AES_KEYLEN) 
    {
      if (          -1==opt) {printf("[%02d] keyexpan .........:", i/AES_KEYLEN); phex(&pctx->RoundKey[i]); }
      if (i/AES_KEYLEN==opt) {printf("[%02d] keyexpan .........:", i/AES_KEYLEN); PEN_GREEN(); phex(&pctx->RoundKey[i]); PEN_NC(); }
    }
}

//MACROS
#define load_128(p, high64, low64) \
  (p)->h[hH]=high64; (p)->h[hL]=low64;

int OR_128(my_uint128_t* p_out, my_uint128_t in1, my_uint128_t in2) 
{
  (*(p_out)).h[hH]=(in1).h[hH] | (in2).h[hH]; 
  (*(p_out)).h[hL]=(in1).h[hL] | (in2).h[hL];
  return ((*(p_out)).h[hH] || (*(p_out)).h[hL]);
}

int AND_128(my_uint128_t* p_out, my_uint128_t in1, my_uint128_t in2) 
{
  (*(p_out)).h[hH]=(in1).h[hH] & (in2).h[hH]; 
  (*(p_out)).h[hL]=(in1).h[hL] & (in2).h[hL];
  return ((*(p_out)).h[hH] || (*(p_out)).h[hL]);
}

int XOR_128(my_uint128_t* p_out, my_uint128_t in1, my_uint128_t in2) 
{
  (*(p_out)).h[hH]=(in1).h[hH] ^ (in2).h[hH]; 
  (*(p_out)).h[hL]=(in1).h[hL] ^ (in2).h[hL];
  return ((*(p_out)).h[hH] || (*(p_out)).h[hL]);
}

#define get_128_w4(in,word_number) ((in).w[wT[(word_number)]])

#define M_AES_ECB_encrypt(ctx, in, out)\
{\
    uint8_t inbuf[TXTSIZ];\
    copy_128_to_8(inbuf, (in)); \
    AES_ECB_encrypt((ctx), inbuf);\
    copy_8_to_128((out), inbuf);\
}\

#define MAX_BC 4   //MAX Byte Candidates per key byte
typedef struct 
{
  int   kbc[MAX_BC]; //kbc= key byte candiate
  int n_kbc;         //number of candidates
} kbc_t;
uint32_t APC_n_kbc_total;

//----------------------------------------------------------------
//----------------------------------------------------------------
#undef  SANITY_TEST

#define M_AES_ECB_encrypt(ctx, in, out)\
{\
    uint8_t inbuf[TXTSIZ];\
    copy_128_to_8(inbuf, (in)); \
    AES_ECB_encrypt((ctx), inbuf);\
    copy_8_to_128((out), inbuf);\
}\

#undef  RULE_BASED_FAULT_BITPOS
#define BIT_POS_STEP                 1

#define ATTACK_01_HITS_NEEDED_CRACK  5

static const char* p_attack_type;
static const char* p_gist;

enum ATTTACK_type_t 
{
  ATTACK_00,
  ATTACK_01,
  ATTACK_02,
  NO_TYPE
};

enum ATTTACK_subtype_t 
{
  ATTACK_02_USED_FOR_01,
  ATTACK_02_USED_FOR_03,
  ATTACK_02_NO_ATTACK,
  ATTACK_02_FLIP_PT_1BIT,
  NO_SUBTYPE
};


uint8_t patt_cix_att02[ATTACK_01_HITS_NEEDED_CRACK+1][AES_KEYLEN];
uint8_t patt_cig_att02[ATTACK_01_HITS_NEEDED_CRACK+1][AES_KEYLEN];
uint8_t patterns_att02_counter[AES_KEYLEN];

static int CountersTotal[AES_KEYLEN];
static struct Counters_t
{
  int hits;
  int tok;
} Counters[AES_KEYLEN][256];

#define DISABLE_QSORT_ISSUES_CYGWIN
#ifndef DISABLE_QSORT_ISSUES_CYGWIN
static int cmpCountersGreater(const void *p1, const void *p2)
{
  return (((struct Counters_t*)p1)->hits < ((struct Counters_t*)p2)->hits);
}
static int cmpCountersLesser(const void *p1, const void *p2)
{
  return (((struct Counters_t*)p1)->hits > ((struct Counters_t*)p2)->hits);
}
static int (*p_comp_func)(const void *p1, const void *p2);

#else
void CountSortLesser(struct Counters_t *p)
{
  int i, j, k;
  for(i= 0; i<256; i++)
  {
    k=i;
    for(j=i+1; j<256; j++) if (p[j].hits < p[k].hits) k = j;
    int hit_k = p[k].hits;
    int tok_k = p[k].tok;
    p[k].hits= p[i].hits; p[k].tok = p[i].tok;
    p[i].hits= hit_k    ; p[i].tok = tok_k;
  }
}
void CountSortGreater(struct Counters_t *p)
{
  int i, j, k;
  for(i= 0; i<256; i++)
  {
    k=i;
    for(j=i+1; j<256; j++) if (p[j].hits > p[k].hits) k = j;
    int hit_k = p[k].hits;
    int tok_k = p[k].tok;
    p[k].hits= p[i].hits; p[k].tok = p[i].tok;
    p[i].hits= hit_k    ; p[i].tok = tok_k;
  }
}
#endif

int main(int argc, char *argv[])
{
  enum ATTTACK_type_t AT=NO_TYPE;
  enum ATTTACK_subtype_t AT_sub=NO_SUBTYPE;
  my_uint128_t PTX, CIG, CIF, CIX, CIA, KEY_FOUND, KEY_MASK;
  uint8_t key_random[AES_KEYLEN];
  uint8_t    key_tmp[AES_KEYLEN];
  uint8_t ptx_random[AES_KEYLEN];
  uint8_t *p_key, *p_RK10;
  struct AES_ctx ctx;
  int aux, n, run, n_tries, n_tries_hit, bit_pos;
  int number_of_runs;
  int num_of_ffs_stuck;
  int ff_stuck_type, still_looking_for_it;
  llu_t h64, l64;
  int are_cis_diff;
  int error=0;
  int max_ffs_stuck=0;
  int print_stats=0;

  if ( ( (2 != argc) && (3 != argc) && (4 != argc) ) || 
       ( (2 == argc) &&
         ((!strcasecmp( "help", argv[1])) ||
          (!strcasecmp("-help", argv[1])) ||
          (!strcasecmp(   "-h", argv[1]))) ) ) error=1;

  if (!error)
  {
    n = sscanf(argv[1], "%d", &aux);
printf("XXXXXXXXX aux=%d\n", aux);
    if ((aux!=0) && (aux!=1) && (aux!=2) && (aux!=21) && 
        (aux!=23) && (aux!=-1) && (aux!=-2))             error=1;
  }

  number_of_runs=-1;
  if (argc >= 3)
  {
    n = sscanf(argv[2], "%d", &number_of_runs);
    if (number_of_runs < 1) error=1;
  }
  else number_of_runs=2;

  print_stats=0;
  if (argc >= 4)
  {
    if (!strcasecmp(  "stats", argv[3])) print_stats=1;
    if (!strcasecmp( "-stats", argv[3])) print_stats=1;
    if (!strcasecmp(   "stat", argv[3])) print_stats=1;
    if (!strcasecmp(  "-stat", argv[3])) print_stats=1;
    if (!strcasecmp( "stats2", argv[3])) print_stats=2;
    if (!strcasecmp("-stats2", argv[3])) print_stats=2;
    if (!strcasecmp(  "stat2", argv[3])) print_stats=2;
    if (!strcasecmp( "-stat2", argv[3])) print_stats=2;
    if (!print_stats) error=1;
  }
  else print_stats=0;

  if (error)
  {
    printf("\nSYNTAX: %s ATTACK_TYPE  [number_of_runs  stats]\n", argv[0]);
    printf("ATTACK_TYPE can be 0|1|2|21|23|-1|-2\n");
    printf("PLEASE choose one of the numbers displayed above\n");
    printf("Have a good day...\n\n");
    exit(-1);
  }

  switch (aux)
  {
    case 0:
      AT = ATTACK_00; AT_sub = NO_SUBTYPE; max_ffs_stuck=10;
      p_attack_type =   "AT0"; p_gist = "**ATACK 00** Attacking M10 - Before AddRoundKey() just to warm up (KEYM)\n";
    break;
    case 1:
      AT = ATTACK_01; AT_sub = NO_SUBTYPE; max_ffs_stuck=1; // Has to be only one at time
      p_attack_type =   "AT1"; p_gist = "**ATACK 01** Attacking M10 - Before SubBytes() via Giraud's Approach (KEYM)\n";
    break;
    case 2:
      AT = ATTACK_02; AT_sub = NO_SUBTYPE; max_ffs_stuck=1; // Has to be only one at time
      p_attack_type =   "AT2"; p_gist = "**ATACK 02** Attacking M9 - Before SubBytes() via Statistical Approach (KEYM)\n";
    break;
    case 21:
      AT = ATTACK_02; AT_sub = ATTACK_02_USED_FOR_01; max_ffs_stuck=1; // Has to be only one at time
      p_attack_type = "AT2_1"; p_gist = "**ATACK 01(2)** Attacking M10 - Before SubBytes() via Statistical Approach (KEYM)\n";
    break;
    case 23:
      AT = ATTACK_02; AT_sub = ATTACK_02_USED_FOR_03; max_ffs_stuck=1; // Has to be only one at time
      p_attack_type = "AT2_3"; p_gist = "**ATACK 03(2)** Attacking M8  - Before SubBytes() via Statistical Approach (KEYM) - Just for fun - It will fail for sure\n";
    break;
    case -1:
      AT = ATTACK_02; AT_sub = ATTACK_02_NO_ATTACK  ; max_ffs_stuck=0; // Has to be only one at time
      p_attack_type = "AT2_NO_FAULT"; p_gist = "**ATACK -1(2)** Not really causing faults and not attacking anything - just collecting statistics (KEYM)\n";
    break;
    case -2:
      AT = ATTACK_02; AT_sub = ATTACK_02_FLIP_PT_1BIT  ; max_ffs_stuck=1; // Has to be only one at time
      p_attack_type = "AT2_FLIP_PT_1BIT_ONLY"; p_gist = "**ATACK -2(2)** Not really causing faults - flips on bit in the PlainText - just collecting statistics (KEYM)\n";
    break;
  }

  srand(11223347); //RAND (SEEDING) *R1*
  p_key=key_random;

  PEN_CYAN(); printf("------------------------------------------------------KEYM\n"); PEN_NC();
  PEN_CYAN(); printf("Fault Attack on AES128 (***FAULT INJECTION***)        KEYM\n"); PEN_NC();
  PEN_CYAN(); printf("------------------------------------------------------KEYM\n"); PEN_NC();
  
  for(run=1; run<=number_of_runs; run++)
  {
    if(ATTACK_02==AT) memset( Counters,      0, sizeof(Counters));
    if(ATTACK_02==AT) memset( CountersTotal, 0, sizeof(CountersTotal));
    memset( patt_cix_att02, 0, sizeof(patt_cix_att02));
    memset( patt_cig_att02, 0, sizeof(patt_cig_att02));
    memset( patterns_att02_counter, 0, sizeof(patterns_att02_counter));

    // If in Random test mode, generates Random Keys to later discover them
    // and calculates the expected ciphers associated with the random keys
    // so that results can be easily compared
#ifndef SANITY_TEST
    for (n=0; n<AES_KEYLEN; n++) p_key[n] = rand();   // RAND(KEY) *R2*
#else
    for (n=0; n<AES_KEYLEN; n++) p_key[n] = key[n];
#endif
    //Initializations and other Pro-forma
    AES_init_ctx(&ctx, p_key);
    p_RK10 = &ctx.RoundKey[10*AES_KEYLEN];
    printf(p_gist);
    printf(">>>>RUN=%05d (max_ffs_stuck=%d)                       KEYM\n", run, max_ffs_stuck); 
    PEN_CYAN(); printf("----------------------------------------------------------\n"); PEN_NC();
    print_keys(p_key, &ctx, -1);
    APC_n_kbc_total = 0;

    // Now progress into the attack
    memset(&KEY_FOUND, 0, sizeof(KEY_FOUND));
    memset( &KEY_MASK, 0, sizeof( KEY_MASK));
    memset(      &CIA, 0, sizeof(      CIA));
#ifdef  RULE_BASED_FAULT_BITPOS
    bit_pos=-BIT_POS_STEP+1; 
#endif
    unsigned int try_mask=0x01U;
    n_tries_hit=0;
    for (n_tries=1, still_looking_for_it=1; still_looking_for_it; n_tries++)
    {
      if(!((n_tries & try_mask) == try_mask))
      {
        printf("PROGRESS n_tries=%8d\n", n_tries);
        try_mask<<=0x01U;
      }
      ClearAllFaults(); // Starts with no Faults in the Simulated Circuit
      h64=0x0000000000000000ULL; l64=0x0000000000000000ULL;

#ifndef SANITY_TEST
      for (n=0; n<AES_KEYLEN; n++) {ptx_random[n] = rand();} copy_8_to_128(&PTX, ptx_random); // RAND (PTEXT) *R3*
#else
      for (n=0; n<AES_KEYLEN; n++) {ptx_random[n] = plain_text[n];} copy_8_to_128(&PTX, ptx_random);
#endif

      if (max_ffs_stuck > 0)
      num_of_ffs_stuck  = rand() % (max_ffs_stuck)+1; // RAND(MAX NUMBER FFs stuck for the try, can be less, at least 1) *R4*
      else num_of_ffs_stuck = 0;
      
      if( (ATTACK_02==AT) || (ATTACK_01==AT)) 
        ff_stuck_type     = 2; // Type 2 is FFs levels flipping
      else 
        ff_stuck_type     = rand() % 2;  // RAND(FF Stuck can be stuck in voltage logic LEVEL 0 or 1 or 2(Flipping state)) *R5*

      for (n=0; n<num_of_ffs_stuck; n++)
        {
#ifdef  RULE_BASED_FAULT_BITPOS
          bit_pos=(bit_pos + BIT_POS_STEP)%128;
#else
          bit_pos = rand()%128; // RAND(Stuck FF POSITION in the RR10) - Needs to change each try! *R6*
#endif
          if (bit_pos < 64) l64|=0x1ULL<<(bit_pos   );
          else              h64|=0x1ULL<<(bit_pos-64);
        }
  
      PEN_CYAN(); printf("----------------------------------------------------------\n"); PEN_NC();
      printf("::::RUN=%05d, HITS=%05d NTRIES=%05d FFs_STUCK_in_state=<%d> N_FFs_STUCK=%d\n", run, n_tries_hit, n_tries, ff_stuck_type, num_of_ffs_stuck);

#ifdef FAULT_PRINTS_AESC_1
      printf("::::ENCRYPT NORM CYCLE:\n");
#endif
      M_AES_ECB_encrypt(&ctx, &PTX, &CIG); // Given. Plain Texts used. Encry team to find the Correct/Non-Faulty Ciphertexts

      // Time to insert fault
      switch (AT)
      {
        case ATTACK_00: setFaultRegister(h64, l64, ff_stuck_type, R10_IN_ADR); break;
        case ATTACK_01: setFaultRegister(h64, l64, ff_stuck_type, R10_IN_SUB); break;
        case ATTACK_02:
	  if      (AT_sub == NO_SUBTYPE)
	  {
	    setFaultRegister(h64, l64, ff_stuck_type, R09_IN_SUB); 
	  }
	  else if (AT_sub == ATTACK_02_USED_FOR_01) 
	  {
	    setFaultRegister(h64, l64, ff_stuck_type, R10_IN_SUB); 
	  }
	  else if (AT_sub == ATTACK_02_USED_FOR_03) 
	  {
	    setFaultRegister(h64, l64, ff_stuck_type, R08_IN_SUB); 
	  }
	  else if (AT_sub == ATTACK_02_FLIP_PT_1BIT) 
	  {
	    setFaultRegister(h64, l64, ff_stuck_type, R01_IN_ADR); 
	  }
	  else if (AT_sub == ATTACK_02_NO_ATTACK) 
	  {
	    // No Fault Set
	  }
	  break;
	case NO_TYPE:
	default:      break;
      }

#ifdef FAULT_PRINTS_AESC_1
      printf("::::ENCRYPT FAUL CYCLE:\n");
#endif
      M_AES_ECB_encrypt(&ctx, &PTX, &CIF); // Given. 'Faulty' Cipher Scanned out of the Chip
      
      are_cis_diff = XOR_128(&CIX, CIG, CIF);

#ifndef FAULT_PRINTS_MAIN_1
      if (are_cis_diff) {
#endif
      //printf("FAULT REGISTER is set  :%016llx%016llx FFs_STUCK_level=%d N_of_FFs_Stuck=%d\n", (llu_t) h64, (llu_t) l64, ff_stuck_type, num_of_ffs_stuck);
      my_uint128_t fau_128; fau_128.h[hH]=h64; fau_128.h[hL]=l64;
      printf("FAULT REGISTER is set  :"); phex_128_n_dots(&fau_128); printf(" FFs_STUCK_level=%d N_of_FFs_Stuck=%d\n", ff_stuck_type, num_of_ffs_stuck);
      printf("|A> PlainText .......  :"); phex_128       (&PTX); 
      printf("|B> CipherText (GOOD)  :"); phex_128       (&CIG);
      printf("|C> CipherText (FAUL)  :"); phex_128_n_colored_not_match(&CIF, &CIG); printf("\n");
      printf("|D> .....XOR(|B>,|C>)  :"); phex_128_n_dots(&CIX); printf("  SAME (|B>,|C>)?=%s\n", are_cis_diff?"NO":"YES");
#ifndef FAULT_PRINTS_MAIN_1
      }
#endif

      // Check for differents in the Good and Faulty CTs and start cracking the RK10
      if ((are_cis_diff) || (AT_sub == ATTACK_02_NO_ATTACK))
      {
	n_tries_hit++;

	//---------------------------------------------------------------------------
        if (ATTACK_00 == AT)
	{
	  OR_128(  &KEY_MASK,   KEY_MASK, CIX);
	  if      (0 == ff_stuck_type) AND_128(&CIA, CIX, CIF);
	  else if (1 == ff_stuck_type) AND_128(&CIA, CIX, CIG);
	  else if (2 == ff_stuck_type) AND_128(&CIA, CIX, CIG);
	  OR_128( &KEY_FOUND,  KEY_FOUND, CIA);
          printf("|E%d> ....AND(|?>,|D>)  :", ff_stuck_type); phex_128_n_dots(&CIA); printf("\n");
          print_keys(NULL, &ctx, 10);
          printf("|F%d> ...PARTIAL RK10)  :", ff_stuck_type); phex_128_n_dots_colored_match(&KEY_FOUND, p_RK10, &KEY_MASK, 'f'); printf("\n");
          printf("|G%d> ..PROGRESS MASK)  :", ff_stuck_type); phex_128_n_dots_colored_nibs (&KEY_MASK, 'f'); printf("\n");
	  OR_128(  &KEY_MASK,   KEY_MASK, CIX);
	} // ATTACK_00

	//---------------------------------------------------------------------------
        if (ATTACK_01 == AT)
        {
	  int pos, s, b, val;
          uint8_t    cix_tmp[AES_KEYLEN]; copy_128_to_8(cix_tmp, &CIX);
          uint8_t    cig_tmp[AES_KEYLEN]; copy_128_to_8(cig_tmp, &CIG);
          uint8_t    key_mask_tmp[AES_KEYLEN];
          uint8_t    key_found_tmp[AES_KEYLEN];
          my_uint128_t tmp_128; 
  
          // Different from Giraud, we prefere to colect the hashes first and loop
	  // only once to find the values at the input of the Sbox by checking
	  // all the hashes at the same time.
          for(pos=0; pos < AES_KEYLEN; pos++) 
          {
            if(!cix_tmp[pos])                                                       continue;
            if(0xb9==cix_tmp[pos]) /* No solution for 135 - See Giraud's Paper */ continue;
            if(patterns_att02_counter[pos] >= ATTACK_01_HITS_NEEDED_CRACK)          continue;
            for (n=0; n < patterns_att02_counter[pos]; n++) 
              if(patt_cix_att02[n][pos] == cix_tmp[pos]) break; // Duplicate
            if (n == patterns_att02_counter[pos])
	    {
              patt_cix_att02[n][pos] = cix_tmp[pos];
              patt_cig_att02[n][pos] = cig_tmp[pos];
              patterns_att02_counter[pos]++;
	    }
          }

          for(n=0; n < ATTACK_01_HITS_NEEDED_CRACK; n++) 
	  {
             copy_8_to_128(&tmp_128, patt_cix_att02[n]);
             printf("|E%d> SaveXOR(|B>,|C>)  :", n); PEN_BLUE(); phex_128_n_dots(&tmp_128); PEN_NC(); printf("\n");
	  }

	  uint8_t candies[256];
	  memset (candies, 0, sizeof(candies));
          copy_128_to_8(key_mask_tmp, &KEY_MASK);
          copy_128_to_8(key_found_tmp, &KEY_FOUND);
	  // Here below we calculate the bytes of the RK10 for the cases
	  // where sufficent hashes have already been collected
          for(pos=0; pos < AES_KEYLEN; pos++) 
          {
            if(0xff == key_mask_tmp[pos])                                           continue; // already found
            if(!cix_tmp[pos])                                                       continue; // no new hash for the pos
            if(patterns_att02_counter[pos] != ATTACK_01_HITS_NEEDED_CRACK)          continue; // enough hashes already collected
            for(n=0; n < ATTACK_01_HITS_NEEDED_CRACK; n++) 
	    {
              for(s=0; s<SBOX_SIZ; s++)
              {
                for(b=0; b<8; b++)
                {
                  if (patt_cix_att02[n][pos] == (get_sbox(s)^get_sbox(s^(0x01U<<b))))
		  {
                    val = get_sbox(s)^patt_cig_att02[n][pos];
		    candies[val]++;
		  }
                } // for(s...)
              } // for(b...)
	    } // for(n...)

	    // The candi(date) with higer rank for each pos 
	    // with sufficient hashes is the right one
	    for (val=0; val<256; val++) 
	    {
	      if(candies[val] >= ATTACK_01_HITS_NEEDED_CRACK) 
	      {
	        key_mask_tmp [pos]=0xff;
	        key_found_tmp[pos]=val;
	        break;
	      }
	    }
          }
          copy_8_to_128( &KEY_MASK,  key_mask_tmp);
          copy_8_to_128(&KEY_FOUND, key_found_tmp);
          printf("|F%d> ...PARTIAL RK10)  :", ff_stuck_type); phex_128_n_dots_colored_match(&KEY_FOUND, p_RK10, &KEY_MASK, 'f'); printf("\n");
          printf("|G%d> ..PROGRESS MASK)  :", ff_stuck_type); phex_128_n_dots_colored_nibs (&KEY_MASK, 'f'); printf("\n");
        } //ATTACK_01

	//---------------------------------------------------------------------------
        if (ATTACK_02 == AT)
	{
	  int pos, s, b, val;
          uint8_t cix_tmp[AES_KEYLEN]; copy_128_to_8(cix_tmp, &CIX);
          uint8_t cig_tmp[AES_KEYLEN]; copy_128_to_8(cig_tmp, &CIG);
  
	  // This attack is similar to the attack 01
	  // However, multiple flips happen at M10 due
	  // to a single fault in M9. Strangely, the hash
	  // with lower frequency is the correct one (?!)
	  // This trend has been found via simulation but
	  // still requires better undertanding.
	  // Also, many more PTs are needed for the statistics
	  // to resolve (the number could be reduced by using
	  // a better algorithm to find the a short list of 
	  // candidates and just try them).
          for(pos=0; pos < AES_KEYLEN; pos++) 
          {
	    if (AT_sub == ATTACK_02_NO_ATTACK) 
	    {
	      // This is just to collect stats about the ciphertext
	      val=cig_tmp[pos];
              Counters[pos][val].hits++; 
              Counters[pos][val].tok=val;
	    }

            if(       !cix_tmp[pos])  continue;
            if ((ATTACK_02_FLIP_PT_1BIT != AT_sub) && (ATTACK_02_NO_ATTACK != AT_sub))
	      if(0xb9 == cix_tmp[pos])continue; // Not solution (as per Giraud's paper)
            if(print_stats>1) printf("@P%02d:",pos);
            for(s=0; s<SBOX_SIZ; s++)
            for(b=0; b<8; b++)
              if (cix_tmp[pos] == (get_sbox(s)^get_sbox(s^(0x01U<<b))))
	      {
                val = get_sbox(s)^cig_tmp[pos]; /* *** */
	        Counters[pos][val].hits++; 
	        Counters[pos][val].tok=val;
                if(print_stats>1) printf("|%02x,%3d",val,Counters[pos][val].hits);
	      }
            if(print_stats>1) printf("|\n");
          }

	// the code below is only used when we do the attack 1
	// using the code for the attack 2 (option 21)
	if (AT_sub == ATTACK_02_USED_FOR_01) 
	{
          uint8_t    key_mask_tmp[AES_KEYLEN];
          uint8_t    key_found_tmp[AES_KEYLEN];
          my_uint128_t tmp_128; 
          for(pos=0; pos < AES_KEYLEN; pos++) 
          {
            if(!cix_tmp[pos])                                                       continue;
            if ((ATTACK_02_FLIP_PT_1BIT != AT_sub) && (ATTACK_02_NO_ATTACK != AT_sub))
	      if(0xb9 == cix_tmp[pos]) /* No solution for 135-See Giraud's Paper */ continue;
            if(patterns_att02_counter[pos] >= ATTACK_01_HITS_NEEDED_CRACK)          continue;
            for (n=0; n < patterns_att02_counter[pos]; n++) 
              if(patt_cix_att02[n][pos] == cix_tmp[pos]) break; // Duplicate
            if (n == patterns_att02_counter[pos])
	    {
              patt_cix_att02[n][pos] = cix_tmp[pos];
              patt_cig_att02[n][pos] = cig_tmp[pos];
              patterns_att02_counter[pos]++;
	    }
          }
          for(n=0; n < ATTACK_01_HITS_NEEDED_CRACK; n++) 
	  {
             copy_8_to_128(&tmp_128, patt_cix_att02[n]);
             printf("|E%d> SaveXOR(|B>,|C>)  :", n); PEN_BLUE(); phex_128_n_dots(&tmp_128); PEN_NC(); printf("\n");
	  }
	  uint8_t candies[256];
	  memset (candies, 0, sizeof(candies));
          copy_128_to_8(key_mask_tmp, &KEY_MASK);
          copy_128_to_8(key_found_tmp, &KEY_FOUND);
          for(pos=0; pos < AES_KEYLEN; pos++) 
          {
            if(0xff == key_mask_tmp[pos])                                           continue;
            if(!cix_tmp[pos])                                                       continue;
            if(patterns_att02_counter[pos] != ATTACK_01_HITS_NEEDED_CRACK)          continue;
            for(n=0; n < ATTACK_01_HITS_NEEDED_CRACK; n++) 
	    {
              for(s=0; s<SBOX_SIZ; s++)
              {
                for(b=0; b<8; b++)
                {
                  if (patt_cix_att02[n][pos] == (get_sbox(s)^get_sbox(s^(0x01U<<b))))
		  {
                    val = get_sbox(s)^patt_cig_att02[n][pos];
		    candies[val]++;
		  }
                } // for(s...)
              } // for(b...)
	    } // for(n...)
	    for (val=0; val<256; val++) 
	    {
	      if(candies[val] >= ATTACK_01_HITS_NEEDED_CRACK) 
	      {
	        key_mask_tmp [pos]=0xff; 
	        //key_mask_tmp [pos]=0xcc; // not 0xff so it keeps going and uses statistics to solve
	        key_found_tmp[pos]=val;
	        break;
	      }
	    }
          }
          copy_8_to_128( &KEY_MASK,  key_mask_tmp);
          copy_8_to_128(&KEY_FOUND, key_found_tmp);
          printf("|F%d> ...PARTIAL RK10)  :", ff_stuck_type); phex_128_n_dots_colored_match(&KEY_FOUND, p_RK10, &KEY_MASK, 'f'); printf("\n");
          printf("|G%d> ..PROGRESS MASK)  :", ff_stuck_type); phex_128_n_dots_colored_nibs (&KEY_MASK, 'f'); printf("\n");
	} // if (AT_sub == ATTACK_02_USED_FOR_01) 
      } //ATTACK_02

      }
#ifdef  RULE_BASED_FAULT_BITPOS
      else bit_pos=(bit_pos - BIT_POS_STEP);
#endif

      if(n_tries >= MAX_TRIES) 
      {
        // For attack 2, wait all tries and after check
	// the counters to find the correct bytes
        if (ATTACK_02 == AT)
        {
          uint8_t    KEYMAX[AES_KEYLEN];
          uint8_t    KEYMIN[AES_KEYLEN];
          int val, val_max,val_min, i_max, i_min;
          for (int p=0; p<AES_KEYLEN; p++)
          {
            val_max=val_min=i_max=i_min=-1;
            for (int i=0; i<256; i++)
            {
              val = Counters[p][i].hits;
              CountersTotal[p] += val;
              if ((-1==val_min) || (val < val_min)) {val_min=val; i_min=i;}
              if ((-1==val_max) || (val > val_max)) {val_max=val; i_max=i;}
              //printf("COUNT,%02d,%04d,%02x\n", p, val, i);
            }
	    KEYMAX[p]=i_max;
	    KEYMIN[p]=i_min;
          }

          for (int p=0; print_stats && (p<AES_KEYLEN); p++)
          {
#ifndef DISABLE_QSORT_ISSUES_CYGWIN
            if (ATTACK_02_USED_FOR_01 == AT_sub) p_comp_func = cmpCountersGreater;
            else                                 p_comp_func = cmpCountersLesser;
	    qsort(&Counters[p][0], 256, sizeof(Counters[0][0]), p_comp_func);
#else
            if (ATTACK_02_USED_FOR_01 == AT_sub) CountSortGreater(&Counters[p][0]);
            else                                 CountSortLesser (&Counters[p][0]);
#endif

            for (int i=0; i<256; i++)
            {
              val = Counters[p][i].hits;
	      const char *pch;
	      const char *pch2="COUNTx";
	      switch(i)
	      {
	        case    0: pch=" (**0**) <----------- BEST CANDIDATE"; break;
	        case    1: pch=" (--1--)"; break;
	        case    2: pch=" (--2--)"; break;
	        case    3: pch=" (--3--)"; break;
	        case    4: pch=" (--4--)"; break;
	        case    5: pch=" (--5--)"; break;
	        case  251: pch=" (--L--)"; break;
	        case  252: pch=" (--A--)"; break;
	        case  253: pch=" (--S--)"; break;
	        case  254: pch=" (--T--)"; break;
		case  255: pch=" (**x**)"; break;
		default:   pch=""; pch2="COUNTn"; break;
	      }
              printf("%s,%3d,%3d,%8d, %02x,%6.2f%%,%6.2f%%0x,%s\n", pch2, p, i, val, Counters[p][i].tok, (100.0*val)/CountersTotal[p], (256.0*val)/CountersTotal[p], pch);
            }
          }

          printf ("........................................................\n");
        //printf ("AES128 KEYM RK10->.... ["); phex_n(p_RK10); printf("]\n");
          printf ("AES128 KEYMAX->....... ["); phex_n(KEYMAX); printf("]\n");
          printf ("AES128 KEYMIN->....... ["); phex_n(KEYMIN); printf("]\n");
          printf ("........................................................\n");
          KEY_MASK.h[hH]= 0xffffffffffffffffULL;
          KEY_MASK.h[hL]= 0xffffffffffffffffULL;
          if (ATTACK_02_USED_FOR_01 == AT_sub) copy_8_to_128(&KEY_FOUND, KEYMAX); // This choice is intriguing
          else                                 copy_8_to_128(&KEY_FOUND, KEYMIN); // This choice is intriguing
        }
        else
        {
          PEN_RED(); printf ("ERROR1: Key not found. No PROGRESS... Something is WRONG. Please fix me. RUN=%05d HITS=%05d TRIES=%05d (%s)\n", run, n_tries_hit, n_tries, p_attack_type);
          exit(-1);
        }
      } // if (n_tries...)

      if((0xffffffffffffffffULL==KEY_MASK.h[hH]) && (0xffffffffffffffffULL==KEY_MASK.h[hL]))
      {
        copy_128_to_8(key_tmp, &KEY_FOUND);
	int are_keys_different=memcmp(key_tmp, p_RK10, sizeof(key_tmp));
	if (!are_keys_different)
        {
          char *pch1=NULL;
          char *pch2=NULL;
          if ((ATTACK_02_USED_FOR_01 == AT_sub) && (n_tries <  MAX_TRIES)) 
	  {
            pch1="";
	    pch2 =  "AES128 RKEY10--> AT1(2)["; 
	  }
	  else                                                             
	  {
            pch1="......................................................KEYM\n";
	    pch2 =  "AES128 RKEYM10--> .... ["; 
	  }
          printf(pch1);
          printf(pch2);phex_n(p_RK10); printf("] <--- EXPECTED RK10.\n");
          printf(pch2);PEN_GREEN();phex_128_n(&KEY_FOUND);PEN_NC(); 
	  printf("] <--- FOUND    RK10. SUCCESS!!! RUN=%05d HITS=%05d TRIES=%05d (%s)\n", run, n_tries_hit, n_tries, p_attack_type);
          printf(pch1);
          if (ATTACK_02_USED_FOR_01 == AT_sub)
	  {
            if(n_tries >= MAX_TRIES) break;
	  }
	  else
	  {
	    break; // Mext run
	  }
        }
	else
        {
          char *pch2= "AES128 RKEYM10--> .... ["; 
          printf(pch2);phex_n(p_RK10); printf("] <--- EXPECTED RK10.\n");
          printf(pch2); PEN_RED()  ; phex_128_n(&KEY_FOUND); PEN_NC(); printf("] <--- NOT FOUND RK10. FAILURE!!! ... RUN=%05d TRIES=%05d (%s)\n", run, n_tries, p_attack_type);
          PEN_RED(); printf ("ERROR2: WRONG Key found. Something is WRONG. Please fix me.\n\n");  PEN_NC();
          exit(-1);
        }
      } // if (0xfffff....)
    } // for(ntries ...)
  } // for(run ...)
  
  exit(0);
} // end if main()
