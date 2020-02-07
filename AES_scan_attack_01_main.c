#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#define MAIN_
#include "aes_SAT.h"

// --------------------------------------------------
// A BRIEF DESCRITION OF THE APPROACH USED
// --------------------------------------------------
// The mapping table right below is very important
// It comes from the criptoanalysis brought
// by Prof. Karri's et al Sec Scan paper 
// Althoug our implementation here differs 
// a bit about how to recover the key byte
// by byte, the foundation is the same as
// in the paper, the fact that changes triggered
// by a byte in the key propagate to only to 
// a specific cluster in round 1 AES register
// what makes possible to reverse project
// the changes in the cluster to the byte
// in the key that cause the change
// Our approach here to discover is 'black-box':
// using the paper proof about the locality
// of the propagation, we use gentle brute force
// (very easy to to do, not time consuming) to
// find the reverse mapping. 
// The reverse mapping is not unique, two or more  key
// candidates are returned per byte in the key.
// --------------------------------------------------
static int mapping_table_keybyte_to_cluster[]={0,3,2,1,1,0,3,2,2,1,0,3,3,2,1,0};

#define TXTSIZ 16
#define MAX_PLAIN_TEXTS_USED 129

void phex_n_dot(uint8_t* str) // prints string as hex
{
    uint8_t len = 16; unsigned char i;
    for (i = 0; i < len; ++i) {printf("%.2x,", str[i]);} // To generate in C format
    //for (i = 0; i < len; ++i) {printf("%.2x", str[i]);} 
    //for (i = 0; i < len; ++i) {str[i] ? printf("%.2x", str[i]) : printf("..");} 
}

void phex_n(uint8_t* str) // prints string as hex
{
    uint8_t len = 16; unsigned char i;
    //for (i = 0; i < len; ++i) {printf("%.2x,", str[i]);} // To generate in C format
    for (i = 0; i < len; ++i) {printf("%.2x", str[i]);} 
    //for (i = 0; i < len; ++i) {str[i] ? printf("%.2x", str[i]) : printf("..");} 
}

void phex(uint8_t* str) // prints string as hex
{
    uint8_t len = 16; unsigned char i;
    //for (i = 0; i < len; ++i) {printf("0x%.2x,", str[i]);} printf("\n"); // To generate in C format
    for (i = 0; i < len; ++i) {printf("%.2x", str[i]);} printf("\n");
}

void phex_128_n(my_uint128_t* in_128)
{
   uint64_t *p =(uint64_t *) in_128;
   printf("%016llx%016llx", (llu_t)(*p),(llu_t)((*(p+1))));
}

void phex_128(my_uint128_t* in_128)
{
   uint64_t *p =(uint64_t *) in_128;
   printf("%016llx%016llx\n", (llu_t)(*p),(llu_t)((*(p+1))));
}

void print_keys(uint8_t *pk, struct AES_ctx *pctx, int opt)
{
    int i;
    printf(  "key            :"); PEN_GREEN(); phex(pk); PEN_NC();
    for (i=0; i<(AES_KEYEXPSIZE); i+=AES_KEYLEN) 
    {
      if (0x01&opt) {printf("[%02d] keyexpan  :", i/AES_KEYLEN); phex(&pctx->RoundKey[i]); }
    }
}

//MACROS
#define load_128(p, high64, low64) \
  (p)->h[hH]=high64; (p)->h[hL]=low64;

#define  xor_128(p_out, in1, in2) \
  (*(p_out)).h[hH]=(in1).h[hH] ^ (in2).h[hH]; \
  (*(p_out)).h[hL]=(in1).h[hL] ^ (in2).h[hL];

#define get_128_w4(in,word_number) ((in).w[wT[(word_number)]])

#define PATTERN_01
#undef  PATTERN_11
#undef  PATTERN_AA
#undef  PATTERN_FF

void copy_128_to_8(uint8_t *p_out, my_uint128_t *p_in)
{ 
  for(int i=0; i<TXTSIZ; i++) p_out[i]=p_in->b[bT[i]]; 
}

void copy_8_to_128(my_uint128_t *p_out, uint8_t *p_in)
{ 
  for(int i=0; i<TXTSIZ; i++) p_out->b[bT[i]]=p_in[i]; 
}

static int load_plaintexts(my_uint128_t *p, uint8_t *p_k2pt)
{
  int n=0;
  //Will do multiple bits at a time
  //As long as the bits dont hit the same 'change cluster' in cipher text, 
  //we are ok. More that 4 bytes at time with make two different bytes
  //to hit/populate the same cluster of 4 bytes after mixcolumns is called
#ifdef PATTERN_01
  // Keybytes  0x10,f,e,d,c,b,a,9,   8,7,6,5,4,3,2,1
  load_128(p+n,0x0000000000000000,0x0000000000000000); n++;
  load_128(p+n,0x0000000000000000,0x0000000001010101); n++;
  load_128(p+n,0x0000000000000000,0x0101010100000000); n++;
  load_128(p+n,0x0000000001010101,0x0000000000000000); n++;
  load_128(p+n,0x0101010100000000,0x0000000000000000); n++;
#endif
#ifdef PATTERN_11
  // Keybytes  0x10,f,e,d,c,b,a,9,   8,7,6,5,4,3,2,1
  load_128(p+n,0x0000000000000000,0x0000000000000000); n++;
  load_128(p+n,0x0000000000000000,0x0000000011111111); n++;
  load_128(p+n,0x0000000000000000,0x1111111100000000); n++;
  load_128(p+n,0x0000000011111111,0x0000000000000000); n++;
  load_128(p+n,0x1111111100000000,0x0000000000000000); n++;
#endif
#ifdef PATTERN_AA
  // Keybytes  0x10,f,e,d,c,b,a,9,   8,7,6,5,4,3,2,1
  load_128(p+n,0x0000000000000000,0x0000000000000000); n++;
  load_128(p+n,0x0000000000000000,0x00000000aaaaaaaa); n++;
  load_128(p+n,0x0000000000000000,0xaaaaaaaa00000000); n++;
  load_128(p+n,0x00000000aaaaaaaa,0x0000000000000000); n++;
  load_128(p+n,0xaaaaaaaa00000000,0x0000000000000000); n++;
#endif
#ifdef PATTERN_FF
  // Keybytes  0x10,f,e,d,c,b,a,9,   8,7,6,5,4,3,2,1
  load_128(p+n,0x0000000000000000,0x0000000000000000); n++;
  load_128(p+n,0x0000000000000000,0x00000000ffffffff); n++;
  load_128(p+n,0x0000000000000000,0xffffffff00000000); n++;
  load_128(p+n,0x00000000ffffffff,0x0000000000000000); n++;
  load_128(p+n,0xffffffff00000000,0x0000000000000000); n++;
#endif
  
  // This table maps what PT to use to what key byte
  p_k2pt[ 0]= p_k2pt[ 1]= p_k2pt[ 2]= p_k2pt[ 3]= 4;
  p_k2pt[ 4]= p_k2pt[ 5]= p_k2pt[ 6]= p_k2pt[ 7]= 3;
  p_k2pt[ 8]= p_k2pt[ 9]= p_k2pt[10]= p_k2pt[11]= 2;
  p_k2pt[12]= p_k2pt[13]= p_k2pt[14]= p_k2pt[15]= 1;

  return n;
}
static int load_plaintexts_file(my_uint128_t *p_pt, uint8_t *p_k2pt, my_uint128_t *p_ci, char *p_file_name)
{
  int n=0, i, c;
  uint8_t inbuf[TXTSIZ];
  // LOAD Plaintexts (note that we are using only 17 plaintexts
  // We need 5 PT minimum, but in this case wwe need 17
  // because we also need on change in each key byte
  // Keybytes     0x10,f,e,d,c,b,a,9,   8,7,6,5,4,3,2,1
  load_128(p_pt+n,0x0000000000000000,0x0000000000000000); n++;
  load_128(p_pt+n,0x0000000000000000,0x0000000000000001); n++;
  load_128(p_pt+n,0x0000000000000000,0x0000000000000100); n++;
  load_128(p_pt+n,0x0000000000000000,0x0000000000010000); n++;
  load_128(p_pt+n,0x0000000000000000,0x0000000001000000); n++;
  load_128(p_pt+n,0x0000000000000000,0x0000000100000000); n++;
  load_128(p_pt+n,0x0000000000000000,0x0000010000000000); n++;
  load_128(p_pt+n,0x0000000000000000,0x0001000000000000); n++;
  load_128(p_pt+n,0x0000000000000000,0x0100000000000000); n++;
  load_128(p_pt+n,0x0000000000000001,0x0000000000000000); n++;
  load_128(p_pt+n,0x0000000000000100,0x0000000000000000); n++;
  load_128(p_pt+n,0x0000000000010000,0x0000000000000000); n++;
  load_128(p_pt+n,0x0000000001000000,0x0000000000000000); n++;
  load_128(p_pt+n,0x0000000100000000,0x0000000000000000); n++;
  load_128(p_pt+n,0x0000010000000000,0x0000000000000000); n++;
  load_128(p_pt+n,0x0001000000000000,0x0000000000000000); n++;
  load_128(p_pt+n,0x0100000000000000,0x0000000000000000); n++;
  // Keybytes     0x10,f,e,d,c,b,a,9,   8,7,6,5,4,3,2,1
  
  // This table maps what PT to use to what key byte
  for (i=15; i>=0; i--) p_k2pt[i]=16-i;
  
  // Now let's LOAD the CI from the file
  // that the it is ASSUMED that the CI match the PT above
  // NOTHING will work if the ASSUMPTION is wrong
  FILE *fp = fopen(p_file_name, "r");
  if (NULL == fp)
  {
    PEN_RED();printf("FATAL ERROR: Can'f open file %s.\n", p_file_name); PEN_NC();
    perror("ERROR message: "); printf("Aborting...\n\n"); 
    exit(-3);
  }

  int expected_numbers = 129*16;
  int nums = 0;
  char str_numx[3]; str_numx[2]='\0';
  int numx;
  printf("------------------------------------------------------------\n");
  while ( EOF != (c =fgetc(fp)) )
  {
    if (!isxdigit(c)) continue;
    str_numx[0]=c;
    if (EOF == (c =fgetc(fp))) 				goto FILE_PARSING_ERROR; 
    if (!isxdigit(c))          				goto FILE_PARSING_ERROR; //Hex digits comes pairs
    str_numx[1]=c;
    c =fgetc(fp);                                       // Dont test EOF (last hex in file may have nothing after)
    if ( isxdigit(c))          				goto FILE_PARSING_ERROR; //After the pair a space
    nums++;
    if( 1 != sscanf(str_numx, "%x", &numx)) 		goto FILE_PARSING_ERROR; //After the pair a space
    //printf("%s,", str_numx); printf("%02x;", numx);
    
    // We will use just 17 specfic scan vectors (one for each byte change)
    
#define GET_CIPHER_LINE(x)                                                      \
    if ((nums >= 1+16*(x)) && (nums <= 16+16*(x))) inbuf[(nums-1)%TXTSIZ] = numx; 

    GET_CIPHER_LINE(     0);
    GET_CIPHER_LINE(1+8* 0);
    GET_CIPHER_LINE(1+8* 1);
    GET_CIPHER_LINE(1+8* 2);
    GET_CIPHER_LINE(1+8* 3);
    GET_CIPHER_LINE(1+8* 4);
    GET_CIPHER_LINE(1+8* 5);
    GET_CIPHER_LINE(1+8* 6);
    GET_CIPHER_LINE(1+8* 7);
    GET_CIPHER_LINE(1+8* 8);
    GET_CIPHER_LINE(1+8* 9);
    GET_CIPHER_LINE(1+8*10);
    GET_CIPHER_LINE(1+8*11);
    GET_CIPHER_LINE(1+8*12);
    GET_CIPHER_LINE(1+8*13);
    GET_CIPHER_LINE(1+8*14);
    GET_CIPHER_LINE(1+8*15);

#define SAVE_CIPHER(x,y)                                                                   \
    case 16+16*(x):                                                                        \
      copy_8_to_128(&p_ci[(y)], inbuf);                                                    \
      printf("%02d: Ciphertext %03d [", (y+1), (x));phex_128_n(&p_ci[(y)]); printf("]\n"); \
      break;

    switch(nums)
    {
      SAVE_CIPHER(     0, 0);
      SAVE_CIPHER(1+8* 0, 1);
      SAVE_CIPHER(1+8* 1, 2);
      SAVE_CIPHER(1+8* 2, 3);
      SAVE_CIPHER(1+8* 3, 4);
      SAVE_CIPHER(1+8* 4, 5);
      SAVE_CIPHER(1+8* 5, 6);
      SAVE_CIPHER(1+8* 6, 7);
      SAVE_CIPHER(1+8* 7, 8);
      SAVE_CIPHER(1+8* 8, 9);
      SAVE_CIPHER(1+8* 9,10);
      SAVE_CIPHER(1+8*10,11);
      SAVE_CIPHER(1+8*11,12);
      SAVE_CIPHER(1+8*12,13);
      SAVE_CIPHER(1+8*13,14);
      SAVE_CIPHER(1+8*14,15);
      SAVE_CIPHER(1+8*15,16);
    }

  }
  if (nums !=expected_numbers) 				goto FILE_PARSING_ERROR; 

  printf("------------------------------------------------------------\n");
  printf("File %s syntax is OK. \nSuccessfully parsed  the ciphertext subset needed (shown above):\n", p_file_name);
  
  return n;

  FILE_PARSING_ERROR: 
    PEN_RED();printf("FATAL ERROR: parsing problems in file %s.\n", p_file_name); PEN_NC(); 
    printf("Aborting...\n\n"); 
    exit(-4);
} /* End of load_plaintexts_file() */

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

static int AES_scan_attack_01(my_uint128_t *PT, my_uint128_t *CI, uint8_t *KB2PT, int num_pt, uint8_t *key_found, int *p_nloop)
{
  static my_uint128_t XO[MAX_PLAIN_TEXTS_USED];
  static kbc_t APC[AES_KEYLEN]; // APC=Attach Progress Control structure
  struct AES_ctx ctx2;
  my_uint128_t c0, c1;
  int k, n, pt, cluster, key_byte_n; 

  memset(APC, 0, sizeof(APC));

  for (pt=0; pt<num_pt; pt++)
  {
    // Bits in all clusters will change, but we know in what cluster
    // we should look for effects of a specific byte in the key
    // for instance byte 16 (LSB) will affect the MSB 4 bytes cluster,
    // byte 15 (LSB) will affect the bytes 5-6-7-8 cluster etc
    xor_128(&XO[pt], CI[0], CI[pt]);
    //printf("XOR Diff0 [%03d]:", pt); phex_128(&XO[pt]); 
    //printf("------------------------------------------------------------\n");
  }

  for (key_byte_n=15; key_byte_n>=0; key_byte_n--)
  {
    pt=KB2PT[key_byte_n];
    cluster=mapping_table_keybyte_to_cluster[key_byte_n];

    //printf("SEARCHING KeyBytePos=%02d: cluster:%d plain text idx:%d PATTERN:", key_byte_n, cluster, pt);
    //PEN_YELLOW();printf("%08x\n", get_128_w4(XO[pt],cluster)); PEN_NC();
  
    // Loop tru all possilbe AES keys who would have the current key byte position
    // 'Gentle' brute force :-) (fast - only 2^8 possibilities)
    memset(key_found, 0x00, AES_KEYLEN * sizeof(uint8_t));
    for (k=0x00; k <= 0xff; k++)
    {
      key_found[key_byte_n]=k; 
      AES_init_ctx(&ctx2, key_found);
      M_AES_ECB_encrypt(&ctx2, &PT[ 0], &c0);
      M_AES_ECB_encrypt(&ctx2, &PT[pt], &c1);
      xor_128(&c1, c1, c0);
  
      //const char *pch;
      //pch="--->COMPARING plaintext=%d cluster:%d key_pos=%02d key_byte_tried=%02x (cluster PATTERN %08x)\n";
      //printf(pch, pt, cluster, key_byte_n, k, get_128_w4(c1,cluster));
      if (get_128_w4(c1,cluster) == get_128_w4(XO[pt],cluster))
      {
         //printf(pch, pt, cluster, key_byte_n, k, get_128_w4(c1,cluster));
         //printf("------>FOUND candiate key=%02x !!!!!!! (maybe real key or a 'shadow')\n", k);

         n = APC[key_byte_n].n_kbc;   
	 if (n < MAX_BC)
	 {
	   APC[key_byte_n].kbc[n]=k;
	   APC[key_byte_n].n_kbc++;
	   APC_n_kbc_total++;
	 }
	 else
	 {
           PEN_RED();printf("FATAL ERROR: too many indistinguishable candidates (MAX is %d). Aborting...\n\n", MAX_BC); PEN_NC();
	   exit(-1);
	 }
      }
    } // End of for(k...)
  } // End of for(key_bytes...)

#if 0 //Enable for more details about the candies found
  for (key_byte_n=0; key_byte_n<AES_KEYLEN; key_byte_n++)
  {
    n = APC[key_byte_n].n_kbc;   
    printf("pos %02d: FOUND %d candies: ",  key_byte_n, n);
    for(  ; n; n--){printf("%02x/", APC[key_byte_n].kbc[n-1]);} printf("\n");
  }
  printf("TOTAL NUMBER of Candies: %d\n", APC_n_kbc_total);
#endif

  //Now the gran-finale
  //Not as time consuming as it seems
  int i[AES_KEYLEN];
  n=0;
#define FOR(n)          for (i[(n)]=0; i[(n)]<APC[(n)].n_kbc; i[(n)]++)
#define LOAD_KEY2(n)    key_found[(n)] = APC[(n)].kbc[i[(n)]];
  FOR( 0) FOR( 1) FOR( 2) FOR( 3)
  FOR( 4) FOR( 5) FOR( 6) FOR( 7)
  FOR( 8) FOR( 9) FOR(10) FOR(11)
  FOR(12) FOR(13) FOR(14) FOR(15)
  {
    n++;
    LOAD_KEY2( 0); LOAD_KEY2( 1); LOAD_KEY2( 2); LOAD_KEY2( 3);
    LOAD_KEY2( 4); LOAD_KEY2( 5); LOAD_KEY2( 6); LOAD_KEY2( 7);
    LOAD_KEY2( 8); LOAD_KEY2( 9); LOAD_KEY2(10); LOAD_KEY2(11);
    LOAD_KEY2(12); LOAD_KEY2(13); LOAD_KEY2(14); LOAD_KEY2(15);

    // Let's try the full candidate key against one of 
    // (known plaintexts, ciphertexts) pairs we obtained
    // from the scan side-attack
    AES_init_ctx(&ctx2, key_found);
    M_AES_ECB_encrypt(&ctx2, &PT[ 1], &c0);

    if (!memcmp(&c0, &CI[1], sizeof(c0))) goto FOUND_KEY_VIVA;
  }

  //NOT_FOUND_KEY:
  *p_nloop = n;
  return(0);

  FOUND_KEY_VIVA:
  *p_nloop = n;
  return (1);

} // End of AES_scan_attack_01()

//----------------------------------------------------------------
//----------------------------------------------------------------

//uint8_t key[]     ={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
//uint8_t key[]     ={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
uint8_t key[]     ={0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};

//static uint8_t plain_text[]={0x6b,0xc0,0xbc,0xe1,0x2a,0x45,0x99,0x91,0xe1,0x34,0x74,0x1a,0x7f,0x9e,0x19,0x25};
int main(int argc, char *argv[])
{
  static my_uint128_t PT[MAX_PLAIN_TEXTS_USED];
  static my_uint128_t CI[MAX_PLAIN_TEXTS_USED];
  uint8_t KB2PT[AES_BLOCKLEN];
  uint8_t  key_found[AES_KEYLEN];
  uint8_t key_random[AES_KEYLEN];
  uint8_t *p_key;
  struct AES_ctx ctx;
  int num_pt, pt, ret, n, run;
  int number_of_runs;
  int is_in_random_test_mode;

  if ( (2 < argc) || 
       ( (argc == 2) &&
         ((!strcasecmp( "help", argv[1])) ||
          (!strcasecmp("-help", argv[1])) ||
          (!strcasecmp(   "-h", argv[1]))) ) )

  {
     PEN_RED(); printf ("ERROR: ");  PEN_NC();
     printf("SYNTAX: %s [PlainTextFile.txt]\n", argv[0]);
     printf("Have a good day...\n\n");
     exit(-1);
  }

  if (1 == argc)
  {
     srand(11223344);
     p_key=key_random;
     number_of_runs=1000;
     is_in_random_test_mode=1;
     num_pt = load_plaintexts(PT, KB2PT);
  }
  else
  {
     number_of_runs=1;
     is_in_random_test_mode=0;
     p_key=NULL;
     num_pt = load_plaintexts_file(PT, KB2PT, CI, argv[1]);
  }

  printf("------------------------------------------------------------\n");
  printf("Testing AES128 (***MODIFIED/WEAKENED*** - Does ONLY 1 round)\n");
  printf("------------------------------------------------------------\n");
  
  for(run=1; run<=number_of_runs; run++)
  {
    // If in Random test mode, generates Random Keys to later discover them
    // and calculates the expected ciphers associated with the random keys
    // so that results can be easily compared
    if(is_in_random_test_mode) 
    {
      for (n=0; n<AES_KEYLEN; n++) key_random[n] = rand();

      //Initializations and other Pro-forma
      AES_init_ctx(&ctx, p_key);
      printf("------------------------------------------------------------\n");
      printf(">>>>RUN=%d\n", run);
      print_keys(p_key, &ctx, 0);
      APC_n_kbc_total = 0;

      //Generate Ciphertexs for all plaintexts that will be used
      //in the AES attack
      printf("------------------------------------------------------------\n");
      printf("These are the plain and ciphertexts obtained for the attack:\n");
      printf("------------------------------------------------------------\n");
      for (pt=0; pt<num_pt; pt++)
      {
        printf("plaintext [%03d]:", pt); phex_128(&PT[pt]); 
        M_AES_ECB_encrypt(&ctx, &PT[pt], &CI[pt]); // Given. Scanned out of the Chip
        printf("encryp cipher  :"); phex_128(&CI[pt]);
      }
    }

    // Now progress into the attack
    // Parameters:
    // PT       : List of PlainTexts  (5 minimum with bit changes in specfic places)
    // CI       : List of CipherTexts associated with the PTs
    // KB2PT    : Lookup table that tells what PT to use for each key byte
    // key_found: the key that was cracked
    // n        : a metric that tells how many loops were needed to find the key
    ret= AES_scan_attack_01(PT, CI, KB2PT, num_pt, key_found, &n); 
  
    if(1==ret)
    {
      printf ("AES128 Key --> ["); 
      PEN_GREEN(); phex_n(key_found); PEN_NC(); printf("]  FOUND. SUCCESS!!! ...%d/%d\n", APC_n_kbc_total, n);
      printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n\n\n");
    }
    else
    {
      printf("Looped  n=%d\n", n);
      PEN_RED(); printf ("ERROR: Key not found. Something is WRONG. Please fix me.\n\n");  PEN_NC();
      exit(-1);
    }
  } // for(run ...)
  
  exit(0);
}
