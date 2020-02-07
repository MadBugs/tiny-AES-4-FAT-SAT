#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define MAIN_
#include "aes_SAT.h"

#define TXTSIZ 16
#define MAX_PLAIN_TEXTS_USED 129

static uint8_t key[]             ={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
//static uint8_t plain_text[TXTSIZ]={0x6b,0xc0,0xbc,0xe1,0x2a,0x45,0x99,0x91,0xe1,0x34,0x74,0x1a,0x7f,0x9e,0x19,0x25};

void phex_n_dot(uint8_t* str) // prints string as hex
{
    uint8_t len = 16; unsigned char i;
    //for (i = 0; i < len; ++i) {printf("%.2x,", str[i]);} // To generate in C format
    //for (i = 0; i < len; ++i) {printf("%.2x", str[i]);} 
    for (i = 0; i < len; ++i) {str[i] ? printf("%.2x", str[i]) : printf("..");} 
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

void print_keys(uint8_t *pk, struct AES_ctx *pctx, int opt)
{
    int i;
    printf(  "key            :"); phex(pk); 
    for (i=0; i<(AES_KEYEXPSIZE); i+=AES_KEYLEN) 
    {
      if (0x01&opt) {printf("[%02d] keyexpan  :", i/AES_KEYLEN); phex(&pctx->RoundKey[i]); }
    }
}

//MACROS
#define load_128(p, high64, low64) \
  (p)[n].h[hH]=high64; (p)[n++].h[hL]=low64;

#define  xor_128(p_out, in1, in2) \
  (*(p_out)).h[hH]=(in1).h[hH] ^ (in2).h[hH]; \
  (*(p_out)).h[hL]=(in1).h[hL] ^ (in2).h[hL];

#define get_128_w4(in,word_number) ((in).w[wT[(word_number)]])

static int load_plaintexts(my_uint128_t *p)
{
  int n=0;
  //Will do multiple bits at a time
  //As long as the bits dont hit the same 'change cluster' in cipher text, 
  //we are ok. More that 4 bytes at time with make two different bytes
  //to hit/populate the same cluster of 4 bytes after mixcolumns is called
  load_128(p,0x0000000000000000,0x0000000000000000);
  load_128(p,0x0000000000000000,0x00000000aaaaaaaa);
  load_128(p,0x0000000000000000,0xaaaaaaaa00000000);
  load_128(p,0x00000000aaaaaaaa,0x0000000000000000);
  load_128(p,0xaaaaaaaa00000000,0x0000000000000000);
  return n;
}

void copy_128_to_8(uint8_t *p_out, my_uint128_t *p_in)
{ for(int i=0; i<TXTSIZ; i++) p_out[i]=p_in->b[bT[i]]; }
void copy_8_to_128(my_uint128_t *p_out, uint8_t *p_in)
{ for(int i=0; i<TXTSIZ; i++) p_out->b[bT[i]]=p_in[i]; }

// --------------------------------------------------
// A BRIEF DESCRITION OF THE APPROACH USED
// --------------------------------------------------
// This mapping table below is very important
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
// The revere mapping is not unique, two key
// candidates are returned per byte in the key.
// However, the 'shadow' candidate is easily 
// deteced is removed from consideration by
// another check at the end.
// With only 5 plain/cipher texts pairs used 
// as inputs the shadow candidates need to 
// be removed that way.  With more suitable 
// pairs (10 minimum, with the proper bit variations) 
// the 'shadow' can be removed by using the fact that 
// reall key bytes REPEAT with bits in the plaintext
// change while the 'shadows' found KEEP CHANGING
// --------------------------------------------------
static int cluster_affected_by_byte[]={0,3,2,1,1,0,3,2,2,1,0,3,3,2,1,0};
static my_uint128_t PT[MAX_PLAIN_TEXTS_USED];
static my_uint128_t CI[MAX_PLAIN_TEXTS_USED];
static my_uint128_t XO[MAX_PLAIN_TEXTS_USED];

static int AES_scan_attack_01(void)
{
  struct AES_ctx ctx;
  struct AES_ctx ctx2;
  uint8_t key2[AES_KEYLEN];
  uint8_t inbuf[TXTSIZ];
  int k, pt, cluster, num_pt, key_byte_n; 
  my_uint128_t c0, c1;
  const char *pch;

  AES_init_ctx(&ctx, key);
  print_keys(key, &ctx, 0);
  num_pt = load_plaintexts(PT);

  // ----

  //Generate Ciphertexs for all plaintexts that will be used
  //in the AES attack
  printf("------------------------------------------------------------\n");
  printf("STEP 01: These are the plaintexts obtained for the attack:\n");
  printf("------------------------------------------------------------\n");
  for (pt=0; pt<num_pt; pt++)
  {
    copy_128_to_8(inbuf, &PT[pt]);
    printf("plaintext [%03d]:", pt); phex(inbuf); 
    AES_ECB_encrypt(&ctx, inbuf); 
    printf("encryp cipher  :"); phex(inbuf); 
    copy_8_to_128(&CI[pt], inbuf);
    // Bit in all clusters will change, but we know in what cluster
    // we should look for effects of a specific byte in the key
    // for instance byte 16 (LSB) will affect the MSB 4 bytes cluster,
    // byte 15 (LSB) will affect the bytes 5-6-7-8 cluster etc
    xor_128(&XO[pt], CI[0], CI[pt]);
    copy_128_to_8(inbuf, &XO[pt]);
    printf("XOR Diff from 0:"); phex(inbuf); 
    printf("------------------------------------------------------------\n");
  }

#define key ERROR_ERROR_DO_NOT_USE_ME // to make sure key is not used by mistake
  // ----
  // ---- No code beyond this point shall be aware of the key
  // ----

  for (key_byte_n=15; key_byte_n>=0; key_byte_n--)
  {
    pt=(15 - key_byte_n)/4 + 1; // This can be improved. Search for the first PT suitable for the byte...
    memset(key2, 0x00, sizeof(key2));
    cluster=cluster_affected_by_byte[key_byte_n];
    printf("STEP 01: SEARCHING KeyBytePos=%d: cluster:%d plain text idx:%d PATTERN:", key_byte_n, cluster, pt);
    PEN_YELLOW();printf("%08x\n", get_128_w4(XO[pt],cluster)); PEN_NC();
  
    // Loop tru all possilbe keys for the current key byte position
    // 'Gentle' brute force :-) (fast - only 2^8 possibilities)
    for (k=0x00; k <= 0xff; k++)
    {
      key2[key_byte_n]=k; AES_init_ctx(&ctx2, key2);
      copy_128_to_8(inbuf, &PT[ 0]); AES_ECB_encrypt(&ctx2, inbuf); copy_8_to_128(&c0, inbuf);
      copy_128_to_8(inbuf, &PT[pt]); AES_ECB_encrypt(&ctx2, inbuf); copy_8_to_128(&c1, inbuf);
      xor_128(&c1, c1, c0);
  
      pch="--->COMPARING plaintext=%d cluster:%d key_pos=%02d key_byte_tried=%02x (cluster PATTERN %08x)\n";
      //printf(pch, pt, cluster, key_byte_n, k, get_128_w4(c1,cluster));
      if (get_128_w4(c1,cluster) == get_128_w4(XO[pt],cluster))
      {
         printf(pch, pt, cluster, key_byte_n, k, get_128_w4(c1,cluster));
         printf("------>FOUND key=%02x !!!!!!!\n", k);
      }
    }
  }

#if 0
    struct AES_ctx ctx;
    struct AES_ctx ctx2;
    uint8_t key2[AES_KEYLEN];
    uint8_t inbuf0[TXTSIZ];
    uint8_t inbuf1[TXTSIZ];
    uint8_t inbuf2[TXTSIZ];
    my_uint128_t Ci0, Ci1, Ci2, Te0, Te1, a0, a1;
    int i, k, w;
    w=0;

//memset(key, 0x00, sizeof(key));
//key[16   -1]=0x3c;
//key[1   -1]=0x2b;
//for(i=0;i<=16;i++) {key[i]k, =0x10U+i;}
    AES_init_ctx(&ctx, key);
    print_keys(key, &ctx, 0);

    // ----
    Te0.h[hH]=0x0; Te0.h[hL]=0x0;
    for(i=0; i<TXTSIZ; i++) inbuf0[i]=Te0.b[bT[i]]; //LE64cpy()
    //printf("plaintext      :"); phex(inbuf0); 
    AES_ECB_encrypt(&ctx, inbuf0); 
    //printf("encryp cipher  :"); phex(inbuf0); 
    for(i=0; i<TXTSIZ; i++) Ci0.b[bT[i]]=inbuf0[i]; //LE64cpy()

    // ----
//Te1.h[hH]=0x00ULL; Te1.h[hL]=0xaaULL; // FIVE RUNS WILL BE NEEDED!!!! Clusters .... 
//Te1.h[hH]=0xaaaaaaaaaaaaaaaaULL; Te1.h[hL]=0xaaaaaaaaaaaaaaaaULL;
//Te1.h[hH]=0x0101010101010101ULL; Te1.h[hL]=0x0101010101010101ULL;
//Te1.h[hH]=0x00ULL; Te1.h[hL]=0x0101010101ULL;
//Te1.h[hH]=0x00ULL; Te1.h[hL]=0x01aaaaaaaaaaULL; //Does not work
//Te1.h[hH]=0x00ULL; Te1.h[hL]=0xaaaaaaaaaaULL;
Te1.h[hH]=0x00ULL; Te1.h[hL]=0x5555555555ULL;
//Te1.h[hH]=0x5555555555555555ULL; Te1.h[hL]=0x5555555555555555ULL;
    //memcpy(inbuf1, plain_text, TXTSIZ);
    for(i=0; i<TXTSIZ; i++) inbuf1[i]=Te1.b[bT[i]]; //LE64cpy()
    //printf("plaintext      :"); phex(inbuf1); 
    AES_ECB_encrypt(&ctx, inbuf1); 
    //printf("encryp cipher  :"); phex(inbuf1); 
    for(i=0; i<TXTSIZ; i++) Ci1.b[bT[i]]=inbuf1[i]; //LE64cpy()
    a0.h[hH]=Ci0.h[hH] ^ Ci1.h[hH]; a0.h[hL]=Ci0.h[hL] ^ Ci1.h[hL];
    printf("2:FIND %d: %08x\n", w, a0.w[wT[w]]);
 
    // ----
    // ----
    // ----
for (k=0x00; k <= 0xff; k++)
{
memset(key2, 0x00, sizeof(key2));
key2[16   -1]=k;
//key2[15   -1]=k;
    AES_init_ctx(&ctx2, key2);
    //print_keys(key2, &ctx2, 0);
    //
    // ----
    for(i=0; i<TXTSIZ; i++) inbuf0[i]=Te1.b[bT[i]]; //LE64cpy()
inbuf0[15]=0;
    //printf("plaintext      :"); phex(inbuf0); 
    AES_ECB_encrypt(&ctx2, inbuf0); 
    //printf("encryp cipher  :"); phex(inbuf0); 
    for(i=0; i<TXTSIZ; i++) Ci0.b[bT[i]]=inbuf0[i]; //LE64cpy()

    // ----
    for(i=0; i<TXTSIZ; i++) inbuf2[i]=Te1.b[bT[i]]; //LE64cpy()
    //printf("plaintext      :"); phex(inbuf2); 
    AES_ECB_encrypt(&ctx2, inbuf2); 
    //printf("encryp cipher  :"); phex(inbuf2); 
    for(i=0; i<TXTSIZ; i++) Ci2.b[bT[i]]=inbuf2[i]; //LE64cpy()
    a1.h[hH]=Ci0.h[hH] ^ Ci2.h[hH]; a1.h[hL]=Ci0.h[hL] ^ Ci2.h[hL];
    //printf("4:WORD %d: %08x (%02x)", w, a1.w[wT[w]], k);

    if (a1.w[wT[w]] == a0.w[wT[w]]) 
    {
       printf("<------ FOUND key=%02x !!!!!!!\n", k);
    }
}
#endif

#if 0
    const char *pch;
    pch=   "ECB3           :%016llx%016llx\n"; px128(pch, &Ci2);

       //phex_n(inbuf2); printf("  ...   "); phex_n(inbuf1); printf("\n");
       for(int i=0; i<TXTSIZ; i++) CT0[t].b[bT[i]] = inbuf1[i]; 
       printf("%03d: ", t); phex_n(inbuf1); 
       if (t > 0)
       {
         //auxor.h[hH]=CT0[t].h[hH] ^ CT0[t-1].h[hH]; auxor.h[hL]=CT0[t].h[hL] ^ CT0[t-1].h[hL]; //AGAINST PREV
         auxor.h[hH]=CT0[t].h[hH] ^ CT0[0  ].h[hH]; auxor.h[hL]=CT0[t].h[hL] ^ CT0[0  ].h[hL]; //AGAINST ZERO-POS
         for(int i=0; i<TXTSIZ; i++) inbuf3[i]=auxor.b[bT[i]];
         printf(" :::> ");
         phex_n_dot(inbuf3); 
       }

       printf("\n");

       AES_ECB_decrypt(&ctx, inbuf1);
       //int all_ok = !memcmp(inbuf2, inbuf2, TXTSIZ);
       //printf("decrypted [%s][%03d]:", all_ok?"OKK":"ERROR", t); phex(inbuf1); 
#endif

    return (1);
} // End of AES_scan_attack_01()

//----------------------------------------------------------------
int main(void)
{
    printf("------------------------------------------------------------\n");
    printf("Testing AES128 (***MODIFIED/WEAKENED*** - Does ONLY 1 round)\n");
    printf("------------------------------------------------------------\n");
    return AES_scan_attack_01();
}
