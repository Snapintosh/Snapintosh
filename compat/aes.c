/* SPDX-License-Identifier: MIT */
#include "aes.h"

void aes_clear(void *memory,size_t size)
{
    volatile uint8_t *p=memory;
    while (size--) *p++=0;
}
static uint8_t xtime(uint8_t a)
{ return (uint8_t)((a<<1) ^ (0x1bU & (0U-(a>>7)))); }
static uint8_t mul(uint8_t a,uint8_t b)
{
    uint8_t v=0;
    for (unsigned i=0;i<8;i++) { v^=a&(uint8_t)(0U-(b&1));a=xtime(a);b>>=1; }
    return v;
}
static uint8_t inverse(uint8_t a)
{
    uint8_t v=1;
    /* a**254 in GF(2**8), including the required inverse(0)=0. */
    for (unsigned i=0;i<8;i++) { if (i) v=mul(v,a);a=mul(a,a); }
    return v;
}
static uint8_t rot(uint8_t x,unsigned n)
{ return (uint8_t)((x<<n)|(x>>(8-n))); }
static uint8_t sub(uint8_t x)
{ x=inverse(x);return x^rot(x,1)^rot(x,2)^rot(x,3)^rot(x,4)^0x63; }
static uint8_t unsub(uint8_t x)
{ return inverse(rot(x,1)^rot(x,3)^rot(x,6)^5); }
int aes_expand(struct aes_key *key,const uint8_t *bytes,size_t size)
{
    if (!key || !bytes || (size!=16 && size!=24 && size!=32)) return 0;
    struct aes_key next={0};next.rounds=(uint32_t)(size/4)+6;
    for (unsigned i=0;i<size;i++) next.round_key[i]=bytes[i];
    uint8_t rc=1;
    for (unsigned i=(unsigned)size;i<16*(next.rounds+1);i+=4) {
        uint8_t t[4];for (unsigned j=0;j<4;j++) t[j]=next.round_key[i-4+j];
        if (!(i%size)) {
            uint8_t first=t[0];t[0]=sub(t[1])^rc;t[1]=sub(t[2]);
            t[2]=sub(t[3]);t[3]=sub(first);rc=xtime(rc);
        } else if (size==32 && i%size==16) for (unsigned j=0;j<4;j++) t[j]=sub(t[j]);
        for (unsigned j=0;j<4;j++) next.round_key[i+j]=next.round_key[i+j-size]^t[j];
        aes_clear(t,sizeof(t));
    }
    /* Volatile copy also keeps freestanding builds independent of memcpy. */
    for (unsigned i=0;i<sizeof(next);i++)
        ((volatile uint8_t *)key)[i]=((const uint8_t *)&next)[i];
    aes_clear(&next,sizeof(next));return 1;
}
static void add_key(uint8_t s[16],const uint8_t *key)
{ for (unsigned i=0;i<16;i++) s[i]^=key[i]; }
static void shift(uint8_t s[16],int decrypt)
{
    uint8_t t[16];
    for (unsigned c=0;c<4;c++) for (unsigned r=0;r<4;r++)
        t[c*4+r]=s[((c+(decrypt ? 4-r : r))&3)*4+r];
    for (unsigned i=0;i<16;i++) s[i]=t[i];
    aes_clear(t,sizeof(t));
}
static void mix(uint8_t s[16],int decrypt)
{
    for (unsigned c=0;c<4;c++) {
        uint8_t *p=s+c*4;
        if (decrypt) {
            uint8_t u=xtime(xtime(p[0]^p[2])),v=xtime(xtime(p[1]^p[3]));
            p[0]^=u;p[2]^=u;p[1]^=v;p[3]^=v;
        }
        uint8_t all=p[0]^p[1]^p[2]^p[3],first=p[0];
        p[0]^=all^xtime(p[0]^p[1]);p[1]^=all^xtime(p[1]^p[2]);
        p[2]^=all^xtime(p[2]^p[3]);p[3]^=all^xtime(p[3]^first);
    }
}
int aes_hardware_supported(uint64_t isar0)
{
    return ((isar0>>4)&15)!=0;
}
/* FIPS-197 byte order matches ld1 {.16b}: rounds-1 AESE+AESMC, one AESE, EOR.
 * The guest's v0/v1 stay live across EL2 entry, so both are saved first and
 * restored last; the saved copy is cleared afterwards. */
static void block_hardware(const struct aes_key *key,const uint8_t input[16],uint8_t output[16])
{
#if defined(__aarch64__)
    uint8_t saved[32] __attribute__((aligned(16)));
    const uint8_t *round_key=key->round_key;uint64_t rounds=key->rounds;
    __asm__ volatile(
        ".arch_extension simd\n\t.arch_extension aes\n\t"
        "st1 {v0.16b,v1.16b},[%[saved]]\n\t"
        "ld1 {v0.16b},[%[in]]\n\t"
        "sub %[n],%[n],#1\n"
        "1:\n\tld1 {v1.16b},[%[rk]],#16\n\t"
        "aese v0.16b,v1.16b\n\taesmc v0.16b,v0.16b\n\t"
        "subs %[n],%[n],#1\n\tb.ne 1b\n\t"
        "ld1 {v1.16b},[%[rk]],#16\n\taese v0.16b,v1.16b\n\t"
        "ld1 {v1.16b},[%[rk]]\n\teor v0.16b,v0.16b,v1.16b\n\t"
        "st1 {v0.16b},[%[out]]\n\t"
        "ld1 {v0.16b,v1.16b},[%[saved]]"
        :[rk]"+r"(round_key),[n]"+r"(rounds)
        :[in]"r"(input),[out]"r"(output),[saved]"r"(saved)
        :"memory","cc");
    aes_clear(saved,sizeof(saved));
#else
    /* Software fallback on non-ARM64 host validation machines */
    aes_block(key,input,output,0);
#endif
}
static int valid(const struct aes_key *key,const uint8_t *input,const uint8_t *output,int decrypt)
{
    if (!key || !input || !output || (decrypt!=0 && decrypt!=1) ||
        (key->rounds!=10 && key->rounds!=12 && key->rounds!=14)) return 0;
    uintptr_t out=(uintptr_t)output,k=(uintptr_t)key;
    return !(out>UINTPTR_MAX-16 || k>UINTPTR_MAX-sizeof(*key) ||
             (out<k+sizeof(*key) && k<out+16));
}
int aes_encrypt_hardware(const struct aes_key *key,const uint8_t input[16],uint8_t output[16])
{
    if (!valid(key,input,output,0)) return 0;
    block_hardware(key,input,output);return 1;
}
int aes_block(const struct aes_key *key,const uint8_t input[16],uint8_t output[16],int decrypt)
{
    if (!valid(key,input,output,decrypt)) return 0;
    uint8_t s[16];for (unsigned i=0;i<16;i++) s[i]=input[i];
    add_key(s,key->round_key+(decrypt ? key->rounds*16 : 0));
    for (unsigned round=1;round<=key->rounds;round++) {
        if (decrypt) {
            shift(s,1);
            for (unsigned i=0;i<16;i++) s[i]=unsub(s[i]);
            add_key(s,key->round_key+(key->rounds-round)*16);
            if (round<key->rounds) mix(s,1);
        } else {
            for (unsigned i=0;i<16;i++) s[i]=sub(s[i]);
            shift(s,0);
            if (round<key->rounds) mix(s,0);
            add_key(s,key->round_key+round*16);
        }
    }
    for (unsigned i=0;i<16;i++) output[i]=s[i];
    aes_clear(s,sizeof(s));return 1;
}
