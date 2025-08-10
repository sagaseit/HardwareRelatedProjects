#ifndef AES_SIMPLE_H
#define AES_SIMPLE_H
#include <stdint.h>

extern const uint8_t SBOX[256];
extern const uint8_t rCon[12];
typedef uint32_t t_state[4];
void subBytes(uint32_t s[4]);
void shiftRows(uint32_t s[4]);
void mixColumns(uint32_t s[4]);
void addRoundKey(uint32_t s[4], const uint32_t ek[], short index);
void expandKey(uint8_t k[16], uint32_t ek[44]);
uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3);
uint8_t wbyte(uint32_t w, int pos);
uint32_t subWord(uint32_t w);
uint32_t rotateWord(uint32_t w);
uint8_t xtime(uint8_t a);
uint32_t mixColumn(uint32_t c);
void aes_simple(uint8_t *in, uint8_t *out, uint32_t *expKey);


#endif // AES_SIMPLE_H