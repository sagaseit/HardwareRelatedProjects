#ifndef AES_OPTIMIZE_H
#define AES_OPTIMIZE_H

#include <stdint.h>


typedef uint32_t t_state[4];

uint32_t subWord_optimize(uint32_t w);
void subBytes_optimize(t_state s);
void shiftRows_optimize(t_state s);
uint8_t xtime_optimize(uint8_t a);
uint32_t mixColumn_optimize(uint32_t c);
void mixColumn_optimizes(t_state s);
uint32_t rotateWord_optimize(uint32_t w);
void expandKey_optimize(uint8_t k[16], uint32_t ek[44]);
void addRoundKey_optimize(t_state s, const uint32_t ek[], short index);
void aes_optimize(uint8_t *in, uint8_t *out, uint32_t *expKey);


#endif // AES_OPTIMIZE_H
