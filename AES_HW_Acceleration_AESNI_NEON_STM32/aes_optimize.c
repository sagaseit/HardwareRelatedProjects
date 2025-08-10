#include "aes_optimize.h"
#include "aes_simple.h"
#include "aes_t_box.h"


extern const uint32_t T0[256], T1[256], T2[256], T3[256];

#define word_optimize(a0, a1, a2, a3) ((a0) | ((uint32_t)(a1) << 8) | ((uint32_t)(a2) << 16) | ((uint32_t)(a3) << 24))
#define wbyte_optimize(w, pos) (((w) >> ((pos) * 8)) & 0xff)

typedef uint32_t t_state[4];

// **************** AES  functions ****************
uint32_t subWord_optimize(uint32_t w) {
    return word_optimize(SBOX[wbyte_optimize(w, 0)], SBOX[wbyte_optimize(w, 1)],
    		SBOX[wbyte_optimize(w, 2)], SBOX[wbyte_optimize(w, 3)]);
}

void subBytes_optimize(t_state s) {
    s[0] = subWord_optimize(s[0]);
    s[1] = subWord_optimize(s[1]);
    s[2] = subWord_optimize(s[2]);
    s[3] = subWord_optimize(s[3]);
}

void shiftRows_optimize(t_state s) {
    uint32_t y0 = s[0];
    uint32_t y1 = s[1];
    uint32_t y2 = s[2];
    uint32_t y3 = s[3];

    s[0] = word_optimize(wbyte_optimize(y0, 0), wbyte_optimize(y1, 1), wbyte_optimize(y2, 2), wbyte_optimize(y3, 3));
    s[1] = word_optimize(wbyte_optimize(y1, 0), wbyte_optimize(y2, 1), wbyte_optimize(y3, 2), wbyte_optimize(y0, 3));
    s[2] = word_optimize(wbyte_optimize(y2, 0), wbyte_optimize(y3, 1), wbyte_optimize(y0, 2), wbyte_optimize(y1, 3));
    s[3] = word_optimize(wbyte_optimize(y3, 0), wbyte_optimize(y0, 1), wbyte_optimize(y1, 2), wbyte_optimize(y2, 3));
}

//took this function from https://gist.github.com/cmrmahesh/8d9b2a7d887ce2038daae2ab3c13f152
uint8_t xtime_optimize(uint8_t a) {
    return (((a << 1) ^ (((a >> 7) & 1) * 0x1b)));
}

uint32_t mixColumn_optimize(uint32_t c) {
    uint8_t c0 = wbyte_optimize(c, 0);
    uint8_t c1 = wbyte_optimize(c, 1);
    uint8_t c2 = wbyte_optimize(c, 2);
    uint8_t c3 = wbyte_optimize(c, 3);

    uint8_t n0 = xtime_optimize(c0) ^ (xtime_optimize(c1) ^ c1) ^ c2 ^ c3;
    uint8_t n1 = c0 ^ xtime_optimize(c1) ^ (xtime_optimize(c2) ^ c2) ^ c3;
    uint8_t n2 = c0 ^ c1 ^ xtime_optimize(c2) ^ (xtime_optimize(c3) ^ c3);
    uint8_t n3 = (xtime_optimize(c0) ^ c0) ^ c1 ^ c2 ^ xtime_optimize(c3);

    return word_optimize(n0, n1, n2, n3);
}

void mixColumn_optimizes(t_state s) {
    s[0] = mixColumn_optimize(s[0]);
    s[1] = mixColumn_optimize(s[1]);
    s[2] = mixColumn_optimize(s[2]);
    s[3] = mixColumn_optimize(s[3]);
}

uint32_t rotateWord_optimize(uint32_t w) {
    return (w << 24) | (w >> 8);
}

/*
* Key expansion from 128bits (4*32b)
* to 11 round keys (11*4*32b)
* each round key is 4*32b
*/
void expandKey_optimize(uint8_t k[16], uint32_t ek[44]) {
    short i = 0, Nk = 4, expandKey_optimizeSize = 44;
    while (i < Nk) {
        ek[i] = word_optimize(k[4 * i], k[4 * i + 1], k[4 * i + 2], k[4 * i + 3]);
        i++;
    }

    i = Nk;
    uint32_t temp_word;
    while (i < expandKey_optimizeSize) {
        temp_word = ek[i - 1];
        if ((i % Nk) == 0) {
            temp_word = subWord_optimize(rotateWord_optimize(temp_word)) ^ rCon[i / Nk];
        }
        ek[i] = ek[i - Nk] ^ temp_word;
        i++;
    }
}

void addRoundKey_optimize(t_state s, const uint32_t ek[], short index) {
    s[0] = s[0] ^ ek[4 * index];
    s[1] = s[1] ^ ek[4 * index + 1];
    s[2] = s[2] ^ ek[4 * index + 2];
    s[3] = s[3] ^ ek[4 * index + 3];
}

void sbox_to_tbox(t_state *state) {
    uint32_t t0 = T0[wbyte_optimize((*state)[0], 0)] ^ T1[wbyte_optimize((*state)[1], 1)]
                  ^ T2[wbyte_optimize((*state)[2], 2)] ^ T3[wbyte_optimize((*state)[3], 3)];
    uint32_t t1 = T0[wbyte_optimize((*state)[1], 0)] ^ T1[wbyte_optimize((*state)[2], 1)]
                  ^ T2[wbyte_optimize((*state)[3], 2)] ^ T3[wbyte_optimize((*state)[0], 3)];
    uint32_t t2 = T0[wbyte_optimize((*state)[2], 0)] ^ T1[wbyte_optimize((*state)[3], 1)]
                  ^ T2[wbyte_optimize((*state)[0], 2)] ^ T3[wbyte_optimize((*state)[1], 3)];
    uint32_t t3 = T0[wbyte_optimize((*state)[3], 0)] ^ T1[wbyte_optimize((*state)[0], 1)]
                  ^ T2[wbyte_optimize((*state)[1], 2)] ^ T3[wbyte_optimize((*state)[2], 3)];

    (*state)[0] = t0;
    (*state)[1] = t1;
    (*state)[2] = t2;
    (*state)[3] = t3;
}


void aes_optimize(uint8_t *in, uint8_t *out, uint32_t *expKey) {
    unsigned short round;
    t_state state;

    state[0] = word_optimize(in[0], in[1], in[2], in[3]);
    state[1] = word_optimize(in[4], in[5], in[6], in[7]);
    state[2] = word_optimize(in[8], in[9], in[10], in[11]);
    state[3] = word_optimize(in[12], in[13], in[14], in[15]);

    addRoundKey_optimize(state, expKey, 0);

    for (round = 1; round < 10; round++) {
        sbox_to_tbox(&state);
        addRoundKey_optimize(state, expKey, (short)round);
    }

    subBytes_optimize(state);
    shiftRows_optimize(state);
    addRoundKey_optimize(state, expKey, 10);

    for (int i = 0; i < 16; i++) {
        if (i < 4) out[i] = wbyte_optimize(state[0], i % 4);
        else if (i < 8) out[i] = wbyte_optimize(state[1], i % 4);
        else if (i < 12) out[i] = wbyte_optimize(state[2], i % 4);
        else out[i] = wbyte_optimize(state[3], i % 4);
    }
}


