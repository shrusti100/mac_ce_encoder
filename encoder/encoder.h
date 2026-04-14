#ifndef ENCODER_H
#define ENCODER_H
#include <stdint.h>

#define MAX_MAC_CE_SIZE 255

#define SUCCESS 0
#define FAILURE -1

typedef struct
{
    uint8_t MPE;
    uint8_t R2;
    uint8_t P;
    uint8_t R;
    uint8_t BT;
    uint8_t X;
} Flags;

#define LCID_SHORT_BSR 61
#define LCID_PHR 57
#define LCID_CRNTI 58
#define LCID_REC_BIT_RATE 53
#define LCID_ONE_OCTET_ELCID 34

#define ELCID_DSR 228
#define ELCID_ENH_SINGLE_ENTRY_PHR_MULTIPLE_TRP_STX2P 221
#define ELCID_SL_LBT 222
#define ELCID_ENH_BFR 235
#define ELCID_EXTENDED_SHORT_TRUNCATED_BSR 245

// Functions
int short_bsr(uint8_t *pdu, int *offset, int argc, int lcg, int buffer);
int phr(uint8_t *pdu, int *offset, int argc, int ph, int pcmax, Flags flags);
int crnti(uint8_t *pdu, int *offset, int argc, int value);
int rec_bit_rate(uint8_t *pdu, int *offset, int argc, int lcid, int rate, int ul_dl, Flags flags);
int dsr(uint8_t *pdu, int *offset, int argc, int *params, Flags flags);
int enhanced_single_entry_phr_multiple_trp_stx2p(uint8_t *pdu, int *offset, int argc, int *params);
int sl_lbt(uint8_t *pdu, int *offset, int value);
int enhanced_bfr(uint8_t *pdu, int *offset, int argc, int *params);
int extended_short_truncated_bsr(uint8_t *pdu, int *offset, int lcg, int buffer);
int parse_and_encode(const char *filename, uint8_t *pdu, int *pdu_size);

void print_hex(uint8_t *data, int len);
void print_bits(uint8_t *data, int len);
void add_padding(uint8_t *buffer, int *offset, int remaining);

#endif
