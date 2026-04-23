
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
#include "input_validation.h"
#include "encoder.h"
#include <assert.h>
static_assert(SUCCESS == 0 && FAILURE != 0,
              "check_range return-value logic requires SUCCESS=0, FAILURE!=0");

#define MAX_LINE 256   /* prevents silent line truncation               */
#define MAX_PARAMS 128 /* max parameters for variable-length CEs        */

static int parse_value_from_line(const char *line, int *out, const char *name);
static int read_required_int(FILE *fp, char *line, int *out, const char *name);
static int read_block_int(char *line, int *out, const char *name);
static int is_blank_line(const char *line);
static int parse_strict_non_negative_int(const char *s, int *out);

/*==================================
 VALIDATION UTILITIES
==================================*/
int check_range(int val, int min, int max, const char *name)
{
    if (val < min || val > max)
    {
        printf("ERROR: %s out of range (%d-%d)\n", name, min, max);
        return FAILURE;
    }
    return SUCCESS;
}

/*
 * check_pdu_space — returns PDU_OVERFLOW (not FAILURE) so the caller
 * can distinguish "encoding logic error" from "buffer full".
 */
int check_pdu_space(int offset, int required, int pdu_size)
{
    if (offset + required > pdu_size)
        return PDU_OVERFLOW;
    return SUCCESS;
}

/*==================================
 MAC CE ENCODING FUNCTIONS
==================================*/

/*******************************************************************
 * function: short_bsr
 *******************************************************************
 *  Brief: MAC subPDU with 8-bit MAC subheader
 *  Subheader: R (2 BITS) LCID (6 BITS)
 *  Format: LCG ID (3 BITS) Buffer Size (5 BITS)
 *  Total MAC CE (2 BYTES)
 *******************************************************************/
int short_bsr(uint8_t *pdu, int *offset, int argc, int lcg, int buffer, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc != 2)
    {
        printf("ERROR: short_bsr %s\n",
               argc == 0 ? "missing parameters (LCG BUFFER)" : argc == 1 ? (lcg == -1 ? "LCG not provided" : "BUFFER not provided")
                                                                         : "extra parameters detected");
        return FAILURE;
    }

    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;
    if (check_range(buffer, 0, 31, "BUFFER"))
        return FAILURE;

    int space = check_pdu_space(*offset, 2, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    pdu[(*offset)++] = LCID_SHORT_BSR;
    pdu[(*offset)++] = (uint8_t)(((lcg & 0x07) << 5) | (buffer & 0x1F));

    return SUCCESS;
}

/*******************************************************************
 function:phr
 ***********************************************************
 * Brief: MAC subPDU with: 8-bit MAC subheader
 * Subheader:R(2 BITS) LCID(6 BITS)
 * Format:Octet 1 -> P (1 BIT) R(1 BIT) PH (6 BITS)
 *        Octet 2 -> R (2 BITS)  PCMACX (6 BITS)
 *        Total MAC CE (3 BYTES)
 *******************************************************************/
int phr(uint8_t *pdu, int *offset, int argc, int ph, int pcmax, Flags flags, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc != 2)
    {
        const char *msgs[] = {"missing parameters (PH PCMAX)", ph == -1 ? "Missing parameter PH" : "Missing parameter PCMAX", "extra parameters detected"};
        printf("ERROR: phr %s\n", msgs[argc > 2 ? 2 : argc]);
        return FAILURE;
    }
    if (check_range(ph, 0, 63, "PH"))
        return FAILURE;
    if (check_range(pcmax, 0, 63, "PCMAX"))
        return FAILURE;

    int space = check_pdu_space(*offset, 3, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    pdu[(*offset)++] = LCID_PHR;
    pdu[(*offset)++] = (uint8_t)((flags.P << 7) | (flags.R << 6) | (ph & 0x3F));
    pdu[(*offset)++] = (uint8_t)((flags.MPE << 7) | (flags.R2 << 6) | (pcmax & 0x3F));

    return SUCCESS;
}

/*******************************************************************
 *function:crnti
 ********************************************************
 * Brief: MAC subPDU with: 8-bit MAC subheader
 * Subheader:R(2 BITS) LCID(6 BITS)
 * Format:Octet 1 ->CRNTI(8 BITS)
 *        Octet 2 -> CRNTI(8 BITS)
 * Total MAC CE (3 BYTES)
 *******************************************************************/
int crnti(uint8_t *pdu, int *offset, int argc, int value, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc != 1)
    {
        printf("ERROR: crnti %s\n", argc == 0 ? "missing parameter (CRNTI value)" : "extra parameters detected");
        return FAILURE;
    }

    if (value == -1)
    {
        printf("ERROR: CRNTI value not provided\n");
        return FAILURE;
    }

    if (check_range(value, 0, 65535, "CRNTI"))
        return FAILURE;

    int space = check_pdu_space(*offset, 3, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    pdu[(*offset)++] = LCID_CRNTI;
    pdu[(*offset)++] = (uint8_t)((value >> 8) & 0xFF);
    pdu[(*offset)++] = (uint8_t)(value & 0xFF);

    return SUCCESS;
}

/*******************************************************************
function : rec_bit_rate
******************************************************************
* MAC subPDU with: 8-bit MAC subheader (LCID = 6 bits , R =2 bits)
* Subheader: R(2 BITS) LCID(6 BITS)
* Format :Octet 1 -> lcid (6 BIT) UL/DL (1 BIT)  BIT RATE (1 BIT)
*         Octet 2 -> BIT RATE (5 BITS) X(1 BIT)  R (2 BITs)
*Total MAC CE payload (3 BYTES)
 *******************************************************************/
int rec_bit_rate(uint8_t *pdu, int *offset, int argc, int lcid, int rate, int ul_dl, Flags flags, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc == 0 || argc > 3)
    {
        printf("ERROR: rec_bit_rate %s\n", argc == 0 ? "missing parameters (LCID BIT_RATE UL/DL)" : "extra parameters detected");
        return FAILURE;
    }

    if (lcid == -1)
    {
        printf("ERROR: Missing parameter LCID\n");
        return FAILURE;
    }
    if (rate == -1)
    {
        printf("ERROR: Missing parameter RATE\n");
        return FAILURE;
    }
    if (ul_dl == -1)
    {
        printf("ERROR: Missing parameter UL/DL\n");
        return FAILURE;
    }

    if (check_range(lcid, 0, 63, "LCID"))
        return FAILURE;
    if (check_range(rate, 0, 63, "BIT_RATE"))
        return FAILURE;
    if (check_range(ul_dl, 0, 1, "UL/DL"))
        return FAILURE;

    int space = check_pdu_space(*offset, 3, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    /* ---- FIXED encoding ----
     * Oct1: LCID(6 bits)[7:2] | UL_DL(1 bit)[1] | rate MSB (bit5)[0]
     * Oct2: rate[4:0](5 bits)[7:3] | X[2] | R[1] | R[0]
     */
    pdu[(*offset)++] = LCID_REC_BIT_RATE;
    pdu[(*offset)++] = (uint8_t)(((lcid & 0x3F) << 2) |
                                 ((ul_dl & 0x01) << 1) |
                                 ((rate >> 5) & 0x01));
    pdu[(*offset)++] = (uint8_t)(((rate & 0x1F) << 3) |
                                 ((flags.X & 0x01) << 2) |
                                 ((flags.R & 0x01) << 1) |
                                 (flags.R2 & 0x01));

    return SUCCESS;
}

/*******************************************************************
 *function:dsr
**********************************************************
* Brief: MAC subPDU with 16-bit MAC subheader (Extended LCID)
* Subheader:Octet 1 → R (1 BITS)| R (1 BITS) | LCID (6 BITS)
            Octet 2 → eLCID(8 BITS)= 228 (DSR)
* Format:   Octet 1 → LCG bitmap (which LCGs are present)
*           Octet →  BT (1 BIT) R (1 BIT)  Remaining Time (6 BITS)
*           Octet → Buffer Size (8 BITS)
* Total MAC CE (5 BYTES)
 *******************************************************************/
int dsr(uint8_t *pdu, int *offset, int argc, int *params, Flags flags, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc < 3 || argc % 3 != 0)
    {
        printf("ERROR: dsr %s\n", argc < 3 ? "missing parameters (LCG RT BUFFER)" : "parameters must be groups of (LCG RT BUFFER)");
        return FAILURE;
    }

    int entries = argc / 3;

    /* validate ALL entries first */
    uint8_t lcg_bitmap = 0;
    for (int i = 0; i < entries; i++)
    {
        int lcg = params[i * 3];
        int rt = params[i * 3 + 1];
        int buffer = params[i * 3 + 2];

        if (lcg == -1)
        {
            printf("ERROR: Missing parameter LCG (entry %d)\n", i + 1);
            return FAILURE;
        }
        if (rt == -1)
        {
            printf("ERROR: Missing parameter RT (entry %d)\n", i + 1);
            return FAILURE;
        }
        if (buffer == -1)
        {
            printf("ERROR: Missing parameter BUFFER (entry %d)\n", i + 1);
            return FAILURE;
        }

        if (check_range(lcg, 0, 7, "LCG"))
            return FAILURE;
        if (check_range(rt, 0, 63, "RT"))
            return FAILURE;
        if (check_range(buffer, 0, 255, "BUFFER"))
            return FAILURE;

        lcg_bitmap |= (uint8_t)(1U << lcg);
    }

    /* space check after full validation, right before encoding */
    int needed = 2 + 1 + (2 * entries); /* subheader(2) + bitmap(1) + 2*entries */
    int space = check_pdu_space(*offset, needed, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    /* encode */
    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_DSR;
    pdu[(*offset)++] = lcg_bitmap;

    for (int i = 0; i < entries; i++)
    {
        int rt = params[i * 3 + 1];
        int buffer = params[i * 3 + 2];
        pdu[(*offset)++] = (uint8_t)((flags.BT << 7) | (flags.R << 6) | (rt & 0x3F));
        pdu[(*offset)++] = (uint8_t)buffer;
    }

    return SUCCESS;
}

/*******************************************************************
 function: enhanced phr
*********************************************************
* MAC subPDU with: 16-bit MAC subheader (Extended LCID)
* Subheader:Octet 1 → R(1 BITS) | R(1 BITS) | LCID(6 BITS)
*           Octet 2 → eLCID (8 BITS)= 221 (ENH_PHR)
* Format :  Octet 1 → P(0/1) | V(0/1) | PH1 (6 BIT)
*           Octet 2 → R(0/1) | V(0/1) | PH2 (6 BIT)
*           Octet 3 → R(0/) 2 BIT | PCMAAX (6 BIT)
* Total MAC CE payload (5 BYTES)
 *******************************************************************/
int enhanced_single_entry_phr_multiple_trp_stx2p(uint8_t *pdu, int *offset, int argc, int *params, Flags flags, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    /* FIXED: spec says exactly 4 params: PH1, PH2, PCMAX1, PCMAX2 */
    if (argc != 4)
    {
        printf("ERROR: enhanced_phr_stx2p requires exactly 4 parameters "
               "(PH1 PH2 PCMAX1 PCMAX2)\n");
        return FAILURE;
    }

    int ph1 = params[0];
    int ph2 = params[1];
    int pcmax1 = params[2];
    int pcmax2 = params[3];

    /* validate */
    if (ph1 == -1)
    {
        printf("ERROR: Missing parameter PH1\n");
        return FAILURE;
    }
    if (ph2 == -1)
    {
        printf("ERROR: Missing parameter PH2\n");
        return FAILURE;
    }
    if (pcmax1 == -1)
    {
        printf("ERROR: Missing parameter PCMAX1\n");
        return FAILURE;
    }
    if (pcmax2 == -1)
    {
        printf("ERROR: Missing parameter PCMAX2\n");
        return FAILURE;
    }

    if (check_range(ph1, 0, 63, "PH1"))
        return FAILURE;
    if (check_range(ph2, 0, 63, "PH2"))
        return FAILURE;
    if (check_range(pcmax1, 0, 63, "PCMAX1"))
        return FAILURE;
    if (check_range(pcmax2, 0, 63, "PCMAX2"))
        return FAILURE;

    /* 2 subheader + 4 payload = 6 bytes total */
    int space = check_pdu_space(*offset, 6, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    /* ---- FIXED encoding ----
     * Oct1: P1(1) | V1(1) | PH1(6)       — V field was missing before
     * Oct2: P2(1) | V2(1) | PH2(6)       — V field was missing before
     * Oct3: MPE1_or_R(2)  | PCMAX1(6)    — now sequential, not interleaved
     * Oct4: MPE2_or_R(2)  | PCMAX2(6)
     *
     * P1=P2=flags.P, V1=V2=flags.R (reuse R as V for single-entry context)
     * MPE1=flags.MPE, MPE2=flags.R2
     */
    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_ENH_SINGLE_ENTRY_PHR_MULTIPLE_TRP_STX2P;

    /* Oct 1 */
    pdu[(*offset)++] = (uint8_t)(((flags.P & 0x01) << 7) |
                                 ((flags.R & 0x01) << 6) |
                                 (ph1 & 0x3F));
    /* Oct 2 */
    pdu[(*offset)++] = (uint8_t)(((flags.P & 0x01) << 7) |
                                 ((flags.R & 0x01) << 6) |
                                 (ph2 & 0x3F));
    /* Oct 3 */
    pdu[(*offset)++] = (uint8_t)(((flags.MPE & 0x03) << 6) |
                                 (pcmax1 & 0x3F));
    /* Oct 4 */
    pdu[(*offset)++] = (uint8_t)(((flags.R2 & 0x03) << 6) |
                                 (pcmax2 & 0x3F));

    return SUCCESS;
}

/*******************************************************************
 * function: sl_lbt
 *********************************************************
 * MAC subPDU with: 16-bit MAC subheader (Extended LCID)
 * Subheader:Octet 1 → R(2 BITS) LCID(6 BITS)
 *         Octet 2 → eLCID(8 BITS)= 222 (SL-LBT)
 * Format: Octet 1 -> | R R R R4 R3 R2 R1 R0 |
 *         R(3 BITS) R4-R0 (5 BITS)
 * Total MAC CE (3 BYTES)
 *******************************************************************/
int sl_lbt(uint8_t *pdu, int *offset, int argc, int value, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc != 1)
    {
        printf("ERROR: sl_lbt %s\n", argc < 1 ? "missing parameter (SL-LBT value)" : "extra parameters detected");
        return FAILURE;
    }
    if (value == -1)
    {
        printf("ERROR: SL-LBT value not provided\n");
        return FAILURE;
    }
    /* 5-bit bitmap R0–R4 */
    if (check_range(value, 0, 31, "SL-LBT"))
        return FAILURE;

    int space = check_pdu_space(*offset, 3, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_SL_LBT;
    /* upper 3 bits are reserved (set to 0); lower 5 bits are Ri flags */
    pdu[(*offset)++] = (uint8_t)(value & 0x1F);

    return SUCCESS;
}

/*******************************************************************
 function:enhanced_bfr
***************************************************************
* MAC subPDU with: 16-bit MAC subheader (Extended LCID)
* Subheader: Octet 1 → R(2 Bits) LCID(6 BITS)
*            Octet 2 → eLCID = 235 (ENH_BFR)
* Format:    Octet 1 -> |C7 C6 C5 C4 C3 C2 C1 SP|
*            Octet 2 -> |S7 S6 S5 S4S S3 S2 S1 S0 |(8 BIT)
*            Octet 3 ->  |AC(0/1) ID(0/1)  CANDIDATE OR R BITS(6 BIT)|
* Total MAC CE(5 BYTES) VARIABLE LENGTH
 *******************************************************************/
int enhanced_bfr(uint8_t *pdu, int *offset, int argc, int *params, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc < 5 || (argc - 2) % 3 != 0)
    {
        printf("ERROR: enhanced_bfr %s\n", argc < 5 ? "requires CI, S and at least one entry (AC ID CID)" : "entries must be groups of (AC ID CID)");
        return FAILURE;
    }

    int entries = (argc - 2) / 3;

    int ci = params[0];
    int s = params[1];

    if (ci == -1)
    {
        printf("ERROR: Missing parameter CI\n");
        return FAILURE;
    }
    if (s == -1)
    {
        printf("ERROR: Missing parameter S\n");
        return FAILURE;
    }

    if (check_range(ci, 0, 255, "CI"))
        return FAILURE;
    if (check_range(s, 0, 255, "S"))
        return FAILURE;

    /* validate ALL entries first */
    for (int i = 0; i < entries; i++)
    {
        int ac = params[2 + i * 3];
        int id = params[2 + i * 3 + 1];
        int cid = params[2 + i * 3 + 2];

        if (ac == -1)
        {
            printf("ERROR: Missing parameter AC (entry %d)\n", i + 1);
            return FAILURE;
        }
        if (id == -1)
        {
            printf("ERROR: Missing parameter ID (entry %d)\n", i + 1);
            return FAILURE;
        }
        if (cid == -1)
        {
            printf("ERROR: Missing parameter CID (entry %d)\n", i + 1);
            return FAILURE;
        }

        if (check_range(ac, 0, 1, "AC"))
            return FAILURE;
        if (check_range(id, 0, 1, "ID"))
            return FAILURE;
        if (check_range(cid, 0, 63, "Candidate ID"))
            return FAILURE;
    }

    /* space check after full validation, right before encoding */
    int needed = 2 + 2 + entries;
    int space = check_pdu_space(*offset, needed, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    /* encode */
    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_ENH_BFR;
    pdu[(*offset)++] = (uint8_t)ci;
    pdu[(*offset)++] = (uint8_t)s;

    for (int i = 0; i < entries; i++)
    {
        int ac = params[2 + i * 3];
        int id = params[2 + i * 3 + 1];
        int cid = params[2 + i * 3 + 2];
        pdu[(*offset)++] = (uint8_t)((ac << 7) | (id << 6) | (cid & 0x3F));
    }

    return SUCCESS;
}

/*******************************************************************
 function: extended_bsr
**************************************************************
* MAC subPDU with: 16-bit MAC subheader (Extended LCID)
* Subheader: Octet 1 → R(2 BITS) LCID(6 BIT)
             Octet 2 → eLCID = 245 (EXTENDED_BSR)
* Format:    Octet 1 -> LCG ID (8 BITS)
             Octet 2 ->Buffer Size (8 BITS)
* Total MAC CE  (4 BYTES)
 *******************************************************************/
int extended_short_truncated_bsr(uint8_t *pdu, int *offset, int argc, int lcg, int buffer, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }

    if (argc != 2)
    {
        const char *msgs[] = {"missing parameters (LCG BUFFER)", lcg == -1 ? "LCG not provided" : "BUFFER not provided", "extra parameters detected"};
        printf("ERROR: extended_bsr %s\n", msgs[argc > 2 ? 2 : argc]);
        return FAILURE;
    }

    /* FIXED: 8-bit LCG field for Extended Short BSR (range 0–255) */
    if (check_range(lcg, 0, 255, "LCG"))
        return FAILURE;
    if (check_range(buffer, 0, 255, "BUFFER"))
        return FAILURE;

    int space = check_pdu_space(*offset, 4, total_pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_EXTENDED_SHORT_TRUNCATED_BSR;
    /* FIXED: full 8-bit mask (was 0x07 — incorrect 3-bit truncation) */
    pdu[(*offset)++] = (uint8_t)(lcg & 0xFF);
    pdu[(*offset)++] = (uint8_t)(buffer & 0xFF);

    return SUCCESS;
}

/*==================================
 OUTPUT HELPERS
==================================*/
void print_hex(uint8_t *data, int len)
{
    if (data == NULL || len <= 0)
        return;
    for (int i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

void print_bits(uint8_t *data, int len)
{
    if (data == NULL || len <= 0)
        return;
    for (int i = 0; i < len; i++)
    {
        for (int j = 7; j >= 0; j--)
            printf("%d", (data[i] >> j) & 1);
        printf(" ");
    }
}

void add_padding(uint8_t *buffer, int *offset, int remaining)
{
    for (int i = 0; i < remaining; i++)
        buffer[(*offset)++] = 0x00;
}

/*==================================
 TYPE TO ID LOOKUP
==================================*/
int get_ce_id(char *type)
{
    if (strcmp(type, "short_bsr") == 0)
        return 1;
    if (strcmp(type, "phr") == 0)
        return 2;
    if (strcmp(type, "crnti") == 0)
        return 3;
    if (strcmp(type, "rec_bit_rate") == 0)
        return 4;
    if (strcmp(type, "dsr") == 0)
        return 5;
    if (strcmp(type, "enhanced_single_entry_phr_multiple_trp_stx2p") == 0 ||
        strcmp(type, "enhanced_phr") == 0)
        return 6;
    if (strcmp(type, "sl_lbt") == 0)
        return 7;
    if (strcmp(type, "enhanced_bfr") == 0)
        return 8;
    if (strcmp(type, "extended_short_truncated_bsr") == 0 ||
        strcmp(type, "extended_bsr") == 0)
        return 9;
    return -1;
}

/*==================================
 INTERNAL PARSING UTILITIES
==================================*/
static int is_blank_line(const char *line)
{
    if (line == NULL)
        return 1;
    while (*line)
        if (!isspace((unsigned char)*line++))
            return 0;
    return 1;
}

static int parse_strict_non_negative_int(const char *s, int *out)
{
    int i = 0, val = 0;
    while (s[i] == ' ' || s[i] == '\t')
        i++;
    if (!s[i] || s[i] == '\n' || s[i] == '\r' || s[i] == '-')
        return FAILURE;
    for (; s[i] && s[i] != '\n' && s[i] != '\r'; i++)
    {
        if (s[i] < '0' || s[i] > '9')
            return FAILURE;
        int d = s[i] - '0';
        if (val > (INT_MAX - d) / 10)
            return FAILURE;
        val = val * 10 + d;
    }
    *out = val;
    return SUCCESS;
}

static int parse_value_from_line(const char *line, int *out, const char *name)
{
    const char *eq = strchr(line, '=');
    if (!eq)
    {
        printf("ERROR: %s — missing '=' sign\n", name);
        return FAILURE;
    }

    char buf[MAX_LINE];
    strncpy(buf, eq + 1, MAX_LINE - 1);
    buf[MAX_LINE - 1] = '\0';

    char *s = buf, *end = buf + strlen(buf);
    while (*s == ' ' || *s == '\t')
        s++;
    while (end > s && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';

    if (!*s)
    {
        printf("ERROR: value of %s is missing\n", name);
        return FAILURE;
    }

    char *endptr = NULL;
    long v = strtol(s, &endptr, 10);
    while (endptr && isspace((unsigned char)*endptr))
        endptr++;
    if (s == endptr || (endptr && *endptr) || v < 0 || v > INT_MAX)
    {
        printf("ERROR: %s must be a non-negative integer (got \"%s\")\n", name, s);
        return FAILURE;
    }

    *out = (int)v;
    return SUCCESS;
}

static int read_required_int(FILE *fp, char *line, int *out, const char *name)
{
    if (!fgets(line, MAX_LINE, fp))
    {
        printf("ERROR: %s parameter line is missing\n", name);
        return FAILURE;
    }
    return parse_value_from_line(line, out, name);
}

static int read_block_int(char *line, int *out, const char *name)
{
    return parse_value_from_line(line, out, name);
}

/*==================================
 PARSE AND ENCODE
==================================*/
int parse_and_encode(const char *filename, uint8_t *pdu, int *total_pdu_size)
{
    int offset = 0;
    printf("STRICT_BUILD_ACTIVE\n");

    if (pdu == NULL || total_pdu_size == NULL)
    {
        printf("ERROR: null pdu or total_pdu_size pointer\n");
        return FAILURE;
    }

    Flags flags = {0};
    flags.P = 1;
    flags.R = 0;
    flags.MPE = 1;
    flags.R2 = 0;
    flags.X = 0;
    flags.BT = 0;

    EncoderState state = {0};

    if (validate_input_file(filename) == FAILURE)
        return FAILURE;

    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        printf("ERROR: Cannot open file: %s\n", filename);
        return FAILURE;
    }

    char line[MAX_LINE];

    /* ---- read total_pdu_size ---- */
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        printf("ERROR: Missing 'Total pdu_size' line\n");
        fclose(fp);
        return FAILURE;
    }
    {
        char *eq = strchr(line, '=');
        if (eq == NULL)
        {
            printf("ERROR: 'Total pdu_size' line missing '='\n");
            fclose(fp);
            return FAILURE;
        }
        eq++;
        while (*eq == ' ' || *eq == '\t')
            eq++;
        if (parse_strict_non_negative_int(eq, total_pdu_size) == FAILURE)
        {
            printf("ERROR: Total pdu_size must be a non-negative integer\n");
            fclose(fp);
            return FAILURE;
        }
    }
    if (*total_pdu_size == 0)
    {
        printf("ERROR: PDU size cannot be zero\n");
        fclose(fp);
        return FAILURE;
    }
    if (*total_pdu_size > MAX_MAC_CE_SIZE)
    {
        printf("ERROR: PDU size %d exceeds maximum allowed %d\n",
               *total_pdu_size, MAX_MAC_CE_SIZE);
        fclose(fp);
        return FAILURE;
    }
    printf("TOTAL PDU SIZE : %d\n", *total_pdu_size);

    /* ---- read num_ce ---- */
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        printf("ERROR: Missing 'num_ce' line\n");
        fclose(fp);
        return FAILURE;
    }
    {
        char *eq = strchr(line, '=');
        if (eq == NULL)
        {
            printf("ERROR: 'num_ce' line missing '='\n");
            fclose(fp);
            return FAILURE;
        }
        eq++;
        while (*eq == ' ' || *eq == '\t')
            eq++;
        if (parse_strict_non_negative_int(eq, &state.num_ce) == FAILURE)
        {
            printf("ERROR: num_ce must be a non-negative integer\n");
            fclose(fp);
            return FAILURE;
        }
    }
    if (state.num_ce <= 0)
    {
        printf("ERROR: num_ce must be greater than zero\n");
        fclose(fp);
        return FAILURE;
    }
    if (state.num_ce > MAX_PARAMS)
    {
        printf("ERROR: num_ce %d exceeds maximum supported %d\n",
               state.num_ce, MAX_PARAMS);
        fclose(fp);
        return FAILURE;
    }
    printf("NUMBER OF CE   : %d\n\n", state.num_ce);

    state.ce_count = 0;
    int blank_count = 0;

    /* ---- main CE parsing loop ---- */
    while (fgets(line, sizeof(line), fp) && state.ce_count < state.num_ce)
    {
        if (is_blank_line(line))
        {
            blank_count++;
            if (blank_count > 1)
            {
                printf("ERROR: More than one consecutive blank line between CEs\n");
                fclose(fp);
                return FAILURE;
            }
            continue;
        }
        blank_count = 0;

        if (line[0] != '<')
        {
            printf("ERROR: Expected '<CE_type>' but got: %s", line);
            fclose(fp);
            return FAILURE;
        }

        char type[128] = {0};
        if (sscanf(line, "<%127[^>]>", type) != 1)
        {
            printf("ERROR: Malformed CE type tag\n");
            fclose(fp);
            return FAILURE;
        }

        int a = -1, b = -1, c = -1;
        int before = offset;
        int ret = FAILURE;

        printf("MAC CE : %s\n", type);

        int id = get_ce_id(type);
        if (id == -1)
        {
            printf("ERROR: Unknown CE type '%s'\n", type);
            fclose(fp);
            return FAILURE;
        }

        switch (id)
        {
        /* ---- case 1: short_bsr ---- */
        case 1:
        {
            if (read_required_int(fp, line, &a, "LCG") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            if (read_required_int(fp, line, &b, "BUFFER") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            ret = short_bsr(pdu, &offset, 2, a, b, *total_pdu_size);
            break;
        }

        /* ---- case 2: phr ---- */
        case 2:
        {
            if (read_required_int(fp, line, &a, "PH") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            if (read_required_int(fp, line, &b, "PCMAX") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            ret = phr(pdu, &offset, 2, a, b, flags, *total_pdu_size);
            break;
        }

        /* ---- case 3: crnti ---- */
        case 3:
        {
            if (read_required_int(fp, line, &a, "CRNTI") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            ret = crnti(pdu, &offset, 1, a, *total_pdu_size);
            break;
        }

        /* ---- case 4: rec_bit_rate ---- */
        case 4:
        {
            if (read_required_int(fp, line, &a, "LCID") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            if (read_required_int(fp, line, &b, "BIT RATE") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            if (read_required_int(fp, line, &c, "UL/DL") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            ret = rec_bit_rate(pdu, &offset, 3, a, b, c, flags, *total_pdu_size);
            break;
        }

        /* ---- case 5: dsr ---- */
        case 5:
        {
            int params[MAX_PARAMS];
            int count = 0;
            fpos_t saved_pos;
            fgetpos(fp, &saved_pos);

            while (fgets(line, sizeof(line), fp))
            {
                if (strchr(line, '<') != NULL)
                {
                    fsetpos(fp, &saved_pos);
                    break;
                }
                if (is_blank_line(line))
                {
                    fgetpos(fp, &saved_pos);
                    continue;
                }

                int val;
                if (read_block_int(line, &val, "DSR parameter") == FAILURE)
                {
                    fclose(fp);
                    return FAILURE;
                }
                if (count >= MAX_PARAMS)
                {
                    printf("ERROR: too many DSR parameters\n");
                    fclose(fp);
                    return FAILURE;
                }
                params[count++] = val;
                fgetpos(fp, &saved_pos);
            }
            if (count < 3 || (count % 3) != 0)
            {
                printf("ERROR: DSR needs groups of (LCG RT BUFFER)\n");
                fclose(fp);
                return FAILURE;
            }

            ret = dsr(pdu, &offset, count, params, flags, *total_pdu_size);
            break;
        }

        /* ---- case 6: enhanced_phr_stx2p ---- */
        case 6:
        {
            /* FIXED: exactly 4 params required — PH1 PH2 PCMAX1 PCMAX2 */
            int params[MAX_PARAMS];
            int count = 0;
            fpos_t saved_pos;
            fgetpos(fp, &saved_pos);

            while (fgets(line, sizeof(line), fp))
            {
                if (strchr(line, '<') != NULL)
                {
                    fsetpos(fp, &saved_pos);
                    break;
                }
                if (is_blank_line(line))
                {
                    fgetpos(fp, &saved_pos);
                    continue;
                }

                int val;
                if (read_block_int(line, &val, "enhanced_phr parameter") == FAILURE)
                {
                    fclose(fp);
                    return FAILURE;
                }
                if (count >= MAX_PARAMS)
                {
                    printf("ERROR: too many enhanced_phr parameters\n");
                    fclose(fp);
                    return FAILURE;
                }
                params[count++] = val;
                fgetpos(fp, &saved_pos);
            }
            if (count != 4)
            {
                printf("ERROR: enhanced_phr_stx2p requires exactly 4 parameters "
                       "(PH1 PH2 PCMAX1 PCMAX2)\n");
                fclose(fp);
                return FAILURE;
            }
            ret = enhanced_single_entry_phr_multiple_trp_stx2p(pdu, &offset, count,
                                                               params, flags,
                                                               *total_pdu_size);
            break;
        }

        /* ---- case 7: sl_lbt ---- */
        case 7:
        {
            if (read_required_int(fp, line, &a, "SL-LBT") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            ret = sl_lbt(pdu, &offset, 1, a, *total_pdu_size);
            break;
        }

        /* ---- case 8: enhanced_bfr ---- */
        case 8:
        {
            int params[MAX_PARAMS];
            int count = 0;
            fpos_t saved_pos;
            fgetpos(fp, &saved_pos);

            while (fgets(line, sizeof(line), fp))
            {
                if (strchr(line, '<') != NULL)
                {
                    fsetpos(fp, &saved_pos);
                    break;
                }
                if (is_blank_line(line))
                {
                    fgetpos(fp, &saved_pos);
                    continue;
                }

                int val;
                if (read_block_int(line, &val, "enhanced_bfr parameter") == FAILURE)
                {
                    fclose(fp);
                    return FAILURE;
                }
                if (count >= MAX_PARAMS)
                {
                    printf("ERROR: too many enhanced_bfr parameters\n");
                    fclose(fp);
                    return FAILURE;
                }
                params[count++] = val;
                fgetpos(fp, &saved_pos);
            }
            if (count < 5 || ((count - 2) % 3) != 0)
            {
                printf("ERROR: enhanced_bfr needs CI S then groups of (AC ID CID)\n");
                fclose(fp);
                return FAILURE;
            }
            ret = enhanced_bfr(pdu, &offset, count, params, *total_pdu_size);
            break;
        }

        /* ---- case 9: extended_short_truncated_bsr ---- */
        case 9:
        {
            if (read_required_int(fp, line, &a, "LCG") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            if (read_required_int(fp, line, &b, "BUFFER") == FAILURE)
            {
                fclose(fp);
                return FAILURE;
            }
            ret = extended_short_truncated_bsr(pdu, &offset, 2, a, b, *total_pdu_size);
            break;
        }

        default:
            printf("ERROR: Unhandled CE id %d\n", id);
            fclose(fp);
            return FAILURE;
        } /* end switch */

        /*
         * PDU_OVERFLOW — buffer full but not a logic error.
         * Skip this CE, restore offset, continue with remaining CEs.
         */
        if (ret == PDU_OVERFLOW)
        {
            printf("ERROR: PDU full — skipping CE '%s' (available: %d bytes)\n\n",
                   type, *total_pdu_size - before);
            offset = before;
            state.ce_count++;
            continue;
        }

        if (ret == FAILURE)
        {
            printf("ERROR: Encoding failed for CE '%s'\n\n", type);
            fclose(fp);
            return FAILURE;
        }

        state.ce_count++;

        int ce_len = offset - before;
        int subheader_size = (pdu[before] == LCID_ONE_OCTET_ELCID) ? 2 : 1;
        int payload_size = ce_len - subheader_size;

        printf("Subheader Size : %d byte(s)\n", subheader_size);
        printf("Payload Size   : %d byte(s)\n", payload_size);
        printf("Total CE Size  : %d byte(s)\n", ce_len);
        printf("Encoded Bits   : ");
        print_bits(&pdu[before], ce_len);
        printf("\n");
        printf("Encoded Hex    : ");
        print_hex(&pdu[before], ce_len);
        printf("\n");
        printf("[SUCCESS] %s encoded\n\n", type);

    } /* end while */

    if (state.ce_count != state.num_ce)
    {
        printf("ERROR: Expected %d CEs but only parsed %d\n",
               state.num_ce, state.ce_count);
        fclose(fp);
        return FAILURE;
    }

    int used = offset;
    int remaining = *total_pdu_size - offset;

    printf("===== FINAL SUMMARY =====\n");
    printf("Total PDU Size   : %d bytes\n", *total_pdu_size);
    printf("Total Used Bytes : %d bytes\n", used);
    printf("Remaining Bytes  : %d bytes\n", remaining);

    if (remaining < 0)
    {
        printf("ERROR: Encoded data exceeds PDU size — buffer overflow prevented\n");
        fclose(fp);
        return FAILURE;
    }

    add_padding(pdu, &offset, remaining);
    printf("\nPadding          : %d zero byte(s) added\n", remaining);
    printf("\nFinal MAC Buffer :\n");
    print_hex(pdu, *total_pdu_size);
    printf("\n");

    fclose(fp);
    return SUCCESS;
}
