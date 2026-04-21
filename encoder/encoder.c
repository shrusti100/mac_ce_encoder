#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
#include "input_validation.h"
#include "encoder.h"

#define MAX_LINE 256   /* prevents silent truncation of long lines          */
#define MAX_PARAMS 128 /* named constant replacing magic number 100          */

/* Forward declaration */
static int ensure_space(int offset, int needed, int total_size);

/*==================================
  VALIDATION
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

/*==================================
  CE ENCODING FUNCTIONS
==================================*/

/*************************************************
 * function: short_bsr
 * Brief: MAC subPDU with 8-bit MAC subheader
 * Subheader: R (2 BITS) LCID (6 BITS)
 * Format: LCG ID (3 BITS) Buffer Size (5 BITS)
 * Total MAC CE: 2 bytes
 ***************************************************/
int short_bsr(uint8_t *pdu, int *offset, int argc, int lcg, int buffer, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 2)
    {
        printf("ERROR: short_bsr missing parameters (LCG BUFFER)\n");
        return FAILURE;
    }
    if (argc > 2)
    {
        printf("ERROR: short_bsr extra parameters detected\n");
        return FAILURE;
    }
    if (lcg < 0 || buffer < 0)
    {
        printf("ERROR: LCG/BUFFER cannot be negative\n");
        return FAILURE;
    }
    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;
    if (check_range(buffer, 0, 31, "BUFFER"))
        return FAILURE;

    if (ensure_space(*offset, 2, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_SHORT_BSR;
    pdu[(*offset)++] = (uint8_t)(((lcg & 0x07) << 5) | (buffer & 0x1F));

    return SUCCESS;
}

/*************************************************
 * function: phr
 * Brief: Power Headroom Report MAC CE
 * Subheader: R (2 BITS) LCID (6 BITS)
 * Format: PH (6 BITS) PCMAX (2 BITS) + Flags
 * Total MAC CE: 3 bytes
 ***************************************************/
int phr(uint8_t *pdu, int *offset, int argc, int ph, int pcmax, Flags flags, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc == 0)
    {
        printf("ERROR: phr missing parameters (PH PCMAX)\n");
        return FAILURE;
    }
    if (argc == 1)
    {
        printf("ERROR: phr missing parameter (PCMAX)\n");
        return FAILURE;
    }
    if (argc > 2)
    {
        printf("ERROR: phr extra parameters detected\n");
        return FAILURE;
    }
    if (check_range(ph, 0, 63, "PH"))
        return FAILURE;
    if (check_range(pcmax, 0, 63, "PCMAX"))
        return FAILURE;

    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_PHR;
    pdu[(*offset)++] = (uint8_t)((flags.P << 7) | (flags.R << 6) | (ph & 0x3F));
    pdu[(*offset)++] = (uint8_t)((flags.MPE << 7) | (flags.R2 << 6) | (pcmax & 0x3F));

    return SUCCESS;
}

/*************************************************
 * function: crnti
 * Brief: C-RNTI MAC CE
 * Subheader: R (2 BITS) LCID (6 BITS)
 * Format: C-RNTI (16 BITS)
 * Total MAC CE: 3 bytes
 ***************************************************/
int crnti(uint8_t *pdu, int *offset, int argc, int value, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc == 0)
    {
        printf("ERROR: crnti missing parameter (CRNTI value)\n");
        return FAILURE;
    }
    if (argc > 1)
    {
        printf("ERROR: crnti extra parameters detected\n");
        return FAILURE;
    }
    if (check_range(value, 0, 65535, "CRNTI"))
        return FAILURE;

    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_CRNTI;
    pdu[(*offset)++] = (uint8_t)((value >> 8) & 0xFF);
    pdu[(*offset)++] = (uint8_t)(value & 0xFF);

    return SUCCESS;
}

/*************************************************
 * function: dsr
 * Brief: Delay Status Report MAC CE
 * Subheader: Extended LCID
 * Format: Delay parameters
 * Total MAC CE: Variable
 *
 * All parameters are fully validated BEFORE any bytes are written to
 * the PDU buffer, preventing partial/corrupt writes on failure.
 ***************************************************/
int dsr(uint8_t *pdu, int *offset, int argc, int *params, Flags flags, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 3)
    {
        printf("ERROR: dsr missing parameters (LCG RT BUFFER)\n");
        return FAILURE;
    }
    if (argc % 3 != 0)
    {
        printf("ERROR: Extra parameters detected\n");
        return FAILURE;
    }

    int entries = argc / 3;
    int needed = 2 + 1 + (2 * entries);

    /* --- Validate ALL entries before touching the PDU buffer --- */
    uint8_t lcg_bitmap = 0;
    for (int i = 0; i < entries; i++)
    {
        int lcg = params[i * 3];
        int rt = params[i * 3 + 1];
        int buffer = params[i * 3 + 2];

        if (lcg < 0 || rt < 0 || buffer < 0)
        {
            printf("ERROR: DSR parameters cannot be negative\n");
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

    /* Space check after validation so no bytes are written on error */
    if (ensure_space(*offset, needed, total_pdu_size) == FAILURE)
        return FAILURE;

    /* --- All valid: now encode --- */
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

/*************************************************
 * function: rec_bit_rate
 * Brief: Recommended Bit Rate MAC CE
 * Subheader: R (2 BITS) LCID (6 BITS)
 * Format: Bit rate fields + Flags
 * Total MAC CE: 3 bytes
 ***************************************************/
int rec_bit_rate(uint8_t *pdu, int *offset, int argc, int lcid, int rate, int ul_dl, Flags flags, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 3)
    {
        printf("ERROR: rec_bit_rate missing parameters (LCID BIT_RATE UL/DL)\n");
        return FAILURE;
    }
    if (argc > 3)
    {
        printf("ERROR: rec_bit_rate extra parameters detected\n");
        return FAILURE;
    }
    if (lcid < 0 || rate < 0 || ul_dl < 0)
    {
        printf("ERROR: negative values not allowed\n");
        return FAILURE;
    }
    if (check_range(lcid, 0, 63, "LCID"))
        return FAILURE;
    if (check_range(rate, 0, 63, "BIT_RATE"))
        return FAILURE;
    if (check_range(ul_dl, 0, 1, "UL/DL"))
        return FAILURE;

    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_REC_BIT_RATE;
    pdu[(*offset)++] = (uint8_t)((lcid << 2) | (ul_dl << 1) | flags.R);
    pdu[(*offset)++] = (uint8_t)((rate << 2) | (flags.X << 1) | flags.R2);

    return SUCCESS;
}

/*************************************************
 * function: enhanced_single_entry_phr_multiple_trp_stx2p
 * Brief: Enhanced Single Entry PHR MAC CE (Multiple TRP)
 * Subheader: Extended LCID
 * Format: PHR fields for multiple TRP
 * Total MAC CE: Variable
 *
 * All (PH, PCMAX) pairs are validated BEFORE any subheader bytes are
 * written, preventing a corrupted PDU on mid-loop failure.
 *
 * NOTE: verify payload layout against the exact Rel-18 STx2P PHR
 * figure/table before final use.
 ***************************************************/
int enhanced_single_entry_phr_multiple_trp_stx2p(uint8_t *pdu, int *offset, int argc, int *params, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 2)
    {
        printf("ERROR: enhanced_single_entry_phr_multiple_trp_stx2p "
               "(needs at least one TRP pair (PH PCMAX))\n");
        return FAILURE;
    }
    if (argc % 2 != 0)
    {
        printf("ERROR: enhanced_single_entry_phr_multiple_trp_stx2p "
               "requires pairs of (PH PCMAX)\n");
        return FAILURE;
    }

    int entries = argc / 2;
    int needed = 2 + (2 * entries);

    /* --- Validate ALL pairs before writing anything --- */
    for (int i = 0; i < entries; i++)
    {
        int ph = params[i * 2];
        int pcmax = params[i * 2 + 1];

        if (ph < 0 || pcmax < 0)
        {
            printf("ERROR: PH/PCMAX cannot be negative or missing\n");
            return FAILURE;
        }
        if (check_range(ph, 0, 63, "PH"))
            return FAILURE;
        if (check_range(pcmax, 0, 63, "PCMAX"))
            return FAILURE;
    }

    /* Space check after validation so no bytes are written on error */
    if (ensure_space(*offset, needed, total_pdu_size) == FAILURE)
        return FAILURE;

    /* --- All valid: write subheader then payload --- */
    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_ENH_SINGLE_ENTRY_PHR_MULTIPLE_TRP_STX2P;

    for (int i = 0; i < entries; i++)
    {
        int ph = params[i * 2];
        int pcmax = params[i * 2 + 1];

        pdu[(*offset)++] = (uint8_t)((1 << 7) | (0 << 6) | (ph & 0x3F));
        pdu[(*offset)++] = (uint8_t)((1 << 7) | (0 << 6) | (pcmax & 0x3F));
    }

    return SUCCESS;
}

/*************************************************
 * function: sl_lbt
 * Brief: Sidelink LBT MAC CE
 * Subheader: Extended LCID
 * Format: LBT parameters
 * Total MAC CE: 3 bytes
 ***************************************************/
int sl_lbt(uint8_t *pdu, int *offset, int argc, int value, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 1)
    {
        printf("ERROR: sl_lbt missing parameter (SL-LBT value)\n");
        return FAILURE;
    }
    if (argc > 1)
    {
        printf("ERROR: sl_lbt extra parameters detected\n");
        return FAILURE;
    }
    if (value < 0)
    {
        printf("ERROR: SL-LBT cannot be negative or missing\n");
        return FAILURE;
    }
    if (check_range(value, 0, 31, "SL-LBT"))
        return FAILURE;

    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_SL_LBT;
    pdu[(*offset)++] = (uint8_t)(value & 0x1F);

    return SUCCESS;
}

/*************************************************
 * function: enhanced_bfr
 * Brief: Enhanced Beam Failure Recovery MAC CE
 * Subheader: Extended LCID
 * Format: BFR parameters
 * Total MAC CE: Variable
 *
 * BUG FIX: ensure_space() is now called AFTER all validation
 * (ci, s, and every entry), matching the validate-then-write contract.
 * Previously ensure_space ran before ci/s were range-checked.
 ***************************************************/
int enhanced_bfr(uint8_t *pdu, int *offset, int argc, int *params, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 5)
    {
        printf("ERROR: enhanced_bfr requires ci, s and entries\n");
        return FAILURE;
    }
    if ((argc - 2) % 3 != 0)
    {
        printf("ERROR: enhanced_bfr entries must be (ac id candidate_id)\n");
        return FAILURE;
    }

    int entries = (argc - 2) / 3;
    int needed = 4 + entries;

    int ci = params[0];
    int s = params[1];

    /* --- Validate ci and s FIRST --- */
    if (ci < 0 || s < 0)
    {
        printf("ERROR: ci/s cannot be negative\n");
        return FAILURE;
    }
    if (check_range(ci, 0, 255, "CI"))
        return FAILURE;
    if (check_range(s, 0, 255, "S"))
        return FAILURE;

    /* --- Validate ALL entries before writing anything --- */
    for (int i = 0; i < entries; i++)
    {
        int ac = params[2 + i * 3];
        int id = params[2 + i * 3 + 1];
        int cid = params[2 + i * 3 + 2];

        if (ac < 0 || id < 0 || cid < 0)
        {
            printf("ERROR: Negative values not allowed\n");
            return FAILURE;
        }
        if (check_range(ac, 0, 1, "AC"))
            return FAILURE;
        if (check_range(id, 0, 1, "ID"))
            return FAILURE;
        if (check_range(cid, 0, 63, "Candidate ID"))
            return FAILURE;
    }

    /* Space check after all validation — no bytes written before this */
    if (ensure_space(*offset, needed, total_pdu_size) == FAILURE)
        return FAILURE;

    /* --- All valid: now encode --- */
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

/*************************************************
 * function: extended_short_truncated_bsr
 * Brief: Extended Short Truncated BSR MAC CE
 * Subheader: Extended LCID
 * Format: LCG ID + Buffer size
 * Total MAC CE: 4 bytes
 ***************************************************/
int extended_short_truncated_bsr(uint8_t *pdu, int *offset, int argc, int lcg, int buffer, int total_pdu_size)
{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 2)
    {
        printf("ERROR: extended_short_truncated_bsr missing parameters (LCG BUFFER)\n");
        return FAILURE;
    }
    if (argc > 2)
    {
        printf("ERROR: extended_short_truncated_bsr extra parameters detected\n");
        return FAILURE;
    }
    if (lcg < 0 || buffer < 0)
    {
        printf("ERROR: LCG/BUFFER cannot be negative\n");
        return FAILURE;
    }
    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;
    if (check_range(buffer, 0, 255, "BUFFER"))
        return FAILURE;

    /* 4 bytes: ELCID header (2) + LCG (1) + BUFFER (1) */
    if (ensure_space(*offset, 4, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_EXTENDED_SHORT_TRUNCATED_BSR;
    pdu[(*offset)++] = (uint8_t)(lcg & 0x07);
    pdu[(*offset)++] = (uint8_t)(buffer & 0xFF);

    return SUCCESS;
}

/*==================================
  OUTPUT UTILITIES
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
  TYPE → ID
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
    if (strcmp(type, "enhanced_single_entry_phr_multiple_trp_stx2p") == 0 || strcmp(type, "enhanced_phr") == 0)
        return 6;
    if (strcmp(type, "sl_lbt") == 0)
        return 7;
    if (strcmp(type, "enhanced_bfr") == 0)
        return 8;
    if (strcmp(type, "extended_short_truncated_bsr") == 0 || strcmp(type, "extended_bsr") == 0)
        return 9;
    return -1;
}

/*==================================
  PARSING UTILITIES
==================================*/

/*
 * Single canonical integer-from-line parser.
 * Both read_required_int() and read_block_int() delegate here.
 */
static int parse_value_from_line(const char *line, int *out, const char *name)
{
    const char *eq = strchr(line, '=');
    if (eq == NULL)
    {
        printf("ERROR: %s parameter is missing\n", name);
        return FAILURE;
    }

    eq++;
    while (*eq == ' ' || *eq == '\t')
        eq++;

    /* Copy and trim trailing whitespace */
    char buf[MAX_LINE];
    strncpy(buf, eq, MAX_LINE - 1);
    buf[MAX_LINE - 1] = '\0';

    char *end = buf + strlen(buf);
    while (end > buf && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';

    if (*buf == '\0')
    {
        printf("ERROR: value of %s is missing\n", name);
        return FAILURE;
    }

    char *endptr = NULL;
    long v = strtol(buf, &endptr, 10);

    while (endptr && isspace((unsigned char)*endptr))
        endptr++;

    if (buf == endptr || (endptr && *endptr != '\0') || v < 0 || v > INT_MAX)
    {
        printf("ERROR: value of %s must be a non-negative integer\n", name);
        return FAILURE;
    }

    *out = (int)v;
    return SUCCESS;
}

static int read_required_int(FILE *fp, char *line, int *out, const char *name)
{
    if (fgets(line, MAX_LINE, fp) == NULL)
    {
        printf("ERROR: %s parameter is missing\n", name);
        return FAILURE;
    }
    return parse_value_from_line(line, out, name);
}

static int read_block_int(char *line, int *out, const char *name)
{
    return parse_value_from_line(line, out, name);
}

static int ensure_space(int offset, int needed, int total_size)
{
    if (offset + needed > total_size)
    {
        printf("ERROR: PDU overflow risk (need %d, remaining %d)\n",
               needed, total_size - offset);
        return FAILURE;
    }
    return SUCCESS;
}

static int is_blank_line(const char *line)
{
    if (line == NULL)
        return 1;
    while (*line)
    {
        if (!isspace((unsigned char)*line))
            return 0;
        line++;
    }
    return 1;
}

static int parse_strict_non_negative_int(const char *s, int *out)
{
    int i = 0;
    int val = 0;

    while (s[i] == ' ' || s[i] == '\t')
        i++;

    if (s[i] == '\0' || s[i] == '\n' || s[i] == '-')
        return FAILURE;

    /* Stop on \r to handle Windows CRLF line endings */
    for (; s[i] != '\0' && s[i] != '\n' && s[i] != '\r'; i++)
    {
        if (s[i] < '0' || s[i] > '9')
            return FAILURE;
        int digit = s[i] - '0';
        if (val > (INT_MAX - digit) / 10)
            return FAILURE;
        val = val * 10 + digit;
    }

    *out = val;
    return SUCCESS;
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
        printf("ERROR: null output buffer/total_pdu_size\n");
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
        printf("ERROR: Cannot open file\n");
        return FAILURE;
    }

    char line[MAX_LINE];

    /* --- Read total PDU size --- */
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        printf("ERROR: Missing Total pdu_size line\n");
        fclose(fp);
        return FAILURE;
    }
    {
        char *eq = strchr(line, '=');
        if (eq == NULL)
        {
            printf("ERROR: Invalid Total pdu_size format\n");
            fclose(fp);
            return FAILURE;
        }
        eq++;
        while (*eq == ' ' || *eq == '\t')
            eq++;

        if (parse_strict_non_negative_int(eq, total_pdu_size) == FAILURE)
        {
            printf("ERROR: Invalid PDU size (integer only)\n");
            fclose(fp);
            return FAILURE;
        }
    }
    printf(" TOTAL PDU SIZE : %d\n", *total_pdu_size);

    if (*total_pdu_size > MAX_MAC_CE_SIZE)
    {
        printf("ERROR: PDU size %d exceeds maximum allowed %d\n",
               *total_pdu_size, MAX_MAC_CE_SIZE);
        fclose(fp);
        return FAILURE;
    }
    if (*total_pdu_size == 0)
    {
        printf("ERROR: PDU size cannot be zero\n");
        fclose(fp);
        return FAILURE;
    }

    /* --- Read num_ce --- */
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        printf("ERROR: Missing num_ce line\n");
        fclose(fp);
        return FAILURE;
    }
    {
        char *eq = strchr(line, '=');
        if (eq == NULL)
        {
            printf("ERROR: Invalid num_ce format\n");
            fclose(fp);
            return FAILURE;
        }
        eq++;
        while (*eq == ' ' || *eq == '\t')
            eq++;

        if (parse_strict_non_negative_int(eq, &state.num_ce) == FAILURE)
        {
            printf("ERROR: Invalid num_ce (integer only)\n");
            fclose(fp);
            return FAILURE;
        }
    }
    if (state.num_ce <= 0)
    {
        printf("ERROR: num_ce must be positive\n");
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
    printf("NUMBER OF CE : %d\n\n", state.num_ce);

    state.ce_count = 0;

    /*
     * BUG FIX: blank_count is now reset to 0 at the TOP of every loop
     * iteration, before the blank-line check.  The original code reset
     * it only on non-blank lines, so a stale count from the previous CE
     * block could carry into the next block and cause a false
     * "More than one blank line" error on a perfectly legal file.
     */
    while (fgets(line, sizeof(line), fp) && state.ce_count < state.num_ce)
    {
        /* --- Per-iteration blank counter — reset here unconditionally --- */
        int blank_count = 0; /* BUG FIX: declared inside loop so it resets each CE */

        /* Consume any leading blank lines before the <tag> */
        while (is_blank_line(line))
        {
            blank_count++;
            if (blank_count > 1)
            {
                printf("ERROR: More than one blank line between CEs\n");
                fclose(fp);
                return FAILURE;
            }
            if (fgets(line, sizeof(line), fp) == NULL)
                goto end_loop; /* EOF after blank — handled by count check below */
        }

        /* At this point line holds the first non-blank line of the next CE */
        if (line[0] != '<')
        {
            printf("ERROR: Invalid line format: %s", line);
            fclose(fp);
            return FAILURE;
        }

        {
            char type[128] = {0};
            if (sscanf(line, "<%127[^>]>", type) != 1)
            {
                printf("ERROR: Invalid CE type format\n\n");
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
                printf("ERROR: Unknown CE %s\n", type);
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

                /*
                 * BUG FIX (fgetpos): saved_pos is updated ONLY after a
                 * parameter value is successfully read — never on blank
                 * lines.  The original code updated saved_pos on blank
                 * lines, so fsetpos would restore to after the blank
                 * rather than before the next <tag>, silently consuming
                 * the blank line that preceded it.
                 */
                fpos_t saved_pos;
                fgetpos(fp, &saved_pos);

                while (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<') != NULL)
                    {
                        fsetpos(fp, &saved_pos); /* restore before the <tag> line */
                        break;
                    }
                    if (is_blank_line(line))
                        continue; /* skip blank; do NOT update saved_pos */

                    int val;
                    if (read_block_int(line, &val, "DSR parameter") == FAILURE)
                    {
                        fclose(fp);
                        return FAILURE;
                    }
                    if (count >= MAX_PARAMS)
                    {
                        printf("ERROR: too many parameters\n");
                        fclose(fp);
                        return FAILURE;
                    }
                    params[count++] = val;
                    fgetpos(fp, &saved_pos); /* update only after a good read */
                }

                if (count < 3 || (count % 3) != 0)
                {
                    printf("ERROR: DSR needs groups of (LCG,RT,BUFFER)\n");
                    fclose(fp);
                    return FAILURE;
                }
                ret = dsr(pdu, &offset, count, params, flags, *total_pdu_size);
                break;
            }

            /* ---- case 6: enhanced_single_entry_phr_multiple_trp_stx2p ---- */
            case 6:
            {
                int params[MAX_PARAMS];
                int count = 0;

                /* BUG FIX (fgetpos): same fix as case 5 */
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
                        continue; /* skip blank; do NOT update saved_pos */

                    int val;
                    if (read_block_int(line, &val, "enhanced_phr parameter") == FAILURE)
                    {
                        fclose(fp);
                        return FAILURE;
                    }
                    if (count >= MAX_PARAMS)
                    {
                        printf("ERROR: too many parameters\n");
                        fclose(fp);
                        return FAILURE;
                    }
                    params[count++] = val;
                    fgetpos(fp, &saved_pos); /* update only after a good read */
                }

                if (count < 2 || (count % 2) != 0)
                {
                    printf("ERROR: enhanced_phr needs pairs (PH,PCMAX)\n");
                    fclose(fp);
                    return FAILURE;
                }
                ret = enhanced_single_entry_phr_multiple_trp_stx2p(pdu, &offset, count, params, *total_pdu_size);
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

                /* BUG FIX (fgetpos): same fix as case 5 */
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
                        continue; /* skip blank; do NOT update saved_pos */

                    int val;
                    if (read_block_int(line, &val, "enhanced_bfr parameter") == FAILURE)
                    {
                        fclose(fp);
                        return FAILURE;
                    }
                    if (count >= MAX_PARAMS)
                    {
                        printf("ERROR: too many parameters\n");
                        fclose(fp);
                        return FAILURE;
                    }
                    params[count++] = val;
                    fgetpos(fp, &saved_pos); /* update only after a good read */
                }

                if (count < 5 || ((count - 2) % 3) != 0)
                {
                    printf("ERROR: enhanced_bfr format invalid\n");
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
            {
                printf("ERROR: Unknown CE id %d\n", id);
                ret = FAILURE;
                break;
            }
            } /* end switch */

            if (ret == FAILURE)
            {
                printf("ERROR: Failed to encode CE '%s'\n\n", type);
                fclose(fp);
                return FAILURE;
            }

            state.ce_count++;

            int ce_len = offset - before;
            int subheader_size = (pdu[before] == LCID_ONE_OCTET_ELCID) ? 2 : 1;
            int payload_size = ce_len - subheader_size;

            printf("Subheader Size : %d byte\n", subheader_size);
            printf("Payload Size   : %d bytes\n", payload_size);
            printf("Total CE Size  : %d bytes\n", ce_len);
            printf("Encoded Bits : ");
            print_bits(&pdu[before], ce_len);
            printf("\n");
            printf("Encoded Hex  : ");
            print_hex(&pdu[before], ce_len);
            printf("\n");
            printf("[SUCCESS] %s Encoded\n\n", type);
        }
    } /* end while */

end_loop:

    if (state.ce_count != state.num_ce)
    {
        printf("ERROR: Expected %d CEs but parsed %d\n", state.num_ce, state.ce_count);
        fclose(fp);
        return FAILURE;
    }

    int total_used_before = offset;
    int remaining = *total_pdu_size - offset;

    printf("\n===== FINAL SUMMARY =====\n");
    printf("Total PDU Size   : %d bytes\n", *total_pdu_size);
    printf("Total Used Bytes : %d bytes\n", total_used_before);
    printf("Remaining Bytes  : %d bytes\n", remaining);

    if (remaining < 0)
    {
        printf("ERROR: Encoded data exceeds PDU size. Buffer overflow prevented.\n");
        fclose(fp);
        return FAILURE;
    }

    add_padding(pdu, &offset, remaining);

    printf("\nRemaining bytes filled with 00.\n");
    printf("\nFinal MAC Buffer:\n");
    print_hex(pdu, *total_pdu_size);
    printf("\n");

    fclose(fp);
    return SUCCESS;
}
