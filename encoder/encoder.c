#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
#include "input_validation.h"
#include "encoder.h"

#define MAX_LINE 100
static int ensure_space(int offset, int needed, int total_size);

/*----------------------------------
 VALIDATION
----------------------------------*/
int check_range(int val, int min, int max, const char *name)
{
    if (val < min || val > max)
    {
        printf("ERROR: %s out of range (%d-%d)\n", name, min, max);
        return FAILURE;
    }
    return SUCCESS;
}

/*************************************************
 * function: short_bsr
 * Brief: MAC subPDU with 8-bit MAC subheader
 * Subheader: R (2 BITS) LCID (6 BITS)
 * Format: LCG ID (3 BITS) Buffer Size (5 BITS)
 * Total MAC CE (2 BYTES)
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

    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;

    if (check_range(buffer, 0, 31, "BUFFER"))
        return FAILURE;

    if (ensure_space(*offset, 2, total_pdu_size) == FAILURE)
        return FAILURE;

    /*Octet:
     Bits [7:5] → LCG ID
     Bits [4:0] → Buffer Size*/

    pdu[(*offset)++] = LCID_SHORT_BSR;
    pdu[(*offset)++] = (uint8_t)(((lcg & 0x07) << 5) | (buffer & 0x1F));

    return SUCCESS;
}

/*************************************************
 * function: phr
 * Brief: Power Headroom Report MAC CE
 * Subheader: R (2 BITS) LCID (6 BITS)
 * Format: PH (6 BITS) PCMAX (2 BITS) + Flags
 * Total MAC CE: Variable
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

    if (ph == -1)
    {
        printf("ERROR: PH not provided \n");
        return FAILURE;
    }

    if (pcmax == -1)
    {
        printf("ERROR: PCMAX not provided \n");
        return FAILURE;
    }

    if (ph < 0)
    {
        printf("ERROR: PH cannot be negative\n");
        return FAILURE;
    }

    if (pcmax < 0)
    {
        printf("ERROR: PCMAX cannot be negative\n");
        return FAILURE;
    }

    if (check_range(ph, 0, 63, "PH"))
        return FAILURE;

    if (check_range(pcmax, 0, 63, "PCMAX"))
        return FAILURE;

    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_PHR;
    pdu[(*offset)++] = (flags.P << 7) | (flags.R << 6) | (ph & 0x3F);
    pdu[(*offset)++] = (flags.MPE << 7) | (flags.R2 << 6) | (pcmax & 0x3F);
    return SUCCESS;
}

/*************************************************
 * function: crnti
 * Brief: C-RNTI MAC CE
 * Subheader: R (2 BITS) LCID (6 BITS)
 * Format: C-RNTI (16 BITS)
 * Total MAC CE (3 BYTES)
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

    if (value == -1)
    {
        printf("ERROR: CRNTI value not provided \n");
        return FAILURE;
    }

    if (value < 0)
    {
        printf("ERROR: CRNTI cannot be negative\n");
        return FAILURE;
    }

    if (value > 65535)
    {
        printf("ERROR: CRNTI out of range (0-65535)\n");
        return FAILURE;
    }

    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    // ENCODING
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
    if (ensure_space(*offset, needed, total_pdu_size) == FAILURE)
        return FAILURE;

    uint8_t lcg_bitmap = 0;

    // -------- BUILD BITMAP --------
    for (int i = 0; i < entries; i++)
    {
        int lcg = params[i * 3];

        if (check_range(lcg, 0, 7, "LCG"))
            return FAILURE;

        lcg_bitmap |= (uint8_t)(1U << lcg);
    }

    // -------- ENCODING --------
    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_DSR;
    pdu[(*offset)++] = lcg_bitmap;

    // -------- ENCODE EACH ENTRY --------
    for (int i = 0; i < entries; i++)
    {
        int rt = params[i * 3 + 1];
        int buffer = params[i * 3 + 2];

        if (check_range(rt, 0, 63, "RT"))
            return FAILURE;

        if (check_range(buffer, 0, 255, "BUFFER"))
            return FAILURE;

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
 * Total MAC CE: Variable
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

    // -------- INVALID CHECK --------
    if (lcid == -1)
    {
        printf("ERROR: logical channel LCID not provided\n");
        return FAILURE;
    }

    if (rate == -1)
    {
        printf("ERROR: bit_rate not provided\n");
        return FAILURE;
    }

    if (ul_dl == -1)
    {
        printf("ERROR: UL/DL not provided\n");
        return FAILURE;
    }

    // -------- NEGATIVE CHECK --------
    if (lcid < 0 || rate < 0 || ul_dl < 0)
    {
        printf("ERROR: negative values not allowed\n");
        return FAILURE;
    }

    // -------- RANGE CHECK --------
    if (check_range(lcid, 0, 63, "LCID"))
        return FAILURE;
    if (check_range(rate, 0, 63, "BIT_RATE"))
        return FAILURE;
    if (check_range(ul_dl, 0, 1, "UL/DL"))
        return FAILURE;
    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    // -------- ENCODING --------

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
 ***************************************************/
/* NOTE: verify payload layout against the exact Rel-18 STx2P PHR figure/table before final use */

int enhanced_single_entry_phr_multiple_trp_stx2p(uint8_t *pdu, int *offset, int argc, int *params, int total_pdu_size)

{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (argc < 2)
    {
        printf("ERROR: enhanced_single_entry_phr_multiple_trp_stx2p (needs at least one TRP pair (PH PCMAX))\n");
        return FAILURE;
    }

    if (argc % 2 != 0)
    {
        printf("ERROR: enhanced_single_entry_phr_multiple_trp_stx2p requires pairs of (PH PCMAX)\n");
        return FAILURE;
    }

    int entries = argc / 2;
    int needed = 2 + (2 * entries);
    if (ensure_space(*offset, needed, total_pdu_size) == FAILURE)
        return FAILURE;

    // -------- ENCODING --------

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_ENH_SINGLE_ENTRY_PHR_MULTIPLE_TRP_STX2P;

    for (int i = 0; i < entries; i++)
    {
        int ph = params[i * 2];
        int pcmax = params[i * 2 + 1];

        // -------- MISSING CHECK --------
        if (ph == -1 || pcmax == -1)
        {
            printf("ERROR: missing PH or PCMAX\n");
            return FAILURE;
        }

        // -------- NEGATIVE CHECK --------
        if (ph < 0 || pcmax < 0)
        {
            printf("ERROR: PH/PCMAX cannot be negative\n");
            return FAILURE;
        }

        // -------- RANGE CHECK --------
        if (check_range(ph, 0, 63, "PH"))
            return FAILURE;
        if (check_range(pcmax, 0, 63, "PCMAX"))
            return FAILURE;

        // -------- ENCODING PER TRP --------
        pdu[(*offset)++] = (1 << 7) | (0 << 6) | (ph & 0x3F);
        pdu[(*offset)++] = (1 << 7) | (0 << 6) | (pcmax & 0x3F);
    }

    return SUCCESS;
}
/***************************************************
 * function: sl_lbt
 * Brief: Sidelink LBT MAC CE
 * Subheader: Extended LCID
 * Format: LBT parameters
 * Total MAC CE: Variable
 ***************************************************/
int sl_lbt(uint8_t *pdu, int *offset, int value, int total_pdu_size)

{
    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (value == -1)
    {
        printf("ERROR: SL-LBT value not provided\n");
        return FAILURE;
    }
    if (value < 0)
    {
        printf("ERROR: SL-LBT cannot be negative\n");
        return FAILURE;
    }
    if (check_range(value, 0, 31, "SL-LBT"))
        return FAILURE;
    if (ensure_space(*offset, 3, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_SL_LBT;

    pdu[(*offset)++] = value & 0x1F;

    return SUCCESS;
}

/*************************************************
 * function: enhanced_bfr
 * Brief: Enhanced Beam Failure Recovery MAC CE
 * Subheader: Extended LCID
 * Format: BFR parameters
 * Total MAC CE: Variable
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
    if (ensure_space(*offset, needed, total_pdu_size) == FAILURE)
        return FAILURE;

    int ci = params[0];
    int s = params[1];

    if (ci < 0 || s < 0)
    {
        printf("ERROR: ci/s cannot be negative\n");
        return FAILURE;
    }

    if (check_range(ci, 0, 255, "CI"))
        return FAILURE;
    if (check_range(s, 0, 255, "S"))
        return FAILURE;

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_ENH_BFR;

    // CI & S
    pdu[(*offset)++] = (uint8_t)ci;
    pdu[(*offset)++] = (uint8_t)s;

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

        pdu[(*offset)++] = (uint8_t)((ac << 7) | (id << 6) | (cid & 0x3F));
    }

    return SUCCESS;
}

/*************************************************
 * function: extended_short_truncated_bsr
 * Brief: Extended Short Truncated BSR MAC CE
 * Subheader: Extended LCID
 * Format: LCG ID + Buffer size
 * Total MAC CE: Variable
 ***************************************************/
int extended_short_truncated_bsr(uint8_t *pdu, int *offset, int lcg, int buffer, int total_pdu_size)

{

    if (pdu == NULL || offset == NULL)
    {
        printf("ERROR: null pdu/offset\n");
        return FAILURE;
    }
    if (lcg == -1 || buffer == -1)
    {
        printf("ERROR: extended_short_truncated_bsr missing parameters (LCG BUFFER)\n");
        return FAILURE;
    }
    // -------- RANGE CHECK --------
    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;
    if (check_range(buffer, 0, 255, "BUFFER"))
        return FAILURE;
    if (ensure_space(*offset, 4, total_pdu_size) == FAILURE)
        return FAILURE;

    pdu[(*offset)++] = LCID_ONE_OCTET_ELCID;
    pdu[(*offset)++] = ELCID_EXTENDED_SHORT_TRUNCATED_BSR;

    pdu[(*offset)++] = (uint8_t)(lcg & 0x07);
    pdu[(*offset)++] = (uint8_t)(buffer & 0xFF);

    return SUCCESS;
}

/*----------------------------------
 PRINT HEX
---------------------------------- */
void print_hex(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

/*----------------------------------
 PRINT BITS
----------------------------------*/
void print_bits(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        for (int j = 7; j >= 0; j--)
            printf("%d", (data[i] >> j) & 1);
        printf(" ");
    }
}

/*---------------------------------
 PADDING
----------------------------------*/
void add_padding(uint8_t *buffer, int *offset, int remaining)
{
    for (int i = 0; i < remaining; i++)
    {
        buffer[(*offset)++] = 0x00;
    }
}

/*----------------------------------
TYPE → ID
----------------------------------*/
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

/*----------------------------------
 PARSE AND ENCODE LOGIC

 Responsibilities:
 1. Reads input file
 2. Extracts total PDU size
 3. Identifies each MAC CE block (<type>)
 4. Calls corresponding encoding function
 5. Tracks buffer offset
 6. Prints encoded bits and hex per CE
 7. Adds padding to match PDU size
 8. Prints final MAC buffer
--------------------------------------*/

/*==================================
    PARSING UTILITIES
==================================*/

static int parse_strict_non_negative_int(const char *s, int *out)
{
    int i = 0;
    int val = 0;

    while (s[i] == ' ' || s[i] == '\t')
        i++;
    if (s[i] == '\0' || s[i] == '\n' || s[i] == '-')
        return FAILURE;

    for (; s[i] != '\0' && s[i] != '\n'; i++)
    {
        if (s[i] < '0' || s[i] > '9')
            return FAILURE;

        int digit = s[i] - '0';
        if (val > (INT_MAX - digit) / 10)
            return FAILURE; // integer overflow

        val = val * 10 + digit;
    }

    *out = val;
    return SUCCESS;
}
static int read_required_int(FILE *fp, char *line, int *out, const char *name)
{
    if (fgets(line, MAX_LINE, fp) == NULL)
    {
        printf("ERROR: %s parameter is missing\n", name);
        return FAILURE;
    }

    char *eq = strchr(line, '=');
    if (eq == NULL)
    {
        printf("ERROR: %s parameter is missing\n", name);
        return FAILURE;
    }

    eq++;
    while (*eq == ' ' || *eq == '\t')
        eq++;

    char *end = eq + strlen(eq);
    while (end > eq && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';

    if (*eq == '\0')
    {
        printf("ERROR: value of %s is missing\n", name);
        return FAILURE;
    }

    char *endptr = NULL;
    long v = strtol(eq, &endptr, 10);

    while (endptr && isspace((unsigned char)*endptr))
        endptr++;

    if (eq == endptr || (endptr && *endptr != '\0') || v < 0 || v > INT_MAX)
    {
        printf("ERROR: value of %s must be integer only\n", name);
        return FAILURE;
    }

    *out = (int)v;

    return SUCCESS;
}

static int read_block_int(char *line, int *out, const char *name)
{
    char *eq = strchr(line, '=');
    if (eq == NULL)
    {
        printf("ERROR: %s parameter is missing\n", name);
        return FAILURE;
    }

    eq++;
    while (*eq == ' ' || *eq == '\t')
        eq++;

    char *end = eq + strlen(eq);
    while (end > eq && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';

    if (*eq == '\0')
    {
        printf("ERROR: value of %s is missing\n", name);
        return FAILURE;
    }

    char *endptr = NULL;
    long v = strtol(eq, &endptr, 10);

    while (endptr && isspace((unsigned char)*endptr))
        endptr++;

    if (eq == endptr || (endptr && *endptr != '\0') || v < 0 || v > INT_MAX)
    {
        printf("ERROR: value of %s must be integer only\n", name);
        return FAILURE;
    }

    *out = (int)v;

    return SUCCESS;
}

static int ensure_space(int offset, int needed, int total_size)
{
    if (offset + needed > total_size)
    {
        printf("ERROR: PDU overflow risk (need %d, remaining %d)\n", needed, total_size - offset);
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
/*----------------------------------
 PARSE AND ENCODE FUNCTION
----------------------------------*/

int parse_and_encode(const char *filename, uint8_t *pdu, int *total_pdu_size)

{
    int offset = 0;
    printf("STRICT_BUILD_ACTIVE\n");

    if (pdu == NULL || total_pdu_size == NULL)
    {
        printf("ERROR: null output buffer/total_pdu_size\n");
        return FAILURE;
    }

    // Flags fields: P, R, MPE, R2, X, BT
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

    if (fgets(line, sizeof(line), fp) == NULL)
    {
        printf("ERROR: Missing Total pdu_size line\n");
        fclose(fp);
        return FAILURE;
    }
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

    if (*total_pdu_size < 0)
    {
        printf("ERROR: PDU size cannot be negative\n");
        fclose(fp);
        return FAILURE;
    }
    printf(" TOTAL PDU SIZE : %d\n", *total_pdu_size);

    if (fgets(line, sizeof(line), fp) == NULL)
    {
        printf("ERROR: Missing num_ce line\n");
        fclose(fp);
        return FAILURE;
    }
    state.ce_count = 0;
    eq = strchr(line, '=');
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

    if (state.num_ce <= 0)
    {
        printf("ERROR: num_ce must be positive\n");
        fclose(fp);
        return FAILURE;
    }
    printf("NUMBER OF CE : %d\n\n", state.num_ce);
    int blank_count = 0;
    // Reset blank_count before processing CEs for clarity
    while (fgets(line, sizeof(line), fp) && state.ce_count < state.num_ce)
    {

        // HANDLE BLANK LINES
        if (is_blank_line(line))

        {
            blank_count++;

            if (blank_count > 1)
            {
                printf("ERROR: More than one blank line between CEs\n");
                fclose(fp);
                return FAILURE;
            }

            continue;
        }
        else
        {
            blank_count = 0;
        }

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
            /*----------------------------------
             CE TYPE HANDLING (SWITCH CASE)
            ----------------------------------
             This switch block processes different MAC CE types
             based on the ID obtained from the CE name.
             Workflow:
             1. Identify CE type using 'id'
             2. Read required parameters from input file
             3. Call corresponding encoding function
             4. Store encoded data into PDU buffer
            ---------------------------------------*/

            switch (id)
            {
            case 1:
            {
                int param_count = 2;

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

                ret = short_bsr(pdu, &offset, param_count, a, b, *total_pdu_size);

                break;
            }

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

            case 4:
            {
                int param_count = 3;

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

                ret = rec_bit_rate(pdu, &offset, param_count, a, b, c, flags, *total_pdu_size);
                break;
            }

            case 5:
            {
                int params[100];
                int count = 0;

                while (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<') != NULL)
                    {
                        fseek(fp, -(long)strlen(line), SEEK_CUR);
                        break;
                    }

                    if (is_blank_line(line))
                        continue;

                    int val;
                    if (read_block_int(line, &val, "DSR parameter") == FAILURE)
                    {
                        fclose(fp);
                        return FAILURE;
                    }

                    if (count >= 100)
                    {
                        printf("ERROR: too many parameters\n");
                        fclose(fp);
                        return FAILURE;
                    }
                    params[count++] = val;
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

            case 6:
            {
                int params[100], count = 0;

                while (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<') != NULL)
                    {
                        fseek(fp, -(long)strlen(line), SEEK_CUR);
                        break;
                    }
                    if (is_blank_line(line))
                        continue;

                    int val;
                    if (read_block_int(line, &val, "enhanced_phr parameter") == FAILURE)
                    {
                        fclose(fp);
                        return FAILURE;
                    }

                    if (count >= 100)
                    {
                        printf("ERROR: too many parameters\n");
                        fclose(fp);
                        return FAILURE;
                    }
                    params[count++] = val;
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

            case 7:
            {
                if (read_required_int(fp, line, &a, "SL-LBT") == FAILURE)
                {
                    fclose(fp);
                    return FAILURE;
                }

                ret = sl_lbt(pdu, &offset, a, *total_pdu_size);

                break;
            }

            case 8:
            {
                int params[100];
                int count = 0;

                while (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<') != NULL)
                    {
                        fseek(fp, -(long)strlen(line), SEEK_CUR);
                        break;
                    }
                    if (is_blank_line(line))
                        continue;

                    int val;
                    if (read_block_int(line, &val, "enhanced_bfr parameter") == FAILURE)
                    {
                        fclose(fp);
                        return FAILURE;
                    }

                    if (count >= 100)
                    {
                        printf("ERROR: too many parameters\n");
                        fclose(fp);
                        return FAILURE;
                    }
                    params[count++] = val;
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

                ret = extended_short_truncated_bsr(pdu, &offset, a, b, *total_pdu_size);
                break;
            }
            default:
            {
                printf("ERROR: Unknown CE id %d\n", id);
                ret = FAILURE;
                break;
            }
            } // end switch

            // Always increment ce_count for each CE block encountered

            if (ret == FAILURE)
            {
                printf("ERROR: Failed to encode CE '%s'\n\n", type);
                fclose(fp);
                return FAILURE;
            }
            state.ce_count++;

            int ce_len = offset - before;

            int subheader_size = (id >= 5) ? 2 : 1;
            int payload_size = ce_len - subheader_size;
            int total_size = ce_len;

            printf("Subheader Size : %d byte\n", subheader_size);
            printf("Payload Size   : %d bytes\n", payload_size);
            printf("Total CE Size  : %d bytes\n", total_size);

            printf("Encoded Bits : ");
            print_bits(&pdu[before], ce_len);
            printf("\n");

            printf("Encoded Hex  : ");
            print_hex(&pdu[before], ce_len);
            printf("\n");
            printf("[SUCCESS] %s Encoded\n\n", type);
        } // end if(line[0] == '<')
    } // end while

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
