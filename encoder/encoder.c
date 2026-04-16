#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "input_validation.h"
#include "encoder.h"
#define PDU_OVERFLOW -2

/******************************************
 VALIDATION
*******************************************/
int check_range(int val, int min, int max, const char *name)
{
    if (val < min || val > max)
    {
        printf("ERROR: %s out of range (%d-%d)\n", name, min, max);
        return FAILURE;
    }
    return SUCCESS;
}

int check_pdu_space(int offset, int required, int pdu_size)
{
    if (offset + required > pdu_size)
    {
        return PDU_OVERFLOW;
    }
    return SUCCESS;
}

/*******************************************************************
 * function: short_bsr
 *******************************************************************
 *  Brief: MAC subPDU with 8-bit MAC subheader
 *  Subheader: R (2 BITS) LCID (6 BITS)
 *  Format: LCG ID (3 BITS) Buffer Size (5 BITS)
 *  Total MAC CE (2 BYTES)
 ********************************************************************/
int short_bsr(uint8_t *pdu, int *offset, int argc, int lcgid, int buffer, int pdu_size)
{
    // -------- PARAM COUNT CHECK --------
    if (argc == 0)
    {
        printf("ERROR: short_bsr missing parameters (LCGID BUFFER)\n");
        return FAILURE;
    }

    if (argc == 1)
    {
        if (lcgid == -1)
            printf("ERROR: LCGID not provided\n");
        else
            printf("ERROR: BUFFER not provided\n");
        return FAILURE;
    }

    if (argc > 2)
    {
        printf("ERROR: short_bsr extra parameters detected\n");
        return FAILURE;
    }

    // -------- NEGATIVE CHECK --------
    if (lcgid < 0)
    {
        printf("ERROR: LCGID cannot be negative\n");
        return FAILURE;
    }

    if (buffer < 0)
    {
        printf("ERROR: BUFFER cannot be negative\n");
        return FAILURE;
    }

    // -------- RANGE CHECK (BIT LIMITS) --------
    if (lcgid > 7)
    {
        printf("ERROR: LCGID out of range (0-7)\n");
        return FAILURE;
    }

    if (buffer > 31)
    {
        printf("ERROR: BUFFER out of range (0-31)\n");
        return FAILURE;
    }
    int space = check_pdu_space(*offset, 2, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    // ENCODING
    pdu[(*offset)++] = LCID_SHORT_BSR;
    pdu[(*offset)++] = (lcgid << 5) | buffer;
    return SUCCESS;
}

/**********************************************************
 function:phr
***********************************************************
* Brief: MAC subPDU with: 8-bit MAC subheader
* Subheader:R(2 BITS) LCID(6 BITS)
* Format:Octet 1 -> P (1 BIT) R(1 BIT) PH (6 BITS)
*        Octet 2 -> R (2 BITS)  PCMACX (6 BITS)
*        Total MAC CE (3 BYTES)
************************************************************/
int phr(uint8_t *pdu, int *offset, int argc, int ph, int pcmax, Flags flags, int pdu_size)
{
    if (argc == 0)
    {
        printf("ERROR: Both parameters missing\n");
        return FAILURE;
    }

    if (argc > 2)
    {
        printf("ERROR: phr extra parameters detected\n");
        return FAILURE;
    }
    if (ph == -1)
    {
        printf("ERROR: Missing parameter PH\n");
        return FAILURE;
    }

    if (pcmax == -1)
    {
        printf("ERROR: Missing parameter Pcmax\n");
        return FAILURE;
    }
    // -------- NEGATIVE CHECK --------
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

    int space = check_pdu_space(*offset, 3, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;
    // subheader
    pdu[(*offset)++] = LCID_PHR;
    // payload
    pdu[(*offset)++] = (flags.P << 7) | (flags.R << 6) | (ph & 0x3F);
    pdu[(*offset)++] = (flags.MPE << 7) | (flags.R2 << 6) | (pcmax & 0x3F);
    return SUCCESS;
}

/*****************************************************
 *function:crnti
 ********************************************************
 * Brief: MAC subPDU with: 8-bit MAC subheader
 * Subheader:R(2 BITS) LCID(6 BITS)
 * Format:Octet 1 ->CRNTI(8 BITS)
 *        Octet 2 -> CRNTI(8 BITS)
 * Total MAC CE (3 BYTES)
 ********************************************************/
int crnti(uint8_t *pdu, int *offset, int argc, int value, int pdu_size)
{
    if (argc == 0)
    {
        printf("ERROR: CRNTI missing parameter(VALUE) \n");
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
    int space = check_pdu_space(*offset, 3, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    // subheader
    pdu[(*offset)++] = LCID_CRNTI;
    // payload
    pdu[(*offset)++] = (value >> 8) & 0xFF;
    pdu[(*offset)++] = value & 0xFF;
    return SUCCESS;
}

/*********************************************************
 *function:dsr
**********************************************************
* Brief: MAC subPDU with 16-bit MAC subheader (Extended LCID)
* Subheader:Octet 1 → R (1 BITS)| R (1 BITS) | LCID (6 BITS)
            Octet 2 → eLCID(8 BITS)= 228 (DSR)
* Format:   Octet 1 → LCG bitmap (which LCGs are present)
*           Octet →  BT (1 BIT) R (1 BIT)  Remaining Time (6 BITS)
*           Octet → Buffer Size (8 BITS)
* Total MAC CE (5 BYTES)
**************************************************************/
int dsr(uint8_t *pdu, int *offset, int argc, int lcg, int rt, int buffer, Flags flags, EncoderState state, int pdu_size)
{
    // -------- PARAMETER COUNT CHECK --------
    if (argc == 0)
    {
        printf("ERROR: Parameter Missing\n");
        return FAILURE;
    }

    if (argc > 3)
    {
        printf("ERROR: dsr extra parameters detected\n");
        return FAILURE;
    }

    // -------- MISSING PARAMETER CHECK --------
    if (lcg == -1)
    {
        printf("ERROR: Missing parameter LCG\n");
        return FAILURE;
    }

    if (rt == -1)
    {
        printf("ERROR: Missing parameter RT\n");
        return FAILURE;
    }

    if (buffer == -1)
    {
        printf("ERROR: Missing parameter BUFFER\n");
        return FAILURE;
    }

    // -------- NEGATIVE CHECK --------
    if (lcg < 0)
    {
        printf("ERROR: LCG cannot be negative\n");
        return FAILURE;
    }

    if (rt < 0)
    {
        printf("ERROR: RT cannot be negative\n");
        return FAILURE;
    }

    if (buffer < 0)
    {
        printf("ERROR: BUFFER cannot be negative\n");
        return FAILURE;
    }

    // -------- RANGE CHECK --------
    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;

    if (check_range(rt, 0, 63, "RT"))
        return FAILURE;

    if (check_range(buffer, 0, 255, "BUFFER"))
        return FAILURE;

    // -------- BITMAP --------
    state.lcg_bitmap |= (1 << lcg);

    int space = check_pdu_space(*offset, 5, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;
    // -------- SUBHEADER --------
    pdu[(*offset)++] = LCID_EXT_1BYTE;
    pdu[(*offset)++] = ELCID_DSR;

    // -------- PAYLOAD --------
    pdu[(*offset)++] = state.lcg_bitmap;

    pdu[(*offset)++] = (flags.BT << 7) | (flags.R << 6) | (rt & 0x3F);
    pdu[(*offset)++] = buffer;

    return SUCCESS;
}

/****************************************************************
function : rec_bit_rate
******************************************************************
* MAC subPDU with: 8-bit MAC subheader (LCID = 6 bits , R =2 bits)
* Subheader: R(2 BITS) LCID(6 BITS)
* Format :Octet 1 -> lcid (6 BIT) UL/DL (1 BIT)  BIT RATE (1 BIT)
*         Octet 2 -> BIT RATE (5 BITS) X(1 BIT)  R (2 BITs)
*Total MAC CE payload (3 BYTES)
*********************************************************************/
int rec_bit_rate(uint8_t *pdu, int *offset, int argc, int lcid, int rate, int ul_dl, Flags flags, int pdu_size)
{
    if (argc == 0)
    {
        printf("ERROR: Parameter Missing\n");
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
        printf("ERROR:  Missing parameter LCID \n");
        return FAILURE;
    }

    if (rate == -1)
    {
        printf("ERROR:  Missing parameter RATE \n");
        return FAILURE;
    }

    if (ul_dl == -1)
    {
        printf("ERROR: Missing parameter UL_DL\n");
        return FAILURE;
    }

    // -------- NEGATIVE CHECK --------
    if (lcid < 0)
    {
        printf("ERROR: LCID cannot be negative\n");
        return FAILURE;
    }

    if (rate < 0)
    {
        printf("ERROR: RATE cannot be negative\n");
        return FAILURE;
    }

    if (ul_dl < 0)
    {
        printf("ERROR: UL/DL cannot be negative\n");
        return FAILURE;
    }

    // -------- RANGE CHECK --------
    if (check_range(lcid, 0, 63, "LCID"))
        return FAILURE;
    if (check_range(rate, 0, 63, "BIT_RATE"))
        return FAILURE;
    if (check_range(ul_dl, 0, 1, "UL/DL"))
        return FAILURE;

    int space = check_pdu_space(*offset, 3, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    // subheader
    pdu[(*offset)++] = LCID_REC_BIT_RATE;
    // payload
    pdu[(*offset)++] = (lcid << 2) | (ul_dl << 1) | flags.R;
    pdu[(*offset)++] = (rate << 2) | (flags.X << 1) | flags.R2;

    return SUCCESS;
}

/********************************************************
function: enhanced phr
*********************************************************
* MAC subPDU with: 16-bit MAC subheader (Extended LCID)
* Subheader:Octet 1 → R(1 BITS) | R(1 BITS) | LCID(6 BITS)
*           Octet 2 → eLCID (8 BITS)= 221 (ENH_PHR)
* Format :  Octet 1 → P(0/1) | V(0/1) | PH1 (6 BIT)
*           Octet 2 → R(0/1) | V(0/1) | PH2 (6 BIT)
*           Octet 3 → R(0/) 2 BIT | PCMAAX (6 BIT)
* Total MAC CE payload (5 BYTES)
*********************************************************/
int enhanced_phr(uint8_t *pdu, int *offset, int argc, int *params, int pdu_size)
{
    // Expected: params = [PH1, PH2, PCMAX]

    int ph1 = (argc > 0) ? params[0] : -1;
    int ph2 = (argc > 1) ? params[1] : -1;
    int pcmax = (argc > 2) ? params[2] : -1;

    // -------- MISSING PARAMETER CHECK --------
    if (ph1 == -1 || ph2 == -1 || pcmax == -1)
    {
        printf("ERROR: Missing parameter ");

        if (ph1 == -1)
            printf("PH1 ");

        if (ph2 == -1)
            printf("PH2 ");

        if (pcmax == -1)
            printf("PCMAX ");

        printf("\n");
        return FAILURE;
    }

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

    if (pcmax == -1)
    {
        printf("ERROR: Missing parameter PCMAX\n");
        return FAILURE;
    }

    // -------- EXTRA PARAMETER CHECK --------
    if (argc > 3)
    {
        printf("ERROR: Extra parameters detected\n");
        return FAILURE;
    }

    // -------- NEGATIVE CHECK --------
    if (ph1 < 0)
    {
        printf("ERROR: PH1 cannot be negative\n");
        return FAILURE;
    }

    if (ph2 < 0)
    {
        printf("ERROR: PH2 cannot be negative\n");
        return FAILURE;
    }

    if (pcmax < 0)
    {
        printf("ERROR: PCMAX cannot be negative\n");
        return FAILURE;
    }

    // -------- RANGE CHECK --------
    if (check_range(ph1, 0, 63, "PH1"))
        return FAILURE;

    if (check_range(ph2, 0, 63, "PH2"))
        return FAILURE;

    if (check_range(pcmax, 0, 63, "PCMAX"))
        return FAILURE;
    int space = check_pdu_space(*offset, 5, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    // -------- SUBHEADER --------
    pdu[(*offset)++] = LCID_EXT_1BYTE;
    pdu[(*offset)++] = ELCID_ENH_PHR;

    // -------- PAYLOAD (3 OCTETS) -------
    pdu[(*offset)++] = (0 << 7) | ((ph1 & 0x3F) << 1) | 0;
    pdu[(*offset)++] = ((ph2 & 0x3F) << 1) | 0;
    pdu[(*offset)++] = ((pcmax & 0x3F) << 1) | 0;

    return SUCCESS;
}
/*********************************************************
 function: sl_lbt
*********************************************************
* MAC subPDU with: 16-bit MAC subheader (Extended LCID)
* Subheader:Octet 1 → R(2 BITS) LCID(6 BITS)
*         Octet 2 → eLCID(8 BITS)= 222 (SL-LBT)
* Format: Octet 1 -> | R R R R4 R3 R2 R1 R0 |
*         R(3 BITS) R4-R0 (5 BITS)
* Total MAC CE (3 BYTES)
***********************************************************/
int sl_lbt(uint8_t *pdu, int *offset, int argc, int value, int pdu_size)
{
    if (argc < 1)
    {
        printf("ERROR: SL-LBT missing parameter\n");
        return FAILURE;
    }
    if (argc > 1)
    {
        printf("ERROR: Extra parameters detected\n");
        return FAILURE;
    }

    if (value < 0)
    {
        printf("ERROR: SL-LBT cannot be negative\n");
        return FAILURE;
    }

    if (check_range(value, 0, 31, "SL-LBT"))
        return FAILURE;
    int space = check_pdu_space(*offset, 3, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    // subheader
    pdu[(*offset)++] = LCID_EXT_1BYTE;
    pdu[(*offset)++] = ELCID_SL_LBT;

    // payload
    pdu[(*offset)++] = value & 0x1F;

    return SUCCESS;
}
/**************************************************************
function:enhanced_bfr
***************************************************************
* MAC subPDU with: 16-bit MAC subheader (Extended LCID)
* Subheader: Octet 1 → R(2 Bits) LCID(6 BITS)
*            Octet 2 → eLCID = 235 (ENH_BFR)
* Format:    Octet 1 -> |C7 C6 C5 C4 C3 C2 C1 SP|
*            Octet 2 -> |S7 S6 S5 S4S S3 S2 S1 S0 |(8 BIT)
*            Octet 3 ->  |AC(0/1) ID(0/1)  CANDIDATE OR R BITS(6 BIT)|
* Total MAC CE(5 BYTES) VARIABLE LENGTH
*********************************************************************/
int enhanced_bfr(uint8_t *pdu, int *offset, int argc, int *params, int pdu_size)
{
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
    int total_size = 2 + 2 + entries;
    // 2 (subheader) + 2 (ci,s) + entries (each 1 byte)
    int space = check_pdu_space(*offset, total_size, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;
    // subheader
    pdu[(*offset)++] = LCID_EXT_1BYTE; // Extended LCID (1 octet)
    pdu[(*offset)++] = ELCID_ENH_BFR;
    // payload
    pdu[(*offset)++] = ci;
    pdu[(*offset)++] = s;

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

        pdu[(*offset)++] = (ac << 7) | (id << 6) | (cid & 0x3F);
    }
    return SUCCESS;
}

/************************************************************
function: extended_bsr
**************************************************************
* MAC subPDU with: 16-bit MAC subheader (Extended LCID)
* Subheader: Octet 1 → R(2 BITS) LCID(6 BIT)
             Octet 2 → eLCID = 245 (EXTENDED_BSR)
* Format:    Octet 1 -> LCG ID (8 BITS)
             Octet 2 ->Buffer Size (8 BITS)
* Total MAC CE  (4 BYTES)
***************************************************************/
int extended_bsr(uint8_t *pdu, int *offset, int argc, int lcg, int buffer, int pdu_size)
{
    // -------- PARAM COUNT CHECK --------
    if (argc == 0)
    {
        printf("ERROR: extended_bsr missing parameters (LCG BUFFER)\n");
        return FAILURE;
    }

    if (argc == 1)
    {
        if (lcg == -1)
            printf("ERROR: LCG not provided\n");
        else
            printf("ERROR: BUFFER not provided\n");
        return FAILURE;
    }

    if (argc > 2)
    {
        printf("ERROR: extended_bsr extra parameters detected\n");
        return FAILURE;
    }

    // -------- NEGATIVE CHECK --------
    if (lcg < 0)
    {
        printf("ERROR: LCG cannot be negative\n");
        return FAILURE;
    }

    if (buffer < 0)
    {
        printf("ERROR: BUFFER cannot be negative\n");
        return FAILURE;
    }

    // -------- RANGE CHECK --------
    if (check_range(lcg, 0, 255, "LCG"))
        return FAILURE;

    if (check_range(buffer, 0, 255, "BUFFER"))
        return FAILURE;
    int space = check_pdu_space(*offset, 4, pdu_size);
    if (space == PDU_OVERFLOW)
        return PDU_OVERFLOW;

    // -------- ENCODING --------
    pdu[(*offset)++] = LCID_EXT_1BYTE;
    pdu[(*offset)++] = ELCID_EXT_BSR;

    pdu[(*offset)++] = lcg & 0x07;
    pdu[(*offset)++] = buffer & 0xFF;

    return SUCCESS;
}

/*********************************************
 PRINT HEX
**********************************************/
void print_hex(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

/********************************************
 PRINT BITS
**********************************************/
void print_bits(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        for (int j = 7; j >= 0; j--)
            printf("%d", (data[i] >> j) & 1);
        printf(" ");
    }
}

/**********************************************
PADDING
*************************************************/
void add_padding(uint8_t *buffer, int *offset, int remaining)
{
    for (int i = 0; i < remaining; i++)
    {
        buffer[(*offset)++] = 0x00;
    }
}

/*******************************************************
TYPE → ID
********************************************************/
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
    if (strcmp(type, "enhanced_phr") == 0)
        return 6;
    if (strcmp(type, "sl_lbt") == 0)
        return 7;
    if (strcmp(type, "enhanced_bfr") == 0)
        return 8;
    if (strcmp(type, "extended_bsr") == 0)
        return 9;
    return -1;
}

/*******************************************
 PARSE AND ENCODE FUNCTION
*********************************************
 Responsibilities:
 1. Reads input file
 2. Extracts total PDU size
 3. Identifies each MAC CE block (<type>)
 4. Calls corresponding encoding function
 5. Tracks buffer offset
 6. Prints encoded bits and hex per CE
 7. Adds padding to match PDU size
 8. Prints final MAC buffer
***********************************************/

int parse_and_encode(const char *filename, uint8_t *pdu, int *pdu_size)
{
    int offset = 0;
    Flags flags = {1, 0, 1, 0, 0, 0};
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

    fgets(line, sizeof(line), fp);
    char extra;
    if (sscanf(line, "Total pdu_size %d %c ", pdu_size, &extra) != 1 || *pdu_size < 0)
    {
        printf("ERROR: Invalid PDU size\n");
        return FAILURE;
    }
    // printf(" TOTAL PDU SIZE : %d\n", *pdu_size);
    //  Read number of CEs
    fgets(line, sizeof(line), fp);
    if (sscanf(line, "num_ce %d", &state.num_ce) != 1 || state.num_ce <= 0)
    {
        printf("ERROR: Invalid num_ce\n");
        return FAILURE;
    }

    // printf("NUMBER OF CE : %d\n\n", state.num_ce);
    int blank_count = 0;
    int ret = SUCCESS;
    while (state.ce_count < state.num_ce && fgets(line, sizeof(line), fp))
    {

        // detect <ce_type>
        if (line[0] == '<')
        {
            char type[20];
            sscanf(line, "<%[^>]>", type);
            int a = -1, b = -1, c = -1;
            int valid_ce = 1;
            int before = offset;
            ret = SUCCESS;

            printf("MAC CE : %s\n", type);
            int id = get_ce_id(type);
            if (id == -1)
            {
                printf("ERROR: Unknown CE %s\n\n", type);
                continue;
            }

            /***********************************************
             CE TYPE HANDLING (SWITCH CASE)
            ************************************************
             This switch block processes different MAC CE types
             based on the ID obtained from the CE name.
             Workflow:
             1. Identify CE type using 'id'
             2. Read required parameters from input file
             3. Call corresponding encoding function
             4. Store encoded data into PDU buffer
            *****************************************************/
            switch (id)
            {
            case 1:
            {
                int a = -1, b = -1;
                int param_count = 0;
                char key[20];
                int val;

                while (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<'))
                    {
                        fseek(fp, -strlen(line), SEEK_CUR);
                        break;
                    }

                    // -------- CHECK '=' PRESENT --------
                    char *ptr = strchr(line, '=');
                    if (!ptr)
                        continue;

                    // -------- READ KEY --------
                    sscanf(line, " %[^=]", key);

                    // -------- CHECK VALUE EXISTS --------
                    if (sscanf(ptr + 1, "%d", &val) != 1)
                    {
                        printf("ERROR: %s value missing or invalid\n", key);
                        ret = FAILURE;
                        break;
                    }
                    param_count++;

                    if (strcmp(key, "lcgid") == 0)
                        a = val;
                    else if (strcmp(key, "buffer") == 0)
                        b = val;
                    else
                    {
                        printf("ERROR: unknown parameter %s\n", key);
                        ret = FAILURE;
                        break;
                    }
                }

                if (ret != FAILURE)
                    ret = short_bsr(pdu, &offset, param_count, a, b, *pdu_size);
                break;
            }

            case 2:
            {
                int param_count = 0;
                int ph = -1, pcmax = -1;

                while (fgets(line, sizeof(line), fp))
                {
                    // STOP when next CE starts
                    if (strchr(line, '<'))
                    {
                        fseek(fp, -strlen(line), SEEK_CUR);
                        break;
                    }

                    // SKIP BLANK LINES
                    if (line[0] == '\n')
                        continue;

                    char *ptr = strchr(line, '=');
                    if (!ptr)
                        continue;

                    // -------- PH --------
                    if (strncmp(line, "ph", 2) == 0)
                    {
                        if (*(ptr + 1) == '\0' || *(ptr + 1) == '\n')
                        {
                            printf("ERROR: Missing value PH\n");
                            ret = FAILURE;
                            break;
                        }

                        char *val = ptr + 1;
                        while (*val == ' ')
                            val++;

                        if (sscanf(val, "%d", &ph) != 1)
                        {
                            printf("ERROR: Invalid value PH\n");
                            ret = FAILURE;
                            break;
                        }

                        param_count++;
                    }

                    // -------- PCMAX --------
                    else if (strncmp(line, "pcmax", 5) == 0)
                    {
                        if (*(ptr + 1) == '\0' || *(ptr + 1) == '\n')
                        {
                            printf("ERROR: Missing value PCMAX\n");
                            ret = FAILURE;
                            break;
                        }

                        char *val = ptr + 1;
                        while (*val == ' ')
                            val++;

                        if (sscanf(val, "%d", &pcmax) != 1)
                        {
                            printf("ERROR: Invalid value PCMAX\n");
                            ret = FAILURE;
                            break;
                        }

                        param_count++;
                    }

                    else
                    {
                        printf("ERROR: Unknown parameter in PHR\n");
                        ret = FAILURE;
                        break;
                    }
                }

                // 🔥 FINAL VALIDATION
                if (ret == FAILURE)
                    break;

                if (ph == -1)
                {
                    printf("ERROR: Missing parameter PH\n");
                    ret = FAILURE;
                    break;
                }

                if (pcmax == -1)
                {
                    printf("ERROR: Missing parameter PCMAX\n");
                    ret = FAILURE;
                    break;
                }

                //  ENCODING CALL
                ret = phr(pdu, &offset, param_count, ph, pcmax, flags, *pdu_size);
                break;
            }
            case 3:
            {
                int param_count = 0;

                if (!fgets(line, sizeof(line), fp))
                    return FAILURE;

                char *ptr = strchr(line, '=');

                if (ptr == NULL)
                {
                    printf("ERROR: Invalid CRNTI format\n");
                    ret = FAILURE;
                    break;
                }

                ptr++;

                if (*ptr == '\0' || *ptr == '\n')
                {
                    printf("ERROR: CRNTI value missing\n");
                    ret = FAILURE; //  DIRECT EXIT
                    break;
                }

                // STRICT CHECK
                for (int i = 0; ptr[i] != '\0' && ptr[i] != '\n'; i++)
                {
                    if (ptr[i] < '0' || ptr[i] > '9')
                    {
                        printf("ERROR: CRNTI must be a positive integer\n");
                        ret = FAILURE; //  DIRECT EXIT
                        break;
                    }
                }

                if (ret != FAILURE)
                {
                    int a = atoi(ptr);
                    param_count++;

                    ret = crnti(pdu, &offset, param_count, a, *pdu_size);
                }
            }
            case 4:
            {
                int param_count = 0;
                int lcid = -1, rate = -1, ul_dl = -1;

                for (int i = 0; i < 3; i++)
                {
                    if (!fgets(line, sizeof(line), fp))
                        break;

                    char *ptr = strchr(line, '=');
                    if (ptr == NULL)

                        continue;

                    // -------- LCID --------
                    if (strncmp(line, "lcid", 4) == 0)
                    {
                        if (*(ptr + 1) == '\n' || *(ptr + 1) == '\0')
                        {
                            printf("ERROR: Missing value LCID\n");
                            ret = FAILURE;
                        }

                        char extra;
                        if (sscanf(ptr + 1, "%d %c", &lcid, &extra) != 1)
                        {
                            printf("ERROR: LCID Must be a positive integer\n");
                            return FAILURE;
                        }
                        param_count++;
                    }

                    // -------- BIT RATE --------
                    else if (strncmp(line, "bit_rate", 8) == 0)
                    {
                        if (*(ptr + 1) == '\n' || *(ptr + 1) == '\0')
                        {
                            printf("ERROR: Missing value RATE\n");
                            ret = FAILURE;
                        }
                        char extra;
                        if (sscanf(ptr + 1, "%d %c", &rate, &extra) != 1)
                        {
                            printf("ERROR: RATE Must be a positive integer\n");
                            ret = FAILURE;
                        }
                        param_count++;
                    }

                    // -------- UL/DL --------
                    else if (strncmp(line, "ul_dl", 5) == 0)
                    {
                        if (*(ptr + 1) == '\n' || *(ptr + 1) == '\0')
                        {
                            printf("ERROR: Missing value UL/DL\n");
                            ret = FAILURE;
                        }

                        char extra;
                        if (sscanf(ptr + 1, "%d %c", &ul_dl, &extra) != 1)
                        {
                            printf("ERROR: UL/DL Must be a positive integer\n");
                            ret = FAILURE;
                        }
                        param_count++;
                    }
                }

                ret = rec_bit_rate(pdu, &offset, param_count, lcid, rate, ul_dl, flags, *pdu_size);
                break;
            }

            case 5:
            {
                int param_count = 0;
                int lcg = -1, rt = -1, buffer = -1;

                while (fgets(line, sizeof(line), fp))
                {
                    // Stop if next CE starts
                    if (strchr(line, '<'))
                    {
                        fseek(fp, -strlen(line), SEEK_CUR);
                        break;
                    }

                    char *ptr = strchr(line, '=');
                    if (ptr == NULL)
                        continue;

                    ptr++; // move after '='

                    // -------- LCG --------
                    if (strncmp(line, "lcg", 3) == 0)
                    {
                        if (*ptr == '\n' || *ptr == '\0')
                        {
                            printf("ERROR: Missing value LCG\n");
                            ret = FAILURE;
                            break;
                        }

                        char extra;
                        if (sscanf(ptr, "%d %c", &lcg, &extra) != 1)
                        {
                            printf("ERROR: LCG must be a positive integer\n");
                            ret = FAILURE;
                            break;
                        }

                        param_count++;
                    }

                    // -------- RT --------
                    else if (strncmp(line, "rt", 2) == 0)
                    {
                        if (*ptr == '\n' || *ptr == '\0')
                        {
                            printf("ERROR: Missing value RT\n");
                            ret = FAILURE;
                            break;
                        }

                        char extra;
                        if (sscanf(ptr, "%d %c", &rt, &extra) != 1)
                        {
                            printf("ERROR: RT must be a positive integer\n");
                            ret = FAILURE;
                            break;
                        }

                        param_count++;
                    }

                    // -------- BUFFER --------
                    else if (strncmp(line, "buffer", 6) == 0)
                    {
                        if (*ptr == '\n' || *ptr == '\0')
                        {
                            printf("ERROR: Missing value BUFFER\n");
                            ret = FAILURE;
                            break;
                        }

                        char extra;
                        if (sscanf(ptr, "%d %c", &buffer, &extra) != 1)
                        {
                            printf("ERROR: BUFFER must be a positive integer\n");
                            ret = FAILURE;
                            break;
                        }

                        param_count++;
                    }

                    else
                    {
                        printf("ERROR: Unknown parameter in DSR\n");
                        ret = FAILURE;
                        break;
                    }
                }

                // 🔥 VERY IMPORTANT: stop further checks if already failed
                if (ret == FAILURE)
                    break;

                // -------- FINAL VALIDATION --------
                if (lcg == -1)
                {
                    printf("ERROR: Missing parameter LCG\n");
                    ret = FAILURE;
                    break;
                }

                if (rt == -1)
                {
                    printf("ERROR: Missing parameter RT\n");
                    ret = FAILURE;
                    break;
                }

                if (buffer == -1)
                {
                    printf("ERROR: Missing parameter BUFFER\n");
                    ret = FAILURE;
                    break;
                }

                // -------- ENCODER CALL --------
                ret = dsr(pdu, &offset, param_count, lcg, rt, buffer, flags, state, *pdu_size);
                break;
            }
            case 6:
            {
                int ph[2] = {-1, -1}; // PH1, PH2
                int pcmax = -1;

                while (fgets(line, sizeof(line), fp))
                {
                    if (line[0] == '<')
                        break;

                    char *ptr = strchr(line, '=');
                    if (ptr == NULL)
                        continue;

                    // -------- PH --------
                    if (strncmp(line, "ph", 2) == 0)
                    {
                        int index;

                        // handle ph= → PH1
                        if (line[2] == '=')
                            index = 1;
                        else
                            index = atoi(line + 2); // ph2

                        if (index <= 0 || index > 2)
                        {
                            printf("ERROR: Invalid PH index\n");
                            ret = FAILURE;
                        }

                        if (*(ptr + 1) == '\0' || *(ptr + 1) == '\n')
                        {
                            printf("ERROR: Missing value PH%d\n", index);
                            ret = FAILURE;
                        }

                        char *val = ptr + 1;
                        while (*val == ' ')
                            val++;

                        if (strchr(val, '.') != NULL)
                        {
                            printf("ERROR: value must be positive integer\n");
                            ret = FAILURE;
                        }

                        int temp;
                        if (sscanf(val, "%d", &temp) != 1)
                        {
                            printf("ERROR: value must be positive integer\n");
                            ret = FAILURE;
                        }

                        ph[index - 1] = temp;
                    }

                    // -------- PCMAX --------
                    else if (strncmp(line, "pcmax", 5) == 0)
                    {
                        if (*(ptr + 1) == '\0' || *(ptr + 1) == '\n')
                        {
                            printf("ERROR: Missing value PCMAX\n");
                            ret = FAILURE;
                        }

                        char *val = ptr + 1;
                        while (*val == ' ')
                            val++;

                        if (strchr(val, '.') != NULL)
                        {
                            printf("ERROR: value must be positive integer\n");
                            ret = FAILURE;
                        }

                        if (sscanf(val, "%d", &pcmax) != 1)
                        {
                            printf("ERROR: value must be positive integer\n");
                            ret = FAILURE;
                            break;
                        }
                    }
                }

                // -------- PREPARE PARAMS (FIXED MAPPING) --------
                int params[3];

                params[0] = ph[0]; // PH1
                params[1] = ph[1]; // PH2
                params[2] = pcmax; // PCMAX

                int param_count = 3;

                // -------- CALL FUNCTION --------
                ret = enhanced_phr(pdu, &offset, param_count, params, *pdu_size);

                if (ret == FAILURE)
                    ret = FAILURE;

                break;
            }
            case 7:
            {
                int param_count = 0;

                fgets(line, sizeof(line), fp);

                char *ptr = strchr(line, '=');

                // -------- CHECK '=' --------
                if (ptr == NULL)
                {
                    printf("ERROR: Invalid SL-LBT format\n");
                    ret = FAILURE;
                    break;
                }

                ptr++; // move after '='

                // -------- CHECK EMPTY VALUE --------
                if (*ptr == '\0' || *ptr == '\n')
                {
                    printf("ERROR: SL-LBT value missing\n");
                    ret = FAILURE;
                    break;
                }

                // -------- STRICT INTEGER CHECK --------
                for (int i = 0; ptr[i] != '\0' && ptr[i] != '\n'; i++)
                {
                    if (ptr[i] < '0' || ptr[i] > '9')
                    {
                        printf("ERROR: SL-LBT must be a positive integer\n");
                        ret = FAILURE;
                        break;
                    }
                }

                // -------- CONVERT --------
                int a = atoi(ptr);
                param_count++;

                // -------- CALL ENCODER --------
                ret = sl_lbt(pdu, &offset, param_count, a, *pdu_size);
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
                        fseek(fp, -strlen(line), SEEK_CUR);
                        break;
                    }

                    if (strchr(line, '=') == NULL)
                        continue;

                    char *ptr = strchr(line, '=');
                    int val = -1;

                    if (ptr && sscanf(ptr + 1, "%d", &val) == 1)
                    {
                        params[count++] = val;
                    }
                    else
                    {
                        printf("ERROR: invalid enhanced_bfr input\n");
                        ret = FAILURE;
                    }
                }
                ret = enhanced_bfr(pdu, &offset, count, params, *pdu_size);
                break;
            }
            case 9:
            {
                int a = -1, b = -1;
                int param_count = 0;
                char key[20];
                int val;

                while (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<'))
                    {
                        fseek(fp, -strlen(line), SEEK_CUR);
                        break;
                    }

                    char *ptr = strchr(line, '=');
                    if (!ptr)
                        continue;

                    // read key
                    sscanf(line, " %[^=]", key);

                    // only format + integer check
                    if (sscanf(ptr + 1, "%d", &val) != 1)
                    {
                        printf("ERROR: %s must be a positive integer\n", key);
                        ret = FAILURE;
                    }

                    param_count++;

                    if (strcmp(key, "lcgid") == 0)
                        a = val;
                    else if (strcmp(key, "buffer") == 0)
                        b = val;
                    else
                    {
                        printf("ERROR: unknown parameter %s\n", key);
                        ret = FAILURE;
                    }
                }

                ret = extended_bsr(pdu, &offset, param_count, a, b, *pdu_size);
                break;
            }
            }
            if (ret == PDU_OVERFLOW)
            {
                printf("ERROR: PDU size exceeded for %s (Available: %d bytes)\n\n",
                       type, *pdu_size - before);

                offset = before;
                continue;
            }

            if (ret == FAILURE)
            {
                printf("\n");
                fclose(fp);
                return FAILURE;
            }
            // rewind safely if next CE already read
            if (strchr(line, '<'))
            {
                fseek(fp, -strlen(line), SEEK_CUR);
            }

            int ce_len = offset - before;

            // SUBHEADER SIZE (DSR = extended)
            int is_extended_ce = (id == 5 || id == 6 || id == 7 || id == 8 || id == 9); // only DSR
            int subheader_size = is_extended_ce ? 2 : 1;

            int payload_size = ce_len - subheader_size;
            int total_size = ce_len;

            printf("Subheader Size : %d byte\n", subheader_size);
            printf("Payload Size   : %d bytes\n", payload_size);
            printf("Total CE Size  : %d bytes (Subheader + Payload)\n", total_size);

            // PRINT BITS
            printf("Encoded Bits : ");
            print_bits(&pdu[before], ce_len);
            printf("\n");

            // PRINT HEX
            printf("Encoded Hex  : ");
            print_hex(&pdu[before], ce_len);
            printf("\n");

            // SUCCESS MESSAGE
            printf("[SUCCESS] %s Encoded\n\n", type);
            state.ce_count++;
            continue;
        }
    }
    // ================= FINAL OUTPUT =================

    int total_used_before = offset;
    int remaining = *pdu_size - offset;

    printf("\n===== FINAL SUMMARY =====\n");
    printf("Total PDU Size   : %d bytes\n", *pdu_size);
    printf("Total Used Bytes : %d bytes\n", total_used_before);
    printf("Remaining Bytes  : %d bytes\n", remaining);

    // PADDING
    add_padding(pdu, &offset, remaining);

    printf("\nRemaining bytes filled with 00.\n");

    // FINAL BUFFER
    printf("\nFinal MAC Buffer:\n");
    print_hex(pdu, *pdu_size);
    printf("\n");
    fclose(fp);
    return SUCCESS;
}
