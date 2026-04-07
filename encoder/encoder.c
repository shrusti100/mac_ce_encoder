#include <stdio.h>
#include <string.h>
#include "input_validation.h"
#include "encoder.h"

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

/*******************************************************************
 * function: short_bsr
 *******************************************************************
 *  Brief: MAC subPDU with 8-bit MAC subheader
 *  Subheader: R (2 BITS) LCID (6 BITS)
 *  Format: LCG ID (3 BITS) Buffer Size (5 BITS)
 *  Total MAC CE (2 BYTES)
 ********************************************************************/
int short_bsr(uint8_t *pdu, int *offset, int argc, int lcg, int buffer)
{
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
        printf("ERROR: Invalid values\n");
        return FAILURE;
    }

    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;
    if (check_range(buffer, 0, 31, "BUFFER"))
        return FAILURE;

    /*Octet:
     Bits [7:6] → LCG ID
     Bits [5:0] → Buffer Size*/
    // subheader
    pdu[(*offset)++] = LCID_SHORT_BSR;
    // payload
    pdu[(*offset)++] = (lcg << 5) | buffer;
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
int phr(uint8_t *pdu, int *offset, int argc, int ph, int pcmax, Flags flags)
{
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
int crnti(uint8_t *pdu, int *offset, int argc, int value)
{
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
int dsr(uint8_t *pdu, int *offset, int argc, int *params, Flags flags, EncoderState state)
{
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
    uint8_t lcg_bitmap = 0;
    for (int i = 0; i < entries; i++)
    {
        int lcg = params[i * 3];

        if (lcg < 0)
        {
            printf("ERROR: LCG cannot be negative\n");
            return FAILURE;
        }

        if (check_range(lcg, 0, 7, "LCG"))
            return FAILURE;

        state.lcg_bitmap |= (1 << lcg);
    }

    // subheader
    pdu[(*offset)++] = (0 << 7) | (0 << 6) |  LCID_EXT_1BYTE  ; // Extended LCID (1 octet)
    pdu[(*offset)++] = eLCID_DSR;                 // eLCID

    // payload
    pdu[(*offset)++] = state.lcg_bitmap;
    for (int i = 0; i < entries; i++)
    {
        int lcg = params[i * 3];
        int rt = params[i * 3 + 1];
        int buffer = params[i * 3 + 2];

        // validation
        if (rt < 0 || buffer < 0)
        {
            printf("ERROR: Negative values not allowed\n");
            return FAILURE;
        }

        if (check_range(rt, 0, 63, "RT"))
            return FAILURE;
        if (check_range(buffer, 0, 255, "BUFFER"))
            return FAILURE;

        pdu[(*offset)++] = (flags.BT << 7) | (flags.R << 6) | (rt & 0x3F);
        pdu[(*offset)++] = buffer;
    }
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
int rec_bit_rate(uint8_t *pdu, int *offset, int argc, int lcid, int rate, int ul_dl, Flags flags)
{
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
int enhanced_phr(uint8_t *pdu, int *offset, int argc, int *params)
{
    if (argc < 2)
    {
        printf("ERROR: enhanced_phr needs at least  one trp(PH PCMAX)\n");
        return FAILURE;
    }

    if (argc % 2 != 0)
    {
        printf("ERROR: enhanced_phr requires pairs of (PH PCMAX)\n");
        return FAILURE;
    }

    int entries = argc / 2;

    // subheader
    pdu[(*offset)++] = (0 << 7) | (0 << 6) |  LCID_EXT_1BYTE  ; // Extended LCID (1 octet)
    pdu[(*offset)++] = eLCID_ENH_PHR;
    // payload
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
int sl_lbt(uint8_t *pdu, int *offset, int value)
{
    if (value == -1)
    {
        printf("ERROR: SL-LBT value not provided\n");
        return FAILURE;
    }
    if (value < 0)
    {
        printf("ERROR:SL-LBT cannot be negative\n");
        return FAILURE;
    }
    if (check_range(value, 0, 31, "SL-LBT"))
        return FAILURE;
    // subheader
    pdu[(*offset)++] = (0 << 7) | (0 << 6) |  LCID_EXT_1BYTE  ; // Extended LCID (1 octet)
    pdu[(*offset)++] = eLCID_SL_LBT;
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
int enhanced_bfr(uint8_t *pdu, int *offset, int argc, int *params)
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

    // subheader
    pdu[(*offset)++] = (0 << 7) | (0 << 6) |  LCID_EXT_1BYTE  ; // Extended LCID (1 octet)
    pdu[(*offset)++] = eLCID_ENH_BFR;
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
int extended_bsr(uint8_t *pdu, int *offset, int lcg, int buffer)
{
    if (lcg == -1 || buffer == -1)
    {
        printf("ERROR: extended_bsr missing parameters (LCG BUFFER)\n");
        return FAILURE;
    }
    // -------- NEGATIVE CHECK --------
    if (lcg < 0 || buffer < 0)
    {
        printf("ERROR: extended_bsr values cannot be negative\n");
        return FAILURE;
    }
    // -------- RANGE CHECK --------
    if (check_range(lcg, 0, 7, "LCG"))
        return FAILURE;
    if (check_range(buffer, 0, 255, "BUFFER"))
        return FAILURE;

    // subheader
    pdu[(*offset)++] = (0 << 7) | (0 << 6) |  LCID_EXT_1BYTE  ; // Extended LCID (1 octet)
    pdu[(*offset)++] = eLCID_EXT_BSR;
    // payload
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
    printf(" TOTAL PDU SIZE : %d\n", *pdu_size);
    // Read number of CEs
    fgets(line, sizeof(line), fp);
    if (sscanf(line, "num_ce %d", &state.num_ce) != 1 || state.num_ce <= 0)
    {
        printf("ERROR: Invalid num_ce\n");
        return FAILURE;
    }

    printf("NUMBER OF CE : %d\n\n", state.num_ce);
    int blank_count = 0;
    while (fgets(line, sizeof(line), fp) && state.ce_count < state.num_ce)
    {

        // HANDLE BLANK LINES
        if (line[0] == '\n')
        {
            blank_count++;

            if (blank_count > 1)
            {
                printf("ERROR: More than one blank line between CEs\n");
                return FAILURE;
            }
            continue;
        }
        else
        {
            blank_count = 0;
        }
        // detect <ce_type>
        if (line[0] == '<')
        {
            char type[20];
            sscanf(line, "<%[^>]>", type);
            int a = -1, b = -1, c = -1;
            int valid_ce = 1;
            int before = offset;
            int ret = FAILURE;

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
                int param_count = 0;

                // Read LCG
                fgets(line, sizeof(line), fp);
                char *ptr = strchr(line, '=');
                if (ptr == NULL || sscanf(ptr + 1, "%d", &a) != 1)
                valid_ce = 0;
                param_count++;

                // Read BUFFER
                fgets(line, sizeof(line), fp);
                sscanf(strchr(line, '=') + 1, "%d", &b);
                param_count++;

                // Check for extra parameter
                long pos = ftell(fp);
                if (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<') == NULL && strchr(line, '=') != NULL)
                    {
                        param_count++; // extra param detected
                    }
                    fseek(fp, pos, SEEK_SET);
                }
                ret = short_bsr(pdu, &offset, param_count, a, b);
                break;
            }

            case 2:
            {
                fgets(line, sizeof(line), fp);
                sscanf(strchr(line, '=') + 1, "%d", &a);

                fgets(line, sizeof(line), fp);
                sscanf(strchr(line, '=') + 1, "%d", &b);

                ret = phr(pdu, &offset, 2, a, b, flags);
                break;
            }

            case 3:
            {
                fgets(line, sizeof(line), fp);
                sscanf(strchr(line, '=') + 1, "%d", &a);

                ret = crnti(pdu, &offset, 1, a);
                break;
            }
            case 4:
            {
                int param_count = 0;

                // LCID
                fgets(line, sizeof(line), fp);
                sscanf(strchr(line, '=') + 1, "%d", &a);
                param_count++;

                // BIT RATE
                fgets(line, sizeof(line), fp);
                sscanf(strchr(line, '=') + 1, "%d", &b);
                param_count++;

                // UL/DL
                fgets(line, sizeof(line), fp);
                sscanf(strchr(line, '=') + 1, "%d", &c);
                param_count++;

                // check extra param
                long pos = ftell(fp);
                if (fgets(line, sizeof(line), fp))
                {
                    if (strchr(line, '<') == NULL && strchr(line, '=') != NULL)
                    {
                        param_count++;
                    }
                    fseek(fp, pos, SEEK_SET);
                }

                ret = rec_bit_rate(pdu, &offset, param_count, a, b, c, flags);
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
                        fseek(fp, -strlen(line), SEEK_CUR);
                        break;
                    }

                    if (strchr(line, '=') == NULL)
                        continue;
                    char *ptr = strchr(line, '=');

                    if (ptr == NULL)
                    {
                        printf("ERROR: Invalid DSR format (missing '=')\n\n");
                        return FAILURE;
                    }

                    int val;
                    if (sscanf(ptr + 1, "%d", &val) != 1)
                    {
                        printf("ERROR: Invalid DSR input (must be integer, no alphabets)\n\n");
                        return FAILURE;
                    }

                    params[count++] = val;
                }

                ret = dsr(pdu, &offset, count, params, flags, state);
                break;
            }
            case 6:
            {
                int params[100], count = 0;
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
                    int val;

                    if (ptr == NULL || sscanf(ptr + 1, "%d", &val) != 1)
                    {
                        printf("ERROR: invalid enhanced_phr input\n\n");
                        return FAILURE;
                    }
                    params[count++] = val;
                }

                if (strchr(line, '<'))
                    fseek(fp, -strlen(line), SEEK_CUR);

                ret = enhanced_phr(pdu, &offset, count, params);
                break;
            }

            case 7:
            {
                fgets(line, sizeof(line), fp);
                char *ptr = strchr(line, '=');

                if (ptr == NULL || sscanf(ptr + 1, "%d", &a) != 1)
                {
                    printf("ERROR: invalid SL-LBT input (must be integer)\n\n");
                    return FAILURE;
                }

                ret = sl_lbt(pdu, &offset, a);
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
                        return FAILURE;
                    }
                }
                ret = enhanced_bfr(pdu, &offset, count, params);
                break;
            }

            case 9:
            {
                while (fgets(line, sizeof(line), fp))
                    if (line[0] == '\n')
                    {
                        printf("ERROR: Blank line inside CE 'extended_bsr'\n\n");
                        ret = FAILURE;
                        break;
                    }
                char *ptr = strchr(line, '=');

                if (ptr == NULL || sscanf(ptr + 1, "%d", &a) != 1)
                {
                    printf("ERROR: invalid LCG in extended_bsr\n\n");
                    return FAILURE;
                }

                // -------- BUFFER --------
                while (fgets(line, sizeof(line), fp))
                    if (line[0] == '\n')
                        continue;
                ptr = strchr(line, '=');

                if (ptr == NULL || sscanf(ptr + 1, "%d", &b) != 1)
                {
                    printf("ERROR: invalid BUFFER in extended_bsr\n\n");
                    return FAILURE;
                }
                ret = extended_bsr(pdu, &offset, a, b);
                break;
            }
            }
            if (ret == FAILURE)
            {
                printf("\n");
                continue;
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
