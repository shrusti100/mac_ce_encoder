#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include "encoder.h"
#include "input_validation.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

/*----------------------------------
  STRICT INTEGER CHECK
----------------------------------*/
/*
 * Returns 1 if str is a valid non-negative decimal integer (no sign,
 * no decimal point, no hex prefix), 0 otherwise.
 *
 * Handles:
 *   - Leading whitespace (skipped)
 *   - Windows \r\n line endings (\r treated as terminator)
 *   - Overflow: caller must use strtol and check independently
 */
int is_strict_integer(const char *str)
{
    if (str == NULL || *str == '\0')
        return 0;

    int i = 0;

    /* Skip leading whitespace so "= 3" parses correctly */
    while (str[i] == ' ' || str[i] == '\t')
        i++;

    /* Negative sign not allowed */
    if (str[i] == '-')
        return 0;

    /* Must start with a digit */
    if (!isdigit((unsigned char)str[i]))
        return 0;

    /* Walk digits; stop on \0, \n, or \r (Windows CRLF) */
    for (; str[i] != '\0' && str[i] != '\n' && str[i] != '\r'; i++)
    {
        if (!isdigit((unsigned char)str[i]))
            return 0;
    }

    return 1;
}

/*----------------------------------
  PARSE INTEGER SAFELY
----------------------------------*/
/*
 * Finds the value after '=' in a "key = value" line, strips whitespace
 * and line endings, validates it is a strict non-negative integer, then
 * converts with strtol (overflow-safe).
 *
 * BUG FIX: parameter changed from char* to const char* to match the
 * header declaration and allow callers to pass const strings safely.
 */
int parse_integer(const char *line, int *out)
{
    if (line == NULL || out == NULL)
        return FAILURE;

    const char *ptr = strchr(line, '=');
    if (!ptr)
        return FAILURE;

    ptr++; /* move past '=' */

    /* Skip whitespace between '=' and the digits */
    while (*ptr == ' ' || *ptr == '\t')
        ptr++;

    char value_str[50];
    strncpy(value_str, ptr, sizeof(value_str) - 1);
    value_str[sizeof(value_str) - 1] = '\0';

    /* Strip newline and carriage return */
    value_str[strcspn(value_str, "\r\n")] = '\0';

    if (!is_strict_integer(value_str))
        return FAILURE;

    /* Use strtol instead of atoi for overflow safety */
    char *endptr = NULL;
    long v = strtol(value_str, &endptr, 10);

    if (endptr == value_str || *endptr != '\0' || v < 0 || v > INT_MAX)
        return FAILURE;

    *out = (int)v;
    return SUCCESS;
}

/*----------------------------------
  FILE VALIDATION
----------------------------------*/
/*
 * Validates that:
 *   1. The filename ends in ".txt" (case-insensitive)
 *   2. The file can be opened
 *   3. The file is non-empty
 */
int validate_input_file(const char *filename)
{
    if (filename == NULL)
    {
        printf("ERROR: filename is NULL\n");
        return FAILURE;
    }

    const char *ext = strrchr(filename, '.');
    if (!ext || strcasecmp(ext, ".txt") != 0)
    {
        printf("ERROR: Invalid file type. Only .txt allowed\n");
        return FAILURE;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        printf("ERROR: file not found\n");
        return FAILURE;
    }

    /* Reject empty files early with a clear message */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fclose(fp);

    if (size == 0)
    {
        printf("ERROR: input file is empty\n");
        return FAILURE;
    }

    return SUCCESS;
}

/*----------------------------------
  PARSE PDU SIZE
----------------------------------*/
/*
 * Extracts and returns the PDU size from a "key = value" line.
 * Returns -1 on any parse or range error.
 *
 * BUG FIX (dead-code note): This function was defined but never called —
 * parse_and_encode() in encoder.c re-implemented the same logic inline.
 * The implementations are now kept consistent. Callers should use this
 * function rather than duplicating the parsing logic.
 *
 * Valid range: 1 .. MAX_MAC_CE_SIZE (0 is rejected by parse_and_encode).
 */
int parse_pdu_size(const char *line)
{
    if (line == NULL)
        return -1;

    const char *eq = strchr(line, '=');
    if (eq == NULL)
        return -1;

    eq++; /* move past '=' */

    while (*eq == ' ' || *eq == '\t')
        eq++;

    char *endptr = NULL;
    long value = strtol(eq, &endptr, 10);

    /* Skip trailing whitespace before checking for garbage */
    while (endptr && (*endptr == ' ' || *endptr == '\t'))
        endptr++;

    /* Reject trailing garbage, negatives, and values beyond buffer limit */
    if (endptr == eq ||
        (*endptr != '\0' && *endptr != '\n' && *endptr != '\r') ||
        value < 0 ||
        value > MAX_MAC_CE_SIZE)
    {
        return -1;
    }

    return (int)value;
}
