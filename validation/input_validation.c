#include <stdio.h>
#include <string.h>
#include "encoder.h"
#include "input_validation.h"
#include <ctype.h>
#include <stdlib.h>

//----------------------------------
// STRICT INTEGER CHECK
//----------------------------------
int is_strict_integer(const char *str)
{
    if (str == NULL || *str == '\0')
        return 0;

    int i = 0;

    // optional negative sign
    if (str[i] == '-')
        return 0; // negative values not allowed
    // must have at least one digit
    if (!isdigit(str[i]))
        return 0;

    for (; str[i] != '\0' && str[i] != '\n'; i++)
    {
        if (!isdigit(str[i]))
            return 0;
    }

    return 1;
}

//----------------------------------
// PARSE INTEGER SAFELY
//----------------------------------
int parse_integer(char *line, int *out)
{
    char *ptr = strchr(line, '=');
    if (!ptr)
        return FAILURE;

    char value_str[50];
    strncpy(value_str, ptr + 1, sizeof(value_str) - 1);
    value_str[sizeof(value_str) - 1] = '\0';

    // remove newline
    value_str[strcspn(value_str, "\n")] = '\0';

    if (!is_strict_integer(value_str))
        return FAILURE;

    *out = atoi(value_str);
    return SUCCESS;
}

//----------------------------------
// FILE VALIDATION
//----------------------------------
int validate_input_file(const char *filename)
{
    const char *ext = strrchr(filename, '.');

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

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

    fclose(fp);
    return SUCCESS;
}
int parse_pdu_size(const char *line)
{
    int value;
    char extra;

    if (line == NULL)
        return -1;

    if (sscanf(line, "Total pdu_size %d %c", &value, &extra) != 1)
        return -1;

    if (value < 0 || value > MAX_MAC_CE_SIZE)
        return -1;

    return value;
}
