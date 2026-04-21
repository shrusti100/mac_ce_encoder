#ifndef INPUT_VALIDATION_H
#define INPUT_VALIDATION_H

#include "encoder.h" /* SUCCESS, FAILURE, MAX_MAC_CE_SIZE */

int validate_input_file(const char *filename);
int is_strict_integer(const char *str);
int parse_integer(const char *line, int *out); /* FIX: const char* — matches .c definition */
int parse_pdu_size(const char *line);

#endif /* INPUT_VALIDATION_H */
