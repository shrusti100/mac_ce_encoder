#ifndef INPUT_VALIDATION_H
#define INPUT_VALIDATION_H

int validate_input_file(const char *filename);
int is_strict_integer(const char *str);
int parse_integer(char *line, int *out);
int parse_pdu_size(const char *line);

#endif
