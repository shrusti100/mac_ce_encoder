#include <stdio.h>
#include <stdint.h>
#include "encoder.h"

int main(void)
{
    uint8_t pdu[MAX_MAC_CE_SIZE] = {0};
    int pdu_size = 0;

    if (parse_and_encode("input.txt", pdu, &pdu_size) == FAILURE)
    {
        return 1;
    }

    return 0;
}
