#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define MAGIC_CONSTANT 0xCAFEBABE

typedef struct __attribute__((packed)) {
    uint32_t magic;     
    uint32_t data_len;   
    uint32_t checksum;   
} PacketHeader;

#endif