#include "config.h"
#include <epan/packet.h>

#include <stdint.h>
#ifndef PACKET_PLDM_H
#define PACKET_PLDM_H

typedef union {
        uint8_t byte;
        struct {
                uint8_t bit0 : 1;
                uint8_t bit1 : 1;
                uint8_t bit2 : 1;
                uint8_t bit3 : 1;
                uint8_t bit4 : 1;
                uint8_t bit5 : 1;
                uint8_t bit6 : 1;
                uint8_t bit7 : 1;
        } __attribute__((packed)) bits;
  } bitfield8_t;

enum PLDMType {
	PLDM_DISCOVERY,
	PLDM_SMBIOS,
	PLDM_PLATFORM,
	PLDM_BIOS,
	PLDM_FRU,
	PLDM_FIRMWARE_UPDATE,
	PLDM_REDFISH,
	PLDM_OEM=63
};

typedef struct pldm_version {
	guint8 major;
	guint8 minor;
	guint8 update;
	guint8 alpha;
} __attribute__((packed)) ver32_t;

struct packet_data {
    guint8 direction;
    guint8 instance_id;
};

#endif
