#include <stdint.h>
#include "packet-pldm-base.h"

static int proto_pldm_fru=-1;
static int hf_pldm_cmd=-1;
static int hf_completion_code=-1;

static int hf_fru_major_ver=-1;
static int hf_fru_minor_ver=-1;
static int hf_fru_table_max_size=-1;
static int hf_fru_table_length=-1;
static int hf_fru_num_record_identifiers=-1;
static int hf_fru_num_records=-1;
static int hf_fru_table_crc=-1;

static int hf_fru_data_handle=-1;
static int hf_fru_transfer_op_flag=-1;
static int hf_fru_next_data_handle=-1;
static int hf_fru_transfer_flag=-1;
//static int hf_fru_=-1;

static const value_string pldm_cmds[] ={
    {0x01, "GetFRURecordTableMetadata"},
    {0x02, "GetFRURecordTable"},
    {0x03, "SetFRURecordTable"},
    {0x04, "GetFRURecordByOption"},
    {0, NULL}
};

static const value_string completion_codes[]={
    {0x0, "Success"},
    {0x1, "Error"},
    {0x2, "Invalid Data"},
    {0x3, "Invalid Length"},
    {0x4, "Not Ready"},
    {0x5, "Unsupported PLDM command"},
    {0x20, "Invalid PLDM type"},
    {0x80, "Invalid data transfer handle"},
    {0x81, "Invalid transfer operation flag"},
    {0x82, "Invalid transfer flag"},
    {0x83, "No FRU table metadata"},
    {0x84, "Invalid data integrity check"},
    {0x85, "Fru data table unavailable"},
    {0, NULL}
};

static const value_string transfer_op_flags[] ={
    {0x0,   "Get Next Part"},
    {0x1,   "Get First Part"},
    {0, NULL}
};

static const value_string transfer_flags[] ={
    {0x1,   "Start"},
    {0x2,   "Middle"},
    {0x4,   "End"},
    {0x5,   "Start and End"},
    {0, NULL}
};

int
dissect_fru(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *p_tree, void* data)
{
    struct packet_data *d = (struct packet_data*) data;
    guint8 request = d->direction;
    guint8 offset = 0;
    guint8 pldm_cmd = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(p_tree, hf_pldm_cmd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset +=1;
    if (!request) {
        proto_tree_add_item(p_tree, hf_completion_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        guint8 completion_code = tvb_get_guint8(tvb, offset);
        if (completion_code)
            return tvb_captured_length(tvb);
        offset +=1;
    }
    switch(pldm_cmd){
    case 0x01: // Get Fru record table metadata
        if (!request) {
            proto_tree_add_item(p_tree, hf_fru_major_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
            proto_tree_add_item(p_tree, hf_fru_minor_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
            proto_tree_add_item(p_tree, hf_fru_table_max_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_fru_table_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_fru_num_record_identifiers, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(p_tree, hf_fru_num_records, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(p_tree, hf_fru_table_crc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }
        break;
    case 0x02: // Get Fru record table
        if (request) {
            proto_tree_add_item(p_tree, hf_fru_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_fru_transfer_op_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(p_tree, hf_fru_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_fru_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        break;
    case 0x03: // Set Fru record table
        if (request) {
            proto_tree_add_item(p_tree, hf_fru_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_fru_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(p_tree, hf_fru_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }
        break;
    default:
        col_append_fstr(pinfo->cinfo, COL_INFO, "Unsupported or Invalid PLDM command");
        g_print("Invalid PLDM fru cmd %x \n", pldm_cmd);
	break;
    }
    return tvb_captured_length(tvb);
}


void
proto_register_fru(void)
{
    static hf_register_info hf[] ={
        { &hf_pldm_cmd,{
            "PLDM Command Type", "pldm.cmd",
            FT_UINT8, BASE_HEX,
            VALS(pldm_cmds), 0x0,
            NULL, HFILL}
         },
         { &hf_completion_code,{
            "Completion Code", "pldm.cc",
            FT_UINT8, BASE_DEC,
            VALS(completion_codes), 0x0,
            NULL, HFILL}
         },
         { &hf_fru_major_ver,{
            "FRU Major version", "pldm.fru.ver.major",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_minor_ver,{
            "FRU Minor version", "pldm.fru.ver.minor",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_table_max_size,{
            "FRU Maximum table size", "pldm.fru.table.max",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_table_length,{
            "FRU Table length", "pldm.fru.table.len",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_num_record_identifiers,{
            "Total number of record set identifiers", "pldm.fru.num_identifiers",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_num_records,{
            "Total number of records in table", "pldm.fru.table.num_records",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_table_crc,{
            "FRU Table CRC", "pldm.fru.table.crc",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_data_handle,{
            "FRU Data transfer handle", "pldm.fru.table.handle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_transfer_op_flag,{
            "FRU Data transfer operation flag", "pldm.fru.table.opflag",
            FT_UINT8, BASE_DEC,
            VALS(transfer_op_flags), 0x0,
            NULL, HFILL}
         },
         { &hf_fru_next_data_handle,{
            "FRU Next data transfer handle", "pldm.fru.table.nexthandle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_fru_transfer_flag,{
            "FRU Data transfer flag", "pldm.fru.table.flag",
            FT_UINT8, BASE_DEC,
            VALS(transfer_flags), 0x0,
            NULL, HFILL}
         },
    };

    proto_pldm_fru = proto_register_protocol (
        "PLDM FRU Data Protocol", /* name */
        "PLDM_FRU",          /* short_name  */
        "pldm.fru"           /* filter_name */
        );
    proto_register_field_array(proto_pldm_fru, hf, array_length(hf));
}

void
proto_reg_handoff_fru(void)
{
    static dissector_handle_t fru_handle;

    fru_handle = create_dissector_handle(dissect_fru, proto_pldm_fru);
    dissector_add_uint("pldm.type", PLDM_FRU, fru_handle);
}
