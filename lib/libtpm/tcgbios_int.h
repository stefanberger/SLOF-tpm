/*****************************************************************************
 * Copyright (c) 2015 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef TCGBIOS_INT_H
#define TCGBIOS_INT_H

#include <stdint.h>
#include <stdbool.h>

#include "tpm_drivers.h"

/* internal error codes */
#define TCGBIOS_OK                       0x0
#define TCGBIOS_LOGOVERFLOW              0x1
#define TCGBIOS_GENERAL_ERROR            0x2
#define TCGBIOS_FIRMWARE_ERROR           0x3
#define TCGBIOS_FATAL_COM_ERROR          0x4
#define TCGBIOS_INVALID_INPUT_PARA       0x5
#define TCGBIOS_COMMAND_ERROR            0x6
#define TCGBIOS_INTERFACE_SHUTDOWN       0x7

#define TPM_ORD_SELF_TEST_FULL           0x00000050
#define TPM_ORD_FORCE_CLEAR              0x0000005d
#define TPM_ORD_GET_CAPABILITY           0x00000065
#define TPM_ORD_PHYSICAL_ENABLE          0x0000006f
#define TPM_ORD_PHYSICAL_DISABLE         0x00000070
#define TPM_ORD_SET_OWNER_INSTALL        0x00000071
#define TPM_ORD_PHYSICAL_SET_DEACTIVATED 0x00000072
#define TPM_ORD_SET_TEMP_DEACTIVATED     0x00000073
#define TPM_ORD_STARTUP                  0x00000099
#define TPM_ORD_PHYSICAL_PRESENCE        0x4000000a
#define TPM_ORD_EXTEND                   0x00000014

#define TPM_ST_CLEAR                     0x1
#define TPM_ST_STATE                     0x2
#define TPM_ST_DEACTIVATED               0x3

#define TPM_PP_CMD_ENABLE                0x0020
#define TPM_PP_PRESENT                   0x0008
#define TPM_PP_NOT_PRESENT_LOCK          0x0014

#define TPM_TAG_RQU_CMD                  0x00c1
#define TPM_TAG_RSP_CMD                  0x00c4

/* TPM command error codes */
#define TPM_INVALID_POSTINIT             0x26

/* event types */
#define EV_POST_CODE                     1
#define EV_SEPARATOR                     4
#define EV_ACTION                        5
#define EV_EVENT_TAG                     6
#define EV_S_CRTM_CONTENTS               7
#define EV_S_CRTM_VERSION                8
#define EV_IPL                          13
#define EV_IPL_PARTITION_DATA           14

#define SHA1_BUFSIZE                    20

/* Input and Output blocks for the TCG BIOS commands */

/* PCClient_PCREventStruct -- format of log entries; compatible with x86 */
struct pcpes {
	uint32_t pcrindex;
	uint32_t eventtype;
	uint8_t digest[SHA1_BUFSIZE];
	uint32_t eventdatasize;
	uint32_t event;
} __attribute__((packed));

struct tpm_req_header {
	uint16_t tag;
	uint32_t totlen;
	uint32_t ordinal;
} __attribute__((packed));

#define TPM_REQ_HEADER_SIZE (sizeof(struct tpm_req_header))

struct tpm_rsp_header {
	uint16_t tag;
	uint32_t totlen;
	uint32_t errcode;
} __attribute__((packed));

#define TPM_RSP_HEADER_SIZE (sizeof(struct tpm_rsp_header))

struct tpm_req_extend {
	struct tpm_req_header hdr;
	uint32_t pcrindex;
	uint8_t digest[SHA1_BUFSIZE];
} __attribute__((packed));

struct tpm_rsp_extend {
	struct tpm_rsp_header hdr;
	uint8_t digest[SHA1_BUFSIZE];
} __attribute__((packed));

struct tpm_req_getcap {
	struct tpm_req_header hdr;
	uint32_t capArea;
	uint32_t subCapSize;
	uint32_t subCap;
} __attribute__((packed));

#define TPM_CAP_FLAG      0x04
#define TPM_CAP_PROPERTY  0x05
#define TPM_CAP_FLAG_PERMANENT  0x108
#define TPM_CAP_PROP_OWNER      0x111
#define TPM_CAP_PROP_DURATION   0x120
#define TPM_CAP_PROP_INPUT_BUFFER 0x124

struct tpm_req_getcap_perm_flags {
	struct tpm_req_header hdr;
	uint32_t cap_area;
	uint32_t sub_cap_zize;
	uint32_t sub_cap;
} __attribute__((packed));

struct tpm_permanent_flags {
	uint16_t tag;
	uint8_t flags[20];
} __attribute__((packed));

#define PERM_FLAG_IDX_DISABLE 0
#define PERM_FLAG_IDX_OWNERSHIP 1
#define PERM_FLAG_IDX_DEACTIVATED 2
#define PERM_FLAG_IDX_DISABLEOWNERCLEAR 4
#define PERM_FLAG_IDX_PHYSICAL_PRESENCE_LIFETIME_LOCK 6
#define PERM_FLAG_IDX_PHYSICAL_PRESENCE_HW_ENABLE 7
#define PERM_FLAG_IDX_PHYSICAL_PRESENCE_CMD_ENABLE 8

struct tpm_rsp_getcap_perm_flags {
	struct tpm_rsp_header hdr;
	uint32_t size;
	struct tpm_permanent_flags perm_flags;
} __attribute__((packed));

struct tpm_req_getcap_stclear_flags {
	struct tpm_req_header hdr;
	uint32_t cap_area;
	uint32_t sub_cap_size;
	uint32_t sub_cap;
} __attribute__((packed));

struct tpm_stclear_flags {
	uint16_t tag;
	uint8_t  flags[5];
} __attribute__((packed));

#define STCLEAR_FLAG_IDX_DEACTIVATED 0
#define STCLEAR_FLAG_IDX_DISABLE_FORCE_CLEAR 1
#define STCLEAR_FLAG_IDX_PHYSICAL_PRESENCE 2
#define STCLEAR_FLAG_IDX_PHYSICAL_PRESENCE_LOCK 3
#define STCLEAR_FLAG_IDX_GLOBAL_LOCK 4

struct tpm_rsp_getcap_stclear_flags {
	struct tpm_rsp_header hdr;
	uint32_t size;
	struct tpm_stclear_flags stclear_flags;
} __attribute__((packed));

struct tpm_rsp_getcap_ownerauth {
	struct tpm_rsp_header hdr;
	uint32_t size;
	uint8_t flag;
} __attribute__((packed));

struct tpm_rsp_getcap_durations {
	struct tpm_rsp_header hdr;
	uint32_t size;
	uint32_t durations[TPM_NUM_DURATIONS];
} __attribute__((packed));

struct tpm_rsp_getcap_buffersize {
	struct tpm_rsp_header hdr;
	uint32_t size;
	uint32_t buffersize;
} __attribute__((packed));

#define TPM_PPI_OP_NOOP 0
#define TPM_PPI_OP_ENABLE 1
#define TPM_PPI_OP_DISABLE 2
#define TPM_PPI_OP_ACTIVATE 3
#define TPM_PPI_OP_DEACTIVATE 4
#define TPM_PPI_OP_CLEAR 5
#define TPM_PPI_OP_SET_OWNERINSTALL_TRUE 8
#define TPM_PPI_OP_SET_OWNERINSTALL_FALSE 9

/****************************************************************
 * TPM v2.0 hardware commands
 ****************************************************************/

#define TPM2_NO                     0
#define TPM2_YES                    1

#define TPM2_SU_CLEAR               0x0000
#define TPM2_SU_STATE               0x0001

#define TPM2_RH_OWNER               0x40000001
#define TPM2_RS_PW                  0x40000009
#define TPM2_RH_ENDORSEMENT         0x4000000b
#define TPM2_RH_PLATFORM            0x4000000c

/* TPM 2 command tags */
#define TPM2_ST_NO_SESSIONS         0x8001
#define TPM2_ST_SESSIONS            0x8002

/* TPM 2 commands */
#define TPM2_CC_HierarchyControl    0x121
#define TPM2_CC_SelfTest            0x143
#define TPM2_CC_Startup             0x144
#define TPM2_CC_GetCapability       0x17a

/* TPM 2 Capabilities */
#define TPM2_CAP_PCRS               0x00000005

/* TPM 2 data structures */

struct tpm2_authblock {
	uint32_t handle;
	uint16_t noncesize;  /* always 0 */
	uint8_t contsession; /* always TPM2_YES */
	uint16_t pwdsize;    /* always 0 */
} __attribute__((packed));

struct tpm2_req_hierarchycontrol {
	struct tpm_req_header hdr;
	uint32_t authhandle;
	uint32_t authblocksize;
	struct tpm2_authblock authblock;
	uint32_t enable;
	uint8_t state;
} __attribute__((packed));

struct tpm2_req_getcapability {
	struct tpm_req_header hdr;
	uint32_t capability;
	uint32_t property;
	uint32_t propertycount;
} __attribute__((packed));

struct tpm2_res_getcapability {
	struct tpm_rsp_header hdr;
	uint8_t moreData;
	uint32_t capability;
	uint8_t data[0]; /* capability dependent data */
} __attribute__((packed));


#endif /* TCGBIOS_INT_H */
