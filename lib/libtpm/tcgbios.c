
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

/*
 *  Implementation of the TPM BIOS extension according to the specification
 *  described in the IBM VTPM Firmware document and the TCG Specification
 *  that can be found here under the following link:
 *  http://www.trustedcomputinggroup.org/resources/pc_client_work_group_specific_implementation_specification_for_conventional_bios
 */

#include <stddef.h>

#include "types.h"
#include "byteorder.h"
#include "tpm_drivers.h"
#include "string.h"
#include "tcgbios.h"
#include "tcgbios_int.h"
#include "stdio.h"
#include "sha1.h"
#include "helpers.h"

#undef TCGBIOS_DEBUG
//#define TCGBIOS_DEBUG
#ifdef TCGBIOS_DEBUG
#define dprintf(_x ...) do { printf("TCGBIOS: " _x); } while(0)
#else
#define dprintf(_x ...)
#endif

struct tpm_state {
	unsigned tpm_probed:1;
	unsigned tpm_found:1;
	unsigned tpm_working:1;
	unsigned has_physical_presence:1;

	/* base address of the log area */
	uint8_t *log_base;

	/* size of the logging area */
	uint32_t log_area_size;

	/* where to write the next log entry to */
	uint8_t *log_area_next_entry;
};

static struct tpm_state tpm_state;

/********************************************************
  Extensions for TCG-enabled BIOS
 *******************************************************/

void tpm_set_log_parameters(void *addr, unsigned int size)
{
	dprintf("Log is at 0x%llx; size is %u bytes\n",
		(uint64_t)addr, size);
	tpm_state.log_base = addr;
	tpm_state.log_area_next_entry = addr;
	tpm_state.log_area_size = size;
}

/*
 * Extend the OFDT log with the given entry by copying the
 * entry data into the log.
 *
 * @pcpes: Pointer to the structure to be copied into the log
 * @event: The event to be appended to 'pcpes'
 * @event_length: The length of the event
 *
 * Returns 0 on success, an error code otherwise.
 */
static uint32_t tpm_log_event_long(struct pcpes *pcpes,
			           const char *event, uint32_t event_length)
{
	uint32_t size;

	dprintf("log base address = %p, next entry = %p\n",
		tpm_state.log_base, tpm_state.log_area_next_entry);

	if (tpm_state.log_area_next_entry == NULL)
		return TCGBIOS_LOGOVERFLOW;

	size = offset_of(struct pcpes, event) + event_length;

	if ((tpm_state.log_area_next_entry + size - tpm_state.log_base) >
	     tpm_state.log_area_size) {
		dprintf("LOG OVERFLOW: size = %d\n", size);
		return TCGBIOS_LOGOVERFLOW;
	}

	pcpes->eventdatasize = event_length;

	memcpy(tpm_state.log_area_next_entry, pcpes,
	       offset_of(struct pcpes, event));
	memcpy(tpm_state.log_area_next_entry + offset_of(struct pcpes, event),
	       event, event_length);

	tpm_state.log_area_next_entry += size;

	return 0;
}

bool tpm_log_event(struct pcpes *pcpes)
{
	const char *event = NULL;
	uint32_t event_length = pcpes->eventdatasize;

	if (event_length)
		event = (void *)pcpes + offset_of(struct pcpes, event);

	return (tpm_log_event_long(pcpes, event, event_length) == 0);
}

static void probe_tpm(void)
{
	tpm_state.tpm_probed = true;
	tpm_state.tpm_found = spapr_is_vtpm_present();
	tpm_state.tpm_working = tpm_state.tpm_found;
}

static bool tpm_is_working(void)
{
	if (!tpm_state.tpm_probed)
		probe_tpm();

	return tpm_state.tpm_working;
}

/* Helper function for sending TPM commands that take a single 
 * optional parameter (0, 1, or 2 bytes) and have no special response.
 */
static int
tpm_simple_cmd(uint8_t locty, uint32_t ordinal, int param_size, uint16_t param,
               enum tpm_duration_type to_t)
{
	struct {
		struct tpm_req_header trqh;
		uint16_t param;
	} __attribute__((packed)) req = {
		.trqh.totlen = cpu_to_be32(sizeof(req.trqh) + param_size),
		.trqh.tag = cpu_to_be16(TPM_TAG_RQU_CMD),
		.trqh.ordinal = cpu_to_be32(ordinal),
	};
	uint8_t obuffer[64];
	struct tpm_rsp_header *trsh = (void *)obuffer;
	uint32_t obuffer_len = sizeof(obuffer);
	int ret;

	switch (param_size) {
	case 2:
		req.param = cpu_to_be16(param);
		break;
	case 1:
		*(uint8_t *)&req.param = param;
		break;
	}

	memset(obuffer, 0, sizeof(obuffer));
	ret = tpmhw_transmit(locty, &req.trqh, obuffer, &obuffer_len, to_t);
	ret = ret ? -1 : be32_to_cpu(trsh->errcode);
	dprintf("Return from tpm_simple_cmd(%x, %x) = %x\n",
	        ordinal, param, ret);

	return ret;
}

static int get_capability(uint32_t cap, uint32_t subcap,
                          struct tpm_rsp_header *rsp, uint32_t rsize)
{
	struct tpm_req_getcap trgc = {
		.hdr.tag = cpu_to_be16(TPM_TAG_RQU_CMD),
		.hdr.totlen = cpu_to_be32(sizeof(trgc)),
		.hdr.ordinal = cpu_to_be32(TPM_ORD_GET_CAPABILITY),
		.capArea = cpu_to_be32(cap),
		.subCapSize = cpu_to_be32(sizeof(trgc.subCap)),
		.subCap = cpu_to_be32(subcap)
	};
	uint32_t resp_size = rsize;
	int ret = tpmhw_transmit(0, &trgc.hdr, rsp, &resp_size,
	                         TPM_DURATION_TYPE_SHORT);
	ret = (ret || resp_size != rsize) ? -1 : be32_to_cpu(rsp->errcode);
	dprintf("TCGBIOS: Return code from TM_GetCapability(%d, %d) = %x\n",
	        cap, subcap, ret);
	return ret;
}

static int read_permanent_flags(char *buf, size_t buf_len)
{
	struct tpm_rsp_getcap_perm_flags pf;
	int ret;

	memset(buf, 0, buf_len);
	ret = get_capability(TPM_CAP_FLAG, TPM_CAP_FLAG_PERMANENT,
	                     &pf.hdr, sizeof(pf));
	if (ret)
		return -1;

	memcpy(buf, &pf.perm_flags, buf_len);

	return 0;
}

static int determine_timeouts(void)
{
	struct tpm_rsp_getcap_durations durations;
	int i;

	int ret = get_capability(TPM_CAP_PROPERTY, TPM_CAP_PROP_DURATION,
	                         &durations.hdr, sizeof(durations));
	if (ret)
		return ret;

	for (i = 0; i < TPM_NUM_DURATIONS; i++)
		durations.durations[i] = be32_to_cpu(durations.durations[i]);

	dprintf("durations: %u %u %u\n",
		durations.durations[0],
		durations.durations[1],
		durations.durations[2]);

	spapr_vtpm_set_durations(durations.durations);

	return 0;
}

static void tpm_set_failure(void)
{
	/* we will try to deactivate the TPM now - ignoring all errors */
	tpm_simple_cmd(0, TPM_ORD_SET_TEMP_DEACTIVATED,
	               0, 0, TPM_DURATION_TYPE_SHORT);

	tpm_state.tpm_working = false;
}

static int assert_physical_presence(void)
{
	struct tpm_permanent_flags pf;
	int ret = tpm_simple_cmd(0, TPM_ORD_PHYSICAL_PRESENCE,
	                         2, TPM_PP_PRESENT, TPM_DURATION_TYPE_SHORT);
	if (!ret)
		return 0;

	ret = read_permanent_flags((char *)&pf, sizeof(pf));
	if (ret)
		return -1;

	/* check if hardware physical presence is supported */
	if (pf.flags[PERM_FLAG_IDX_PHYSICAL_PRESENCE_HW_ENABLE]) {
		/* HW. phys. presence may not be asserted ... */
		return 0;
	}

	if (!pf.flags[PERM_FLAG_IDX_PHYSICAL_PRESENCE_LIFETIME_LOCK]
	   && !pf.flags[PERM_FLAG_IDX_PHYSICAL_PRESENCE_CMD_ENABLE]) {
		tpm_simple_cmd(0, TPM_ORD_PHYSICAL_PRESENCE,
			       2, TPM_PP_CMD_ENABLE, TPM_DURATION_TYPE_SHORT);
		return tpm_simple_cmd(0, TPM_ORD_PHYSICAL_PRESENCE,
				      2, TPM_PP_PRESENT,
				      TPM_DURATION_TYPE_SHORT);
	}
	return -1;
}

static int tpm_startup(void)
{
	dprintf("Starting with TPM_Startup(ST_CLEAR)\n");
	int ret = tpm_simple_cmd(0, TPM_ORD_STARTUP,
	                         2, TPM_ST_CLEAR, TPM_DURATION_TYPE_SHORT);
	if (ret)
		goto err_exit;

	/* asssertion of physical presence is only possible after startup */
	ret = assert_physical_presence();
	if (!ret)
		tpm_state.has_physical_presence = true;

	ret = determine_timeouts();
	if (ret)
		goto err_exit;

	ret = tpm_simple_cmd(0, TPM_ORD_SELF_TEST_FULL,
	                     0, 0, TPM_DURATION_TYPE_LONG);
	if (ret)
		goto err_exit;

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	return -1;
}

uint32_t tpm_start(void)
{
	tpm_state.has_physical_presence = false;

	probe_tpm();

	if (!tpm_is_working()) {
		dprintf("%s: Machine does not have a working TPM\n",
			__func__);
		return TCGBIOS_FATAL_COM_ERROR;
	}

	return tpm_startup();
}

void tpm_finalize(void)
{
	spapr_vtpm_finalize();
}

/*
 * Give up physical presence; this function has to be called before
 * the firmware transitions to the boot loader.
 */
uint32_t tpm_unassert_physical_presence(void)
{
	if (tpm_state.has_physical_presence)
		tpm_simple_cmd(0, TPM_ORD_PHYSICAL_PRESENCE,
		               2, TPM_PP_NOT_PRESENT_LOCK,
		               TPM_DURATION_TYPE_SHORT);

	return 0;
}

/*
 * Extend a PCR of the TPM with the given hash
 *
 * @hash: sha1 hash (20 bytes) to extend PCR with
 * @pcrindex: the PCR to extend [ 0..23 ]
 */
static int tpm_extend(uint8_t *hash, uint32_t pcrindex)
{
	struct tpm_req_extend tre = {
		.hdr.tag = cpu_to_be16(TPM_TAG_RQU_CMD),
		.hdr.totlen = cpu_to_be32(sizeof(tre)),
		.hdr.ordinal = cpu_to_be32(TPM_ORD_EXTEND),
		.pcrindex = cpu_to_be32(pcrindex),
	};
	struct tpm_rsp_extend rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret;

	memcpy(tre.digest, hash, sizeof(tre.digest));

	ret = tpmhw_transmit(0, &tre.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_SHORT);

	if (ret || resp_length != sizeof(rsp) || rsp.hdr.errcode) {
		dprintf("TPM_Extend response has unexpected size: %u\n",
			rsplen);
		return -1;
	}

	return 0;
}

/*
 * tpm_hash_all: Function for interfacing with the firmware API
 */
uint32_t tpm_hash_all(const void *data, uint32_t datalen, void *hashptr)
{
	return sha1(data, datalen, hashptr);
}

static uint32_t hash_log_extend(struct pcpes *pcpes,
				const void *hashdata,
			        uint32_t hashdata_length,
				const char *event, uint32_t event_length,
				uint32_t pcrindex,
				bool extend)
{
	int ret;

	if (pcpes->pcrindex >= 24)
		return TCGBIOS_INVALID_INPUT_PARA;
	if (hashdata)
		tpm_hash_all(hashdata, hashdata_length, pcpes->digest);

	if (extend) {
		ret = tpm_extend(pcpes->digest, pcrindex);
		if (ret)
			return TCGBIOS_COMMAND_ERROR;
	}
	ret = tpm_log_event_long(pcpes, event, event_length);
	if (ret)
		return TCGBIOS_LOGOVERFLOW;
	return 0;
}

/*
 * tpm_hash_log_extend_event: Function for interfacing with the firmware API
 */
uint32_t tpm_hash_log_extend_event(struct pcpes *pcpes)
{
	const char *event = NULL;
	uint32_t event_length = pcpes->eventdatasize;

	if (!tpm_is_working())
		return TCGBIOS_GENERAL_ERROR;

	if (event_length)
		event = (void *)pcpes + offset_of(struct pcpes, event);

	return hash_log_extend(pcpes,
			       &pcpes->event, pcpes->eventdatasize,
			       event, event_length,
			       pcpes->pcrindex, true);
}
