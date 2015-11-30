
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

#define MIN(a, b) ((a) < (b) ? (a) : (b))

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

typedef uint8_t tpm_ppi_op;

/********************************************************
  Extensions for TCG-enabled BIOS
 *******************************************************/

static void probe_tpm(void)
{
	tpm_state.tpm_probed = true;
	tpm_state.tpm_found = spapr_is_vtpm_present();
	tpm_state.tpm_working = tpm_state.tpm_found;
}

/****************************************************************
 * TPM hardware command wrappers
 ****************************************************************/

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

static int tpm12_get_capability(uint32_t cap, uint32_t subcap,
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
	dprintf("TCGBIOS: Return code from TPM_GetCapability(%d, %d) = %x\n",
		cap, subcap, ret);
	return ret;
}

static int tpm12_read_permanent_flags(char *buf, size_t buf_len)
{
	struct tpm_rsp_getcap_perm_flags pf;
	int ret;

	memset(buf, 0, buf_len);
	ret = tpm12_get_capability(TPM_CAP_FLAG, TPM_CAP_FLAG_PERMANENT,
				   &pf.hdr, sizeof(pf));
	if (ret)
		return -1;

	memcpy(buf, &pf.perm_flags, buf_len);

	return 0;
}

static int tpm12_determine_timeouts(void)
{
	struct tpm_rsp_getcap_durations durations;
	int i;
	int ret = tpm12_get_capability(TPM_CAP_PROPERTY, TPM_CAP_PROP_DURATION,
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
			resp_length);
		return -1;
	}

	return 0;
}

/****************************************************************
 * Setup and Measurements
 ****************************************************************/

bool tpm_is_working(void)
{
	if (!tpm_state.tpm_probed)
		probe_tpm();

	return tpm_state.tpm_working;
}

static void tpm_set_failure(void)
{
	/* we will try to deactivate the TPM now - ignoring all errors */
	tpm_simple_cmd(0, TPM_ORD_SET_TEMP_DEACTIVATED,
		       0, 0, TPM_DURATION_TYPE_SHORT);

	tpm_state.tpm_working = false;
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
				   const void *event, uint32_t event_length)
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

static int tpm12_assert_physical_presence(void)
{
	struct tpm_permanent_flags pf;
	int ret = tpm_simple_cmd(0, TPM_ORD_PHYSICAL_PRESENCE,
				 2, TPM_PP_PRESENT, TPM_DURATION_TYPE_SHORT);
	if (!ret)
		return 0;

	ret = tpm12_read_permanent_flags((char *)&pf, sizeof(pf));
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

static int tpm12_startup(void)
{
	dprintf("Starting with TPM_Startup(ST_CLEAR)\n");
	int ret = tpm_simple_cmd(0, TPM_ORD_STARTUP,
				 2, TPM_ST_CLEAR, TPM_DURATION_TYPE_SHORT);
	if (ret)
		goto err_exit;

	/* asssertion of physical presence is only possible after startup */
	ret = tpm12_assert_physical_presence();
	if (!ret)
		tpm_state.has_physical_presence = true;

	ret = tpm12_determine_timeouts();
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

	return tpm12_startup();
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

/****************************************************************
 * Forth interface
 ****************************************************************/

void tpm_set_log_parameters(void *addr, unsigned int size)
{
	dprintf("Log is at 0x%llx; size is %u bytes\n",
		(uint64_t)addr, size);
	tpm_state.log_base = addr;
	tpm_state.log_area_next_entry = addr;
	tpm_state.log_area_size = size;
}

uint32_t tpm_get_logsize(void)
{
	uint32_t logsize = tpm_state.log_area_next_entry - tpm_state.log_base;

	dprintf("log size: %u\n", logsize);

	return logsize;
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
				bool extend)
{
	int ret;

	if (pcpes->pcrindex >= 24)
		return TCGBIOS_INVALID_INPUT_PARA;
	if (hashdata)
		tpm_hash_all(hashdata, hashdata_length, pcpes->digest);

	if (extend) {
		ret = tpm_extend(pcpes->digest, pcpes->pcrindex);
		if (ret)
			return TCGBIOS_COMMAND_ERROR;
	}
	ret = tpm_log_event_long(pcpes, event, event_length);
	if (ret)
		return TCGBIOS_LOGOVERFLOW;
	return 0;
}

/*
 * Add a measurement to the log;
 *
 * Input parameters:
 *  @pcrindex : PCR to extend
 *  @event_type : type of event
 *  @info : pointer to info (i.e., string) to be added to the log as-is
 *  @info_length: length of the info
 *  @hashdata : pointer to data to be hashed
 *  @hashdata_length: length of the data
 *
 */
static uint32_t tpm_add_measurement_to_log(uint32_t pcrindex,
					   uint32_t eventtype,
					   const char *info,
					   uint32_t infolen,
					   const uint8_t *hashdata,
					   uint32_t hashdatalen)
{
	struct pcpes pcpes;

	pcpes.pcrindex	= pcrindex;
	pcpes.eventtype = eventtype;
	memset(&pcpes.digest, 0, sizeof(pcpes.digest));

	return hash_log_extend(&pcpes, hashdata, hashdatalen,
			       info, infolen, true);
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
			       event, event_length, true);
}

/*
 * Add an EV_ACTION measurement to the list of measurements
 */
static uint32_t tpm_add_action(uint32_t pcrIndex, const char *string)
{
	uint32_t len = strlen(string);

	return tpm_add_measurement_to_log(pcrIndex, EV_ACTION,
					  string, len, (uint8_t *)string, len);
}

/*
 * Add event separators for a range of PCRs
 */
uint32_t tpm_add_event_separators(uint32_t start_pcr, uint32_t end_pcr)
{
	static const uint8_t evt_separator[] = {0xff,0xff,0xff,0xff};
	uint32_t rc = 0;
	uint32_t pcrIndex;

	if (!tpm_is_working())
		return TCGBIOS_GENERAL_ERROR;

	if (start_pcr >= 24 || start_pcr > end_pcr)
		return TCGBIOS_INVALID_INPUT_PARA;

	/* event separators need to be extended and logged for PCRs 0-7 */
	for (pcrIndex = start_pcr; pcrIndex <= end_pcr; pcrIndex++) {
		rc = tpm_add_measurement_to_log(pcrIndex, EV_SEPARATOR,
						NULL, 0,
						evt_separator,
						sizeof(evt_separator));
		if (rc)
			break;
	}

	return rc;
}

uint32_t tpm_measure_bcv_mbr(uint32_t bootdrv, const uint8_t *addr,
			     uint32_t length)
{
	uint32_t rc;
	const char *string;

	if (!tpm_is_working())
		return TCGBIOS_GENERAL_ERROR;

	if (length < 0x200)
		return TCGBIOS_INVALID_INPUT_PARA;

	string = "Booting BCV device 00h (Floppy)";
	if (bootdrv == BCV_DEVICE_HDD)
		string = "Booting BCV device 80h (HDD)";

	rc = tpm_add_action(4, string);
	if (rc)
		return rc;

	/*
	 * equivalent to: dd if=/dev/hda ibs=1 count=440 | sha1sum
	 */
	string = "MBR";
	rc = tpm_add_measurement_to_log(4, EV_IPL,
					string, strlen(string),
					addr, 0x1b8);
	if (rc)
		return rc;

	/*
	 * equivalent to: dd if=/dev/hda ibs=1 count=72 skip=440 | sha1sum
	 */
	string = "MBR PARTITION TABLE";
	return tpm_add_measurement_to_log(5, EV_IPL_PARTITION_DATA,
					  string, strlen(string),
					  addr + 0x1b8, 0x48);
}

/****************************************************************
 * TPM Configuration Menu
 ****************************************************************/

static int tpm12_read_has_owner(bool *has_owner)
{
	struct tpm_rsp_getcap_ownerauth oauth;
	int ret = tpm12_get_capability(TPM_CAP_PROPERTY, TPM_CAP_PROP_OWNER,
				       &oauth.hdr, sizeof(oauth));
	if (ret)
		return -1;

	*has_owner = oauth.flag;

	return 0;
}

static int tpm12_enable_tpm(bool enable, bool verbose)
{
	struct tpm_permanent_flags pf;
	int ret = tpm12_read_permanent_flags((char *)&pf, sizeof(pf));
	if (ret)
		return -1;

	if (pf.flags[PERM_FLAG_IDX_DISABLE] && !enable)
		return 0;

	ret = tpm_simple_cmd(0, enable ? TPM_ORD_PHYSICAL_ENABLE
				       : TPM_ORD_PHYSICAL_DISABLE,
			     0, 0, TPM_DURATION_TYPE_SHORT);
	if (ret) {
		if (enable) {
			dprintf("TCGBIOS: Enabling the TPM failed.\n");
		} else {
			dprintf("TCGBIOS: Disabling the TPM failed.\n");
		}
	}
	return ret;
}

static int tpm12_activate_tpm(bool activate, bool allow_reset, bool verbose)
{
	struct tpm_permanent_flags pf;
	int ret = tpm12_read_permanent_flags((char *)&pf, sizeof(pf));
	if (ret)
		return -1;

	if (pf.flags[PERM_FLAG_IDX_DEACTIVATED] && !activate)
		return 0;

	if (pf.flags[PERM_FLAG_IDX_DISABLE])
		return 0;

	ret = tpm_simple_cmd(0, TPM_ORD_PHYSICAL_SET_DEACTIVATED,
			     1, activate ? 0 : 1,
			     TPM_DURATION_TYPE_SHORT);
	if (ret)
		return ret;

	if (activate && allow_reset) {
		if (verbose)
			printf("Requiring a reboot to activate the TPM.\n");
	}

	return 0;
}

static int tpm12_enable_activate(int allow_reset, bool verbose)
{
	int ret = tpm12_enable_tpm(true, verbose);
	if (ret)
		return ret;

	return tpm12_activate_tpm(true, allow_reset, verbose);
}

static int tpm12_force_clear(bool enable_activate_before,
			     bool enable_activate_after,
			     bool verbose)
{
	bool has_owner;
	int ret = tpm12_read_has_owner(&has_owner);
	if (ret)
		return -1;
	if (!has_owner) {
		if (verbose)
			printf("TPM does not have an owner.\n");
		return 0;
	}

	if (enable_activate_before) {
		ret = tpm12_enable_activate(false, verbose);
		if (ret) {
			dprintf("TCGBIOS: Enabling/activating the TPM failed.\n");
			return ret;
		}
	}

	ret = tpm_simple_cmd(0, TPM_ORD_FORCE_CLEAR,
			     0, 0, TPM_DURATION_TYPE_SHORT);
	if (ret)
		return ret;

	if (!enable_activate_after) {
		if (verbose)
			printf("Owner successfully cleared.\n"
			       "You will need to enable/activate the TPM again.\n\n");
		return 0;
	}

	return tpm12_enable_activate(true, verbose);
}

static int tpm12_set_owner_install(bool allow, bool verbose)
{
	bool has_owner;
	struct tpm_permanent_flags pf;
	int ret = tpm12_read_has_owner(&has_owner);
	if (ret)
		return -1;

	if (has_owner) {
		if (verbose)
			printf("Must first remove owner.\n");
		return 0;
	}

	ret = tpm12_read_permanent_flags((char *)&pf, sizeof(pf));
	if (ret)
		return -1;

	if (pf.flags[PERM_FLAG_IDX_DISABLE]) {
		if (verbose)
			printf("TPM must first be enable.\n");
		return 0;
	}

	ret = tpm_simple_cmd(0, TPM_ORD_SET_OWNER_INSTALL,
			     1, allow ? 1 : 0, TPM_DURATION_TYPE_SHORT);
	if (ret)
		return ret;

	if (verbose)
		printf("Installation of owner %s.\n",
		      allow ? "enabled" : "disabled");

	return 0;
}

static int tpm12_process_cfg(tpm_ppi_op ppi_op, bool verbose)
{
	int ret = 0;

	switch (ppi_op) {
	case TPM_PPI_OP_NOOP: /* no-op */
		break;

	case TPM_PPI_OP_ENABLE:
		ret = tpm12_enable_tpm(true, verbose);
		break;

	case TPM_PPI_OP_DISABLE:
		ret = tpm12_enable_tpm(false, verbose);
		break;

	case TPM_PPI_OP_ACTIVATE:
		ret = tpm12_activate_tpm(true, true, verbose);
		break;

	case TPM_PPI_OP_DEACTIVATE:
		ret = tpm12_activate_tpm(false, true, verbose);
		break;

	case TPM_PPI_OP_CLEAR:
		ret = tpm12_force_clear(true, false, verbose);
		break;

	case TPM_PPI_OP_SET_OWNERINSTALL_TRUE:
		ret = tpm12_set_owner_install(true, verbose);
		break;

	case TPM_PPI_OP_SET_OWNERINSTALL_FALSE:
		ret = tpm12_set_owner_install(false, verbose);
		break;

	default:
		break;
	}

	if (ret)
		printf("Op %d: An error occurred: 0x%x TPM\n",
		       ppi_op, ret);

	return ret;
}

uint32_t tpm_process_opcode(uint8_t op, bool verbose)
{
	return tpm12_process_cfg(op, verbose);
}

int tpm_get_state(void)
{
	int state = 0;
	struct tpm_permanent_flags pf;
	bool has_owner;

	if (tpm12_read_permanent_flags((char *)&pf, sizeof(pf)) ||
	    tpm12_read_has_owner(&has_owner))
		return ~0;

	if (!pf.flags[PERM_FLAG_IDX_DISABLE])
		state |= TPM_STATE_ENABLED; /* enabled */

	if (!pf.flags[PERM_FLAG_IDX_DEACTIVATED])
		state |= TPM_STATE_ACTIVE; /* active */

	if (has_owner) {
		state |= TPM_STATE_OWNED; /* has owner */
	} else {
		if (pf.flags[PERM_FLAG_IDX_OWNERSHIP])
			state |= TPM_STATE_OWNERINSTALL; /* owner can be installed */
	}

	dprintf("TPM state flags = 0x%x\n", state);

	return state;
}

uint32_t tpm_measure_scrtm(void)
{
	uint32_t rc;

	extern long print_version, print_version_end;
	extern long _slof_data, _slof_data_end;

	char *version_start = (char *)&print_version;
	uint32_t version_length = (long)&print_version_end - (long)&print_version;

	char *slof_start = (char *)&_slof_data;
	uint32_t slof_length = (long)&_slof_data_end - (long)&_slof_data;

	const char *scrtm = "S-CRTM Contents";

	dprintf("Measure S-CRTM Version: addr = %p, length = %d\n",
		version_start, version_length);

	rc = tpm_add_measurement_to_log(0, EV_S_CRTM_VERSION,
					version_start, version_length,
					(uint8_t *)version_start,
					version_length);

	if (rc)
		return rc;

	dprintf("Measure S-CRTM Content: start = %p, length = %d\n",
		&slof_start, slof_length);

	rc = tpm_add_measurement_to_log(0, EV_S_CRTM_CONTENTS,
					scrtm, strlen(scrtm),
					(uint8_t *)slof_start, slof_length);

	return rc;
}

/*
 * tpm_get_maximum_cmd_size: Function for interfacing with the firmware API
 *
 * This function returns the maximum size a TPM command (or response) may have.
 */
uint32_t tpm_get_maximum_cmd_size(void)
{
	struct tpm_rsp_getcap_buffersize trgb;
	int ret;

	if (!tpm_is_working())
		return 0;

	ret = tpm12_get_capability(TPM_CAP_PROPERTY, TPM_CAP_PROP_INPUT_BUFFER,
				   &trgb.hdr, sizeof(trgb));
	if (ret)
		return 0;

	return  MIN(cpu_to_be32(trgb.buffersize),
	            spapr_vtpm_get_buffersize());
}
