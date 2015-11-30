
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

static const uint8_t startup_st_clear[] = { 0x00, TPM_ST_CLEAR };
//static const uint8_t startup_st_state[] = { 0x00, TPM_ST_STATE };

static const uint8_t physical_presence_cmd_enable[]  = { 0x00, 0x20 };
//static const uint8_t physical_presence_cmd_disable[] = { 0x01, 0x00 };
static const uint8_t physical_presence_present[]     = { 0x00, 0x08 };
static const uint8_t physical_presence_not_present_lock[] = { 0x00, 0x14 };

static const uint8_t command_flag_false[] = { 0x00 };
static const uint8_t command_flag_true[]  = { 0x01 };

static const uint8_t get_capability_permanent_flags[] = {
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x08
};

static const uint8_t get_capability_stclear_flags[] = {
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x09
};

static const uint8_t get_capability_owner_auth[] = {
	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x11
};

//static const uint8_t get_capability_timeouts[] = {
//	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
//	0x00, 0x00, 0x01, 0x15
//};

static const uint8_t get_capability_durations[] = {
	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x20
};

static const uint8_t get_capability_buffer_size[] = {
	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x24
};

static uint8_t evt_separator[] = {0xff,0xff,0xff,0xff};

struct tpm_state {
	unsigned tpm_probed:1;
	unsigned tpm_found:1;
	unsigned tpm_working:1;

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

static bool has_working_tpm(void)
{
	if (!tpm_state.tpm_probed)
		probe_tpm();

	return tpm_state.tpm_working;
}

bool tpm_is_working(void)
{
	return has_working_tpm();
}

/*
 * tpm_driver_get_state: Function for interfacing with the firmware API
 */
uint32_t tpm_driver_get_state(void)
{
	/* do not check for a working TPM here */
	if (!tpm_state.tpm_found)
		return VTPM_DRV_STATE_INVALID;

	return spapr_vtpm_get_state();
}

/*
 * tpm_driver_get_failure_reason: Function for interfacing with the firmware
 *                                API
 */
uint32_t tpm_driver_get_failure_reason(void)
{
	/* do not check for a working TPM here */
	if (!tpm_state.tpm_found)
		return VTPM_DRV_STATE_INVALID;

	return spapr_vtpm_get_error();
}

static uint32_t transmit(struct tpm_req_header *req,
			 uint8_t *respbuffer, uint32_t *respbufferlen,
			 enum tpm_duration_type to_t)
{
	if (!spapr_vtpm_transmit((uint8_t *)req, be32_to_cpu(req->totlen),
	                         to_t, respbuffer, respbufferlen))
		goto err_exit;

	return 0;

err_exit:
	/* do not send any commands */
	tpm_state.tpm_working = false;

	return TCGBIOS_FATAL_COM_ERROR;
}

/*
 * Send a TPM command with the given ordinal. Append the given buffer
 * containing all data in network byte order to the command (this is
 * the custom part per command) and expect a response of the given size.
 * If a buffer is provided, the response will be copied into it.
 */
static uint32_t build_and_send_cmd(uint32_t ordinal,
				   const uint8_t *append,
				   uint32_t append_size,
				   uint8_t *resbuffer,
				   uint32_t return_size,
				   uint32_t *return_code,
				   enum tpm_duration_type to_t)
{
	uint32_t rc;
	struct {
		struct tpm_req_header trqh;
		uint8_t cmd[64];
	} __attribute__((packed)) req = {
		.trqh.tag = cpu_to_be16(TPM_TAG_RQU_CMD),
		.trqh.totlen = cpu_to_be32(TPM_REQ_HEADER_SIZE + append_size),
		.trqh.ordinal = cpu_to_be32(ordinal),
	};
	uint8_t obuffer[64];
	struct tpm_rsp_header *trsh = (struct tpm_rsp_header *)obuffer;
	uint32_t obuffer_len = sizeof(obuffer);

	if (return_size > sizeof(obuffer) || append_size > sizeof(req.cmd)) {
		printf("TCGBIOS: Error: size of requested response buffer too big.");
		return TCGBIOS_FIRMWARE_ERROR;
	}

	memset(obuffer, 0, sizeof(obuffer));

	if (append_size)
		memcpy(req.cmd, append, append_size);

	rc = transmit(&req.trqh, obuffer, &obuffer_len, to_t);
	if (rc)
		return rc;

	*return_code = be32_to_cpu(trsh->errcode);

	if (resbuffer)
		memcpy(resbuffer, trsh, return_size);

	return 0;
}

static void tpm_set_failure(void)
{
	uint32_t return_code;

	/* we will try to deactivate the TPM now - ignoring all errors */
	build_and_send_cmd(TPM_ORD_PHYSICAL_PRESENCE,
			   physical_presence_cmd_enable,
			   sizeof(physical_presence_cmd_enable),
			   NULL, 0, &return_code,
			   TPM_DURATION_TYPE_SHORT);

	build_and_send_cmd(TPM_ORD_PHYSICAL_PRESENCE,
			   physical_presence_present,
			   sizeof(physical_presence_present),
			   NULL, 0, &return_code,
			   TPM_DURATION_TYPE_SHORT);

	build_and_send_cmd(TPM_ORD_SET_TEMP_DEACTIVATED,
			   NULL, 0, NULL, 0, &return_code,
			   TPM_DURATION_TYPE_SHORT);

	tpm_state.tpm_working = false;
}

static uint32_t determine_timeouts(void)
{
	uint32_t rc;
	uint32_t return_code;
	struct tpm_rsp_getcap_durations durations;
	unsigned int i;

	rc = build_and_send_cmd(TPM_ORD_GET_CAPABILITY,
				get_capability_durations,
				sizeof(get_capability_durations),
				(uint8_t *)&durations, sizeof(durations),
				&return_code, TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_GetCapability(Durations) = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	for (i = 0; i < TPM_NUM_DURATIONS; i++)
		durations.durations[i] = be32_to_cpu(durations.durations[i]);

	dprintf("durations: %u %u %u\n",
		durations.durations[0],
		durations.durations[1],
		durations.durations[2]);

	spapr_vtpm_set_durations(durations.durations);

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t tpm_startup(void)
{
	uint32_t rc;
	uint32_t return_code;

	if (!has_working_tpm())
		return TCGBIOS_GENERAL_ERROR;

	dprintf("Starting with TPM_Startup(ST_CLEAR)\n");
	rc = build_and_send_cmd(TPM_ORD_STARTUP,
				startup_st_clear, sizeof(startup_st_clear),
				NULL, 0, &return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_Startup = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	rc = build_and_send_cmd(TPM_ORD_SELF_TEST_FULL, NULL, 0,
				NULL, 0, &return_code,
				TPM_DURATION_TYPE_LONG);

	dprintf("Return code from TPM_SelfTestFull = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	rc = determine_timeouts();
	if (rc)
		goto err_exit;

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

uint32_t tpm_start(void)
{
	tpm_state.tpm_probed = false;
	tpm_state.tpm_found = false;
	tpm_state.tpm_working = false;

	if (!has_working_tpm()) {
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
	uint32_t rc;
	uint32_t return_code;

	if (!has_working_tpm())
		return TCGBIOS_GENERAL_ERROR;

	rc = build_and_send_cmd(TPM_ORD_PHYSICAL_PRESENCE,
				physical_presence_cmd_enable,
				sizeof(physical_presence_cmd_enable),
				NULL, 0, &return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_PhysicalPresence(CMD_ENABLE) = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	rc = build_and_send_cmd(TPM_ORD_PHYSICAL_PRESENCE,
				physical_presence_not_present_lock,
				sizeof(physical_presence_not_present_lock),
				NULL, 0, &return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_PhysicalPresence(NOT_PRESENT_LOCK) = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static bool pass_through_to_tpm(unsigned char *req,
				uint32_t reqlen,
				enum tpm_duration_type to_t,
				unsigned char *rsp,
				uint32_t *rsplen)
{
	struct tpm_req_header *trqh;

	if (!has_working_tpm())
	       return TCGBIOS_FATAL_COM_ERROR;

	trqh = (struct tpm_req_header *)req;
	if (reqlen < sizeof(*trqh))
		return TCGBIOS_INVALID_INPUT_PARA;

	return transmit(trqh, rsp, rsplen, to_t);
}

/*
 * tpm_pass_through_to_tpm: Function for interfacing with the firmware API
 *
 * buf: buffer holding the command; also used for holding the entire response
 * cmdlen: length of the command in the buffer
 *
 * Returns 0 in case of failure, the size of the response otherwise.
 */
uint32_t tpm_pass_through_to_tpm(unsigned char *buf, uint32_t cmdlen)
{
	uint32_t resplen = PAPR_VTPM_MAX_BUFFER_SIZE;

	/*
	 * API spec: caller must ensure that the buffer is large
	 *           enough to receive the full response into
	 *           the same buffer where the command is in.
	 *           We anticipate the largest possible buffer
	 *           the driver supports in 'resplen'.
	 * For duration we use the worst-case timeout 'LONG'
	 * so that any command can be sent and will not time out.
	 */
	if (pass_through_to_tpm(buf, cmdlen,
				TPM_DURATION_TYPE_LONG,
				buf, &resplen))
		return 0;

	return resplen;
}

/*
 * Extend a PCR of the TPM with the given hash
 *
 * @hash: sha1 hash (20 bytes) to extend PCR with
 * @pcrindex: the PCR to extend [ 0..23 ]
 */
static uint32_t tpm_extend(uint8_t *hash, uint32_t pcrindex)
{
	struct tpm_req_extend req = {
		.hdr.tag = cpu_to_be16(TPM_TAG_RQU_CMD),
		.hdr.totlen = cpu_to_be32(sizeof(req)),
		.hdr.ordinal = cpu_to_be32(TPM_ORD_EXTEND),
		.pcrindex = cpu_to_be32(pcrindex),
	};
	struct tpm_rsp_extend rsp;
	uint32_t rsplen = sizeof(rsp);
	uint32_t rc;

	memcpy(req.digest, hash, sizeof(req.digest));

	rc = transmit(&req.hdr, (uint8_t *)&rsp, &rsplen,
	              TPM_DURATION_TYPE_SHORT);

	if (rc || rsplen != sizeof(rsp)) {
		dprintf("TPM_Extend response has unexpected size: %u\n",
			rsplen);
		tpm_set_failure();
	}

	return rc;
}

/*
 * tpm_hash_all: Function for interfacing with the firmware API
 */
uint32_t tpm_hash_all(const void *data, uint32_t datalen, void *hashptr)
{
	return sha1(data, datalen, hashptr);
}

/*
 * Hash the given input data and append the hash to the log
 *
 * @hashdata: the data to hash
 * @hashdatalen: the size of the data to hash
 * @pcpes: the 'pcpes' to append to the log; the hash will be written into this
 *         structure
 * @event: the event to append to the pcpes
 * @event_length: the lenth of the event array
 */
static uint32_t hash_log_event(const void *hashdata,
			       uint32_t hashdatalen,
			       struct pcpes *pcpes,
			       const char *event, uint32_t event_length)
{
	/* TPM has PCRs 0 to 23 */
	if (pcpes->pcrindex >= 24)
		return TCGBIOS_INVALID_INPUT_PARA;

	if (hashdata)
		sha1(hashdata, hashdatalen, pcpes->digest);

	return tpm_log_event_long(pcpes, event, event_length);
}

static uint32_t hash_log_extend_event(const void *hashdata,
				      uint32_t hashdatalen,
				      struct pcpes *pcpes,
				      const char *event, uint32_t event_length,
				      uint32_t pcrindex)
{
	uint32_t rc;

	rc = hash_log_event(hashdata, hashdatalen, pcpes, event, event_length);

	/*
	 * Like PCCLient spec.: evn if log is full extend the PCR
	 */
	tpm_extend(pcpes->digest, pcrindex);

	return rc;
}

/*
 * tpm_hash_log_extend_event: Function for interfacing with then firmware API
 */
uint32_t tpm_hash_log_extend_event(struct pcpes *pcpes)
{
	const char *event = NULL;
	uint32_t event_length = pcpes->eventdatasize;

	if (!has_working_tpm())
		return TCGBIOS_GENERAL_ERROR;

	if (event_length)
		event = (void *)pcpes + offset_of(struct pcpes, event);

	return hash_log_extend_event(&pcpes->event, pcpes->eventdatasize,
				     pcpes, event, event_length,
				     pcpes->pcrindex);
}

/*
 * Add a measurement to the log;
 *
 * Input parameters:
 *  @pcrindex : PCR to extend
 *  @event_type : type of event
 *  @info : pointer to info (i.e., string) to be added to the log as-is
 *  @info_length: length of the info
 *  @data : pointer to data to be hashed
 *  @data_length: length of the data
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

	return hash_log_extend_event(hashdata, hashdatalen, &pcpes,
				     info, infolen, pcrindex);
}

/*
 * Add an EV_ACTION measurement to the list of measurements
 */
static uint32_t tpm_add_action(uint32_t pcrindex, const char *string)
{
	uint32_t len = strlen(string);

	return tpm_add_measurement_to_log(pcrindex, EV_ACTION,
					  string, len, (uint8_t *)string, len);
}

/*
 * Add event separators for a range of PCRs
 */
uint32_t tpm_add_event_separators(uint32_t start_pcr, uint32_t end_pcr)
{
	uint32_t rc = 0;
	uint32_t pcrindex;

	if (!has_working_tpm())
		return TCGBIOS_GENERAL_ERROR;

	if (start_pcr >= 24 || start_pcr > end_pcr)
		return TCGBIOS_INVALID_INPUT_PARA;

	/* event separators need to be extended and logged for PCRs 0-7 */
	for (pcrindex = start_pcr; pcrindex <= end_pcr; pcrindex++) {
		rc = tpm_add_measurement_to_log(pcrindex, EV_SEPARATOR,
						NULL, 0,
						(uint8_t *)evt_separator,
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

	if (!has_working_tpm())
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

static uint32_t read_stclear_flags(char *buf, int buf_len)
{
	uint32_t rc;
	uint32_t return_code;
	struct tpm_rsp_getcap_stclear_flags stcf;

	memset(buf, 0, buf_len);

	rc = build_and_send_cmd(TPM_ORD_GET_CAPABILITY,
				get_capability_stclear_flags,
				sizeof(get_capability_stclear_flags),
				(uint8_t *)&stcf, sizeof(stcf),
				&return_code, TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_GetCapability() = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	memcpy(buf, &stcf.stclear_flags, buf_len);

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t assert_physical_presence(bool verbose)
{
	uint32_t rc = 0;
	uint32_t return_code;
	struct tpm_stclear_flags stcf;

	rc = read_stclear_flags((char *)&stcf, sizeof(stcf));
	if (rc) {
		dprintf("Error reading STClear flags: 0x%08x\n", rc);
		return rc;
	}

	if (stcf.flags[STCLEAR_FLAG_IDX_PHYSICAL_PRESENCE])
		/* physical presence already asserted */
		return rc;

	rc = build_and_send_cmd(TPM_ORD_PHYSICAL_PRESENCE,
				physical_presence_cmd_enable,
				sizeof(physical_presence_cmd_enable),
				NULL, 0, &return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TSC_PhysicalPresence(CMD_ENABLE) = 0x%08x\n",
		return_code);

	if (rc || return_code) {
		if (verbose)
			printf("Error: Could not enable physical presence.\n\n");
		goto err_exit;
	}

	rc = build_and_send_cmd(TPM_ORD_PHYSICAL_PRESENCE,
				physical_presence_present,
				sizeof(physical_presence_present),
				NULL, 0, &return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TSC_PhysicalPresence(PRESENT) = 0x%08x\n",
		return_code);

	if (rc || return_code) {
		if (verbose)
			printf("Error: Could not set presence flag.\n\n");
		goto err_exit;
	}

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t read_permanent_flags(char *buf, int buf_len)
{
	uint32_t rc;
	uint32_t return_code;
	struct tpm_rsp_getcap_perm_flags pf;

	memset(buf, 0, buf_len);

	rc = build_and_send_cmd(TPM_ORD_GET_CAPABILITY,
				get_capability_permanent_flags,
				sizeof(get_capability_permanent_flags),
				(uint8_t *)&pf, sizeof(pf),
				&return_code, TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_GetCapability() = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	memcpy(buf, &pf.perm_flags, buf_len);

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t read_has_owner(bool *has_owner)
{
	uint32_t rc;
	uint32_t return_code;
	struct tpm_rsp_getcap_ownerauth oauth;

	rc = build_and_send_cmd(TPM_ORD_GET_CAPABILITY,
				get_capability_owner_auth,
				sizeof(get_capability_owner_auth),
				(uint8_t *)&oauth, sizeof(oauth),
				&return_code, TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_GetCapability() = 0x%08x\n",
		return_code);

	if (rc || return_code)
		goto err_exit;

	*has_owner = oauth.flag;

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t enable_tpm(bool enable, uint32_t *return_code, bool verbose)
{
	uint32_t rc;
	struct tpm_permanent_flags pf;

	rc = read_permanent_flags((char *)&pf, sizeof(pf));
	if (rc)
		return rc;

	if (pf.flags[PERM_FLAG_IDX_DISABLE] && !enable)
		return 0;

	rc = assert_physical_presence(verbose);
	if (rc) {
		dprintf("Asserting physical presence failed.\n");
		return rc;
	}

	rc = build_and_send_cmd(enable ? TPM_ORD_PHYSICAL_ENABLE
				       : TPM_ORD_PHYSICAL_DISABLE,
				NULL, 0, NULL, 0, return_code,
				TPM_DURATION_TYPE_SHORT);
	if (enable) {
		dprintf("Return code from TPM_PhysicalEnable = 0x%08x\n",
			*return_code);
	} else {
		dprintf("Return code from TPM_PhysicalDisable = 0x%08x\n",
			*return_code);
	}

	if (rc || *return_code)
		goto err_exit;

	return 0;

err_exit:
	if (enable) {
		dprintf("Enabling the TPM failed.\n");
	} else {
		dprintf("Disabling the TPM failed.\n");
	}
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t activate_tpm(bool activate, bool allow_reset,
			     uint32_t *return_code, bool verbose)
{
	uint32_t rc;
	struct tpm_permanent_flags pf;

	rc = read_permanent_flags((char *)&pf, sizeof(pf));
	if (rc)
		return rc;

	if (pf.flags[PERM_FLAG_IDX_DEACTIVATED] && !activate)
		return 0;

	if (pf.flags[PERM_FLAG_IDX_DISABLE])
		return 0;

	rc = assert_physical_presence(verbose);
	if (rc) {
		dprintf("Asserting physical presence failed.\n");
		return rc;
	}

	rc = build_and_send_cmd(TPM_ORD_PHYSICAL_SET_DEACTIVATED,
				activate ? command_flag_false
					 : command_flag_true,
				activate ? sizeof(command_flag_false)
					 : sizeof(command_flag_true),
				NULL, 0, return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from PhysicalSetDeactivated(%d) = 0x%08x\n",
		activate ? 0 : 1, *return_code);

	if (rc || *return_code)
		goto err_exit;

	if (activate && allow_reset && verbose) {
		printf("Requiring a reboot to activate the TPM.\n");
	}

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t enable_activate(int allow_reset, uint32_t *return_code,
				bool verbose)
{
	uint32_t rc;

	rc = enable_tpm(true, return_code, verbose);
	if (rc) {
		dprintf("Could not enable the TPM.\n");
		return rc;
	}

	rc = activate_tpm(true, allow_reset, return_code, verbose);

	return rc;
}

static uint32_t force_clear(bool enable_activate_before,
			    bool enable_activate_after,
			    uint32_t *return_code, bool verbose)
{
	uint32_t rc;
	bool has_owner;

	rc = read_has_owner(&has_owner);
	if (rc) {
		dprintf("Could not determine whether TPM has an owner\n");
		return rc;
	}
	if (!has_owner) {
		if (verbose)
			printf("TPM does not have an owner.\n");
		return 0;
	}

	if (enable_activate_before) {
		rc = enable_activate(false, return_code, verbose);
		if (rc) {
			dprintf("Enabling/activating the TPM failed.\n");
			return rc;
		}
	}

	rc = assert_physical_presence(verbose);
	if (rc) {
		dprintf("Asserting physical presence failed.\n");
		return rc;
	}

	rc = build_and_send_cmd(TPM_ORD_FORCE_CLEAR,
				NULL, 0, NULL, 0, return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_ForceClear() = 0x%08x\n",
		*return_code);

	if (rc || *return_code)
		goto err_exit;

	if (!enable_activate_after) {
		if (verbose)
			printf("Owner successfully cleared.\n"
			       "You will need to enable/activate the TPM again.\n\n");
		return 0;
	}

	enable_activate(true, return_code, verbose);

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t set_owner_install(bool allow, uint32_t *return_code,
				  bool verbose)
{
	uint32_t rc;
	bool has_owner;
	struct tpm_permanent_flags pf;

	rc = read_has_owner(&has_owner);
	if (rc)
		return rc;
	if (has_owner) {
		if (verbose)
			printf("Must first remove owner.\n");
		return 0;
	}

	rc = read_permanent_flags((char *)&pf, sizeof(pf));
	if (rc)
		return rc;

	if (pf.flags[PERM_FLAG_IDX_DISABLE]) {
		if (verbose)
			printf("TPM must first be enable.\n");
		return 0;
	}

	rc = assert_physical_presence(verbose);
	if (rc) {
		dprintf("Asserting physical presence failed.\n");
		return rc;
	}

	rc = build_and_send_cmd(TPM_ORD_SET_OWNER_INSTALL,
				(allow) ? command_flag_true :
					  command_flag_false,
				sizeof(command_flag_true),
				NULL, 0, return_code,
				TPM_DURATION_TYPE_SHORT);

	dprintf("Return code from TPM_SetOwnerInstall() = 0x%08x\n",
		*return_code);

	if (rc || *return_code)
		goto err_exit;

	if (verbose) {
		if (allow)
			printf("Installation of owner enabled.\n");
		else
			printf("Installation of owner disabled.\n");
	}

	return 0;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);
	tpm_set_failure();
	if (rc)
		return rc;
	return TCGBIOS_COMMAND_ERROR;
}

static uint32_t tpm_process_cfg(tpm_ppi_op ppi_op, bool verbose,
				uint32_t *return_code)
{
	uint32_t rc = 0;

	switch (ppi_op) {
	case TPM_PPI_OP_NOOP: /* no-op */
		break;

	case TPM_PPI_OP_ENABLE:
		rc = enable_tpm(true, return_code, verbose);
		break;

	case TPM_PPI_OP_DISABLE:
		rc = enable_tpm(false, return_code, verbose);
		break;

	case TPM_PPI_OP_ACTIVATE:
		rc = activate_tpm(true, true, return_code, verbose);
		break;

	case TPM_PPI_OP_DEACTIVATE:
		rc = activate_tpm(false, true, return_code, verbose);
		break;

	case TPM_PPI_OP_CLEAR:
		rc = force_clear(true, false, return_code, verbose);
		break;

	case TPM_PPI_OP_SET_OWNERINSTALL_TRUE:
		rc = set_owner_install(true, return_code, verbose);
		break;

	case TPM_PPI_OP_SET_OWNERINSTALL_FALSE:
		rc = set_owner_install(false, return_code, verbose);
		break;

	default:
		break;
	}

	if (rc)
		printf("Op %d: An error occurred: 0x%x TPM return code: 0x%x\n",
		       ppi_op, rc, *return_code);

	return rc;
}

uint32_t tpm_process_opcode(uint8_t op, bool verbose)
{
	uint32_t return_code;

	return tpm_process_cfg(op, verbose, &return_code);
}

int tpm_get_state(void)
{
	int state = 0;
	struct tpm_permanent_flags pf;
	bool has_owner;

	if (read_permanent_flags((char *)&pf, sizeof(pf)) ||
	    read_has_owner(&has_owner))
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

/*
 * tpm_get_maximum_cmd_size: Function for interfacing with the firmware API
 *
 * This function returns the maximum size a TPM command (or response) may have.
 */
uint32_t tpm_get_maximum_cmd_size(void)
{
	uint32_t rc;
	uint32_t return_code;
	struct tpm_rsp_getcap_buffersize buffersize;
	uint32_t result;

	if (!has_working_tpm())
		return 0;

	rc = build_and_send_cmd(TPM_ORD_GET_CAPABILITY,
				get_capability_buffer_size,
				sizeof(get_capability_buffer_size),
				(uint8_t *)&buffersize, sizeof(buffersize),
				&return_code, TPM_DURATION_TYPE_SHORT);

	if (rc || return_code)
		goto err_exit;

	result = MIN(cpu_to_be32(buffersize.buffersize),
	             spapr_vtpm_get_buffersize());

	return result;

err_exit:
	dprintf("TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();

	return 0;
}
