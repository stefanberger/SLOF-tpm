
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

#include "types.h"
#include "byteorder.h"
#include "tpm_drivers.h"
#include "string.h"
#include "tcgbios.h"
#include "tcgbios_int.h"
#include "stdio.h"

#undef TCGBIOS_DEBUG
//#define TCGBIOS_DEBUG
#ifdef TCGBIOS_DEBUG
#define dprintf(_x ...) do { printf("TCGBIOS: " _x); } while(0)
#else
#define dprintf(_x ...)
#endif

static const uint8_t startup_st_clear[] = { 0x00, TPM_ST_CLEAR };
static const uint8_t startup_st_state[] = { 0x00, TPM_ST_STATE };

static const uint8_t physical_presence_cmd_enable[]  = { 0x00, 0x20 };
static const uint8_t physical_presence_cmd_disable[] = { 0x01, 0x00 };
static const uint8_t physical_presence_present[]     = { 0x00, 0x08 };
static const uint8_t physical_presence_not_present_lock[] = { 0x00, 0x14 };

static const uint8_t command_flag_false[] = { 0x00 };
static const uint8_t command_flag_true[]  = { 0x01 };

static const uint8_t get_capability_permanent_flags[] = {
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x08
};

static const uint8_t get_capability_owner_auth[] = {
	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x11
};

static const uint8_t get_capability_timeouts[] = {
	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x15
};

static const uint8_t get_capability_durations[] = {
	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x01, 0x20
};

struct tpm_state {
	unsigned tpm_probed:1;
	unsigned tpm_found:1;
	unsigned tpm_working:1;
};

static struct tpm_state tpm_state;

/********************************************************
  Extensions for TCG-enabled BIOS
 *******************************************************/

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
