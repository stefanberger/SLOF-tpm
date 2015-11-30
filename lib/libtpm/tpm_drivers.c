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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "string.h"
#include "helpers.h"
#include "byteorder.h"
#include "tpm_drivers.h"
#include "libhvcall.h"
#include "paflof.h"

#undef PAPR_VTPM_DEBUG
//#define PAPR_VTPM_DEBUG
#ifdef PAPR_VTPM_DEBUG
#define dprintf(_x ...) do { printf("VTPM CRQ: " _x); } while(0)
#else
#define dprintf(_x ...)
#endif

#define MIN(a, b) ((a) > (b) ? (b) : (a))

/* layout of the command request queue for vTPM */
struct crq {
	uint8_t valid;
	uint8_t msg;
	uint16_t len;
	uint32_t data;
	uint64_t reserved;
} __attribute__((packed));

#define PAPR_VTPM_INIT_CRQ_COMMAND      0xC0
#define PAPR_VTPM_VALID_COMMAND         0x80
#define PAPR_VTPM_MSG_RESULT            0x80

/* crq.msg request types when crq.valid = PAPR_VTPM_INIT_CRQ_COMMAND */
#define PAPR_VTPM_INIT_CRQ_RESULT       0x1

/* crq.msg request types when crq.valid = PAPR_VTPM_VALID_COMMAND */
#define PAPR_VTPM_GET_VERSION           0x1
#define PAPR_VTPM_TPM_COMMAND           0x2
#define PAPR_VTPM_GET_RTCE_BUFFER_SIZE  0x3

static const uint32_t tpm_default_durations[TPM_NUM_DURATIONS] = {
	TPM_DEFAULT_DURATION_SHORT,
	TPM_DEFAULT_DURATION_MEDIUM,
	TPM_DEFAULT_DURATION_LONG,
};

#define QUEUE_SIZE 4096

/* state of the PAPR CRQ VTPM driver */
static struct spapr_vtpm_driver_state {
	/* whether it driver been initialized */
	bool initialized;

	/* durations of short, medium, & long commands */
	uint32_t durations[TPM_NUM_DURATIONS];

	/* unit number */
	unsigned long unit;

	/* CRQ queue address and size */
	unsigned char *qaddr;
	unsigned long qsize;

	/* current q_entry */
	unsigned int curr_q_entry;

	/* current response CRQ */
	struct crq *response;

	/* power firmware defined state and error code */
	vtpm_drv_state driver_state;
	vtpm_drv_error driver_error;

	/* size of buffer supported by hypervisor */
	unsigned int buffer_size;

	/* version of the TPM we talk to -- from CRQ message */
	uint32_t tpm_version;
} spapr_vtpm = {
	.qsize = QUEUE_SIZE,
	.driver_state = VTPM_DRV_STATE_INVALID,
	.driver_error = VTPM_DRV_ERROR_NO_FAILURE,
};

static void vtpm_drv_state_set(vtpm_drv_state s, vtpm_drv_error e)
{
	spapr_vtpm.driver_state = s;
	spapr_vtpm.driver_error = e;
}

static vtpm_drv_state vtpm_drv_state_get(void)
{
	return spapr_vtpm.driver_state;
}

static vtpm_drv_error vtpm_drv_error_get(void)
{
	return spapr_vtpm.driver_error;
}

void spapr_vtpm_set_durations(const uint32_t durations[TPM_NUM_DURATIONS])
{
	memcpy(spapr_vtpm.durations, durations,
	       TPM_NUM_DURATIONS * sizeof(durations[0]));
}

static struct crq* get_crq(void *qaddr, unsigned long q_entry)
{
	return &((struct crq *)qaddr)[q_entry];
}

/*
 * Get the crq where the response will be found. This
 * function will clear the CRQ's valid field and advance
 * the entry counter to the next entry.
 */
static struct crq *get_response_crq(void)
{
	struct crq *crq;

	dprintf("curr_q_entry = %d\n", spapr_vtpm.curr_q_entry);

	crq = get_crq(spapr_vtpm.qaddr, spapr_vtpm.curr_q_entry);
	memset(crq, 0, sizeof(*crq));

	spapr_vtpm.curr_q_entry += 1;
	if (spapr_vtpm.curr_q_entry == (spapr_vtpm.qsize / sizeof(struct crq)))
		spapr_vtpm.curr_q_entry = 0;

	return crq;
}

/*
 * Send a message via CRQ and wait for the response
 */
static bool spapr_send_crq_and_wait(unsigned long unit,
				    struct crq *crq,
				    struct crq **response,
				    unsigned timeout,
				    vtpm_drv_state state1,
				    vtpm_drv_state state2)
{
	long rc;
	unsigned i;

	*response = get_response_crq();

	vtpm_drv_state_set(state1, VTPM_DRV_ERROR_NO_FAILURE);

	rc = hv_send_crq(unit, (uint64_t *)crq);
	if (rc != H_SUCCESS) {
		vtpm_drv_state_set(VTPM_DRV_STATE_WAIT_INIT,
				   VTPM_DRV_ERROR_TPM_CRQ_ERROR);
		return false;
	}

	vtpm_drv_state_set(state2, VTPM_DRV_ERROR_NO_FAILURE);

	for (i = 0; i < timeout; i += 1000) {
		if (((*response)->valid & PAPR_VTPM_MSG_RESULT))
			return true;
		SLOF_usleep(1000);
	}

	vtpm_drv_state_set(VTPM_DRV_STATE_FAILURE,
			   VTPM_DRV_ERROR_WAIT_TIMEOUT);

	dprintf("Received no response from CRQ\n");
	return false;
}

/*
 * Get parameters from the CRQ
 */
static bool spapr_vtpm_get_params(void)
{
	struct crq crq, *response;
	static bool completed = false; /* only once */

	if (completed)
		return true;

	/* get the TPM version */
	crq.valid = PAPR_VTPM_VALID_COMMAND;
	crq.msg = PAPR_VTPM_GET_VERSION;

	if (!spapr_send_crq_and_wait(spapr_vtpm.unit, &crq, &response, 10,
				     VTPM_DRV_STATE_SEND_GET_VERSION,
				     VTPM_DRV_STATE_WAIT_VERSION)) {
		dprintf("Failure getting TPM version from CRQ\n");
		return false;
	}

	vtpm_drv_state_set(VTPM_DRV_STATE_CHECK_VERSION,
			   VTPM_DRV_ERROR_NO_FAILURE);

	spapr_vtpm.tpm_version = be32_to_cpu(response->data);
	dprintf("TPM backend version: %d\n", spapr_vtpm.tpm_version);

	/* get the TPM's buffer size */
	crq.valid = PAPR_VTPM_VALID_COMMAND;
	crq.msg = PAPR_VTPM_GET_RTCE_BUFFER_SIZE;

	if (!spapr_send_crq_and_wait(spapr_vtpm.unit, &crq, &response, 10,
				     VTPM_DRV_STATE_SEND_BUFSIZE_REQ,
				     VTPM_DRV_STATE_WAIT_BUFSIZE)) {
		dprintf("Failure getting RTCE buffer size from CRQ\n");
		return false;
	}

	vtpm_drv_state_set(VTPM_DRV_STATE_ALLOC_RTCE_BUF,
			   VTPM_DRV_ERROR_NO_FAILURE);

	dprintf("RTCE buffer size: %u\n", be16_to_cpu(response->len));
	spapr_vtpm.buffer_size = response->len;
	if (spapr_vtpm.buffer_size < 1024) {
		dprintf("RTCE buffer size of %u bytes is too small. "
			"Minimum is 1024 bytes.\n", spapr_vtpm.buffer_size);
		vtpm_drv_state_set(VTPM_DRV_STATE_FAILURE,
				   VTPM_DRV_ERROR_BAD_RTCE_SIZE);
		return false;
	}

	completed = true;

	return true;
}

static bool spapr_vtpm_activate(void)
{
	long rc;
	struct crq crq, *response;

	if (vtpm_drv_error_get() != VTPM_DRV_ERROR_NO_FAILURE) {
		printf("VTPM CRQ: In failure mode\n");
		return false;
	}

	vtpm_drv_state_set(VTPM_DRV_STATE_REG_CRQ,
			   VTPM_DRV_ERROR_NO_FAILURE);

	rc = hv_reg_crq(spapr_vtpm.unit, (unsigned long)spapr_vtpm.qaddr,
			spapr_vtpm.qsize);
	if (rc != H_SUCCESS) {
		vtpm_drv_state_set(VTPM_DRV_STATE_WAIT_INIT,
				   VTPM_DRV_ERROR_UNEXPECTED_REG_ERROR);
		dprintf("CRQ registration failed\n");
		return false;
	}

	/* we always start with curr_q_entry 0 */
	spapr_vtpm.curr_q_entry = 0;

	if (!spapr_vtpm.initialized) {

		crq.valid = PAPR_VTPM_INIT_CRQ_COMMAND;
		crq.msg = PAPR_VTPM_INIT_CRQ_RESULT;

		if (!spapr_send_crq_and_wait(spapr_vtpm.unit,
					     &crq,
					     &response,
					     10,
					     VTPM_DRV_STATE_SEND_INIT,
					     VTPM_DRV_STATE_WAIT_INIT_COMP)) {
			dprintf("Initializing CRQ failed\n");
			goto err_exit;
		}
		dprintf("Successfully initialized CRQ\n");

		spapr_vtpm.initialized = true;
	}

	if (spapr_vtpm_get_params())
		return true;

err_exit:
	hv_free_crq(spapr_vtpm.unit);
	spapr_vtpm.unit = 0;

	return false;
}

static bool spapr_vtpm_init(void)
{
	spapr_vtpm_set_durations(tpm_default_durations);

	return true;
}

void spapr_vtpm_finalize(void)
{
	if (spapr_vtpm.unit)
		hv_free_crq(spapr_vtpm.unit);
}

/*
 * Check whether we have a CRQ underneath us; if we do, the CRQ will
 * be left open.
 */
static bool spapr_vtpm_probe(void)
{
	spapr_vtpm_init();

	if (!spapr_vtpm.qaddr) {
		spapr_vtpm.qaddr = SLOF_alloc_mem(spapr_vtpm.qsize);
		if (!spapr_vtpm.qaddr) {
			printf("spapr-vtpm: Unable to allocate memory\n");
			return false;
		}
		memset(spapr_vtpm.qaddr, 0, spapr_vtpm.qsize);

		dprintf("getting FORTH vtpm-unit\n");
		spapr_vtpm.unit = SLOF_get_vtpm_unit();
		if (!spapr_vtpm.unit) {
			printf("spapr-vtpm: Could not get valid vtpm-unit\n");
			return false;
		}
	}

	dprintf("vtpm_unit = %lx, buffer = %p\n",
		spapr_vtpm.unit, spapr_vtpm.qaddr);

	if (!spapr_vtpm_activate())
		return false;

	return true;
}

static bool spapr_vtpm_senddata(const uint8_t *const data, uint32_t len)
{
	struct crq crq;
	long rc;

	if (vtpm_drv_error_get() != VTPM_DRV_ERROR_NO_FAILURE) {
		printf("VTPM CRQ: In failure mode\n");
		return false;
	}

	if (len > spapr_vtpm.buffer_size) {
		dprintf("VTPM CRQ: Send buffer too large: %u > %u\n",
		        len, spapr_vtpm.buffer_size);
		return false;
	}

	spapr_vtpm.response = get_response_crq();
	/* response CRQ has been set and valid field cleared */

	crq.valid = PAPR_VTPM_VALID_COMMAND;
	crq.msg = PAPR_VTPM_TPM_COMMAND;
	crq.len = cpu_to_be16(len);
	crq.data = cpu_to_be32((uint64_t)data);

	vtpm_drv_state_set(VTPM_DRV_STATE_SEND_TPM_CMD,
			   VTPM_DRV_ERROR_NO_FAILURE);

	rc = hv_send_crq(spapr_vtpm.unit, (uint64_t *)&crq);

	if (rc == H_SUCCESS) {
		vtpm_drv_state_set(VTPM_DRV_STATE_WAIT_TPM_RSP,
				   VTPM_DRV_ERROR_NO_FAILURE);
	} else {
		vtpm_drv_state_set(VTPM_DRV_STATE_WAIT_INIT,
				   VTPM_DRV_ERROR_UNEXPECTED_SEND_ERROR);
	}

	return (rc == H_SUCCESS);
}

static bool spapr_vtpm_waitresponseready(enum tpm_duration_type to_t)
{
	uint32_t timeout = spapr_vtpm.durations[to_t];
	int i;

	if (vtpm_drv_error_get() != VTPM_DRV_ERROR_NO_FAILURE) {
		printf("VTPM CRQ: In failure mode\n");
		return false;
	}

	/* response CRQ has been set */

	for (i = 0; i < timeout; i += 1000) {
		if (spapr_vtpm.response->valid & PAPR_VTPM_MSG_RESULT) {
			/* TPM responded: move to Send tpm-cmd state */
			vtpm_drv_state_set(VTPM_DRV_STATE_SEND_TPM_CMD,
					   VTPM_DRV_ERROR_NO_FAILURE);
			dprintf("Received response to TPM command\n");
			return true;
		}
		SLOF_usleep(1000);
	}

	vtpm_drv_state_set(VTPM_DRV_STATE_FAILURE,
			   VTPM_DRV_ERROR_WAIT_TIMEOUT);

	dprintf("Received NO response to TPM command");

	return false;
}

static bool spapr_vtpm_readresponse(uint8_t *buffer, uint32_t *len)
{
	if (vtpm_drv_error_get() != VTPM_DRV_ERROR_NO_FAILURE) {
		printf("VTPM CRQ: In failure mode\n");
		return false;
	}

	/* response CRQ has been set */
	*len = MIN(*len, be32_to_cpu(spapr_vtpm.response->len));

	memcpy(buffer, (void *)(uint64_t)spapr_vtpm.response->data, *len);

	dprintf("Length of copied response: %d\n", *len);

	spapr_vtpm.response = NULL;

	return true;
}

uint32_t spapr_vtpm_get_buffersize(void)
{
	return spapr_vtpm.buffer_size;
}

vtpm_drv_state spapr_vtpm_get_state(void)
{
	return vtpm_drv_state_get();
}

vtpm_drv_error spapr_vtpm_get_error(void)
{
	return vtpm_drv_error_get();
}

/**** higher layer interface ****/

bool spapr_is_vtpm_present(void)
{
	bool rc = false;

	if (spapr_vtpm_probe()) {
		spapr_vtpm_init();
		rc = true;
	}

	return rc;
}
