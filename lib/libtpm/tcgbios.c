/*****************************************************************************
 * Copyright (c) 2015-2020 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *     Kevin O'Connor (SeaBIOS)
 *****************************************************************************/

/*
 *  Implementation of the TPM BIOS extension according to the specification
 *  described in the IBM VTPM Firmware document and the TCG Specification
 *  that can be found here under the following link:
 *  http://www.trustedcomputinggroup.org/resources/pc_client_work_group_specific_implementation_specification_for_conventional_bios
 */

#include <stddef.h>
#include <stdlib.h>

#include "types.h"
#include "byteorder.h"
#include "tpm_drivers.h"
#include "string.h"
#include "tcgbios.h"
#include "tcgbios_int.h"
#include "stdio.h"
#include "sha1.h"
#include "helpers.h"
#include "version.h"
#include "OF.h"

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

	/* base address of the log area */
	uint8_t *log_base;

	/* size of the logging area */
	size_t log_area_size;

	/* where to write the next log entry to */
	uint8_t *log_area_next_entry;
};

static struct tpm_state tpm_state;

/*
 * TPM 2 logs are written in little endian format.
 */
static inline uint32_t log32_to_cpu(uint32_t val)
{
	return le32_to_cpu(val);
}

static inline uint32_t cpu_to_log32(uint32_t val)
{
	return cpu_to_le32(val);
}

static inline uint16_t cpu_to_log16(uint16_t val)
{
	return cpu_to_le16(val);
}

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
 * Digest formatting
 ****************************************************************/

static uint32_t tpm20_pcr_selection_size;
static struct tpml_pcr_selection *tpm20_pcr_selection;

/* A 'struct tpm_log_entry' is a local data structure containing a
 * 'tpm_log_header' followed by space for the maximum supported
 * digest.  (The digest is a sha1 hash on tpm1.2 or a series of
 * tpm2_digest_value structs on tpm2.0)
 */
struct tpm_log_entry {
	struct tpm_log_header hdr;
	uint8_t pad[sizeof(struct tpm2_digest_values)
	   + 5 * sizeof(struct tpm2_digest_value)
	   + SHA1_BUFSIZE + SHA256_BUFSIZE + SHA384_BUFSIZE
	   + SHA512_BUFSIZE + SM3_256_BUFSIZE];
} __attribute__((packed));

static const struct hash_parameters {
	uint16_t hashalg;
	uint8_t  hashalg_flag;
	uint8_t  hash_buffersize;
	const char *name;
} hash_parameters[] = {
	{
		.hashalg = TPM2_ALG_SHA1,
		.hash_buffersize = SHA1_BUFSIZE,
	}, {
		.hashalg = TPM2_ALG_SHA256,
		.hash_buffersize = SHA256_BUFSIZE,
	}, {
		.hashalg = TPM2_ALG_SHA384,
		.hash_buffersize = SHA384_BUFSIZE,
	}, {
		.hashalg = TPM2_ALG_SHA512,
		.hash_buffersize = SHA512_BUFSIZE,
	}, {
		.hashalg = TPM2_ALG_SM3_256,
		.hash_buffersize = SM3_256_BUFSIZE,
	}
};

static int
tpm20_get_hash_buffersize(uint16_t hashAlg)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(hash_parameters); i++) {
		if (hash_parameters[i].hashalg == hashAlg)
			return hash_parameters[i].hash_buffersize;
	}
	return -1;
}

/*
 * Build the TPM2 tpm2_digest_values data structure from the given hash.
 * Follow the PCR bank configuration of the TPM and write the same hash
 * in either truncated or zero-padded form in the areas of all the other
 * hashes. For example, write the sha1 hash in the area of the sha256
 * hash and fill the remaining bytes with zeros. Or truncate the sha256
 * hash when writing it in the area of the sha1 hash.
 *
 * le: the log entry to build the digest in
 * sha1: the sha1 hash value to use
 * bigEndian: whether to build in big endian format for the TPM or log
 *            little endian for the log (TPM 2.0)
 *
 * Returns the digest size; -1 on fatal error
 */
static int tpm20_build_digest(struct tpm_log_entry *le, const uint8_t *sha1,
			      bool bigEndian)
{
	struct tpms_pcr_selection *sel;
	void *nsel, *end;
	void *dest = le->hdr.digest + sizeof(struct tpm2_digest_values);
	uint32_t count;
	struct tpm2_digest_value *v;
	struct tpm2_digest_values *vs;

	if (!tpm20_pcr_selection)
		return -1;

	sel = tpm20_pcr_selection->selections;
	end = (void *)tpm20_pcr_selection + tpm20_pcr_selection_size;

	for (count = 0; count < be32_to_cpu(tpm20_pcr_selection->count); count++) {
		int hsize;
		uint8_t sizeOfSelect = sel->sizeOfSelect;

		nsel = (void*)sel + sizeof(*sel) + sizeOfSelect;
		if (nsel > end)
			break;

		hsize = tpm20_get_hash_buffersize(be16_to_cpu(sel->hashAlg));
		if (hsize < 0) {
			dprintf("TPM is using an unsupported hash: %d\n",
				be16_to_cpu(sel->hashAlg));
			return -1;
		}

		/* buffer size sanity check before writing */
		v = dest;
		if (dest + sizeof(*v) + hsize > (void*)le + sizeof(*le)) {
			dprintf("tpm_log_entry is too small\n");
			return -1;
		}

		if (bigEndian)
			v->hashAlg = sel->hashAlg;
		else
			v->hashAlg = cpu_to_le16(be16_to_cpu(sel->hashAlg));

		memset(v->hash, 0, hsize);
		memcpy(v->hash, sha1, hsize > SHA1_BUFSIZE ? SHA1_BUFSIZE : hsize);

		dest += sizeof(*v) + hsize;
		sel = nsel;
	}

	if (sel != end) {
		dprintf("Malformed pcr selection structure fron TPM\n");
		return -1;
	}

	vs = (void*)le->hdr.digest;
	if (bigEndian)
		vs->count = cpu_to_be32(count);
	else
		vs->count = cpu_to_le32(count);

	return dest - (void*)le->hdr.digest;
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
		.trqh.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
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

static int
tpm20_getcapability(uint32_t capability, uint32_t property, uint32_t count,
	            struct tpm_rsp_header *rsp, uint32_t rsize)
{
	struct tpm2_req_getcapability trg = {
		.hdr.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trg)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_GetCapability),
		.capability = cpu_to_be32(capability),
		.property = cpu_to_be32(property),
		.propertycount = cpu_to_be32(count),
	};

	uint32_t resp_size = rsize;
	int ret = tpmhw_transmit(0, &trg.hdr, rsp, &resp_size,
				 TPM_DURATION_TYPE_SHORT);
	ret = (ret ||
	       rsize < be32_to_cpu(rsp->totlen)) ? -1
						 : be32_to_cpu(rsp->errcode);

	dprintf("TCGBIOS: Return value from sending TPM2_CC_GetCapability = 0x%08x\n",
		ret);

	return ret;
}

static int
tpm20_get_pcrbanks(void)
{
	uint8_t buffer[128];
	uint32_t size;
	struct tpm2_res_getcapability *trg =
		(struct tpm2_res_getcapability *)&buffer;

	int ret = tpm20_getcapability(TPM2_CAP_PCRS, 0, 8, &trg->hdr,
				      sizeof(buffer));
	if (ret)
		return ret;

	/* defend against (broken) TPM sending packets that are too short */
	uint32_t resplen = be32_to_cpu(trg->hdr.totlen);
	if (resplen <= offset_of(struct tpm2_res_getcapability, data))
		return -1;

	size = resplen - offset_of(struct tpm2_res_getcapability, data);
	/* we need a valid tpml_pcr_selection up to and including sizeOfSelect*/
	if (size < offset_of(struct tpml_pcr_selection, selections) +
		   offset_of(struct tpms_pcr_selection, pcrSelect))
		return -1;

	tpm20_pcr_selection = SLOF_alloc_mem(size);
	if (tpm20_pcr_selection) {
		memcpy(tpm20_pcr_selection, &trg->data, size);
		tpm20_pcr_selection_size = size;
	} else {
		printf("TCGBIOS: Failed to allocated %u bytes.\n", size);
		ret = -1;
	}

	return ret;
}

static int tpm20_extend(struct tpm_log_entry *le, int digest_len)
{
	struct tpm2_req_extend tmp_tre = {
		.hdr.tag     = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen  = cpu_to_be32(0),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_PCR_Extend),
		.pcrindex    = cpu_to_be32(log32_to_cpu(le->hdr.pcrindex)),
		.authblocksize = cpu_to_be32(sizeof(tmp_tre.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
	};
	uint8_t buffer[sizeof(tmp_tre) + sizeof(le->pad)];
	struct tpm2_req_extend *tre = (struct tpm2_req_extend *)buffer;

	memcpy(tre, &tmp_tre, sizeof(tmp_tre));
	memcpy(&tre->digest[0], le->hdr.digest, digest_len);

	tre->hdr.totlen = cpu_to_be32(sizeof(tmp_tre) + digest_len);

	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret = tpmhw_transmit(0, &tre->hdr, &rsp, &resp_length,
	                         TPM_DURATION_TYPE_SHORT);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		return -1;

	return 0;
}

static int tpm20_stirrandom(void)
{
	struct tpm2_req_stirrandom stir = {
		.hdr.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(stir)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_StirRandom),
		.size = cpu_to_be16(sizeof(stir.stir)),
		.stir = rand(),
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret = tpmhw_transmit(0, &stir.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_SHORT);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_StirRandom = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_getrandom(uint8_t *buf, uint16_t buf_len)
{
	struct tpm2_res_getrandom rsp;
	struct tpm2_req_getrandom trgr = {
		.hdr.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trgr)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_GetRandom),
		.bytesRequested = cpu_to_be16(buf_len),
	};
	uint32_t resp_length = sizeof(rsp);

	if (buf_len > sizeof(rsp.rnd.buffer))
		return -1;

	int ret = tpmhw_transmit(0, &trgr.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.hdr.errcode)
		ret = -1;
	else
		memcpy(buf, rsp.rnd.buffer, buf_len);

	dprintf("TCGBIOS: Return value from sending TPM2_CC_GetRandom = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_hierarchychangeauth(uint8_t auth[20])
{
	struct tpm2_req_hierarchychangeauth trhca = {
		.hdr.tag = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trhca)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_HierarchyChangeAuth),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trhca.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
		.newAuth = {
			.size = cpu_to_be16(sizeof(trhca.newAuth.buffer)),
		},
	};
	memcpy(trhca.newAuth.buffer, auth, sizeof(trhca.newAuth.buffer));

	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret = tpmhw_transmit(0, &trhca.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_HierarchyChangeAuth = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_hierarchycontrol(uint32_t hierarchy, uint8_t state)
{
	/* we will try to deactivate the TPM now - ignoring all errors */
	struct tpm2_req_hierarchycontrol trh = {
		.hdr.tag = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trh)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_HierarchyControl),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trh.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
		.enable = cpu_to_be32(hierarchy),
		.state = state,
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret = tpmhw_transmit(0, &trh.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_HierarchyControl = 0x%08x\n",
		ret);

	return ret;
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
	tpm20_hierarchycontrol(TPM2_RH_ENDORSEMENT, TPM2_NO);
	tpm20_hierarchycontrol(TPM2_RH_OWNER, TPM2_NO);

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
static uint32_t tpm_log_event_long(struct tpm_log_header *entry,
				   int digest_len,
				   const void *event, uint32_t event_length)
{
	size_t size, logsize;
	void *dest;

	dprintf("log base address = %p, next entry = %p\n",
		tpm_state.log_base, tpm_state.log_area_next_entry);

	if (tpm_state.log_area_next_entry == NULL)
		return TCGBIOS_LOGOVERFLOW;

	size = sizeof(*entry) + digest_len +
	       sizeof(struct tpm_log_trailer) + event_length;
	logsize = (tpm_state.log_area_next_entry + size -
	           tpm_state.log_base);
	if (logsize > tpm_state.log_area_size) {
		dprintf("TCGBIOS: LOG OVERFLOW: size = %zu\n", size);
		return TCGBIOS_LOGOVERFLOW;
	}

	dest = tpm_state.log_area_next_entry;
	memcpy(dest, entry, sizeof(*entry) + digest_len);
	struct tpm_log_trailer *t = dest + sizeof(*entry) + digest_len;
	t->eventdatasize = cpu_to_log32(event_length);
	if (event_length)
		memcpy(t->event, event, event_length);

	tpm_state.log_area_next_entry += size;

	return 0;
}

/* Add an entry at the start of the log describing digest formats
 */
static int tpm20_write_EfiSpecIdEventStruct(void)
{
	if (!tpm20_pcr_selection)
		return -1;

	struct {
		struct TCG_EfiSpecIdEventStruct hdr;
		uint32_t pad[256];
	} event = {
		.hdr.signature = "Spec ID Event03",
		.hdr.platformClass = TPM_TCPA_ACPI_CLASS_CLIENT,
		.hdr.specVersionMinor = 0,
		.hdr.specVersionMajor = 2,
		.hdr.specErrata = 0,
		.hdr.uintnSize = 2,
	};

	struct tpms_pcr_selection *sel = tpm20_pcr_selection->selections;
	void *nsel, *end = (void*)tpm20_pcr_selection + tpm20_pcr_selection_size;
	int event_size;
	uint32_t *vendorInfoSize;
	struct tpm_log_entry le = {
		.hdr.eventtype = cpu_to_log32(EV_NO_ACTION),
	};
	uint32_t count;

	for (count = 0;
	     count < be32_to_cpu(tpm20_pcr_selection->count);
	     count++) {
		int hsize;
		uint8_t sizeOfSelect = sel->sizeOfSelect;

		nsel = (void*)sel + sizeof(*sel) + sizeOfSelect;
		if (nsel > end)
			break;

		hsize = tpm20_get_hash_buffersize(be16_to_cpu(sel->hashAlg));
		if (hsize < 0) {
			dprintf("TPM is using an unsupported hash: %d\n",
				be16_to_cpu(sel->hashAlg));
			return -1;
		}

		event_size = offset_of(struct TCG_EfiSpecIdEventStruct,
				       digestSizes[count+1]);
		if (event_size > sizeof(event) - sizeof(uint32_t)) {
			dprintf("EfiSpecIdEventStruct pad too small\n");
			return -1;
		}

		event.hdr.digestSizes[count].algorithmId =
			cpu_to_log16(be16_to_cpu(sel->hashAlg));
		event.hdr.digestSizes[count].digestSize = cpu_to_log16(hsize);

		sel = nsel;
	}

	if (sel != end) {
		dprintf("Malformed pcr selection structure fron TPM\n");
		return -1;
	}

	event.hdr.numberOfAlgorithms = cpu_to_log32(count);
	event_size = offset_of(struct TCG_EfiSpecIdEventStruct,
			       digestSizes[count]);
	vendorInfoSize = (void*)&event + event_size;
	*vendorInfoSize = 0;
	event_size += sizeof(*vendorInfoSize);

	return tpm_log_event_long(&le.hdr, SHA1_BUFSIZE, &event, event_size);
}

static int tpm20_startup(void)
{
	int ret;

	ret = tpm_simple_cmd(0, TPM2_CC_Startup,
			     2, TPM2_SU_CLEAR, TPM_DURATION_TYPE_SHORT);
	dprintf("TCGBIOS: Return value from sending TPM2_CC_Startup(SU_CLEAR) = 0x%08x\n",
		ret);

	if (ret)
		goto err_exit;

	ret = tpm_simple_cmd(0, TPM2_CC_SelfTest,
			     1, TPM2_YES, TPM_DURATION_TYPE_LONG);

	dprintf("TCGBIOS: Return value from sending TPM2_CC_SELF_TEST = 0x%08x\n",
		ret);

	if (ret)
		goto err_exit;

	ret = tpm20_get_pcrbanks();
	if (ret)
		goto err_exit;

	/* the log parameters will be passed from Forth layer */

	return 0;

err_exit:
	dprintf("TCGBIOS: TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	return -1;
}

uint32_t tpm_start(void)
{
	probe_tpm();

	if (!tpm_is_working()) {
		dprintf("%s: Machine does not have a working TPM\n",
			__func__);
		return TCGBIOS_FATAL_COM_ERROR;
	}

	return tpm20_startup();
}

void tpm_finalize(void)
{
	spapr_vtpm_finalize();
}

static void tpm20_prepboot(void)
{
	uint8_t auth[20];
	int ret = tpm20_stirrandom();
	if (ret)
		 goto err_exit;

	ret = tpm20_getrandom(&auth[0], sizeof(auth));
	if (ret)
		goto err_exit;

	ret = tpm20_hierarchychangeauth(auth);
	if (ret)
		goto err_exit;

	return;

err_exit:
	dprintf("TCGBIOS: TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
}

/*
 * Prepare TPM for boot; this function has to be called before
 * the firmware transitions to the boot loader.
 */
uint32_t tpm_leave_firmware(void)
{
	tpm20_prepboot();

	return 0;
}

/****************************************************************
 * Forth interface
 ****************************************************************/

void tpm_set_log_parameters(void *addr, size_t size)
{
	int ret;

	dprintf("Log is at 0x%llx; size is %zu bytes\n",
		(uint64_t)addr, size);
	tpm_state.log_base = addr;
	tpm_state.log_area_next_entry = addr;
	tpm_state.log_area_size = size;

	ret = tpm20_write_EfiSpecIdEventStruct();
	if (ret)
		tpm_set_failure();
}

uint32_t tpm_get_logsize(void)
{
	uint32_t logsize = tpm_state.log_area_next_entry - tpm_state.log_base;

	dprintf("log size: %u\n", logsize);

	return logsize;
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
	uint8_t hash[SHA1_BUFSIZE];
	struct tpm_log_entry le = {
		.hdr.pcrindex = cpu_to_log32(pcrindex),
		.hdr.eventtype = cpu_to_log32(eventtype),
	};
	int digest_len;

	sha1(hashdata, hashdatalen, hash);
	digest_len = tpm20_build_digest(&le, hash, true);
	if (digest_len < 0)
		return TCGBIOS_GENERAL_ERROR;
	int ret = tpm20_extend(&le, digest_len);
	if (ret) {
		tpm_set_failure();
		return TCGBIOS_COMMAND_ERROR;
	}
	tpm20_build_digest(&le, hash, false);
	return tpm_log_event_long(&le.hdr, digest_len, info, infolen);
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

uint32_t tpm_measure_scrtm(void)
{
	uint32_t rc;
	char *version_start = strstr((char *)&print_version, "FW Version");
	char *version_end;
	uint32_t version_length;
	char *slof_data_start = (char *)&_slof_data;
	char *slof_text_start = (char *)&_slof_text;
	uint32_t slof_data_length = (long)&_slof_data_end - (long)&_slof_data;
	uint32_t slof_text_length = (long)&_slof_text_end - (long)&_slof_text;
	const char *scrtm = "S-CRTM Contents";

	version_end = strchr(version_start, '\r');
	version_length = version_end - version_start;

	dprintf("Measure S-CRTM Version: addr = %p, length = %d\n",
		version_start, version_length);

	rc = tpm_add_measurement_to_log(0, EV_S_CRTM_VERSION,
					version_start, version_length,
					(uint8_t *)version_start,
					version_length);

	if (rc)
		return rc;

	dprintf("Measure S-CRTM Content (data): start = %p, length = %d\n",
		slof_data_start, slof_data_length);

	rc = tpm_add_measurement_to_log(0, EV_S_CRTM_CONTENTS,
					scrtm, strlen(scrtm),
					(uint8_t *)slof_data_start,
					slof_data_length);

	dprintf("Measure S-CRTM Content (text): start = %p, length = %d\n",
		slof_text_start, slof_text_length);

	rc = tpm_add_measurement_to_log(0, EV_S_CRTM_CONTENTS,
					scrtm, strlen(scrtm),
					(uint8_t *)slof_text_start,
					slof_text_length);

	return rc;
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

/*
 * tpm_driver_set_failure_reason: Function for interfacing with the firmware
 *                                API
 */
void tpm_driver_set_failure_reason(uint32_t errcode)
{
	if (!tpm_state.tpm_found)
		return;

	spapr_vtpm_set_error(errcode);
}
