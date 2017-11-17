
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

#define TPM_version spapr_get_tpm_version()

/*
 * TPM 1.2 logs are written in big endian format and TPM 2 logs
 * are written in little endian format.
 */
static inline uint32_t log32_to_cpu(uint32_t val)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return be32_to_cpu(val);
	case TPM_VERSION_2:
		return le32_to_cpu(val);
	}
	return 0;
}

static inline uint32_t cpu_to_log32(uint32_t val)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return cpu_to_be32(val);
	case TPM_VERSION_2:
		return cpu_to_le32(val);
	}
	return 0;
}

static inline uint16_t cpu_to_log16(uint16_t val)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return cpu_to_be16(val);
	case TPM_VERSION_2:
		return cpu_to_le16(val);
	}
	return 0;
}

static inline bool tpm_log_is_be(void)
{
	return TPM_version == TPM_VERSION_1_2;
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
		.hashalg_flag = TPM2_ALG_SHA1_FLAG,
		.hash_buffersize = SHA1_BUFSIZE,
		.name = "SHA1",
	}, {
		.hashalg = TPM2_ALG_SHA256,
		.hashalg_flag = TPM2_ALG_SHA256_FLAG,
		.hash_buffersize = SHA256_BUFSIZE,
		.name = "SHA256",
	}, {
		.hashalg = TPM2_ALG_SHA384,
		.hashalg_flag = TPM2_ALG_SHA384_FLAG,
		.hash_buffersize = SHA384_BUFSIZE,
		.name = "SHA384",

	}, {
		.hashalg = TPM2_ALG_SHA512,
		.hashalg_flag = TPM2_ALG_SHA512_FLAG,
		.hash_buffersize = SHA512_BUFSIZE,
		.name = "SHA512",
	}, {
		.hashalg = TPM2_ALG_SM3_256,
		.hashalg_flag = TPM2_ALG_SM3_256_FLAG,
		.hash_buffersize = SM3_256_BUFSIZE,
		.name = "SM3-256",
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

static uint8_t
tpm20_hashalg_to_flag(uint16_t hashAlg)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(hash_parameters); i++) {
		if (hash_parameters[i].hashalg == hashAlg)
			return hash_parameters[i].hashalg_flag;
	}
	return 0;
}

static uint16_t
tpm20_hashalg_flag_to_hashalg(uint8_t hashalg_flag)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(hash_parameters); i++) {
		if (hash_parameters[i].hashalg_flag == hashalg_flag)
			return hash_parameters[i].hashalg;
	}
	return 0;
}

static const char *
tpm20_hashalg_flag_to_name(uint8_t hashalg_flag)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(hash_parameters); i++) {
		if (hash_parameters[i].hashalg_flag == hashalg_flag)
			return hash_parameters[i].name;
	}
	return NULL;
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

static int tpm12_build_digest(struct tpm_log_entry *le, const uint8_t *sha1)
{
	// On TPM 1.2 the digest contains just the SHA1 hash
	memcpy(le->hdr.digest, sha1, SHA1_BUFSIZE);
	return SHA1_BUFSIZE;
}

static int
tpm_build_digest(struct tpm_log_entry *le, const uint8_t *sha1, bool bigEndian)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return tpm12_build_digest(le, sha1);
	case TPM_VERSION_2:
		return tpm20_build_digest(le, sha1, bigEndian);
	}
	return -1;
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
		.trqh.ordinal = cpu_to_be32(ordinal),
	};
	uint8_t obuffer[64];
	struct tpm_rsp_header *trsh = (void *)obuffer;
	uint32_t obuffer_len = sizeof(obuffer);
	int ret;

	switch (TPM_version) {
	case TPM_VERSION_1_2:
		req.trqh.tag = cpu_to_be16(TPM_TAG_RQU_CMD);
		break;
	case TPM_VERSION_2:
		req.trqh.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS);
		break;
	}

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

static int
tpm20_get_suppt_pcrbanks(uint8_t *suppt_pcrbanks, uint8_t *active_pcrbanks)
{
	*suppt_pcrbanks = 0;
	*active_pcrbanks = 0;

	if (!tpm20_pcr_selection)
		return -1;

	struct tpms_pcr_selection *sel = tpm20_pcr_selection->selections;
	void *end = (void*)tpm20_pcr_selection + tpm20_pcr_selection_size;

	while (1) {
		uint8_t sizeOfSelect = sel->sizeOfSelect;
		void *nsel = (void*)sel + sizeof(*sel) + sizeOfSelect;
		if (nsel > end)
			return 0;

		uint16_t hashalg = be16_to_cpu(sel->hashAlg);
		uint8_t hashalg_flag = tpm20_hashalg_to_flag(hashalg);

		*suppt_pcrbanks |= hashalg_flag;

		unsigned i;
		for (i = 0; i < sizeOfSelect; i++) {
			if (sel->pcrSelect[i]) {
				*active_pcrbanks |= hashalg_flag;
				break;
			}
		}

		sel = nsel;
	}
}

static int
tpm20_set_pcrbanks(uint32_t active_banks)
{
	struct tpm2_req_pcr_allocate trpa = {
		.hdr.tag = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_PCR_Allocate),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trpa.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
	};
	struct tpms_pcr_selection3 {
		uint16_t hashAlg;
		uint8_t sizeOfSelect;
		uint8_t pcrSelect[3];
	} tps[ARRAY_SIZE(trpa.tpms_pcr_selections)];
	int i = 0;
	uint8_t hashalg_flag = TPM2_ALG_SHA1_FLAG;
	uint8_t dontcare, suppt_banks;

	tpm20_get_suppt_pcrbanks(&suppt_banks, &dontcare);

	while (hashalg_flag) {
		if ((hashalg_flag & suppt_banks)) {
			uint16_t hashalg = tpm20_hashalg_flag_to_hashalg(hashalg_flag);

			if (hashalg) {
				uint8_t mask = 0;

				tps[i].hashAlg = cpu_to_be16(hashalg);
				tps[i].sizeOfSelect = 3;

				if (active_banks & hashalg_flag)
					mask = 0xff;

				tps[i].pcrSelect[0] = mask;
				tps[i].pcrSelect[1] = mask;
				tps[i].pcrSelect[2] = mask;
				i++;
			}
		}
		hashalg_flag <<= 1;
	}

	trpa.count = cpu_to_be32(i);
	memcpy(trpa.tpms_pcr_selections, tps, i * sizeof(tps[0]));
	trpa.hdr.totlen = cpu_to_be32(offset_of(struct tpm2_req_pcr_allocate,
						tpms_pcr_selections) +
				      i * sizeof(tps[0]));

	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);

	int ret = tpmhw_transmit(0, &trpa.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_SHORT);
	ret = ret ? -1 : be32_to_cpu(rsp.errcode);

	return ret;
}

static int tpm20_activate_pcrbanks(uint32_t active_banks)
{
	int ret = tpm20_set_pcrbanks(active_banks);
	if (!ret)
		ret = tpm_simple_cmd(0, TPM2_CC_Shutdown,
				     2, TPM2_SU_CLEAR, TPM_DURATION_TYPE_SHORT);
	if (!ret)
		SLOF_reset();
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

static void tpm20_set_timeouts(void)
{
	uint32_t durations[3] = {
		TPM2_DEFAULT_DURATION_SHORT,
		TPM2_DEFAULT_DURATION_MEDIUM,
		TPM2_DEFAULT_DURATION_LONG,
	};

	spapr_vtpm_set_durations(durations);
}

/*
 * Extend a PCR of the TPM with the given hash
 *
 * @hash: sha1 hash (20 bytes) to extend PCR with
 * @pcrindex: the PCR to extend [ 0..23 ]
 */
static int tpm12_extend(struct tpm_log_entry *le, int digest_len)
{
	struct tpm_req_extend tre = {
		.hdr.tag = cpu_to_be16(TPM_TAG_RQU_CMD),
		.hdr.totlen = cpu_to_be32(sizeof(tre)),
		.hdr.ordinal = cpu_to_be32(TPM_ORD_EXTEND),
		.pcrindex = cpu_to_be32(log32_to_cpu(le->hdr.pcrindex)),
	};
	struct tpm_rsp_extend rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret;

	memcpy(tre.digest, le->hdr.digest, sizeof(tre.digest));

	ret = tpmhw_transmit(0, &tre.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_SHORT);

	if (ret || resp_length != sizeof(rsp) || rsp.hdr.errcode) {
		dprintf("TPM_Extend response has unexpected size: %u\n",
			resp_length);
		return -1;
	}

	return 0;
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

static int tpm_extend(struct tpm_log_entry *le, int digest_len)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return tpm12_extend(le, digest_len);
	case TPM_VERSION_2:
		return tpm20_extend(le, digest_len);
	}
	return -1;
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
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		/* we will try to deactivate the TPM now - ignoring all errors */
		tpm_simple_cmd(0, TPM_ORD_SET_TEMP_DEACTIVATED,
			       0, 0, TPM_DURATION_TYPE_SHORT);
		break;
	case TPM_VERSION_2:
		tpm20_hierarchycontrol(TPM2_RH_ENDORSEMENT, TPM2_NO);
		tpm20_hierarchycontrol(TPM2_RH_OWNER, TPM2_NO);
		break;
	}

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
	uint32_t size, logsize;
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
		dprintf("TCGBIOS: LOG OVERFLOW: size = %u\n", size);
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

bool tpm_log_event(struct pcpes *pcpes)
{
	const char *event = NULL;
	uint32_t event_length = log32_to_cpu(pcpes->eventdatasize);
	struct tpm_log_entry le = {
		.hdr.pcrindex = pcpes->pcrindex,
		.hdr.eventtype = pcpes->eventtype,
	};
	int digest_len, ret;

	if (event_length)
		event = (void *)pcpes + offset_of(struct pcpes, event);

	digest_len = tpm_build_digest(&le, pcpes->digest, tpm_log_is_be());
	if (digest_len < 0)
		return false;

	ret = tpm_log_event_long(&le.hdr, digest_len, event, event_length);
	if (ret)
		return false;
	return true;
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

static int tpm20_startup(void)
{
	int ret;

	tpm20_set_timeouts();

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

static int tpm_startup(void)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return tpm12_startup();
	case TPM_VERSION_2:
		return tpm20_startup();
	}
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
 * Give up physical presence; this function has to be called before
 * the firmware transitions to the boot loader.
 */
uint32_t tpm_unassert_physical_presence(void)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		if (tpm_state.has_physical_presence)
			tpm_simple_cmd(0, TPM_ORD_PHYSICAL_PRESENCE,
				       2, TPM_PP_NOT_PRESENT_LOCK,
				       TPM_DURATION_TYPE_SHORT);
	break;
	case TPM_VERSION_2:
		tpm20_prepboot();
	}

	return 0;
}

/****************************************************************
 * Forth interface
 ****************************************************************/

void tpm_set_log_parameters(void *addr, unsigned int size)
{
	int ret;

	dprintf("Log is at 0x%llx; size is %u bytes\n",
		(uint64_t)addr, size);
	tpm_state.log_base = addr;
	tpm_state.log_area_next_entry = addr;
	tpm_state.log_area_size = size;

	switch (TPM_version) {
	case TPM_VERSION_2:
		ret = tpm20_write_EfiSpecIdEventStruct();
		if (ret)
			tpm_set_failure();
	}
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
	struct tpm_log_entry le;
	int digest_len;

	if (log32_to_cpu(pcpes->pcrindex) >= 24)
		return TCGBIOS_INVALID_INPUT_PARA;
	if (hashdata)
		tpm_hash_all(hashdata, hashdata_length, pcpes->digest);

	le = (struct tpm_log_entry) {
		.hdr.pcrindex = pcpes->pcrindex,
		.hdr.eventtype = pcpes->eventtype,
	};
	digest_len = tpm_build_digest(&le, pcpes->digest, true);
	if (digest_len < 0)
		return TCGBIOS_GENERAL_ERROR;

	if (extend) {
		ret = tpm_extend(&le, digest_len);
		if (ret)
			return TCGBIOS_COMMAND_ERROR;
	}
	tpm_build_digest(&le, pcpes->digest, tpm_log_is_be());
	ret = tpm_log_event_long(&le.hdr, digest_len, event, event_length);
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
	uint8_t hash[SHA1_BUFSIZE];
	struct tpm_log_entry le = {
		.hdr.pcrindex = cpu_to_log32(pcrindex),
		.hdr.eventtype = cpu_to_log32(eventtype),
	};
	int digest_len;

	sha1(hashdata, hashdatalen, hash);
	digest_len = tpm_build_digest(&le, hash, true);
	if (digest_len < 0)
		return TCGBIOS_GENERAL_ERROR;
	int ret = tpm_extend(&le, digest_len);
	if (ret) {
		tpm_set_failure();
		return TCGBIOS_COMMAND_ERROR;
	}
	tpm_build_digest(&le, hash, tpm_log_is_be());
	return tpm_log_event_long(&le.hdr, digest_len, info, infolen);
}

/*
 * tpm_hash_log_extend_event: Function for interfacing with the firmware API
 */
uint32_t tpm_hash_log_extend_event(struct pcpes *pcpes)
{
	const char *event = NULL;
	uint32_t event_length = log32_to_cpu(pcpes->eventdatasize);

	if (!tpm_is_working())
		return TCGBIOS_GENERAL_ERROR;

	if (event_length)
		event = (void *)pcpes + offset_of(struct pcpes, event);

	return hash_log_extend(pcpes,
			       &pcpes->event,
			       log32_to_cpu(pcpes->eventdatasize),
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

static int
tpm20_clearcontrol(uint8_t disable, bool verbose)
{
	struct tpm2_req_clearcontrol trc = {
		.hdr.tag     = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen  = cpu_to_be32(sizeof(trc)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_ClearControl),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trc.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
		.disable = disable,
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret = tpmhw_transmit(0, &trc.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_SHORT);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_ClearControl = 0x%08x\n",
		ret);

	return ret;
}

static int
tpm20_clear(void)
{
	struct tpm2_req_clear trq = {
		.hdr.tag	 = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen  = cpu_to_be32(sizeof(trq)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_Clear),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trq.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret = tpmhw_transmit(0, &trq.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_Clear = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_process_cfg(tpm_ppi_op msgCode, bool verbose)
{
	int ret = 0;

	switch (msgCode) {
	case TPM_PPI_OP_NOOP: /* no-op */
		break;

	case TPM_PPI_OP_CLEAR:
		ret = tpm20_clearcontrol(false, verbose);
		if (!ret)
			ret = tpm20_clear();
		break;
	}

	if (ret)
		dprintf("Op %d: An error occurred: 0x%x\n", msgCode, ret);

	return ret;
}

uint32_t tpm_process_opcode(uint8_t op, bool verbose)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return tpm12_process_cfg(op, verbose);
	case TPM_VERSION_2:
		return tpm20_process_cfg(op, verbose);
	}
	return TCGBIOS_GENERAL_ERROR;
}

static int tpm12_get_state(void)
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

int tpm_get_state(void)
{
	switch (TPM_version) {
	case TPM_VERSION_1_2:
		return tpm12_get_state();
	case TPM_VERSION_2:
		break;
	}
	return ~0;
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

static bool pass_through_to_tpm(unsigned char *req,
				uint32_t reqlen,
				enum tpm_duration_type to_t,
				unsigned char *rsp,
				uint32_t *rsplen)
{
	struct tpm_req_header *trqh;
	int ret;

	if (!tpm_is_working())
	       return TCGBIOS_FATAL_COM_ERROR;

	trqh = (struct tpm_req_header *)req;
	if (reqlen < sizeof(*trqh))
		return TCGBIOS_INVALID_INPUT_PARA;

	ret = tpmhw_transmit(0, trqh, rsp, rsplen, to_t);
	if (ret)
		return TCGBIOS_FATAL_COM_ERROR;

	return 0;
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

uint32_t tpm_get_tpm_version(void)
{
	return TPM_version;
}

static int tpm20_menu_change_active_pcrbanks(void)
{
	uint8_t active_banks, suppt_banks;

	tpm20_get_suppt_pcrbanks(&suppt_banks, &active_banks);

	uint8_t activate_banks = active_banks;

	while (1) {
		uint8_t hashalg_flag = TPM2_ALG_SHA1_FLAG;
		uint8_t i = 0;

		printf("\nToggle active PCR banks by pressing number key\n\n");

		while (hashalg_flag) {
			uint8_t flag = hashalg_flag & suppt_banks;
			const char *hashname = tpm20_hashalg_flag_to_name(flag);

			i++;
			if (hashname) {
				printf("  %d: %s", i, hashname);
				if (activate_banks & hashalg_flag)
					printf(" (enabled)");
				printf("\n");
			}

			hashalg_flag <<= 1;
		}
		printf("\n"
		       "ESC: return to previous menu without changes\n");
		if (activate_banks)
			printf("a  : activate selection\n");

		uint8_t flagnum;
		int show = 0;
		while (!show) {
			int key_code = SLOF_get_keystroke();

			switch (key_code) {
			case ~0:
				continue;
			case 27: /* ESC */
				printf("\n");
				return -1;
			case '1' ... '5': /* keys 1 .. 5 */
				flagnum = key_code - '0';
				if (flagnum > i)
					continue;
				if (suppt_banks & (1 << (flagnum - 1))) {
					activate_banks ^= 1 << (flagnum - 1);
					show = 1;
				}
				break;
			case 'a': /* a */
				if (activate_banks)
					tpm20_activate_pcrbanks(activate_banks);
			}
		}
	}
}

void tpm20_menu(void)
{
	int key_code;
	int waitkey;
	tpm_ppi_op msgCode;

	for (;;) {
		printf("1. Clear TPM\n");
		printf("2. Change active PCR banks\n");

		printf("\nIf not change is desired or if this menu was reached by "
		       "mistake, press ESC to\ncontinue the boot.\n");

		msgCode = TPM_PPI_OP_NOOP;

		waitkey = 1;

		while (waitkey) {
			key_code = SLOF_get_keystroke();
			switch (key_code) {
			case 27:
				// ESC
				return;
			case '1':
				msgCode = TPM_PPI_OP_CLEAR;
				break;
			case '2':
				tpm20_menu_change_active_pcrbanks();
				waitkey = 0;
				continue;
			default:
				continue;
			}

			tpm20_process_cfg(msgCode, 0);
			waitkey = 0;
		}
	}
}
