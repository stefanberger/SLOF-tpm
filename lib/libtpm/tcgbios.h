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

#ifndef TCGBIOS_H
#define TCGBIOS_H

#include <stdint.h>
#include <stdbool.h>

#define BCV_DEVICE_FLOPPY  0x0
#define BCV_DEVICE_HDD     0x80

struct pcpes;

uint32_t tpm_start(void);
void tpm_finalize(void);
uint32_t tpm_unassert_physical_presence(void);
uint32_t tpm_measure_scrtm(void);
void tpm_set_log_parameters(void *address, unsigned int size);
uint32_t tpm_get_logsize(void);
uint32_t tpm_hash_log_extend_event(struct pcpes *pcpes);
bool tpm_log_event(struct pcpes *pcpes);
uint32_t tpm_hash_all(const void *data, uint32_t datalen, void *hashptr);
uint32_t tpm_measure_bcv_mbr(uint32_t bootdrv, const uint8_t *addr,
                             uint32_t length);
uint32_t tpm_add_event_separators(uint32_t start_pcr, uint32_t end_pcr);
uint32_t tpm_process_opcode(uint8_t op, bool verbose);
uint32_t tpm_get_maximum_cmd_size(void);
uint32_t tpm_pass_through_to_tpm(unsigned char *buf, uint32_t cmdlen);
uint32_t tpm_driver_get_state(void);
uint32_t tpm_driver_get_failure_reason(void);
void tpm_driver_set_failure_reason(uint32_t errcode);

/* flags returned by tpm_get_state */
#define TPM_STATE_ENABLED        1
#define TPM_STATE_ACTIVE         2
#define TPM_STATE_OWNED          4
#define TPM_STATE_OWNERINSTALL   8

int tpm_get_state(void);
bool tpm_is_working(void);

#endif /* TCGBIOS_H */
