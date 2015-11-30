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

uint32_t tpm_start(void);
void tpm_finalize(void);
uint32_t tpm_unassert_physical_presence(void);
void tpm_set_log_parameters(void *address, unsigned int size);

#endif /* TCGBIOS_H */
