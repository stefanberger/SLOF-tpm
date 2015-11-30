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

#ifndef __SHA1_H
#define __SHA1_H

#include "types.h"

uint32_t sha1(const uint8_t *data, uint32_t length, uint8_t *hash);

#endif /* __SHA1_H */