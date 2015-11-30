\ *****************************************************************************
\ * Copyright (c) 2015 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ KVM/qemu TPM Stored Measurement Log (SML) entries in /ibm,vtpm

" /" find-device

new-device

false VALUE    vtpm-debug?
0     VALUE    log-base
40000 CONSTANT LOG-SIZE   \ 256k per VTPM FW spec.

LOG-SIZE BUFFER: log-base

\ create /ibm,vtpm
s" ibm,vtpm" 2dup device-name device-type

\ convey logbase and size to the C driver
log-base LOG-SIZE tpm-set-log-parameters

: sml-get-allocated-size ( -- buffer-size)
    vtpm-debug? IF
        ." Call to sml-get-allocated-size; size = 0x" LOG-SIZE . cr
    THEN
    LOG-SIZE
;

: sml-handover ( dest size -- )
    vtpm-debug? IF
        2dup
        ." Call to sml-handover; size = 0x" . ." dest = " . cr
    THEN
    log-base        ( dest size src )
    -rot            ( src dest size )
    move
;

\
\ internal API calls
\

: unassert-physical-presence ( -- )
    tpm-unassert-physical-presence                    ( -- errcode )
    dup 0<> IF
        ." VTPM: Error code from tpm-unassert-physical-presence: " . cr
    ELSE
        drop
    THEN
;

: open  true ;
: close ;

finish-device
device-end
