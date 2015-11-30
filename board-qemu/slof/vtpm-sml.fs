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

: sml-get-handover-size ( -- size )
    tpm-get-logsize
    vtpm-debug? IF
        ." Call to sml-get-handover-size; size = 0x" dup . cr
    THEN
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

: hash-all ( data-ptr data-len hash-ptr -- )
    vtpm-debug? IF
        ." Call to hash-all" cr
    THEN
    tpm-hash-all                                   ( -- errcode )
    dup 0<> IF
        ." VTPM: Error code from tpm-hash-all: " . cr
    ELSE
        drop
    THEN
;

: log-event ( event-ptr -- success? )
    vtpm-debug? IF
        ." Call to log-event" cr
    THEN
    tpm-log-event                                  ( -- success? )
    dup 0= IF
        ." VTPM: Returned bool from tpm-log-event: " dup . cr
    THEN
;

: hash-log-extend-event ( event-ptr -- rc )
    vtpm-debug? IF
        ." Call to hash-log-extend-event" cr
    THEN
    tpm-hash-log-extend-event                      ( -- rc )
    dup 0<> IF
        ." VTPM: Error code from tpm-hash-log-extend-event: " dup . cr
    THEN
;

\
\ internal API calls
\

: separator-event ( start-pcr end-pcr -- )
    tpm-add-event-separators                          ( -- errcode )
    dup 0<> IF
        ." VTPM: Error code from tpm-add-event-separators: " . cr
    ELSE
        drop
    THEN
;

80 CONSTANT BCV_DEVICE_HDD

: measure-hdd-mbr ( addr -- )
    4 5 separator-event
    200 BCV_DEVICE_HDD                         ( addr length bootdrv -- )
    -rot                                       ( bootdrv addr length -- )
    tpm-measure-bcv-mbr                        ( -- errcode )
    dup 0<> IF
        ." VTPM: Error code from tpm-measure-hdd: " . cr
    ELSE
        drop
    THEN
;

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
