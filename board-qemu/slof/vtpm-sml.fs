\ *****************************************************************************
\ * Copyright (c) 2015-2020 IBM Corporation
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

e     CONSTANT VTPM_DRV_ERROR_SML_HANDED_OVER

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

    VTPM_DRV_ERROR_SML_HANDED_OVER tpm-driver-set-failure-reason
;

: get-failure-reason ( -- reason )
    tpm-driver-get-failure-reason                  ( reason )
    vtpm-debug? IF
        ." VTPM: Return value from tpm-driver-get-failure-reason: " dup . cr
    THEN
;

: reformat-sml-to-efi-alignment ( -- success? )
    vtpm-debug? IF
        ." Call to reformat-sml-to-efi-alignment" cr
    THEN
    \ a no-op since already byte aligned
    true
;

\
\ internal API calls
\

: separator-event ( start-pcr end-pcr -- )
    tpm-add-event-separators                          ( errcode )
    ?dup IF
        ." VTPM: Error code from tpm-add-event-separators: " . cr
    THEN
;

80 CONSTANT BCV_DEVICE_HDD

: measure-hdd-mbr ( addr length -- )
    0 7 separator-event
    BCV_DEVICE_HDD                             ( addr length bootdrv )
    -rot                                       ( bootdrv addr length )
    tpm-measure-bcv-mbr                        ( errcode )
    ?dup IF
        ." VTPM: Error code from tpm-measure-hdd: " . cr
    THEN
;

: leave-firmware ( -- )
    tpm-leave-firmware                         ( errcode )
    ?dup IF
        ." VTPM: Error code from tpm-leave-firmware: " . cr
    THEN
;

: measure-scrtm ( -- )
    tpm-measure-scrtm                                     ( errcode )
    ?dup IF
        ." VTPM: Error code from tpm-measure-scrtm: " . cr
    THEN
;

: open  true ;
: close ;

finish-device
device-end
