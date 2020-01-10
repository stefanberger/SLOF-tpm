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

\ create /ibm,vtpm
s" ibm,vtpm" 2dup device-name device-type

\
\ only internal API calls
\

: separator-event ( start-pcr end-pcr -- )
    tpm-add-event-separators                   ( errcode )
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
    tpm-measure-scrtm                          ( errcode )
    ?dup IF
        ." VTPM: Error code from tpm-measure-scrtm: " . cr
    THEN
;

: open  true ;
: close ;

finish-device
device-end
