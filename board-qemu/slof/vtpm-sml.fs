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

: get-state ( -- state )
    vtpm-debug? IF
        ." Call to get-state" cr
    THEN
    tpm-driver-get-state                           ( state )
    vtpm-debug? IF
        ." VTPM: Return value from tpm-driver-get-state: " dup . cr
    THEN
;

: get-failure-reason ( -- reason )
    tpm-driver-get-failure-reason                  ( reason )
    vtpm-debug? IF
        ." VTPM: Return value from tpm-driver-get-failure-reason: " dup . cr
    THEN
;

: hash-all ( data-ptr data-len hash-ptr -- )
    vtpm-debug? IF
        ." Call to hash-all" cr
    THEN
    tpm-hash-all                                   ( errcode )
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
    tpm-log-event                                  ( success? )
    dup 0= IF
        ." VTPM: Returned bool from tpm-log-event: " dup . cr
    THEN
;

: hash-log-extend-event ( event-ptr -- rc )
    vtpm-debug? IF
        ." Call to hash-log-extend-event" cr
    THEN
    tpm-hash-log-extend-event                      ( rc )
    dup 0<> IF
        ." VTPM: Error code from tpm-hash-log-extend-event: " dup . cr
    THEN
;

: get-maximum-cmd-size ( -- max-size )
    vtpm-debug? IF
        ." Call to get-maximum-cmd-size" cr
    THEN
    tpm-get-maximum-cmd-size                       ( max-size )
    dup 0= IF     \ Display if return value is 0
        ." VTPM: Return value from tpm-get-maximum-cmd-size: " dup . cr
    THEN
;

: pass-through-to-tpm ( buf-addr cmd-size -- rsp-size )
    vtpm-debug? IF
        ." Call to pass-through-to-tpm" cr
    THEN
    tpm-pass-through-to-tpm                        ( rsp-size )
    vtpm-debug? IF
        ." VTPM: Return value from tpm-pass-through-to-tpm: " dup . cr
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
    dup 0<> IF
        ." VTPM: Error code from tpm-add-event-separators: " . cr
    ELSE
        drop
    THEN
;

80 CONSTANT BCV_DEVICE_HDD

: measure-hdd-mbr ( addr -- )
    4 5 separator-event
    200 BCV_DEVICE_HDD                         ( addr length bootdrv )
    -rot                                       ( bootdrv addr length )
    tpm-measure-bcv-mbr                        ( errcode )
    dup 0<> IF
        ." VTPM: Error code from tpm-measure-hdd: " . cr
    ELSE
        drop
    THEN
;

: unassert-physical-presence ( -- )
    tpm-unassert-physical-presence                    ( errcode )
    dup 0<> IF
        ." VTPM: Error code from tpm-unassert-physical-presence: " . cr
    ELSE
        drop
    THEN
;

: measure-scrtm ( -- )
    tpm-measure-scrtm                                     ( errcode )
    dup 0<> IF
        ." VTPM: Error code from tpm-measure-scrtm: " . cr
    ELSE
        drop
    THEN
;

\
\  TPM menu
\

1 CONSTANT TPM_ST_ENABLED
2 CONSTANT TPM_ST_ACTIVE
4 CONSTANT TPM_ST_OWNED
8 CONSTANT TPM_ST_OWNERINSTALL

\ helper to test whether the TPM is enabled and active
: is-enabled-active? ( state -- ok? )
    TPM_ST_ENABLED TPM_ST_ACTIVE OR dup rot AND =
;

\ display the menu for manipulating TPM state; we get
\ the state of the TPM in form of flags from the C-driver
\
\ Some info about the TPM's states:
\ - enabling/disabling can be done at any time
\ - activating/deactivating the TPM requires an enabled TPM
\ - clearing ownership can be done even if the TPM is deactivated and disabled
\ - allowing/preventing owner installation requires an enabled and active TPM
\
: tpm12-menu-show ( -- )
    tpm-is-working IF
        ." The TPM is "

        tpm-get-state                   ( flags )

        dup TPM_ST_ENABLED AND TPM_ST_ENABLED <> IF
            ." disabled"
        ELSE
            ." enabled"
        THEN

        dup TPM_ST_ACTIVE AND TPM_ST_ACTIVE <> IF
            ." , deactivated"
        ELSE
            ." , active"
        THEN

        dup TPM_ST_OWNED AND TPM_ST_OWNED <> IF
            ." , does not have an owner "
            dup TPM_ST_OWNERINSTALL AND TPM_ST_OWNERINSTALL <> IF
                ." and an owner cannot be installed."
            ELSE
                ." but one can be installed."
            THEN
        ELSE
            ." , and has an owner."
        THEN

        cr cr
        ." To configure the TPM, choose one of the following actions:"
        cr cr

        dup TPM_ST_ENABLED AND TPM_ST_ENABLED <> IF
            ." e. Enable the TPM" cr
        ELSE
            ." d. Disable the TPM" cr

            dup TPM_ST_ACTIVE AND TPM_ST_ACTIVE <> IF
                ." a. Activate the TPM" cr
            ELSE
                ." v. Deactivate the TPM" cr

                dup TPM_ST_OWNERINSTALL AND TPM_ST_OWNERINSTALL <> IF
                    ." s. Allow installation of an owner" cr
                ELSE
                    ." p. Prevent installation of an owner" cr
                THEN
            THEN

        THEN

        dup TPM_ST_OWNED AND TPM_ST_OWNED = IF
           ." c. Clear ownership" cr
        THEN

        cr
        \ If the TPM is either disabled or deactivated, show message
        is-enabled-active? 0= IF
            ." Note: To be able to use all features of the TPM, it must be enabled and active."
            cr cr
        THEN

    ELSE
       ." The TPM is not working correctly." cr
    THEN

    ." Press escape to continue boot." cr cr
;

\ Send a code to the C-driver to change the state of the vTPM
: process-opcode ( verbose? opcode -- )
    tpm-process-opcode
    dup 0<> IF
        ." VTPM: Error code from tpm-process-opcode: " . cr
    ELSE
        drop
    THEN
;

1  CONSTANT PPI_OP_ENABLE
2  CONSTANT PPI_OP_DISABLE
3  CONSTANT PPI_OP_ACTIVATE
4  CONSTANT PPI_OP_DEACTIVATE
5  CONSTANT PPI_OP_CLEAR
8  CONSTANT PPI_OP_SETOWNERINSTALL_TRUE
9  CONSTANT PPI_OP_SETOWNERINSTALL_FALSE

\ if there's a vtpm available, display the menu
\ wait for keyboard input and have the C-driver
\ process opcodes we derive from the chosen menu
\ item
: vtpm12-menu
    tpm-is-working IF
        \ vtpm-empty-keybuffer
        tpm12-menu-show
        BEGIN
            0 \ loop end-flag                                           ( 0 )
            key CASE
            [char] e OF  tpm-get-state                                  ( 0 flags )
                         TPM_ST_ENABLED AND TPM_ST_ENABLED <> IF
                             0 PPI_OP_ENABLE     process-opcode
                             tpm12-menu-show
                         THEN
                     ENDOF
            [char] d OF  tpm-get-state                                  ( 0 flags )
                         TPM_ST_ENABLED AND TPM_ST_ENABLED = IF
                             0 PPI_OP_DISABLE    process-opcode
                             tpm12-menu-show
                         THEN
                     ENDOF
            [char] a OF  tpm-get-state                                  ( 0 flags )
                         TPM_ST_ACTIVE AND TPM_ST_ACTIVE <> IF
                             0 PPI_OP_ACTIVATE   process-opcode
                             tpm-get-state
                             TPM_ST_ACTIVE AND TPM_ST_ACTIVE = IF
                                 ." The system needs to reboot to activate the TPM."
                                 100 MS \ so the message shows
                                 reset-all
                             THEN
                         THEN
                     ENDOF
            [char] v OF  tpm-get-state                                  ( 0 flags )
                         TPM_ST_ACTIVE AND TPM_ST_ACTIVE = IF
                             0 PPI_OP_DEACTIVATE process-opcode
                             tpm12-menu-show
                         THEN
                     ENDOF
            [char] c OF  tpm-get-state                                  ( 0 flags )
                         TPM_ST_OWNED AND TPM_ST_OWNED = IF
                             0 PPI_OP_CLEAR      process-opcode
                             tpm12-menu-show
                         THEN
                     ENDOF
            [char] s OF  tpm-get-state                                  ( 0 flags )
                         \ The TPM must be enabled and active to allow
                         \ owner installation mods
                         dup is-enabled-active? IF
                             TPM_ST_OWNERINSTALL AND TPM_ST_OWNERINSTALL <> IF
                                 0 PPI_OP_SETOWNERINSTALL_TRUE  process-opcode
                                 tpm12-menu-show
                             THEN
                         THEN
                     ENDOF
            [char] p OF  tpm-get-state                                  ( 0 flags )
                         \ The TPM must be enabled and active to allow
                         \ owner installation mods
                         dup is-enabled-active? IF
                             TPM_ST_OWNERINSTALL AND TPM_ST_OWNERINSTALL = IF
                                 0 PPI_OP_SETOWNERINSTALL_FALSE process-opcode
                                 tpm12-menu-show
                             THEN
                         THEN
                     ENDOF
            1b       OF                                                ( 0 )
                         drop 1                                        ( 1 )
                     ENDOF
            ENDCASE
        UNTIL
    THEN
;

: vtpm20-menu
    tpm-is-working IF
        tpm20-menu
    THEN
;

: vtpm-menu
    tpm-get-tpm-version CASE
    1 OF
        vtpm12-menu
      ENDOF
    2 OF
        vtpm20-menu
      ENDOF
    ENDCASE
;

: open  true ;
: close ;

finish-device
device-end
