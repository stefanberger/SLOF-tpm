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

." Populating " pwd

false VALUE vtpm-debug?
0     VALUE vtpm-unit
0     VALUE vtpm-ihandle

: setup-alias
    " ibm,vtpm" find-alias 0= IF
        " ibm,vtpm" get-node node>path set-alias
    ELSE
        drop
    THEN
;

: vtpm-cleanup ( )
    vtpm-debug? IF ." VTPM: Disabling RTAS bypass" cr THEN
    tpm-finalize
    vtpm-unit 0 rtas-set-tce-bypass
;

: vtpm-init ( -- true | false )
    0 0 get-node open-node ?dup 0= IF EXIT THEN
    my-self >r
    dup to my-self

    vtpm-debug? IF ." VTPM: Initializing for c-driver" cr THEN

    my-unit to vtpm-unit

    \ Enable TCE bypass special qemu feature
    vtpm-unit 1 rtas-set-tce-bypass

    \ Have TCE bypass cleaned up
    ['] vtpm-cleanup add-quiesce-xt

    tpm-start dup 0= IF
        vtpm-debug? IF ." VTPM: Success from tpm-start" cr THEN
        drop
        setup-alias
    ELSE
        ." VTPM: Error code from tpm-start: " . cr
    THEN

    close-node
    r> to my-self
;

\ forward a call to /ibm,vtpm, which implements the function with the
\ given name
: vtpm-call-forward ( arg ... arg name namelen -- failure? ret ... ret )
    \ assign /ibm,vtpm node to vtpm-ihandle, if not assigned
    vtpm-ihandle 0= IF
        s" /ibm,vtpm" open-dev to vtpm-ihandle
    THEN

    vtpm-ihandle 0<> IF
        vtpm-ihandle                   ( arg ... arg name namelen ihandle )
        $call-method                   ( -- ret ... ret )
        false                          ( ret ... ret --- ret ... ret false )
    ELSE
        true                           ( -- true )
    THEN
;

\ firmware API call
: sml-get-allocated-size ( -- buffer-size)
    " sml-get-allocated-size" vtpm-call-forward IF
        \ vtpm-call-forward failed
        0
    THEN
;

\ firmware API call
: sml-get-handover-size ( -- size)
    " sml-get-handover-size" vtpm-call-forward IF
        \ vtpm-call-forward failed
        0
    THEN
;

\ firmware API call
: sml-handover ( dest size -- )
    " sml-handover" vtpm-call-forward IF
        \ vtpm-call-forward failed; clean up stack
        2drop
    THEN
;

\ firmware API call
: hash-all ( data-ptr data-len hash-ptr -- )
    " hash-all" vtpm-call-forward IF
        \ vtpm-call-forward failed; clean up stack
        3drop
    THEN
;

\ firmware API call
: log-event ( event-ptr -- success? )
    " log-event" vtpm-call-forward IF
        drop
        false
    THEN
;

\ firmware API call
: hash-log-extend-event ( event-ptr -- rc )
    " hash-log-extend-event" vtpm-call-forward IF
        drop
        9 \ TPM_FAIL
    THEN
;

: open ( )
    vtpm-debug? IF ." VTPM: vTPM open()" cr THEN
    true
;

: close ( )
    vtpm-debug? IF ." VTPM: vTPM close()" cr THEN
;

\ setup alias and the RTAS bypass
vtpm-init

\ setup the log
include vtpm-sml.fs

s" /ibm,vtpm" find-node dup IF
  s" measure-scrtm" rot $call-static
ELSE
  drop
THEN
