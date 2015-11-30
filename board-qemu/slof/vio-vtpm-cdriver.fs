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
