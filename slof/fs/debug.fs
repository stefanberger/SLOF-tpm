\ *****************************************************************************
\ * Copyright (c) 2004, 2007 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

false constant <debug-dummy>

12 34 2constant (2constant) ' (2constant) cell+ @ 
\ fake device node
here 0
dup , dup , dup , dup , dup , 
over 7 cells + , 
dup , dup , dup , dup , dup , 
dup , drop
current-node ! \ FAKE!
12 instance value (instancevalue) ' (instancevalue) cell+ @
instance variable (instancevariable) ' (instancevariable) cell+ @
instance defer (instancedefer) ' (instancedefer) cell+ @
0 current-node !

forget <debug-dummy>

constant <instancedefer>
constant <instancevariable>
constant <instancevalue>
constant <2constant>


\ Get the name of Forth command whose execution token is xt

: xt>name ( xt -- str len )
    BEGIN
	cell - dup c@ 0 2 within IF
	    dup 2+ swap 1+ c@ exit
	THEN
    AGAIN
;

cell -1 * CONSTANT -cell
: cell- ( n -- n-cell-size )
   [ cell -1 * ] LITERAL +
;    

\ Search for xt of given address
: find-xt-addr ( addr -- xt )
   BEGIN
      dup @ <colon> = IF
	 EXIT
      THEN
      cell-
   AGAIN
; 

: (.immediate) ( xt -- )
   \ is it immediate?
   xt>name drop 2 - c@ \ skip len and flags
   immediate? IF
     ."  IMMEDIATE"
   THEN
;

: (.xt) ( xt -- )
   xt>name type
;

\ Trace back on current return stack.
\ Start at 1, since 0 is return of trace-back itself

: trace-back (  )
   1
   BEGIN
      cr dup dup . ."  : " rpick dup . ."  : "  
      ['] tib here within IF 
	  dup rpick find-xt-addr (.xt)
      THEN   	  
      1+ dup rdepth 5 - >= IF cr drop EXIT THEN   
   AGAIN
;   

: (see-colon) ( xt -- )
   ." : " dup (.xt) cr 3 spaces
   BEGIN
      cell + dup @
      dup <semicolon> <> 
   WHILE
      dup (.xt) ."  " 
      CASE
	 <0branch>  OF cell+ dup @ . ENDOF
	 <branch>   OF cell+ dup @ . ENDOF
	 <do?do>    OF cell+ dup @ . ENDOF	   
	 <lit>      OF cell+ dup @ . ENDOF
	 <dotick>   OF cell+ dup @ (.xt) ."  " ENDOF	   
	 <doloop>   OF cell+ dup @ . ENDOF
	 <do+loop>  OF cell+ dup @ . ENDOF	   	   
	 <sliteral> OF cell+ dup count dup >r type ."  " 
	    r> -cell and + .s ENDOF
	 dup        OF ."  " ENDOF
      ENDCASE
   REPEAT
   2drop
   cr ." ;" 
;

\ Create words are a bit tricky. We find out where their code points.
\ If this code is part of SLOF, it is not a user generated CREATE.

: (see-create) ( xt -- )
   dup cell+ @
   CASE
      <2constant> OF
         dup cell+ cell+ dup @ swap cell+ @ . .  ." 2CONSTANT " 
      ENDOF

      <instancevalue> OF
         dup cell+ cell+ @ . ." INSTANCE VALUE " 
      ENDOF

      <instancevariable> OF
         ." INSTANCE VARIABLE "
      ENDOF

      dup OF
         ." CREATE "
      ENDOF
   ENDCASE
   (.xt)
;

\ Decompile Forth command whose execution token is xt

: (see) ( xt -- )
   cr dup dup @ 
   CASE 
      <variable> OF ." VARIABLE " (.xt) ENDOF
      <value>    OF dup execute . ." VALUE " (.xt) ENDOF
      <constant> OF dup execute . ." CONSTANT " (.xt) ENDOF
      <defer>    OF dup cell+ @ swap ." DEFER " (.xt) ."  is " (.xt) ENDOF
      <alias>    OF dup cell+ @ swap ." ALIAS " (.xt) ."  " (.xt) ENDOF
      <buffer:>  OF ." BUFFER: " (.xt) ENDOF
      <create>   OF (see-create) ENDOF
      <colon>    OF (see-colon)  ENDOF
      dup        OF ." ??? PRIM " (.xt) ENDOF
   ENDCASE
   (.immediate) cr
  ;

\ Decompile Forth command old-name

: see ( "old-name<>" -- )
   ' (see)
; 

\ Work in progress...

0    value forth-ip
true value trace>stepping?
true value trace>print?
true value trace>up?
0    value trace>depth
0    value trace>rdepth
: trace-depth+ ( -- ) trace>depth 1+ to trace>depth ;
: trace-depth- ( -- ) trace>depth 1- to trace>depth ;

: stepping ( -- )
    true to trace>stepping?
;

: tracing ( -- )
    false to trace>stepping?
;

: trace-print-on ( -- )
    true to trace>print?
;    

: trace-print-off ( -- )
    false to trace>print?
;    


\ Add n to ip

: fip-add ( n -- )
   forth-ip + to forth-ip
;    

: trace-print ( -- )
   forth-ip cr u. ." : " 
   forth-ip @ xt>name type ."  " 
   ."     ( " .s  ."  )  | "
;  

: trace-interpret ( -- )
   rdepth 1- to trace>rdepth
   BEGIN
      depth . [char] > dup emit emit space
      source expect                        ( str len )
      ['] interpret catch print-status
   AGAIN	
;

\ Save execution token address and content

0 value debug-last-xt
0 value debug-last-xt-content

\ Main trace routine, trace a colon definition

: trace-xt ( xt -- )
   debug-last-xt ['] breakpoint @ swap !     \ Re-arm break point
    r> drop                                  \ Drop return of 'trace-xt call   
    cell + to forth-ip                       \ Step over ":"
    true to trace>print? 
    BEGIN
       trace>print? IF trace-print THEN

       forth-ip                                              ( ip )    
       trace>stepping? IF
	  BEGIN 
             key	    
             CASE
		[char] d OF dup @ @ <colon> = IF             \ recurse only into colon definitions      
			                         trace-depth+ dup >r @ recurse
		                              THEN true ENDOF
	        [char] u OF trace>depth IF tracing trace-print-off true ELSE false THEN ENDOF
	        [char] f OF drop cr trace-interpret ENDOF	\ quit trace and start interpreter FIXME rstack
	        [char] c OF tracing true ENDOF	  
		[char] t OF trace-back false ENDOF
		[char] q OF drop cr quit ENDOF		
	        20       OF true ENDOF
		dup      OF cr ." Press d:       Down into current word" cr
		            ." Press u:       Up to caller" cr
		            ." Press f:       Switch to forth interpreter, 'resume' will continue tracing" cr
                            ." Press c:       Switch to tracing" cr
		            ." Press <space>: Execute current word" cr
		            ." Press q:       Abort execution, switch to interpreter" cr
		            false ENDOF
	     ENDCASE
	  UNTIL  
       THEN	                                              ( ip' )  
       dup to forth-ip @ dup                                  ( xt xt )

       CASE
	    <sliteral>  OF drop forth-ip cell+ dup dup c@ + -cell and to forth-ip ENDOF 
	    <dotick>    OF drop forth-ip cell+ @ cell fip-add ENDOF	    
	    <lit>       OF drop forth-ip cell+ @ cell fip-add ENDOF
	    <doto>      OF drop forth-ip cell+ @ cell+ ! cell fip-add ENDOF    
	    <0branch>   OF drop IF
		                    cell fip-add
		                ELSE
				    forth-ip cell+ @ cell+ fip-add THEN
			ENDOF
            <do?do>     OF drop 2dup <> IF
				           swap >r >r cell fip-add
		                        ELSE
					   forth-ip cell+ @ cell+ fip-add 2drop THEN
		        ENDOF    
	    <branch>    OF drop forth-ip cell+ @ cell+ fip-add ENDOF
	    <doloop>    OF drop r> 1+ r> 2dup = IF
		                                   2drop cell fip-add
		                                ELSE >r >r 
						    forth-ip cell+ @ cell+ fip-add THEN
			ENDOF			
	    <do+loop>   OF drop r> + r> 2dup = IF
		                                   2drop cell fip-add
		                                ELSE >r >r 
						    forth-ip cell+ @ cell+ fip-add THEN
			ENDOF
	    
	    <semicolon> OF trace>depth 0> IF
		                             trace-depth- stepping drop r> recurse
		                          ELSE
		                             drop exit THEN
			ENDOF
            <exit>      OF trace>depth 0> IF
		                             trace-depth- stepping drop r> recurse
		                          ELSE
				             drop exit THEN
			ENDOF	    
	    dup         OF execute ENDOF
	ENDCASE
	forth-ip cell+ to forth-ip 
    AGAIN
;    

\ Resume execution from tracer
: resume ( -- )
    trace>rdepth rdepth!
    forth-ip cell - trace-xt
;    
    
\ Turn debug off, by erasing breakpoint

: debug-off ( -- )
    debug-last-xt IF 
	debug-last-xt-content debug-last-xt !  \ Restore overwriten token
	0 to debug-last-xt
    THEN	
;



\ Entry point for debug

: (break-entry) ( -- )
   debug-last-xt-content debug-last-xt !       \ Restore overwriten token
   r> drop                                     \ Don't return to bp, but to caller
   debug-last-xt-content <colon> <> IF         \ Execute non colon definition 
      debug-last-xt cr u. ." : " 
      debug-last-xt xt>name type ."  " 
      ."     ( " .s  ."  )  | "
      key drop 
      debug-last-xt execute
   ELSE	
      debug-last-xt 0 to trace>depth trace-xt   \ Trace colon definition
   THEN
;  

\ Put entry point bp defer
' (break-entry) to BP

\ Mark the command indicated by xt for debugging

: (debug ( xt --  )
   debug-off                       ( xt )  \ Remove active breakpoint        
   dup to debug-last-xt            ( xt )  \ Save token for later debug
   dup @ to debug-last-xt-content  ( xt )  \ Save old value 
   ['] breakpoint @ swap !
;    

\ Mark the command indicated by xt for debugging

: debug ( "old-name<>" -- )
    parse-word $find IF                       \ Get xt for old-name
       (debug
    ELSE
       ." undefined word " type cr
    THEN
; 