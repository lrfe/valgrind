/*--------------------------------------------------------------------*/
/*--- The core dispatch loop, for jumping to a code address.       ---*/
/*---                                        dispatch-or1k-linux.S ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2026 Ali Ahmet Memis

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_core_basics_asm.h"

#if defined(VGP_or1k_linux)

#include "pub_core_dispatch_asm.h"
#include "pub_core_transtab_asm.h"
#include "libvex_guest_offsets.h"

/* The translations use r30 as the guest-state pointer; r11/r12 carry
   the (TRC, second-word) pair back to the caller.

   void VG_(disp_run_translations)( UWord* two_words,   // r3
                                    void*  guest_state,  // r4
                                    Addr   host_addr );  // r5
*/

.text
.globl VG_(disp_run_translations)
VG_(disp_run_translations):
    l.addi  r1, r1, -48
    l.sw    0(r1), r9            /* return address */
    l.sw    4(r1), r2            /* frame pointer  */
    l.sw    8(r1), r3            /* two_words ptr  */
    l.sw    12(r1), r14
    l.sw    16(r1), r16
    l.sw    20(r1), r18
    l.sw    24(r1), r20
    l.sw    28(r1), r22
    l.sw    32(r1), r24
    l.sw    36(r1), r26
    l.sw    40(r1), r28
    l.sw    44(r1), r30
    /* set the guest-state pointer and enter the translation */
    l.ori   r30, r4, 0
    l.jr    r5
     l.nop

postamble:
    l.lwz   r3, 8(r1)            /* two_words ptr */
    l.sw    0(r3), r11           /* two_words[0] = TRC */
    l.sw    4(r3), r12           /* two_words[1] = arg */
    l.lwz   r9,  0(r1)
    l.lwz   r2,  4(r1)
    l.lwz   r14, 12(r1)
    l.lwz   r16, 16(r1)
    l.lwz   r18, 20(r1)
    l.lwz   r20, 24(r1)
    l.lwz   r22, 28(r1)
    l.lwz   r24, 32(r1)
    l.lwz   r26, 36(r1)
    l.lwz   r28, 40(r1)
    l.lwz   r30, 44(r1)
    l.addi  r1, r1, 48
    l.jr    r9
     l.nop

.global VG_(disp_cp_chain_me_to_slowEP)
VG_(disp_cp_chain_me_to_slowEP):
    l.movhi r11, hi(VG_TRC_CHAIN_ME_TO_SLOW_EP)
    l.ori   r11, r11, lo(VG_TRC_CHAIN_ME_TO_SLOW_EP)
    /* r9 (LR) points 16 bytes past the patchable region; back it up. */
    l.addi  r12, r9, -16
    l.j     postamble
     l.nop

.global VG_(disp_cp_chain_me_to_fastEP)
VG_(disp_cp_chain_me_to_fastEP):
    l.movhi r11, hi(VG_TRC_CHAIN_ME_TO_FAST_EP)
    l.ori   r11, r11, lo(VG_TRC_CHAIN_ME_TO_FAST_EP)
    /* r9 (LR) points 16 bytes past the patchable region; back it up. */
    l.addi  r12, r9, -16
    l.j     postamble
     l.nop

.global VG_(disp_cp_xindir)
VG_(disp_cp_xindir):
    /* Simplified: always report a fast-cache miss and let C do the
       lookup.  (No hand-coded fast-cache probe yet.) */
    l.movhi r11, hi(VG_TRC_INNER_FASTMISS)
    l.ori   r11, r11, lo(VG_TRC_INNER_FASTMISS)
    l.ori   r12, r0, 0
    l.j     postamble
     l.nop

.global VG_(disp_cp_xassisted)
VG_(disp_cp_xassisted):
    /* r11 already holds the guest TRC value set by the assisted exit. */
    l.ori   r12, r0, 0
    l.j     postamble
     l.nop

.global VG_(disp_cp_evcheck_fail)
VG_(disp_cp_evcheck_fail):
    l.movhi r11, hi(VG_TRC_INNER_COUNTERZERO)
    l.ori   r11, r11, lo(VG_TRC_INNER_COUNTERZERO)
    l.ori   r12, r0, 0
    l.j     postamble
     l.nop

.size VG_(disp_run_translations), .-VG_(disp_run_translations)

#endif

MARK_STACK_NO_EXEC

/*--------------------------------------------------------------------*/
/*--- end                                  dispatch-or1k-linux.S ---*/
/*--------------------------------------------------------------------*/
