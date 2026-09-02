/*---------------------------------------------------------------*/
/*--- begin                              guest_or1k_helpers.c ---*/
/*---------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2026 Ali Ahmet Memiş

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.

   The GNU General Public License is contained in the file COPYING.
*/

#include "libvex_basictypes.h"
#include "libvex_emnote.h"
#include "libvex_guest_or1k.h"
#include "libvex_ir.h"
#include "libvex.h"

#include "main_util.h"
#include "guest_generic_bb_to_IR.h"
#include "guest_or1k_defs.h"

/* helpers for the OpenRISC guest: state init, layout descriptor, spechelper. */

/*--- initialise the guest state ---*/

void LibVEX_GuestOR1K_initialise ( /*OUT*/VexGuestOR1KState* vex_state )
{
   vex_state->host_EvC_FAILADDR = 0;
   vex_state->host_EvC_COUNTER  = 0;

   /* all GPRs zero; r0 is always zero anyway. */
   vex_state->guest_r0  = 0;  vex_state->guest_r1  = 0;
   vex_state->guest_r2  = 0;  vex_state->guest_r3  = 0;
   vex_state->guest_r4  = 0;  vex_state->guest_r5  = 0;
   vex_state->guest_r6  = 0;  vex_state->guest_r7  = 0;
   vex_state->guest_r8  = 0;  vex_state->guest_r9  = 0;
   vex_state->guest_r10 = 0;  vex_state->guest_r11 = 0;
   vex_state->guest_r12 = 0;  vex_state->guest_r13 = 0;
   vex_state->guest_r14 = 0;  vex_state->guest_r15 = 0;
   vex_state->guest_r16 = 0;  vex_state->guest_r17 = 0;
   vex_state->guest_r18 = 0;  vex_state->guest_r19 = 0;
   vex_state->guest_r20 = 0;  vex_state->guest_r21 = 0;
   vex_state->guest_r22 = 0;  vex_state->guest_r23 = 0;
   vex_state->guest_r24 = 0;  vex_state->guest_r25 = 0;
   vex_state->guest_r26 = 0;  vex_state->guest_r27 = 0;
   vex_state->guest_r28 = 0;  vex_state->guest_r29 = 0;
   vex_state->guest_r30 = 0;  vex_state->guest_r31 = 0;

   vex_state->guest_PC    = 0;
   vex_state->guest_SR_F  = 0;
   vex_state->guest_SR_CY = 0;
   vex_state->guest_SR_OV = 0;
   vex_state->guest_MACHI = 0;
   vex_state->guest_MACLO = 0;

   vex_state->guest_EMNOTE        = EmNote_NONE;
   vex_state->guest_CMSTART       = 0;
   vex_state->guest_CMLEN         = 0;
   vex_state->guest_NRADDR        = 0;
   vex_state->guest_IP_AT_SYSCALL = 0;

   vex_state->guest_LLSC_ACTIVE = 0;
   vex_state->guest_LLSC_ADDR   = 0;
   vex_state->guest_LLSC_DATA   = 0;
}

/*--- spechelper ---*/

/* nothing to specialise yet. eager flags mean no clean-helper calls to fold. */
IRExpr* guest_or1k_spechelper ( const HChar* function_name,
                                IRExpr**     args,
                                IRStmt**     precedingStmts,
                                Int          n_precedingStmts )
{
   return NULL;
}

/*--- precise memory exceptions ---*/

/* SP, FP and PC must be current at a faulting access: the unwinder and */
/* the stack-tracking machinery both read them there. */
Bool guest_or1k_state_requires_precise_mem_exns (
        Int minoff, Int maxoff, VexRegisterUpdates pxControl )
{
   Int sp_min = offsetof(VexGuestOR1KState, guest_r1);
   Int sp_max = sp_min + 4 - 1;
   Int fp_min = offsetof(VexGuestOR1KState, guest_r2);
   Int fp_max = fp_min + 4 - 1;
   Int pc_min = offsetof(VexGuestOR1KState, guest_PC);
   Int pc_max = pc_min + 4 - 1;

   if (!(maxoff < sp_min || minoff > sp_max))
      return True;
   if (pxControl == VexRegUpdSpAtMemAccess)
      return False;
   if (!(maxoff < fp_min || minoff > fp_max))
      return True;
   if (!(maxoff < pc_min || minoff > pc_max))
      return True;
   return False;
}

/*--- guest-state layout ---*/

/* OpenRISC ABI: SP=r1, FP=r2, LR=r9. */
/* r0 and the bookkeeping words are always-defined so memcheck stays quiet. */
VexGuestLayout
   or1kGuest_layout
      = {
          .total_sizeB = sizeof(VexGuestOR1KState),
          .offset_SP   = offsetof(VexGuestOR1KState, guest_r1),
          .sizeof_SP   = 4,
          .offset_FP   = offsetof(VexGuestOR1KState, guest_r2),
          .sizeof_FP   = 4,
          .offset_IP   = offsetof(VexGuestOR1KState, guest_PC),
          .sizeof_IP   = 4,
          .n_alwaysDefd = 7,
          .alwaysDefd
             = { /* 0 */ { .offset = offsetof(VexGuestOR1KState, guest_r0),
                           .size   = 4 },
                 /* 1 */ { .offset = offsetof(VexGuestOR1KState, guest_PC),
                           .size   = 4 },
                 /* 2 */ { .offset = offsetof(VexGuestOR1KState, guest_EMNOTE),
                           .size   = 4 },
                 /* 3 */ { .offset = offsetof(VexGuestOR1KState, guest_CMSTART),
                           .size   = 4 },
                 /* 4 */ { .offset = offsetof(VexGuestOR1KState, guest_CMLEN),
                           .size   = 4 },
                 /* 5 */ { .offset = offsetof(VexGuestOR1KState, guest_NRADDR),
                           .size   = 4 },
                 /* 6 */ { .offset = offsetof(VexGuestOR1KState,
                                              guest_IP_AT_SYSCALL),
                           .size   = 4 } }
        };

/*---------------------------------------------------------------*/
/*--- end                                guest_or1k_helpers.c ---*/
/*---------------------------------------------------------------*/
