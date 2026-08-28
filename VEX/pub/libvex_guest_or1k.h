/*---------------------------------------------------------------*/
/*--- begin                              libvex_guest_or1k.h ---*/
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

#ifndef __LIBVEX_PUB_GUEST_OR1K_H
#define __LIBVEX_PUB_GUEST_OR1K_H

#include "libvex_basictypes.h"

/*--- OpenRISC 1000 CPU state ---*/

/* SR[F] is the compare/branch flag (l.sf* set it, l.bf/l.bnf read it), */
/* SR[CY]/SR[OV] feed l.addc/l.subc. explicit 0/1 words, no lazy flag */
/* thunk — or1k's flag model is simple enough that eager costs zero. */
/* delay slots aren't guest state: a branch + its one delay-slot insn */
/* decode into a single IRSB, so nothing crosses SB boundaries. */

typedef
   struct {
      /* Event-check fail addr + counter; MUST be first, dispatcher asm hard-codes these. */
      /*    0 */ UInt host_EvC_FAILADDR;
      /*    4 */ UInt host_EvC_COUNTER;

      /* GPRs r0..r31; r0 hardwired to 0 (front end reads it as constant 0). */
      /*    8 */ UInt guest_r0;
      /*   12 */ UInt guest_r1;
      /*   16 */ UInt guest_r2;
      /*   20 */ UInt guest_r3;
      /*   24 */ UInt guest_r4;
      /*   28 */ UInt guest_r5;
      /*   32 */ UInt guest_r6;
      /*   36 */ UInt guest_r7;
      /*   40 */ UInt guest_r8;
      /*   44 */ UInt guest_r9;    /* link register (l.jal writes r9) */
      /*   48 */ UInt guest_r10;   /* TLS / thread pointer on Linux */
      /*   52 */ UInt guest_r11;   /* return value / syscall retval */
      /*   56 */ UInt guest_r12;
      /*   60 */ UInt guest_r13;
      /*   64 */ UInt guest_r14;
      /*   68 */ UInt guest_r15;
      /*   72 */ UInt guest_r16;
      /*   76 */ UInt guest_r17;
      /*   80 */ UInt guest_r18;
      /*   84 */ UInt guest_r19;
      /*   88 */ UInt guest_r20;
      /*   92 */ UInt guest_r21;
      /*   96 */ UInt guest_r22;
      /*  100 */ UInt guest_r23;
      /*  104 */ UInt guest_r24;
      /*  108 */ UInt guest_r25;
      /*  112 */ UInt guest_r26;
      /*  116 */ UInt guest_r27;
      /*  120 */ UInt guest_r28;
      /*  124 */ UInt guest_r29;
      /*  128 */ UInt guest_r30;
      /*  132 */ UInt guest_r31;

      /*  136 */ UInt guest_PC;    /* program counter */

      /*  140 */ UInt guest_SR_F;  /* SR[F]  compare/branch flag */
      /*  144 */ UInt guest_SR_CY; /* SR[CY] carry */
      /*  148 */ UInt guest_SR_OV; /* SR[OV] overflow */

      /* MAC unit accumulator (l.mac / l.macrc / l.msb). */
      /*  152 */ UInt guest_MACHI;
      /*  156 */ UInt guest_MACLO;

      /* FPU (ORFPX32) omitted for integer-first bring-up; add before FP workloads. */

      /*  160 */ UInt guest_EMNOTE;        /* emulation-warning code */
      /*  164 */ UInt guest_CMSTART;       /* self-modifying-code range start */
      /*  168 */ UInt guest_CMLEN;         /* self-modifying-code range length */
      /*  172 */ UInt guest_NRADDR;        /* used by the nraddr client request */
      /*  176 */ UInt guest_IP_AT_SYSCALL; /* PC of the l.sys, for syscall restart */

      /* Pad to a multiple of 16. */
      /*  180 */ UInt _padding[3];
   }
   VexGuestOR1KState;

/*--- utility functions ---*/

/* Initialise all guest OR1K state. */
extern
void LibVEX_GuestOR1K_initialise ( /*OUT*/VexGuestOR1KState* vex_state );

#endif /* ndef __LIBVEX_PUB_GUEST_OR1K_H */

/*---------------------------------------------------------------*/
/*--- end                                libvex_guest_or1k.h ---*/
/*---------------------------------------------------------------*/
