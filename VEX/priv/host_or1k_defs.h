/*---------------------------------------------------------------*/
/*--- begin                                  host_or1k_defs.h ---*/
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

/* Only to be used within the host-or1k directory. */

#ifndef __VEX_HOST_OR1K_DEFS_H
#define __VEX_HOST_OR1K_DEFS_H

#include "libvex_basictypes.h"

/* ORBIS32 instruction encoders, the bit-packing layer emit_OR1KInstr  */
/* calls. Each returns the 32-bit word (emitted MSB-first). */

/* opcode 0x38 form; op11 = bits[10:0] (add=0x000, sub=0x002, sll=0x008, mul=0x306). */
extern UInt or1k_enc_rrr    ( UInt op11, UInt rD, UInt rA, UInt rB );

/* addi=0x27, andi=0x29, ori=0x2a, xori=0x2b. */
extern UInt or1k_enc_ri     ( UInt opc, UInt rD, UInt rA, UInt imm16 );

extern UInt or1k_enc_movhi  ( UInt rD, UInt imm16 );

/* type 0=sll 1=srl 2=sra 3=ror. */
extern UInt or1k_enc_shifti ( UInt type, UInt rD, UInt rA, UInt amt6 );

/* lwz=0x21, lbz=0x23, lbs=0x24, lhz=0x25, lhs=0x26. */
extern UInt or1k_enc_load   ( UInt opc, UInt rD, UInt rA, UInt disp16 );

/* split-immediate stores: sw=0x35, sb=0x36, sh=0x37. */
extern UInt or1k_enc_store  ( UInt opc, UInt rA, UInt rB, UInt disp16 );

/* set-flag compare; code = l.sf* selector (eq=0, ne=1, ...). */
extern UInt or1k_enc_sf     ( UInt code, UInt rA, UInt rB );
extern UInt or1k_enc_sfi    ( UInt code, UInt rA, UInt imm16 );

/* rel is a signed word offset. */
extern UInt or1k_enc_branch ( UInt opc, Int rel );
extern UInt or1k_enc_jr     ( UInt rB );
extern UInt or1k_enc_jalr   ( UInt rB );

extern UInt or1k_enc_nop    ( UInt k );
extern UInt or1k_enc_sys    ( UInt k );

#endif /* ndef __VEX_HOST_OR1K_DEFS_H */

/*---------------------------------------------------------------*/
/*--- end                                    host_or1k_defs.h ---*/
/*---------------------------------------------------------------*/
