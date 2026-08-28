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
#include "host_generic_regs.h"

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

/*--- host instructions ---*/

/* universe index of GPR n: allocable r3..r8, r11..r29, r31 first, then */
/* the reserved r0/r1/r2/r9/r10/r30. mkHReg needs this index, not n. */
static inline UInt or1k_gpr_ix ( UInt n ) {
   if (n >= 3 && n <= 8)   return n - 3;
   if (n >= 11 && n <= 29) return 6 + (n - 11);
   if (n == 31) return 25;
   if (n == 0)  return 26;
   if (n == 1)  return 27;
   if (n == 2)  return 28;
   if (n == 9)  return 29;
   if (n == 10) return 30;
   return 31;                                 /* r30 */
}
/* real GPR n as a host register. */
static inline HReg hregOR1K_GPR ( UInt n ) {
   return mkHReg(False, HRcInt32, n, or1k_gpr_ix(n));
}

typedef enum {
   OR1Kalu_ADD=0x000, OR1Kalu_SUB=0x002, OR1Kalu_AND=0x003,
   OR1Kalu_OR =0x004, OR1Kalu_XOR=0x005, OR1Kalu_SLL=0x008,
   OR1Kalu_SRL=0x048, OR1Kalu_SRA=0x088, OR1Kalu_MUL=0x306,
   OR1Kalu_CMOV=0x00e
} OR1KAluOp;   /* value is the opcode 0x38 op11 field */

typedef enum {
   OR1Kext_EXTHS=0x00c, OR1Kext_EXTBS=0x04c,
   OR1Kext_EXTHZ=0x08c, OR1Kext_EXTBZ=0x0cc
} OR1KExtOp;

/* AL = unconditional; F/NF = take the transfer iff SR[F] set / clear. */
typedef enum { OR1Kcc_AL, OR1Kcc_F, OR1Kcc_NF } OR1KCondCode;

typedef enum {
   OR1Kin_Alu, OR1Kin_AluI, OR1Kin_ShiftI, OR1Kin_MovHi,
   OR1Kin_Load, OR1Kin_Store, OR1Kin_Cmp, OR1Kin_CmpI, OR1Kin_Ext,
   OR1Kin_XDirect, OR1Kin_XIndir, OR1Kin_XAssisted
} OR1KInstrTag;

typedef struct {
   OR1KInstrTag tag;
   union {
      struct { OR1KAluOp op; HReg dst, srcL, srcR;   } Alu;
      struct { UInt opc;     HReg dst, src; UShort imm; } AluI;   /* addi/andi/ori/xori */
      struct { UInt type;    HReg dst, src; UChar amt;  } ShiftI;
      struct { HReg dst; UShort imm;                    } MovHi;
      struct { UInt opc; HReg dst, base; Short disp;    } Load;   /* lwz/lbz/.. */
      struct { UInt opc; HReg base, src; Short disp;    } Store;  /* sw/sb/sh */
      struct { UInt code; HReg srcL, srcR;              } Cmp;
      struct { UInt code; HReg src; UShort imm;         } CmpI;
      struct { OR1KExtOp op; HReg dst, src;             } Ext;
      struct { UInt dstGA; Int pcOff; OR1KCondCode cond; } XDirect;
      struct { HReg dstGA; Int pcOff; OR1KCondCode cond; } XIndir;
      struct { HReg dstGA; Int pcOff; OR1KCondCode cond; IRJumpKind jk; } XAssisted;
   } OR1Kin;
} OR1KInstr;

extern OR1KInstr* OR1KInstr_Alu    ( OR1KAluOp, HReg dst, HReg srcL, HReg srcR );
extern OR1KInstr* OR1KInstr_AluI   ( UInt opc, HReg dst, HReg src, UShort imm );
extern OR1KInstr* OR1KInstr_ShiftI ( UInt type, HReg dst, HReg src, UChar amt );
extern OR1KInstr* OR1KInstr_MovHi  ( HReg dst, UShort imm );
extern OR1KInstr* OR1KInstr_Load   ( UInt opc, HReg dst, HReg base, Short disp );
extern OR1KInstr* OR1KInstr_Store  ( UInt opc, HReg base, HReg src, Short disp );
extern OR1KInstr* OR1KInstr_Cmp    ( UInt code, HReg srcL, HReg srcR );
extern OR1KInstr* OR1KInstr_CmpI   ( UInt code, HReg src, UShort imm );
extern OR1KInstr* OR1KInstr_Ext    ( OR1KExtOp, HReg dst, HReg src );
extern OR1KInstr* OR1KInstr_XDirect   ( UInt dstGA, Int pcOff, OR1KCondCode );
extern OR1KInstr* OR1KInstr_XIndir    ( HReg dstGA, Int pcOff, OR1KCondCode );
extern OR1KInstr* OR1KInstr_XAssisted ( HReg dstGA, Int pcOff, OR1KCondCode, IRJumpKind );

extern void ppOR1KInstr ( const OR1KInstr* i );

/* encode one instruction into buf (4 bytes, MSB-first); returns 4. */
extern Int emit_OR1KInstr ( UChar* buf, Int nbuf, const OR1KInstr* i );

/* r30 is the host-side guest-state pointer; r0 is hardwired zero.  Both */
/* are reserved from allocation. */
#define OR1K_GSP  (hregOR1K_GPR(30))
#define OR1K_ZERO (hregOR1K_GPR(0))

extern const RRegUniverse* getRRegUniverse_OR1K ( void );
extern void  getRegUsage_OR1K ( HRegUsage*, const OR1KInstr*, Bool );
extern void  mapRegs_OR1K     ( HRegRemap*, OR1KInstr*, Bool );
extern void  genSpill_OR1K    ( HInstr**, HInstr**, HReg, Int, Bool );
extern void  genReload_OR1K   ( HInstr**, HInstr**, HReg, Int, Bool );
extern HInstr* genMove_OR1K   ( HReg from, HReg to, Bool );
extern UInt  ppHRegOR1K       ( HReg );

extern HInstrArray* iselSB_OR1K ( const IRSB*, VexArch, const VexArchInfo*,
                                  const VexAbiInfo*, Int, Int, Bool, Bool, Addr );

#endif /* ndef __VEX_HOST_OR1K_DEFS_H */

/*---------------------------------------------------------------*/
/*--- end                                    host_or1k_defs.h ---*/
/*---------------------------------------------------------------*/
