/*---------------------------------------------------------------*/
/*--- begin                                 guest_or1k_toIR.c ---*/
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

/* Translates ORBIS32 (OpenRISC 1000, 32-bit) into VEX IR. Integer   */
/* subset for the bring-up; FPU and the rarer ops come later.        */

#include "libvex_basictypes.h"
#include "libvex_ir.h"
#include "libvex.h"
#include "libvex_guest_or1k.h"

#include "main_util.h"
#include "main_globals.h"
#include "guest_generic_bb_to_IR.h"
#include "guest_or1k_defs.h"

/*--- globals ---*/

/* the IRSB we append to, set once per instruction by disInstr_OR1K. */
static IRSB* irsb;

/* or1k is big-endian, so memory refs use Iend_BE. */
#define OR1K_ENDNESS Iend_BE

/* disassembly print, gated on the front-end trace flag. */
#define DIP(format, args...)           \
   if (vex_traceflags & VEX_TRACE_FE)  \
      vex_printf(format, ## args)

/*--- IR helpers ---*/

static IRExpr* mkU32 ( UInt i )        { return IRExpr_Const(IRConst_U32(i)); }
static void    stmt  ( IRStmt* st )    { addStmtToIRSB(irsb, st); }
static IRTemp  newTemp ( IRType ty )   { return newIRTemp(irsb->tyenv, ty); }
static IRExpr* mkexpr ( IRTemp t )     { return IRExpr_RdTmp(t); }
static void    assign ( IRTemp t, IRExpr* e ) { stmt(IRStmt_WrTmp(t, e)); }
static IRExpr* unop  ( IROp op, IRExpr* a )            { return IRExpr_Unop(op, a); }
static IRExpr* binop ( IROp op, IRExpr* a, IRExpr* b ) { return IRExpr_Binop(op, a, b); }
static IRExpr* load32 ( IRExpr* addr ) { return IRExpr_Load(OR1K_ENDNESS, Ity_I32, addr); }

#define OFFB(_f)  offsetof(VexGuestOR1KState, _f)
#define OFFB_PC   OFFB(guest_PC)

/* r0 always reads 0 and writes to it are dropped. */
static UInt gprOff ( UInt n ) { return OFFB(guest_r0) + 4 * n; }
static IRExpr* getIReg ( UInt n ) {
   return n == 0 ? mkU32(0) : IRExpr_Get(gprOff(n), Ity_I32);
}
static void putIReg ( UInt n, IRExpr* e ) {
   if (n != 0) stmt(IRStmt_Put(gprOff(n), e));
}
static IRExpr* getSR_F ( void )        { return IRExpr_Get(OFFB(guest_SR_F), Ity_I32); }
static void    putSR_F ( IRExpr* e )   { stmt(IRStmt_Put(OFFB(guest_SR_F), e)); }
static void    putPC   ( IRExpr* e )   { stmt(IRStmt_Put(OFFB_PC, e)); }

/*--- bit twiddling ---*/

static UInt fetch32BE ( const UChar* p ) {
   return ((UInt)p[0] << 24) | ((UInt)p[1] << 16)
        | ((UInt)p[2] <<  8) | ((UInt)p[3]);
}
static UInt sext16 ( UInt x ) { return (UInt)(((Int)(x << 16)) >> 16); }
static Int  sext26 ( UInt x ) { x &= 0x03FFFFFF;
                                return (Int)(x & 0x02000000 ? x | 0xFC000000 : x); }

/* insn field extractors (ORBIS32 layout). */
static UInt opcOf ( UInt i ) { return i >> 26; }
static UInt rD    ( UInt i ) { return (i >> 21) & 0x1F; }
static UInt rA    ( UInt i ) { return (i >> 16) & 0x1F; }
static UInt rB    ( UInt i ) { return (i >> 11) & 0x1F; }
static UInt imm16 ( UInt i ) { return i & 0xFFFF; }

/* set SR[F] from an Ity_I1 condition. */
static void setFlagFrom ( IRExpr* condI1 ) {
   putSR_F(unop(Iop_1Uto32, condI1));
}

/* build the Ity_I1 for one l.sf* comparison code, comparing a and b. */
static IRExpr* mkCompare ( UInt code, IRExpr* a, IRExpr* b ) {
   switch (code) {
      case 0x0: return binop(Iop_CmpEQ32, a, b);              /* sfeq  */
      case 0x1: return binop(Iop_CmpNE32, a, b);              /* sfne  */
      case 0x2: return binop(Iop_CmpLT32U, b, a);             /* sfgtu */
      case 0x3: return binop(Iop_CmpLE32U, b, a);             /* sfgeu */
      case 0x4: return binop(Iop_CmpLT32U, a, b);             /* sfltu */
      case 0x5: return binop(Iop_CmpLE32U, a, b);             /* sfleu */
      case 0xa: return binop(Iop_CmpLT32S, b, a);             /* sfgts */
      case 0xb: return binop(Iop_CmpLE32S, b, a);             /* sfges */
      case 0xc: return binop(Iop_CmpLT32S, a, b);             /* sflts */
      case 0xd: return binop(Iop_CmpLE32S, a, b);             /* sfles */
      default:  return NULL;
   }
}

/*--- one non-control insn -> IR (returns False if unrecognised) ---*/

static Bool dis_simple ( UInt insn )
{
   UInt op = opcOf(insn);

   switch (op) {

      case 0x05:                                  /* l.nop */
         DIP("l.nop 0x%x\n", imm16(insn));
         return True;

      case 0x06:                                  /* l.movhi (bit16==0) */
         if ((insn >> 16) & 1) return False;      /* l.macrc: later */
         DIP("l.movhi r%u,0x%x\n", rD(insn), imm16(insn));
         putIReg(rD(insn), mkU32(imm16(insn) << 16));
         return True;

      case 0x27:                                  /* l.addi rD,rA,imm (signed) */
         DIP("l.addi r%u,r%u,%d\n", rD(insn), rA(insn), (Int)sext16(imm16(insn)));
         putIReg(rD(insn), binop(Iop_Add32, getIReg(rA(insn)),
                                 mkU32(sext16(imm16(insn)))));
         return True;

      case 0x29:                                  /* l.andi rD,rA,imm (zero-ext) */
         DIP("l.andi r%u,r%u,0x%x\n", rD(insn), rA(insn), imm16(insn));
         putIReg(rD(insn), binop(Iop_And32, getIReg(rA(insn)), mkU32(imm16(insn))));
         return True;

      case 0x2a:                                  /* l.ori rD,rA,imm (zero-ext) */
         DIP("l.ori r%u,r%u,0x%x\n", rD(insn), rA(insn), imm16(insn));
         putIReg(rD(insn), binop(Iop_Or32, getIReg(rA(insn)), mkU32(imm16(insn))));
         return True;

      case 0x21: {                                /* l.lwz rD,imm(rA) */
         IRExpr* ea = binop(Iop_Add32, getIReg(rA(insn)), mkU32(sext16(imm16(insn))));
         DIP("l.lwz r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), load32(ea));
         return True;
      }

      case 0x35: {                                /* l.sw imm(rA),rB (split imm) */
         UInt imm = (rD(insn) << 11) | (insn & 0x7FF);
         IRExpr* ea = binop(Iop_Add32, getIReg(rA(insn)), mkU32(sext16(imm)));
         DIP("l.sw %d(r%u),r%u\n", (Int)sext16(imm), rA(insn), rB(insn));
         stmt(IRStmt_Store(OR1K_ENDNESS, ea, getIReg(rB(insn))));
         return True;
      }

      case 0x38: {                                /* ALU rD,rA,rB (opcode2 in [9:6],[3:0]) */
         if ((insn >> 6) & 0xF) return False;     /* shift/extend variants: later */
         IROp iop;
         const HChar* nm;
         switch (insn & 0xF) {
            case 0x0: iop = Iop_Add32; nm = "l.add"; break;
            case 0x2: iop = Iop_Sub32; nm = "l.sub"; break;
            case 0x3: iop = Iop_And32; nm = "l.and"; break;
            case 0x4: iop = Iop_Or32;  nm = "l.or";  break;
            case 0x5: iop = Iop_Xor32; nm = "l.xor"; break;
            default:  return False;
         }
         DIP("%s r%u,r%u,r%u\n", nm, rD(insn), rA(insn), rB(insn));
         putIReg(rD(insn), binop(iop, getIReg(rA(insn)), getIReg(rB(insn))));
         return True;
      }

      case 0x2f: {                                /* l.sf*i rA,imm (code in rD field) */
         IRExpr* c = mkCompare(rD(insn), getIReg(rA(insn)), mkU32(sext16(imm16(insn))));
         if (!c) return False;
         DIP("l.sf*i(0x%x) r%u,%d\n", rD(insn), rA(insn), (Int)sext16(imm16(insn)));
         setFlagFrom(c);
         return True;
      }

      case 0x39: {                                /* l.sf* rA,rB (code in rD field) */
         IRExpr* c = mkCompare(rD(insn), getIReg(rA(insn)), getIReg(rB(insn)));
         if (!c) return False;
         DIP("l.sf*(0x%x) r%u,r%u\n", rD(insn), rA(insn), rB(insn));
         setFlagFrom(c);
         return True;
      }

      default:
         return False;
   }
}

/* decode the single delay-slot insn at delta. a branch there is illegal. */
static Bool dis_delay_slot ( const UChar* code, Long delta )
{
   UInt insn = fetch32BE(code + delta);
   UInt op   = opcOf(insn);
   if (op==0x00 || op==0x01 || op==0x03 || op==0x04 ||
       op==0x08 || op==0x09 || op==0x11 || op==0x12)
      return False;                              /* control insn in delay slot */
   return dis_simple(insn);
}

/*--- the per-instruction dispatcher ---*/

static DisResult disInstr_OR1K_WRK ( const UChar* code, Long delta,
                                     Addr guest_IP, Bool sigill_diag )
{
   DisResult dres;
   UInt insn = fetch32BE(code + delta);
   UInt pc   = (UInt)guest_IP;

   dres.len         = 4;
   dres.whatNext    = Dis_Continue;
   dres.hint        = Dis_HintNone;
   dres.jk_StopHere = Ijk_INVALID;

   switch (opcOf(insn)) {

      case 0x00: {                               /* l.j N */
         UInt target = pc + (UInt)(sext26(insn) << 2);
         DIP("l.j 0x%x\n", target);
         if (!dis_delay_slot(code, delta + 4)) goto decode_failure;
         putPC(mkU32(target));
         dres.len = 8; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Boring;
         break;
      }

      case 0x01: {                               /* l.jal N (link in r9) */
         UInt target = pc + (UInt)(sext26(insn) << 2);
         DIP("l.jal 0x%x\n", target);
         putIReg(9, mkU32(pc + 8));
         if (!dis_delay_slot(code, delta + 4)) goto decode_failure;
         putPC(mkU32(target));
         dres.len = 8; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Call;
         break;
      }

      case 0x03:                                 /* l.bnf N */
      case 0x04: {                               /* l.bf  N */
         Bool isBf = opcOf(insn) == 0x04;
         UInt target = pc + (UInt)(sext26(insn) << 2);
         IRTemp cond = newTemp(Ity_I1);
         /* capture the flag before the delay slot runs. */
         assign(cond, binop(isBf ? Iop_CmpNE32 : Iop_CmpEQ32, getSR_F(), mkU32(0)));
         DIP("%s 0x%x\n", isBf ? "l.bf" : "l.bnf", target);
         if (!dis_delay_slot(code, delta + 4)) goto decode_failure;
         stmt(IRStmt_Exit(mkexpr(cond), Ijk_Boring, IRConst_U32(target), OFFB_PC));
         putPC(mkU32(pc + 8));                   /* not-taken falls past delay slot */
         dres.len = 8; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Boring;
         break;
      }

      case 0x11: {                               /* l.jr rB */
         IRTemp t = newTemp(Ity_I32);
         assign(t, getIReg(rB(insn)));           /* capture before delay slot */
         DIP("l.jr r%u\n", rB(insn));
         if (!dis_delay_slot(code, delta + 4)) goto decode_failure;
         putPC(mkexpr(t));
         dres.len = 8; dres.whatNext = Dis_StopHere;
         dres.jk_StopHere = rB(insn) == 9 ? Ijk_Ret : Ijk_Boring;
         break;
      }

      case 0x12: {                               /* l.jalr rB (link in r9) */
         IRTemp t = newTemp(Ity_I32);
         assign(t, getIReg(rB(insn)));
         DIP("l.jalr r%u\n", rB(insn));
         putIReg(9, mkU32(pc + 8));
         if (!dis_delay_slot(code, delta + 4)) goto decode_failure;
         putPC(mkexpr(t));
         dres.len = 8; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Call;
         break;
      }

      case 0x08:                                 /* l.sys (system group) */
         DIP("l.sys 0x%x\n", imm16(insn));
         putPC(mkU32(pc + 4));
         dres.len = 4; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Sys_syscall;
         break;

      default:
         if (!dis_simple(insn)) goto decode_failure;
         break;
   }

   return dres;

  decode_failure:
   if (sigill_diag)
      vex_printf("disInstr(or1k): unhandled instruction 0x%08x\n", insn);
   putPC(mkU32(pc));
   dres.len = 0; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_NoDecode;
   return dres;
}

/*--- the top-level entry point (a DisOneInstrFn) ---*/

DisResult disInstr_OR1K ( IRSB*        irsb_IN,
                          const UChar* guest_code,
                          Long         delta,
                          Addr         guest_IP,
                          VexArch      guest_arch,
                          const VexArchInfo* archinfo,
                          const VexAbiInfo*  abiinfo,
                          VexEndness   host_endness,
                          Bool         sigill_diag )
{
   irsb = irsb_IN;
   vassert(guest_arch == VexArchOR1K);
   return disInstr_OR1K_WRK(guest_code, delta, guest_IP, sigill_diag);
}

/*---------------------------------------------------------------*/
/*--- end                                   guest_or1k_toIR.c ---*/
/*---------------------------------------------------------------*/
