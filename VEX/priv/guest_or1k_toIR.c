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
static IRExpr* mkU8  ( UInt i )        { return IRExpr_Const(IRConst_U8((UChar)i)); }
static void    stmt  ( IRStmt* st )    { addStmtToIRSB(irsb, st); }
static IRTemp  newTemp ( IRType ty )   { return newIRTemp(irsb->tyenv, ty); }
static IRExpr* mkexpr ( IRTemp t )     { return IRExpr_RdTmp(t); }
static void    assign ( IRTemp t, IRExpr* e ) { stmt(IRStmt_WrTmp(t, e)); }
static IRExpr* unop  ( IROp op, IRExpr* a )            { return IRExpr_Unop(op, a); }
static IRExpr* binop ( IROp op, IRExpr* a, IRExpr* b ) { return IRExpr_Binop(op, a, b); }
static IRExpr* load32 ( IRExpr* addr ) { return IRExpr_Load(OR1K_ENDNESS, Ity_I32, addr); }
static IRExpr* load16 ( IRExpr* addr ) { return IRExpr_Load(OR1K_ENDNESS, Ity_I16, addr); }
static IRExpr* load8  ( IRExpr* addr ) { return IRExpr_Load(OR1K_ENDNESS, Ity_I8,  addr); }

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
static IRExpr* getSR_CY ( void )       { return IRExpr_Get(OFFB(guest_SR_CY), Ity_I32); }
static void    putSR_CY ( IRExpr* e )  { stmt(IRStmt_Put(OFFB(guest_SR_CY), e)); }
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

/* effective address for the base+disp memory forms. */
static IRExpr* memEA ( UInt insn ) {
   return binop(Iop_Add32, getIReg(rA(insn)), mkU32(sext16(imm16(insn))));
}
/* split immediate shared by l.sw/l.sb/l.sh. */
static UInt splitImm ( UInt insn ) {
   return sext16((rD(insn) << 11) | (insn & 0x7FF));
}

/* rD = a + b (+ carry in), writing the unsigned carry out to SR[CY]. */
/* SR[OV] is left alone: user mode cannot read it without SPR access. */
static void addSettingCarry ( UInt rd, IRExpr* ea, IRExpr* eb, Bool withCarryIn )
{
   IRTemp a = newTemp(Ity_I32), b = newTemp(Ity_I32), s = newTemp(Ity_I32);
   assign(a, ea);
   assign(b, eb);
   assign(s, binop(Iop_Add32, mkexpr(a), mkexpr(b)));
   if (!withCarryIn) {
      putSR_CY(unop(Iop_1Uto32, binop(Iop_CmpLT32U, mkexpr(s), mkexpr(a))));
      putIReg(rd, mkexpr(s));
      return;
   }
   /* the carry in can carry a second time, so fold both carries together. */
   IRTemp t = newTemp(Ity_I32), c1 = newTemp(Ity_I32), c2 = newTemp(Ity_I32);
   assign(t, binop(Iop_Add32, mkexpr(s), getSR_CY()));
   assign(c1, unop(Iop_1Uto32, binop(Iop_CmpLT32U, mkexpr(s), mkexpr(a))));
   assign(c2, unop(Iop_1Uto32, binop(Iop_CmpLT32U, mkexpr(t), mkexpr(s))));
   putSR_CY(binop(Iop_Or32, mkexpr(c1), mkexpr(c2)));
   putIReg(rd, mkexpr(t));
}

/* rotate right by the low 5 bits of the amount; amount 0 rotates by 0. */
static IRExpr* rotateRight32 ( IRExpr* val, IRExpr* amt32 )
{
   IRTemp v = newTemp(Ity_I32), n = newTemp(Ity_I32);
   assign(v, val);
   assign(n, binop(Iop_And32, amt32, mkU32(31)));
   return binop(Iop_Or32,
                binop(Iop_Shr32, mkexpr(v), unop(Iop_32to8, mkexpr(n))),
                binop(Iop_Shl32, mkexpr(v),
                      unop(Iop_32to8, binop(Iop_And32,
                                            binop(Iop_Sub32, mkU32(32),
                                                  mkexpr(n)),
                                            mkU32(31)))));
}

static Bool dis_simple ( UInt insn, UInt pc )
{
   UInt op = opcOf(insn);

   switch (op) {

      case 0x02:                                  /* l.adrp rD,imm (page base) */
         /* the immediate counts 8K pages from the page holding this insn. */
         DIP("l.adrp r%u,0x%x\n", rD(insn), insn & 0x1FFFFF);
         putIReg(rD(insn), mkU32((pc & ~0x1FFFu)
                                 + (((UInt)(((Int)(insn << 11)) >> 11)) << 13)));
         return True;

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
         addSettingCarry(rD(insn), getIReg(rA(insn)),
                         mkU32(sext16(imm16(insn))), False);
         return True;

      case 0x28:                                  /* l.addic rD,rA,imm (+SR[CY]) */
         DIP("l.addic r%u,r%u,%d\n", rD(insn), rA(insn), (Int)sext16(imm16(insn)));
         addSettingCarry(rD(insn), getIReg(rA(insn)),
                         mkU32(sext16(imm16(insn))), True);
         return True;

      case 0x2c:                                  /* l.muli rD,rA,imm (signed) */
         DIP("l.muli r%u,r%u,%d\n", rD(insn), rA(insn), (Int)sext16(imm16(insn)));
         putIReg(rD(insn), binop(Iop_Mul32, getIReg(rA(insn)),
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

      case 0x2b:                                  /* l.xori rD,rA,imm (signed) */
         DIP("l.xori r%u,r%u,0x%x\n", rD(insn), rA(insn), imm16(insn));
         putIReg(rD(insn), binop(Iop_Xor32, getIReg(rA(insn)),
                                 mkU32(sext16(imm16(insn)))));
         return True;

      case 0x2e: {                                /* l.slli/srli/srai/rori rD,rA,L */
         UInt amt = insn & 0x3F;
         IRExpr* a = getIReg(rA(insn));
         IROp iop;
         const HChar* nm;
         switch ((insn >> 6) & 0x3) {
            case 0: iop = Iop_Shl32; nm = "l.slli"; break;
            case 1: iop = Iop_Shr32; nm = "l.srli"; break;
            case 2: iop = Iop_Sar32; nm = "l.srai"; break;
            default:
               DIP("l.rori r%u,r%u,0x%x\n", rD(insn), rA(insn), amt);
               putIReg(rD(insn), rotateRight32(a, mkU32(amt)));
               return True;
         }
         DIP("%s r%u,r%u,0x%x\n", nm, rD(insn), rA(insn), amt);
         putIReg(rD(insn), binop(iop, a, mkU8(amt)));
         return True;
      }

      case 0x1b:                                  /* l.lwa rD,imm(rA) (load-linked) */
         /* single-threaded guest: a plain word load is enough. */
         DIP("l.lwa r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), load32(memEA(insn)));
         return True;

      case 0x22:                                  /* l.lws rD,imm(rA) */
         /* a 32-bit sign-extending word load is just a word load here. */
         DIP("l.lws r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), load32(memEA(insn)));
         return True;

      case 0x21:                                  /* l.lwz rD,imm(rA) */
         DIP("l.lwz r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), load32(memEA(insn)));
         return True;

      case 0x23:                                  /* l.lbz (byte, zero-ext) */
         DIP("l.lbz r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), unop(Iop_8Uto32, load8(memEA(insn))));
         return True;

      case 0x24:                                  /* l.lbs (byte, sign-ext) */
         DIP("l.lbs r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), unop(Iop_8Sto32, load8(memEA(insn))));
         return True;

      case 0x25:                                  /* l.lhz (half, zero-ext) */
         DIP("l.lhz r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), unop(Iop_16Uto32, load16(memEA(insn))));
         return True;

      case 0x26:                                  /* l.lhs (half, sign-ext) */
         DIP("l.lhs r%u,%d(r%u)\n", rD(insn), (Int)sext16(imm16(insn)), rA(insn));
         putIReg(rD(insn), unop(Iop_16Sto32, load16(memEA(insn))));
         return True;

      case 0x33: {                                /* l.swa imm(rA),rB (store-cond.) */
         /* single-threaded guest: the store always succeeds, so set SR[F]. */
         IRExpr* ea = binop(Iop_Add32, getIReg(rA(insn)), mkU32(splitImm(insn)));
         DIP("l.swa %d(r%u),r%u\n", (Int)splitImm(insn), rA(insn), rB(insn));
         stmt(IRStmt_Store(OR1K_ENDNESS, ea, getIReg(rB(insn))));
         putSR_F(mkU32(1));
         return True;
      }

      case 0x35: {                                /* l.sw imm(rA),rB */
         IRExpr* ea = binop(Iop_Add32, getIReg(rA(insn)), mkU32(splitImm(insn)));
         DIP("l.sw %d(r%u),r%u\n", (Int)splitImm(insn), rA(insn), rB(insn));
         stmt(IRStmt_Store(OR1K_ENDNESS, ea, getIReg(rB(insn))));
         return True;
      }

      case 0x36: {                                /* l.sb imm(rA),rB (low 8) */
         IRExpr* ea = binop(Iop_Add32, getIReg(rA(insn)), mkU32(splitImm(insn)));
         DIP("l.sb %d(r%u),r%u\n", (Int)splitImm(insn), rA(insn), rB(insn));
         stmt(IRStmt_Store(OR1K_ENDNESS, ea, unop(Iop_32to8, getIReg(rB(insn)))));
         return True;
      }

      case 0x37: {                                /* l.sh imm(rA),rB (low 16) */
         IRExpr* ea = binop(Iop_Add32, getIReg(rA(insn)), mkU32(splitImm(insn)));
         DIP("l.sh %d(r%u),r%u\n", (Int)splitImm(insn), rA(insn), rB(insn));
         stmt(IRStmt_Store(OR1K_ENDNESS, ea, unop(Iop_32to16, getIReg(rB(insn)))));
         return True;
      }

      case 0x38: {                                /* register ALU / shift / extend / mul */
         UInt opc2 = (insn >> 8) & 0x3;
         UInt opc3 = insn & 0xF;
         if (opc2 == 0) {
            switch (opc3) {
               case 0x0:                          /* l.add rD,rA,rB */
                  DIP("l.add r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
                  addSettingCarry(rD(insn), getIReg(rA(insn)), getIReg(rB(insn)),
                                  False);
                  return True;

               case 0x1:                          /* l.addc rD,rA,rB (+SR[CY]) */
                  DIP("l.addc r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
                  addSettingCarry(rD(insn), getIReg(rA(insn)), getIReg(rB(insn)),
                                  True);
                  return True;

               case 0x2: {                        /* l.sub rD,rA,rB */
                  IRTemp a = newTemp(Ity_I32), b = newTemp(Ity_I32);
                  assign(a, getIReg(rA(insn)));
                  assign(b, getIReg(rB(insn)));
                  DIP("l.sub r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
                  /* SR[CY] is the borrow out of the subtraction. */
                  putSR_CY(unop(Iop_1Uto32,
                                binop(Iop_CmpLT32U, mkexpr(a), mkexpr(b))));
                  putIReg(rD(insn), binop(Iop_Sub32, mkexpr(a), mkexpr(b)));
                  return True;
               }

               case 0x3: case 0x4: case 0x5: {
                  IROp iop; const HChar* nm;
                  switch (opc3) {
                     case 0x3: iop = Iop_And32; nm = "l.and"; break;
                     case 0x4: iop = Iop_Or32;  nm = "l.or";  break;
                     default:  iop = Iop_Xor32; nm = "l.xor"; break;
                  }
                  DIP("%s r%u,r%u,r%u\n", nm, rD(insn), rA(insn), rB(insn));
                  putIReg(rD(insn), binop(iop, getIReg(rA(insn)), getIReg(rB(insn))));
                  return True;
               }
               case 0x8: {                        /* l.sll/srl/sra rD,rA,rB */
                  IROp iop; const HChar* nm;
                  IRExpr* amt = unop(Iop_32to8,
                                     binop(Iop_And32, getIReg(rB(insn)), mkU32(0x1F)));
                  switch ((insn >> 6) & 0x3) {
                     case 0: iop = Iop_Shl32; nm = "l.sll"; break;
                     case 1: iop = Iop_Shr32; nm = "l.srl"; break;
                     case 2: iop = Iop_Sar32; nm = "l.sra"; break;
                     default:
                        DIP("l.ror r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
                        putIReg(rD(insn), rotateRight32(getIReg(rA(insn)),
                                                        getIReg(rB(insn))));
                        return True;
                  }
                  DIP("%s r%u,r%u,r%u\n", nm, rD(insn), rA(insn), rB(insn));
                  putIReg(rD(insn), binop(iop, getIReg(rA(insn)), amt));
                  return True;
               }
               case 0xc: {                        /* l.ext{b,h}{s,z} rD,rA */
                  IROp iop; const HChar* nm;
                  switch ((insn >> 6) & 0x3) {
                     case 0: iop = Iop_16Sto32; nm = "l.exths"; goto half;
                     case 2: iop = Iop_16Uto32; nm = "l.exthz"; goto half;
                     case 1: iop = Iop_8Sto32;  nm = "l.extbs"; goto byte;
                     default: iop = Iop_8Uto32;  nm = "l.extbz"; goto byte;
                  }
                half:
                  DIP("%s r%u,r%u\n", nm, rD(insn), rA(insn));
                  putIReg(rD(insn), unop(iop, unop(Iop_32to16, getIReg(rA(insn)))));
                  return True;
                byte:
                  DIP("%s r%u,r%u\n", nm, rD(insn), rA(insn));
                  putIReg(rD(insn), unop(iop, unop(Iop_32to8, getIReg(rA(insn)))));
                  return True;
               }
               case 0xd:                          /* l.extw{s,z}: 32-bit no-op */
                  DIP("%s r%u,r%u\n", ((insn >> 6) & 0x3) == 0 ? "l.extws"
                                                              : "l.extwz",
                      rD(insn), rA(insn));
                  putIReg(rD(insn), getIReg(rA(insn)));
                  return True;

               case 0xe:                          /* l.cmov rD,rA,rB (on SR[F]) */
                  DIP("l.cmov r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
                  putIReg(rD(insn),
                          IRExpr_ITE(binop(Iop_CmpNE32, getSR_F(), mkU32(0)),
                                     getIReg(rA(insn)), getIReg(rB(insn))));
                  return True;

               case 0xf: {                        /* l.ff1 rD,rA (lowest set bit) */
                  IRTemp a = newTemp(Ity_I32);
                  assign(a, getIReg(rA(insn)));
                  DIP("l.ff1 r%u,r%u\n", rD(insn), rA(insn));
                  /* one-based index of the lowest set bit, or 0 for no bits. */
                  putIReg(rD(insn),
                          IRExpr_ITE(binop(Iop_CmpEQ32, mkexpr(a), mkU32(0)),
                                     mkU32(0),
                                     binop(Iop_Add32,
                                           unop(Iop_CtzNat32, mkexpr(a)),
                                           mkU32(1))));
                  return True;
               }
               default: return False;
            }
         } else if (opc2 == 1 && opc3 == 0xf) {   /* l.fl1 rD,rA (highest set bit) */
            IRTemp a = newTemp(Ity_I32);
            assign(a, getIReg(rA(insn)));
            DIP("l.fl1 r%u,r%u\n", rD(insn), rA(insn));
            /* one-based index of the highest set bit; an all-zero word */
            /* counts 32 leading zeroes, which gives the required 0. */
            putIReg(rD(insn), binop(Iop_Sub32, mkU32(32),
                                    unop(Iop_ClzNat32, mkexpr(a))));
            return True;
         } else if (opc2 == 3 && opc3 == 0xb) {   /* l.mulu rD,rA,rB */
            /* the low 32 bits are the same for a signed or unsigned product. */
            DIP("l.mulu r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
            putIReg(rD(insn), binop(Iop_Mul32, getIReg(rA(insn)), getIReg(rB(insn))));
            return True;
         } else if (opc2 == 3 && opc3 == 0x6) {   /* l.mul rD,rA,rB */
            DIP("l.mul r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
            putIReg(rD(insn), binop(Iop_Mul32, getIReg(rA(insn)), getIReg(rB(insn))));
            return True;
         } else if (opc2 == 3 && opc3 == 0x9) {   /* l.div rD,rA,rB (signed) */
            DIP("l.div r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
            putIReg(rD(insn), binop(Iop_DivS32, getIReg(rA(insn)), getIReg(rB(insn))));
            return True;
         } else if (opc2 == 3 && opc3 == 0xa) {   /* l.divu rD,rA,rB (unsigned) */
            DIP("l.divu r%u,r%u,r%u\n", rD(insn), rA(insn), rB(insn));
            putIReg(rD(insn), binop(Iop_DivU32, getIReg(rA(insn)), getIReg(rB(insn))));
            return True;
         }
         return False;
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
static Bool dis_delay_slot ( const UChar* code, Long delta, UInt pc )
{
   UInt insn = fetch32BE(code + delta);
   UInt op   = opcOf(insn);
   if (op==0x00 || op==0x01 || op==0x03 || op==0x04 ||
       op==0x08 || op==0x09 || op==0x11 || op==0x12)
      return False;                              /* control insn in delay slot */
   return dis_simple(insn, pc);
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

   /* Client-request magic: l.srli r0,r0,{13,29,3,19} then a marker word. */
   if (insn == 0xB800004Du
       && fetch32BE(code + delta + 4)  == 0xB800005Du
       && fetch32BE(code + delta + 8)  == 0xB8000043u
       && fetch32BE(code + delta + 12) == 0xB8000053u) {
      UInt mark = fetch32BE(code + delta + 16);
      if (mark == 0xE1AD6804u) {                 /* l.or r13,r13,r13: request */
         DIP("or1k-clientreq\n");
         putPC(mkU32(pc + 20));
         dres.len = 20; dres.whatNext = Dis_StopHere;
         dres.jk_StopHere = Ijk_ClientReq;
         return dres;
      }
      if (mark == 0xE1CE7004u) {                 /* l.or r14,r14,r14: NRADDR */
         DIP("or1k-get-nraddr\n");
         putIReg(11, IRExpr_Get(offsetof(VexGuestOR1KState, guest_NRADDR),
                                Ity_I32));
         putPC(mkU32(pc + 20));
         dres.len = 20;
         return dres;
      }
      if (mark == 0xE1EF7804u) {                 /* l.or r15,r15,r15: noredir */
         DIP("or1k-call-noredir-r25\n");
         putIReg(9, mkU32(pc + 20));
         putPC(getIReg(25));
         dres.len = 20; dres.whatNext = Dis_StopHere;
         dres.jk_StopHere = Ijk_NoRedir;
         return dres;
      }
      /* no marker: the shifts are architectural no-ops, decode normally. */
   }

   switch (opcOf(insn)) {

      case 0x00: {                               /* l.j N */
         UInt target = pc + (UInt)(sext26(insn) << 2);
         DIP("l.j 0x%x\n", target);
         if (!dis_delay_slot(code, delta + 4, pc + 4)) goto decode_failure;
         putPC(mkU32(target));
         dres.len = 8; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Boring;
         break;
      }

      case 0x01: {                               /* l.jal N (link in r9) */
         UInt target = pc + (UInt)(sext26(insn) << 2);
         DIP("l.jal 0x%x\n", target);
         putIReg(9, mkU32(pc + 8));
         if (!dis_delay_slot(code, delta + 4, pc + 4)) goto decode_failure;
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
         if (!dis_delay_slot(code, delta + 4, pc + 4)) goto decode_failure;
         stmt(IRStmt_Exit(mkexpr(cond), Ijk_Boring, IRConst_U32(target), OFFB_PC));
         putPC(mkU32(pc + 8));                   /* not-taken falls past delay slot */
         dres.len = 8; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Boring;
         break;
      }

      case 0x11: {                               /* l.jr rB */
         IRTemp t = newTemp(Ity_I32);
         assign(t, getIReg(rB(insn)));           /* capture before delay slot */
         DIP("l.jr r%u\n", rB(insn));
         if (!dis_delay_slot(code, delta + 4, pc + 4)) goto decode_failure;
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
         if (!dis_delay_slot(code, delta + 4, pc + 4)) goto decode_failure;
         putPC(mkexpr(t));
         dres.len = 8; dres.whatNext = Dis_StopHere; dres.jk_StopHere = Ijk_Call;
         break;
      }

      case 0x08:                                 /* l.sys/l.trap/the syncs */
         switch ((insn >> 16) & 0x3FF) {
            case 0x000:                          /* l.sys imm */
               DIP("l.sys 0x%x\n", imm16(insn));
               putPC(mkU32(pc + 4));
               dres.len = 4; dres.whatNext = Dis_StopHere;
               dres.jk_StopHere = Ijk_Sys_syscall;
               break;
            case 0x100:                          /* l.trap imm */
               DIP("l.trap 0x%x\n", imm16(insn));
               putPC(mkU32(pc + 4));
               dres.len = 4; dres.whatNext = Dis_StopHere;
               dres.jk_StopHere = Ijk_SigTRAP;
               break;
            case 0x200:                          /* l.msync */
               DIP("l.msync\n");
               stmt(IRStmt_MBE(Imbe_Fence));
               putPC(mkU32(pc + 4));
               break;
            case 0x280: case 0x300:              /* l.psync, l.csync */
               /* pipeline and cache sync: nothing to model here. */
               DIP("%s\n", ((insn >> 16) & 0x3FF) == 0x280 ? "l.psync"
                                                           : "l.csync");
               putPC(mkU32(pc + 4));
               break;
            default:
               goto decode_failure;
         }
         break;

      default:
         if (!dis_simple(insn, pc)) goto decode_failure;
         /* Every instruction's IR must end by writing the fall-through PC to
            the guest IP, so the block can stop cleanly after any insn. */
         putPC(mkU32(pc + 4));
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
