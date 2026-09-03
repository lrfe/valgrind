/*---------------------------------------------------------------*/
/*--- begin                                  host_or1k_isel.c ---*/
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

/* IR -> OR1KInstr instruction selection. Integer subset; conditional  */
/* branches (Ist_Exit) come next. */

#include "libvex_basictypes.h"
#include "libvex_ir.h"
#include "libvex.h"
#include "main_util.h"
#include "host_generic_regs.h"
#include "host_or1k_defs.h"

/*--- selection environment ---*/

typedef struct {
   IRTypeEnv*   type_env;
   HReg*        vregmap;
   HReg*        vregmapHI;   /* upper half of Ity_I64 temps */
   Int          n_vregmap;
   HInstrArray* code;
   Int          vreg_ctr;
   Bool         chainingAllowed;
} ISelEnv;

static HReg newVRegI ( ISelEnv* env ) {
   return mkHReg(True, HRcInt32, 0, env->vreg_ctr++);
}
static HReg lookupIRTemp ( ISelEnv* env, IRTemp t ) {
   vassert(t < env->n_vregmap);
   return env->vregmap[t];
}
static void lookupIRTemp64 ( HReg* hi, HReg* lo, ISelEnv* env, IRTemp t ) {
   vassert(t < env->n_vregmap);
   vassert(!hregIsInvalid(env->vregmapHI[t]));
   *hi = env->vregmapHI[t];
   *lo = env->vregmap[t];
}
static void addInstr ( ISelEnv* env, OR1KInstr* i ) {
   addHInstr(env->code, (HInstr*)i);
}

static Bool fitsS16 ( UInt c ) { Int s = (Int)c; return s >= -32768 && s <= 32767; }
static Bool fitsU16 ( UInt c ) { return c <= 0xFFFF; }

static HReg iselIntExpr_R ( ISelEnv* env, IRExpr* e );
static void iselInt64Expr ( HReg* hi, HReg* lo, ISelEnv* env, IRExpr* e );
static OR1KCondCode iselCondCode ( ISelEnv* env, IRExpr* guard );
static HReg condTo01 ( ISelEnv* env, IRExpr* guard );   /* I1 -> 0/1 in a reg */
static Bool doHelperCall ( RetLoc*, ISelEnv*, IRExpr* guard, IRCallee*,
                           IRType retTy, IRExpr** args );

/*--- constant materialization ---*/

static HReg iselConst ( ISelEnv* env, UInt val ) {
   HReg dst = newVRegI(env);
   UInt hi = val >> 16, lo = val & 0xFFFF;
   if (hi == 0 && lo < 0x8000) {
      addInstr(env, OR1KInstr_AluI(0x27, dst, OR1K_ZERO, (UShort)lo));   /* addi */
   } else {
      addInstr(env, OR1KInstr_MovHi(dst, (UShort)hi));
      if (lo != 0)
         addInstr(env, OR1KInstr_AluI(0x2a, dst, dst, (UShort)lo));      /* ori */
   }
   return dst;
}

/*--- addressing: fold Add32(base,const) into base+disp ---*/

static void iselAddr ( ISelEnv* env, /*OUT*/HReg* base, /*OUT*/Short* disp, IRExpr* a ) {
   if (a->tag == Iex_Binop && a->Iex.Binop.op == Iop_Add32
       && a->Iex.Binop.arg2->tag == Iex_Const
       && fitsS16(a->Iex.Binop.arg2->Iex.Const.con->Ico.U32)) {
      *base = iselIntExpr_R(env, a->Iex.Binop.arg1);
      *disp = (Short)a->Iex.Binop.arg2->Iex.Const.con->Ico.U32;
      return;
   }
   *base = iselIntExpr_R(env, a);
   *disp = 0;
}

/*--- integer expression -> register ---*/

static HReg iselIntExpr_R ( ISelEnv* env, IRExpr* e )
{
   switch (e->tag) {

      case Iex_RdTmp:
         return lookupIRTemp(env, e->Iex.RdTmp.tmp);

      case Iex_Get: {
         HReg dst = newVRegI(env);
         addInstr(env, OR1KInstr_Load(0x21, dst, OR1K_GSP, (Short)e->Iex.Get.offset));
         return dst;
      }

      case Iex_Const: {
         UInt v;
         switch (e->Iex.Const.con->tag) {
            case Ico_U32: v = e->Iex.Const.con->Ico.U32;        break;
            case Ico_U16: v = e->Iex.Const.con->Ico.U16;        break;
            case Ico_U8:  v = e->Iex.Const.con->Ico.U8;         break;
            case Ico_U1:  v = e->Iex.Const.con->Ico.U1 ? 1 : 0; break;
            default: vpanic("iselIntExpr_R(or1k): bad const type");
         }
         return iselConst(env, v);
      }

      case Iex_Load: {
         HReg base, dst = newVRegI(env);
         Short disp;
         /* Pick the load width from the result type: lwz/lhz/lbz. */
         UInt opc;
         switch (e->Iex.Load.ty) {
            case Ity_I8:  opc = 0x23; break;   /* l.lbz */
            case Ity_I16: opc = 0x25; break;   /* l.lhz */
            case Ity_I32: opc = 0x21; break;   /* l.lwz */
            default: vpanic("iselIntExpr_R(or1k): bad load type");
         }
         iselAddr(env, &base, &disp, e->Iex.Load.addr);
         addInstr(env, OR1KInstr_Load(opc, dst, base, disp));
         return dst;
      }

      case Iex_Unop: {
         IROp op = e->Iex.Unop.op;
         IRExpr* a = e->Iex.Unop.arg;
         switch (op) {
            case Iop_32to8: case Iop_32to16:
               return iselIntExpr_R(env, a);          /* low bits already there */
            case Iop_64HIto32: case Iop_64to32: {
               HReg hi, lo;
               iselInt64Expr(&hi, &lo, env, a);
               return op == Iop_64HIto32 ? hi : lo;
            }
            case Iop_Not32: {
               HReg s = iselIntExpr_R(env, a);
               HReg dst = newVRegI(env);
               /* ~x == x XOR -1 */
               HReg m1 = iselConst(env, 0xFFFFFFFF);
               addInstr(env, OR1KInstr_Alu(OR1Kalu_XOR, dst, s, m1));
               return dst;
            }
            case Iop_Left32: {
               /* Left32(x) = x | (-x); MSB ends up set iff x != 0. */
               HReg s = iselIntExpr_R(env, a);
               HReg neg = newVRegI(env), dst = newVRegI(env);
               addInstr(env, OR1KInstr_Alu(OR1Kalu_SUB, neg, OR1K_ZERO, s));
               addInstr(env, OR1KInstr_Alu(OR1Kalu_OR, dst, s, neg));
               return dst;
            }
            case Iop_CmpwNEZ32: {
               /* all-ones iff x != 0: (x | -x) >>s 31. */
               HReg s = iselIntExpr_R(env, a);
               HReg neg = newVRegI(env), t = newVRegI(env), dst = newVRegI(env);
               addInstr(env, OR1KInstr_Alu(OR1Kalu_SUB, neg, OR1K_ZERO, s));
               addInstr(env, OR1KInstr_Alu(OR1Kalu_OR, t, s, neg));
               addInstr(env, OR1KInstr_ShiftI(2/*sra*/, dst, t, 31));
               return dst;
            }
            case Iop_1Sto8: case Iop_1Sto16: case Iop_1Sto32: {
               /* all-ones or zero from an I1, honouring the F/NF sense. */
               OR1KCondCode c = iselCondCode(env, a);
               HReg m1 = iselConst(env, 0xFFFFFFFF);
               HReg dst = newVRegI(env);
               if (c == OR1Kcc_F)
                  addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, m1, OR1K_ZERO));
               else
                  addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, OR1K_ZERO, m1));
               return dst;
            }
            case Iop_16HIto8: case Iop_32HIto16: {
               /* high half: shift the significant bits down. */
               HReg s = iselIntExpr_R(env, a);
               HReg dst = newVRegI(env);
               addInstr(env, OR1KInstr_ShiftI(1/*srl*/, dst, s,
                                              op == Iop_16HIto8 ? 8 : 16));
               return dst;
            }
            case Iop_16to8:
               return iselIntExpr_R(env, a);          /* low bits already there */
            case Iop_CtzNat32: {
               /* l.ff1 gives a one-based index, so take one off it; l.ff1 */
               /* answers 0 for an all-zero word, which must become 32. */
               HReg s = iselIntExpr_R(env, a);
               HReg t = newVRegI(env), d = newVRegI(env);
               HReg c32 = iselConst(env, 32), dst = newVRegI(env);
               addInstr(env, OR1KInstr_Alu(OR1Kalu_FF1, t, s, OR1K_ZERO));
               addInstr(env, OR1KInstr_AluI(0x27, d, t, (UShort)0xFFFF));
               addInstr(env, OR1KInstr_CmpI(0x0/*sfeqi*/, t, 0));
               addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, c32, d));
               return dst;
            }
            case Iop_ClzNat32: {
               /* l.fl1 gives the one-based highest set bit, and 0 for an */
               /* all-zero word, so 32 minus it is right in both cases. */
               HReg s = iselIntExpr_R(env, a);
               HReg t = newVRegI(env), c = iselConst(env, 32);
               HReg dst = newVRegI(env);
               addInstr(env, OR1KInstr_Alu(OR1Kalu_FL1, t, s, OR1K_ZERO));
               addInstr(env, OR1KInstr_Alu(OR1Kalu_SUB, dst, c, t));
               return dst;
            }
            case Iop_1Uto32: {
               /* materialize the I1 into 0/1 via l.sf* + l.cmov, honouring
                  the F/NF sense that iselCondCode reports. */
               OR1KCondCode c = iselCondCode(env, a);
               HReg one = iselConst(env, 1);
               HReg dst = newVRegI(env);
               if (c == OR1Kcc_F)                     /* dst = F  ? 1 : 0 */
                  addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, one, OR1K_ZERO));
               else                                   /* dst = !F ? 1 : 0 */
                  addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, OR1K_ZERO, one));
               return dst;
            }
            case Iop_8Uto32: case Iop_8Sto32:
            case Iop_16Uto32: case Iop_16Sto32: {
               if (a->tag == Iex_Load) {
                  HReg base, dst = newVRegI(env);
                  Short disp;
                  UInt opc = op==Iop_8Uto32 ? 0x23 : op==Iop_8Sto32 ? 0x24
                           : op==Iop_16Uto32 ? 0x25 : 0x26;
                  iselAddr(env, &base, &disp, a->Iex.Load.addr);
                  addInstr(env, OR1KInstr_Load(opc, dst, base, disp));
                  return dst;
               } else {
                  HReg src = iselIntExpr_R(env, a);
                  HReg dst = newVRegI(env);
                  OR1KExtOp x = op==Iop_8Uto32 ? OR1Kext_EXTBZ : op==Iop_8Sto32 ? OR1Kext_EXTBS
                              : op==Iop_16Uto32 ? OR1Kext_EXTHZ : OR1Kext_EXTHS;
                  addInstr(env, OR1KInstr_Ext(x, dst, src));
                  return dst;
               }
            }
            default:
               break;
         }
         break;
      }

      case Iex_Binop: {
         IROp op = e->Iex.Binop.op;
         IRExpr* a1 = e->Iex.Binop.arg1;
         IRExpr* a2 = e->Iex.Binop.arg2;

         /* shifts by an immediate */
         if ((op==Iop_Shl32 || op==Iop_Shr32 || op==Iop_Sar32)
             && a2->tag == Iex_Const && a2->Iex.Const.con->tag == Ico_U8) {
            HReg src = iselIntExpr_R(env, a1);
            HReg dst = newVRegI(env);
            UInt type = op==Iop_Shl32 ? 0 : op==Iop_Shr32 ? 1 : 2;
            addInstr(env, OR1KInstr_ShiftI(type, dst, src, a2->Iex.Const.con->Ico.U8));
            return dst;
         }

         /* immediate-form ALU */
         if (a2->tag == Iex_Const && a2->Iex.Const.con->tag == Ico_U32) {
            UInt c = a2->Iex.Const.con->Ico.U32;
            UInt opc = 0;
            if      (op==Iop_Add32 && fitsS16(c)) opc = 0x27;
            else if (op==Iop_And32 && fitsU16(c)) opc = 0x29;
            else if (op==Iop_Or32  && fitsU16(c)) opc = 0x2a;
            else if (op==Iop_Xor32 && fitsS16(c)) opc = 0x2b;
            if (opc) {
               HReg src = iselIntExpr_R(env, a1);
               HReg dst = newVRegI(env);
               addInstr(env, OR1KInstr_AluI(opc, dst, src, (UShort)c));
               return dst;
            }
         }

         /* concatenations used by memcheck: (hi << w) | (lo & mask) */
         if (op == Iop_16HLto32 || op == Iop_8HLto16) {
            UInt w    = op == Iop_16HLto32 ? 16 : 8;
            UInt mask = op == Iop_16HLto32 ? 0xFFFF : 0xFF;
            HReg hi = iselIntExpr_R(env, a1);
            HReg lo = iselIntExpr_R(env, a2);
            HReg hs = newVRegI(env), lm = newVRegI(env), dst = newVRegI(env);
            addInstr(env, OR1KInstr_ShiftI(0/*sll*/, hs, hi, (UChar)w));
            addInstr(env, OR1KInstr_AluI(0x29/*andi*/, lm, lo, (UShort)mask));
            addInstr(env, OR1KInstr_Alu(OR1Kalu_OR, dst, hs, lm));
            return dst;
         }

         /* register-register (narrow widths share the 32-bit ALU op). */
         OR1KAluOp aop;
         switch (op) {
            case Iop_Add32: case Iop_Add16: case Iop_Add8: aop = OR1Kalu_ADD; break;
            case Iop_Sub32: case Iop_Sub16: case Iop_Sub8: aop = OR1Kalu_SUB; break;
            case Iop_And32: case Iop_And16: case Iop_And8: aop = OR1Kalu_AND; break;
            case Iop_Or32:  case Iop_Or16:  case Iop_Or8:  aop = OR1Kalu_OR;  break;
            case Iop_Xor32: case Iop_Xor16: case Iop_Xor8: aop = OR1Kalu_XOR; break;
            case Iop_Mul32: case Iop_Mul16: case Iop_Mul8: aop = OR1Kalu_MUL; break;
            case Iop_DivS32: aop = OR1Kalu_DIVS; break;
            case Iop_DivU32: aop = OR1Kalu_DIVU; break;
            case Iop_Shl32: aop = OR1Kalu_SLL; break;
            case Iop_Shr32: aop = OR1Kalu_SRL; break;
            case Iop_Sar32: aop = OR1Kalu_SRA; break;
            default: goto irreducible;
         }
         HReg rL = iselIntExpr_R(env, a1);
         HReg rR = iselIntExpr_R(env, a2);
         HReg dst = newVRegI(env);
         addInstr(env, OR1KInstr_Alu(aop, dst, rL, rR));
         return dst;
      }

      case Iex_ITE: {
         /* Compute both arms first; iselCondCode is done last so the
            arms' compares can't clobber SR[F] before the l.cmov. */
         HReg rt  = iselIntExpr_R(env, e->Iex.ITE.iftrue);
         HReg rf  = iselIntExpr_R(env, e->Iex.ITE.iffalse);
         OR1KCondCode c = iselCondCode(env, e->Iex.ITE.cond);
         HReg dst = newVRegI(env);
         if (c == OR1Kcc_F)                        /* dst = F  ? rt : rf */
            addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, rt, rf));
         else                                      /* dst = !F ? rt : rf */
            addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, rf, rt));
         return dst;
      }

      case Iex_CCall: {
         RetLoc rloc = mk_RetLoc_INVALID();
         if (!doHelperCall(&rloc, env, NULL/*guard*/, e->Iex.CCall.cee,
                           e->Iex.CCall.retty, e->Iex.CCall.args))
            goto irreducible;
         vassert(rloc.pri == RLPri_Int);
         HReg dst = newVRegI(env);
         addInstr(env, (OR1KInstr*)genMove_OR1K(hregOR1K_GPR(11), dst, False));
         return dst;
      }

      default:
         break;
   }

  irreducible:
   ppIRExpr(e);
   vpanic("iselIntExpr_R(or1k): cannot reduce expression");
}

/*--- condition codes: emit an l.sf* setting SR[F] from an I1 guard ---*/

static OR1KCondCode iselCondCode ( ISelEnv* env, IRExpr* guard )
{
   /* Not1(x): compute x's flag and return the inverted sense. */
   if (guard->tag == Iex_Unop && guard->Iex.Unop.op == Iop_Not1) {
      OR1KCondCode c = iselCondCode(env, guard->Iex.Unop.arg);
      return c == OR1Kcc_F ? OR1Kcc_NF : OR1Kcc_F;
   }
   /* CmpNEZ{8,16,32}(x): F <- (x != 0), masking narrow widths first. */
   if (guard->tag == Iex_Unop
       && (guard->Iex.Unop.op == Iop_CmpNEZ8 || guard->Iex.Unop.op == Iop_CmpNEZ16
           || guard->Iex.Unop.op == Iop_CmpNEZ32)) {
      HReg s = iselIntExpr_R(env, guard->Iex.Unop.arg);
      UInt mask = guard->Iex.Unop.op == Iop_CmpNEZ8  ? 0xFF
                : guard->Iex.Unop.op == Iop_CmpNEZ16 ? 0xFFFF : 0;
      if (mask) {
         HReg m = newVRegI(env);
         addInstr(env, OR1KInstr_AluI(0x29/*andi*/, m, s, (UShort)mask));
         s = m;
      }
      addInstr(env, OR1KInstr_CmpI(1/*ne*/, s, 0));
      return OR1Kcc_F;
   }
   /* And1/Or1: materialize both operands as 0/1 and test the combination.
      A single SR[F] can't hold a two-condition combination directly. */
   if (guard->tag == Iex_Binop
       && (guard->Iex.Binop.op == Iop_And1 || guard->Iex.Binop.op == Iop_Or1)) {
      HReg rx = condTo01(env, guard->Iex.Binop.arg1);
      HReg ry = condTo01(env, guard->Iex.Binop.arg2);
      HReg t  = newVRegI(env);
      addInstr(env, OR1KInstr_Alu(guard->Iex.Binop.op == Iop_And1
                                     ? OR1Kalu_AND : OR1Kalu_OR, t, rx, ry));
      addInstr(env, OR1KInstr_CmpI(1/*ne*/, t, 0));   /* F <- (t != 0) */
      return OR1Kcc_F;
   }
   if (guard->tag == Iex_Binop) {
      UInt code; Bool ok = True;
      switch (guard->Iex.Binop.op) {
         case Iop_CmpEQ32:  case Iop_CasCmpEQ32: code = 0;  break;
         case Iop_CmpNE32:  case Iop_CasCmpNE32:
         case Iop_ExpCmpNE32:                    code = 1;  break;
         case Iop_CmpLT32U: code = 4;  break;
         case Iop_CmpLE32U: code = 5;  break;
         case Iop_CmpLT32S: code = 12; break;
         case Iop_CmpLE32S: code = 13; break;
         default: ok = False; code = 0; break;
      }
      if (ok) {
         IRExpr* a = guard->Iex.Binop.arg1;
         IRExpr* b = guard->Iex.Binop.arg2;
         HReg ra = iselIntExpr_R(env, a);
         if (b->tag == Iex_Const && b->Iex.Const.con->tag == Ico_U32
             && fitsS16(b->Iex.Const.con->Ico.U32))
            addInstr(env, OR1KInstr_CmpI(code, ra, (UShort)b->Iex.Const.con->Ico.U32));
         else
            addInstr(env, OR1KInstr_Cmp(code, ra, iselIntExpr_R(env, b)));
         return OR1Kcc_F;
      }
   }
   /* fallback: flag set iff the guard value is nonzero. */
   addInstr(env, OR1KInstr_CmpI(1, iselIntExpr_R(env, guard), 0));
   return OR1Kcc_F;
}

/* 64-bit values live in a (hi, lo) register pair. Only what the core and
   the tools actually emit for a 32-bit host is supported here. */
static void iselInt64Expr ( HReg* hi, HReg* lo, ISelEnv* env, IRExpr* e )
{
   vassert(typeOfIRExpr(env->type_env, e) == Ity_I64);
   switch (e->tag) {
      case Iex_RdTmp:
         lookupIRTemp64(hi, lo, env, e->Iex.RdTmp.tmp);
         return;
      case Iex_Const: {
         ULong v = e->Iex.Const.con->Ico.U64;
         vassert(e->Iex.Const.con->tag == Ico_U64);
         *hi = iselConst(env, (UInt)(v >> 32));
         *lo = iselConst(env, (UInt)v);
         return;
      }
      case Iex_Load: {
         HReg base;
         Short disp;
         vassert(e->Iex.Load.ty == Ity_I64);
         iselAddr(env, &base, &disp, e->Iex.Load.addr);
         *hi = newVRegI(env);
         *lo = newVRegI(env);
         addInstr(env, OR1KInstr_Load(0x21, *hi, base, disp));      /* big-endian */
         addInstr(env, OR1KInstr_Load(0x21, *lo, base, disp + 4));
         return;
      }
      case Iex_Binop: {
         IROp op = e->Iex.Binop.op;
         if (op == Iop_32HLto64) {
            *hi = iselIntExpr_R(env, e->Iex.Binop.arg1);
            *lo = iselIntExpr_R(env, e->Iex.Binop.arg2);
            return;
         }
         if (op == Iop_Add64) {
            HReg aH, aL, bH, bL;
            iselInt64Expr(&aH, &aL, env, e->Iex.Binop.arg1);
            iselInt64Expr(&bH, &bL, env, e->Iex.Binop.arg2);
            *hi = newVRegI(env);
            *lo = newVRegI(env);
            /* l.add sets CY, l.addc consumes it; nothing may come between. */
            addInstr(env, OR1KInstr_Alu(OR1Kalu_ADD,  *lo, aL, bL));
            addInstr(env, OR1KInstr_Alu(OR1Kalu_ADDC, *hi, aH, bH));
            return;
         }
         break;
      }
      default:
         break;
   }
   ppIRExpr(e);
   vpanic("iselInt64Expr(or1k): cannot reduce expression");
}

/* Materialize an Ity_I1 condition as a 0/1 value in a fresh register. */
static HReg condTo01 ( ISelEnv* env, IRExpr* guard )
{
   OR1KCondCode c = iselCondCode(env, guard);
   HReg one = iselConst(env, 1);
   HReg dst = newVRegI(env);
   if (c == OR1Kcc_F)
      addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, one, OR1K_ZERO));
   else
      addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, OR1K_ZERO, one));
   return dst;
}

/*--- helper calls ---*/

/* Marshal the arguments for a C helper call and emit it.  Only integer args
   up to 32 bits (in r3..r8), an optional GSPTR, and an optional guard are
   handled; the result comes back in r11.  Uses the always-correct slow
   scheme (compute args into vregs, then move them to the arg registers). */
static Bool doHelperCall ( /*OUT*/RetLoc* retloc, ISelEnv* env,
                           IRExpr* guard, IRCallee* cee,
                           IRType retTy, IRExpr** args )
{
   *retloc = mk_RetLoc_INVALID();

   UInt n_args = 0, nGSPTRs = 0;
   for (UInt i = 0; args[i] != NULL; i++) {
      if (args[i]->tag == Iex_GSPTR)  nGSPTRs++;
      else if (args[i]->tag == Iex_VECRET) return False;   /* no vector return */
      n_args++;
   }
   if (nGSPTRs > 1 || n_args > 6) return False;   /* only r3..r8 available */

   HReg tmpregs[6];
   for (UInt i = 0; i < n_args; i++) {
      IRExpr* arg = args[i];
      if (arg->tag == Iex_GSPTR) {
         tmpregs[i] = OR1K_GSP;                    /* r30 holds the guest state */
      } else {
         IRType aTy = typeOfIRExpr(env->type_env, arg);
         if (aTy != Ity_I32 && aTy != Ity_I16 && aTy != Ity_I8 && aTy != Ity_I1)
            return False;                          /* only <=32-bit int args */
         tmpregs[i] = (aTy == Ity_I1) ? condTo01(env, arg)
                                      : iselIntExpr_R(env, arg);
      }
   }

   HReg cond = INVALID_HREG;
   if (guard) {
      if (guard->tag == Iex_Const && guard->Iex.Const.con->tag == Ico_U1
          && guard->Iex.Const.con->Ico.U1 == True) {
         /* unconditional */
      } else {
         cond = condTo01(env, guard);
      }
   }

   for (UInt i = 0; i < n_args; i++)
      addInstr(env, (OR1KInstr*)genMove_OR1K(tmpregs[i], hregOR1K_GPR(3 + i),
                                             False));

   switch (retTy) {
      case Ity_INVALID: *retloc = mk_RetLoc_simple(RLPri_None); break;
      case Ity_I8: case Ity_I16: case Ity_I32:
         *retloc = mk_RetLoc_simple(RLPri_Int); break;
      default: return False;
   }

   addInstr(env, OR1KInstr_Call((Addr)cee->addr, *retloc, cond, (UChar)n_args));
   return True;
}

/*--- statements ---*/

static void iselStmt ( ISelEnv* env, IRStmt* stmt )
{
   switch (stmt->tag) {

      case Ist_IMark:
      case Ist_NoOp:
      case Ist_AbiHint:
         return;

      case Ist_Put: {
         HReg r = iselIntExpr_R(env, stmt->Ist.Put.data);
         addInstr(env, OR1KInstr_Store(0x35, OR1K_GSP, r, (Short)stmt->Ist.Put.offset));
         return;
      }

      case Ist_WrTmp: {
         HReg dst = lookupIRTemp(env, stmt->Ist.WrTmp.tmp);
         IRExpr* data = stmt->Ist.WrTmp.data;
         if (typeOfIRExpr(env->type_env, data) == Ity_I1) {
            /* a condition temp: materialize it as 0/1, honouring F/NF. */
            OR1KCondCode c = iselCondCode(env, data);
            HReg one = iselConst(env, 1);
            if (c == OR1Kcc_F)
               addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, one, OR1K_ZERO));
            else
               addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, OR1K_ZERO, one));
         } else if (typeOfIRExpr(env->type_env, data) == Ity_I64) {
            HReg dHi, dLo, hi, lo;
            lookupIRTemp64(&dHi, &dLo, env, stmt->Ist.WrTmp.tmp);
            iselInt64Expr(&hi, &lo, env, data);
            addInstr(env, (OR1KInstr*)genMove_OR1K(hi, dHi, False));
            addInstr(env, (OR1KInstr*)genMove_OR1K(lo, dLo, False));
         } else {
            HReg r = iselIntExpr_R(env, data);
            addInstr(env, (OR1KInstr*)genMove_OR1K(r, dst, False));
         }
         return;
      }

      case Ist_Store: {
         HReg base, r;
         Short disp;
         /* Pick the store width from the data type: l.sw/l.sh/l.sb. */
         UInt opc;
         switch (typeOfIRExpr(env->type_env, stmt->Ist.Store.data)) {
            case Ity_I8:  opc = 0x36; break;   /* l.sb */
            case Ity_I16: opc = 0x37; break;   /* l.sh */
            case Ity_I32: opc = 0x35; break;   /* l.sw */
            case Ity_I64: {
               HReg hi, lo;
               iselInt64Expr(&hi, &lo, env, stmt->Ist.Store.data);
               iselAddr(env, &base, &disp, stmt->Ist.Store.addr);
               addInstr(env, OR1KInstr_Store(0x35, base, hi, disp));
               addInstr(env, OR1KInstr_Store(0x35, base, lo, disp + 4));
               return;
            }
            default: vpanic("iselStmt(or1k): bad store type");
         }
         iselAddr(env, &base, &disp, stmt->Ist.Store.addr);
         r = iselIntExpr_R(env, stmt->Ist.Store.data);
         addInstr(env, OR1KInstr_Store(opc, base, r, disp));
         return;
      }

      case Ist_Exit: {
         vassert(stmt->Ist.Exit.dst->tag == Ico_U32);
         OR1KCondCode cc = iselCondCode(env, stmt->Ist.Exit.guard);
         if (stmt->Ist.Exit.jk == Ijk_Boring && env->chainingAllowed) {
            addInstr(env, OR1KInstr_XDirect(stmt->Ist.Exit.dst->Ico.U32,
                                            stmt->Ist.Exit.offsIP, cc));
         } else {
            /* a non-boring side exit, or chaining is off: assisted exit. */
            HReg r = iselConst(env, stmt->Ist.Exit.dst->Ico.U32);
            addInstr(env, OR1KInstr_XAssisted(r, stmt->Ist.Exit.offsIP, cc,
                                              stmt->Ist.Exit.jk));
         }
         return;
      }

      case Ist_CAS: {
         IRCAS* cas = stmt->Ist.CAS.details;
         vassert(cas->oldHi == IRTemp_INVALID && cas->expdHi == NULL);
         HReg base = iselIntExpr_R(env, cas->addr);
         HReg expd = iselIntExpr_R(env, cas->expdLo);
         HReg data = iselIntExpr_R(env, cas->dataLo);
         HReg old  = lookupIRTemp(env, cas->oldLo);
         addInstr(env, OR1KInstr_CASW(old, base, expd, data));
         return;
      }

      case Ist_Dirty: {
         IRDirty* d = stmt->Ist.Dirty.details;
         IRType retty = Ity_INVALID;
         if (d->tmp != IRTemp_INVALID)
            retty = typeOfIRTemp(env->type_env, d->tmp);
         RetLoc rloc = mk_RetLoc_INVALID();
         if (!doHelperCall(&rloc, env, d->guard, d->cee, retty, d->args))
            vpanic("iselStmt(or1k): Ist_Dirty");
         if (d->tmp != IRTemp_INVALID) {
            vassert(rloc.pri == RLPri_Int);        /* result is in r11 */
            addInstr(env, (OR1KInstr*)genMove_OR1K(hregOR1K_GPR(11),
                                        lookupIRTemp(env, d->tmp), False));
         }
         return;
      }

      case Ist_MBE:
         /* memory-bus events: nothing to do for a serialized guest. */
         return;

      default:
         ppIRStmt(stmt);
         vpanic("iselStmt(or1k)");
   }
}

/*--- the entry point ---*/

HInstrArray* iselSB_OR1K ( const IRSB* bb,
                           VexArch      arch_host,
                           const VexArchInfo* archinfo_host,
                           const VexAbiInfo*  vbi,
                           Int          offs_evc_counter,
                           Int          offs_evc_fa,
                           Bool         chaining,
                           Bool         addProfInc,
                           Addr         max_ga )
{
   Int i;
   ISelEnv env;
   env.type_env  = bb->tyenv;
   env.code      = newHInstrArray();
   env.vreg_ctr  = 0;
   env.chainingAllowed = chaining;
   env.n_vregmap = bb->tyenv->types_used;
   env.vregmap   = LibVEX_Alloc_inline(env.n_vregmap * sizeof(HReg));
   env.vregmapHI = LibVEX_Alloc_inline(env.n_vregmap * sizeof(HReg));
   for (i = 0; i < env.n_vregmap; i++) {
      env.vregmap[i]   = mkHReg(True, HRcInt32, 0, env.vreg_ctr++);
      env.vregmapHI[i] = INVALID_HREG;
      if (bb->tyenv->types[i] == Ity_I64)
         env.vregmapHI[i] = mkHReg(True, HRcInt32, 0, env.vreg_ctr++);
   }

   /* Every superblock opens with a dispatch-counter check. */
   addInstr(&env, OR1KInstr_EvCheck(offs_evc_counter, offs_evc_fa));

   /* Optionally a profiler increment (used with --profile-flags). */
   if (addProfInc)
      addInstr(&env, OR1KInstr_ProfInc());


   for (i = 0; i < bb->stmts_used; i++)
      iselStmt(&env, bb->stmts[i]);

   /* Transfer to bb->next.  The jump kind decides how and takes priority
      over a constant target, so a syscall still reaches the scheduler. */
   if ((bb->jumpkind == Ijk_Boring || bb->jumpkind == Ijk_Call
        || bb->jumpkind == Ijk_Ret) && env.chainingAllowed) {
      if (bb->next->tag == Iex_Const) {
         vassert(bb->next->Iex.Const.con->tag == Ico_U32);
         addInstr(&env, OR1KInstr_XDirect(bb->next->Iex.Const.con->Ico.U32,
                                          bb->offsIP, OR1Kcc_AL));
      } else {
         addInstr(&env, OR1KInstr_XIndir(iselIntExpr_R(&env, bb->next),
                                         bb->offsIP, OR1Kcc_AL));
      }
   } else if (bb->jumpkind == Ijk_Boring || bb->jumpkind == Ijk_Call
              || bb->jumpkind == Ijk_Ret) {
      /* chaining is off (a no-redirect translation): assisted, boring. */
      addInstr(&env, OR1KInstr_XAssisted(iselIntExpr_R(&env, bb->next),
                                         bb->offsIP, OR1Kcc_AL, Ijk_Boring));
   } else {
      /* Assisted exits always go through a register target. */
      addInstr(&env, OR1KInstr_XAssisted(iselIntExpr_R(&env, bb->next),
                                         bb->offsIP, OR1Kcc_AL, bb->jumpkind));
   }

   env.code->n_vregs = env.vreg_ctr;
   return env.code;
}

/*---------------------------------------------------------------*/
/*--- end                                    host_or1k_isel.c ---*/
/*---------------------------------------------------------------*/
