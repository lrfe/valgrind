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
   Int          n_vregmap;
   HInstrArray* code;
   Int          vreg_ctr;
} ISelEnv;

static HReg newVRegI ( ISelEnv* env ) {
   return mkHReg(True, HRcInt32, 0, env->vreg_ctr++);
}
static HReg lookupIRTemp ( ISelEnv* env, IRTemp t ) {
   vassert(t < env->n_vregmap);
   return env->vregmap[t];
}
static void addInstr ( ISelEnv* env, OR1KInstr* i ) {
   addHInstr(env->code, (HInstr*)i);
}

static Bool fitsS16 ( UInt c ) { Int s = (Int)c; return s >= -32768 && s <= 32767; }
static Bool fitsU16 ( UInt c ) { return c <= 0xFFFF; }

static HReg iselIntExpr_R ( ISelEnv* env, IRExpr* e );
static OR1KCondCode iselCondCode ( ISelEnv* env, IRExpr* guard );

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
         vassert(e->Iex.Const.con->tag == Ico_U32);
         return iselConst(env, e->Iex.Const.con->Ico.U32);
      }

      case Iex_Load: {
         HReg base, dst = newVRegI(env);
         Short disp;
         iselAddr(env, &base, &disp, e->Iex.Load.addr);
         addInstr(env, OR1KInstr_Load(0x21, dst, base, disp));   /* lwz */
         return dst;
      }

      case Iex_Unop: {
         IROp op = e->Iex.Unop.op;
         IRExpr* a = e->Iex.Unop.arg;
         switch (op) {
            case Iop_32to8: case Iop_32to16:
               return iselIntExpr_R(env, a);          /* low bits already there */
            case Iop_1Uto32: {
               /* materialize the I1 into 0/1 via l.sf* + l.cmov. */
               iselCondCode(env, a);                  /* sets SR[F] = cond */
               HReg one = iselConst(env, 1);
               HReg dst = newVRegI(env);
               addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, one, OR1K_ZERO));
               return dst;                            /* dst = F ? 1 : 0 */
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

         /* register-register */
         OR1KAluOp aop;
         switch (op) {
            case Iop_Add32: aop = OR1Kalu_ADD; break;
            case Iop_Sub32: aop = OR1Kalu_SUB; break;
            case Iop_And32: aop = OR1Kalu_AND; break;
            case Iop_Or32:  aop = OR1Kalu_OR;  break;
            case Iop_Xor32: aop = OR1Kalu_XOR; break;
            case Iop_Mul32: aop = OR1Kalu_MUL; break;
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
   if (guard->tag == Iex_Binop) {
      UInt code; Bool ok = True;
      switch (guard->Iex.Binop.op) {
         case Iop_CmpEQ32:  code = 0;  break;
         case Iop_CmpNE32:  code = 1;  break;
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
            /* a condition temp: materialize it as 0/1. */
            iselCondCode(env, data);
            HReg one = iselConst(env, 1);
            addInstr(env, OR1KInstr_Alu(OR1Kalu_CMOV, dst, one, OR1K_ZERO));
         } else {
            HReg r = iselIntExpr_R(env, data);
            addInstr(env, (OR1KInstr*)genMove_OR1K(r, dst, False));
         }
         return;
      }

      case Ist_Store: {
         HReg base, r;
         Short disp;
         iselAddr(env, &base, &disp, stmt->Ist.Store.addr);
         r = iselIntExpr_R(env, stmt->Ist.Store.data);
         addInstr(env, OR1KInstr_Store(0x35, base, r, disp));
         return;
      }

      case Ist_Exit: {
         vassert(stmt->Ist.Exit.dst->tag == Ico_U32);
         OR1KCondCode cc = iselCondCode(env, stmt->Ist.Exit.guard);
         addInstr(env, OR1KInstr_XDirect(stmt->Ist.Exit.dst->Ico.U32,
                                         stmt->Ist.Exit.offsIP, cc));
         return;
      }

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
   env.n_vregmap = bb->tyenv->types_used;
   env.vregmap   = LibVEX_Alloc_inline(env.n_vregmap * sizeof(HReg));
   for (i = 0; i < env.n_vregmap; i++)
      env.vregmap[i] = mkHReg(True, HRcInt32, 0, env.vreg_ctr++);

   for (i = 0; i < bb->stmts_used; i++)
      iselStmt(&env, bb->stmts[i]);

   /* block terminator: transfer to bb->next. */
   if (bb->next->tag == Iex_Const) {
      vassert(bb->next->Iex.Const.con->tag == Ico_U32);
      addInstr(&env, OR1KInstr_XDirect(bb->next->Iex.Const.con->Ico.U32,
                                       bb->offsIP, OR1Kcc_AL));
   } else {
      HReg r = iselIntExpr_R(&env, bb->next);
      if (bb->jumpkind == Ijk_Boring || bb->jumpkind == Ijk_Call
          || bb->jumpkind == Ijk_Ret)
         addInstr(&env, OR1KInstr_XIndir(r, bb->offsIP, OR1Kcc_AL));
      else
         addInstr(&env, OR1KInstr_XAssisted(r, bb->offsIP, OR1Kcc_AL, bb->jumpkind));
   }

   env.code->n_vregs = env.vreg_ctr;
   return env.code;
}

/*---------------------------------------------------------------*/
/*--- end                                    host_or1k_isel.c ---*/
/*---------------------------------------------------------------*/
