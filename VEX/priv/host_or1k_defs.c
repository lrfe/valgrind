/*---------------------------------------------------------------*/
/*--- begin                                  host_or1k_defs.c ---*/
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
#include "libvex.h"
#include "main_util.h"
#include "host_generic_regs.h"
#include "host_or1k_defs.h"
#include "libvex_trc_values.h"

/*--- ORBIS32 instruction encoders ---*/

#define OPC(o)  (((UInt)(o) & 0x3F) << 26)
#define RD(r)   (((UInt)(r) & 0x1F) << 21)
#define RA(r)   (((UInt)(r) & 0x1F) << 16)
#define RB(r)   (((UInt)(r) & 0x1F) << 11)
#define IMM(i)  ((UInt)(i) & 0xFFFF)

UInt or1k_enc_rrr ( UInt op11, UInt rD, UInt rA, UInt rB ) {
   return OPC(0x38) | RD(rD) | RA(rA) | RB(rB) | (op11 & 0x7FF);
}

UInt or1k_enc_ri ( UInt opc, UInt rD, UInt rA, UInt imm16 ) {
   return OPC(opc) | RD(rD) | RA(rA) | IMM(imm16);
}

UInt or1k_enc_movhi ( UInt rD, UInt imm16 ) {
   return OPC(0x06) | RD(rD) | IMM(imm16);
}

UInt or1k_enc_shifti ( UInt type, UInt rD, UInt rA, UInt amt6 ) {
   return OPC(0x2e) | RD(rD) | RA(rA) | ((type & 3) << 6) | (amt6 & 0x3F);
}

UInt or1k_enc_load ( UInt opc, UInt rD, UInt rA, UInt disp16 ) {
   return OPC(opc) | RD(rD) | RA(rA) | IMM(disp16);
}

/* the store displacement is split: high 5 bits sit in the rD slot. */
UInt or1k_enc_store ( UInt opc, UInt rA, UInt rB, UInt disp16 ) {
   UInt d = disp16 & 0xFFFF;
   return OPC(opc) | (((d >> 11) & 0x1F) << 21) | RA(rA) | RB(rB) | (d & 0x7FF);
}

UInt or1k_enc_sf ( UInt code, UInt rA, UInt rB ) {
   return OPC(0x39) | RD(code) | RA(rA) | RB(rB);
}

UInt or1k_enc_sfi ( UInt code, UInt rA, UInt imm16 ) {
   return OPC(0x2f) | RD(code) | RA(rA) | IMM(imm16);
}

UInt or1k_enc_branch ( UInt opc, Int rel ) {
   return OPC(opc) | ((UInt)rel & 0x03FFFFFF);
}

UInt or1k_enc_jr   ( UInt rB ) { return OPC(0x11) | RB(rB); }
UInt or1k_enc_jalr ( UInt rB ) { return OPC(0x12) | RB(rB); }

UInt or1k_enc_nop  ( UInt k )  { return 0x15000000 | IMM(k); }
UInt or1k_enc_sys  ( UInt k )  { return 0x20000000 | IMM(k); }

/*--- OR1KInstr constructors ---*/

static OR1KInstr* mk ( OR1KInstrTag tag ) {
   OR1KInstr* i = LibVEX_Alloc_inline(sizeof(OR1KInstr));
   i->tag = tag;
   return i;
}
OR1KInstr* OR1KInstr_Alu ( OR1KAluOp op, HReg dst, HReg srcL, HReg srcR ) {
   OR1KInstr* i = mk(OR1Kin_Alu);
   i->OR1Kin.Alu.op=op; i->OR1Kin.Alu.dst=dst; i->OR1Kin.Alu.srcL=srcL; i->OR1Kin.Alu.srcR=srcR;
   return i;
}
OR1KInstr* OR1KInstr_AluI ( UInt opc, HReg dst, HReg src, UShort imm ) {
   OR1KInstr* i = mk(OR1Kin_AluI);
   i->OR1Kin.AluI.opc=opc; i->OR1Kin.AluI.dst=dst; i->OR1Kin.AluI.src=src; i->OR1Kin.AluI.imm=imm;
   return i;
}
OR1KInstr* OR1KInstr_ShiftI ( UInt type, HReg dst, HReg src, UChar amt ) {
   OR1KInstr* i = mk(OR1Kin_ShiftI);
   i->OR1Kin.ShiftI.type=type; i->OR1Kin.ShiftI.dst=dst; i->OR1Kin.ShiftI.src=src; i->OR1Kin.ShiftI.amt=amt;
   return i;
}
OR1KInstr* OR1KInstr_MovHi ( HReg dst, UShort imm ) {
   OR1KInstr* i = mk(OR1Kin_MovHi);
   i->OR1Kin.MovHi.dst=dst; i->OR1Kin.MovHi.imm=imm;
   return i;
}
OR1KInstr* OR1KInstr_Load ( UInt opc, HReg dst, HReg base, Short disp ) {
   OR1KInstr* i = mk(OR1Kin_Load);
   i->OR1Kin.Load.opc=opc; i->OR1Kin.Load.dst=dst; i->OR1Kin.Load.base=base; i->OR1Kin.Load.disp=disp;
   return i;
}
OR1KInstr* OR1KInstr_Store ( UInt opc, HReg base, HReg src, Short disp ) {
   OR1KInstr* i = mk(OR1Kin_Store);
   i->OR1Kin.Store.opc=opc; i->OR1Kin.Store.base=base; i->OR1Kin.Store.src=src; i->OR1Kin.Store.disp=disp;
   return i;
}
OR1KInstr* OR1KInstr_Cmp ( UInt code, HReg srcL, HReg srcR ) {
   OR1KInstr* i = mk(OR1Kin_Cmp);
   i->OR1Kin.Cmp.code=code; i->OR1Kin.Cmp.srcL=srcL; i->OR1Kin.Cmp.srcR=srcR;
   return i;
}
OR1KInstr* OR1KInstr_CmpI ( UInt code, HReg src, UShort imm ) {
   OR1KInstr* i = mk(OR1Kin_CmpI);
   i->OR1Kin.CmpI.code=code; i->OR1Kin.CmpI.src=src; i->OR1Kin.CmpI.imm=imm;
   return i;
}
OR1KInstr* OR1KInstr_Ext ( OR1KExtOp op, HReg dst, HReg src ) {
   OR1KInstr* i = mk(OR1Kin_Ext);
   i->OR1Kin.Ext.op=op; i->OR1Kin.Ext.dst=dst; i->OR1Kin.Ext.src=src;
   return i;
}
OR1KInstr* OR1KInstr_XDirect ( UInt dstGA, Int pcOff, OR1KCondCode cond ) {
   OR1KInstr* i = mk(OR1Kin_XDirect);
   i->OR1Kin.XDirect.dstGA=dstGA; i->OR1Kin.XDirect.pcOff=pcOff; i->OR1Kin.XDirect.cond=cond;
   return i;
}
OR1KInstr* OR1KInstr_XIndir ( HReg dstGA, Int pcOff, OR1KCondCode cond ) {
   OR1KInstr* i = mk(OR1Kin_XIndir);
   i->OR1Kin.XIndir.dstGA=dstGA; i->OR1Kin.XIndir.pcOff=pcOff; i->OR1Kin.XIndir.cond=cond;
   return i;
}
OR1KInstr* OR1KInstr_XAssisted ( HReg dstGA, Int pcOff, OR1KCondCode cond, IRJumpKind jk ) {
   OR1KInstr* i = mk(OR1Kin_XAssisted);
   i->OR1Kin.XAssisted.dstGA=dstGA; i->OR1Kin.XAssisted.pcOff=pcOff;
   i->OR1Kin.XAssisted.cond=cond; i->OR1Kin.XAssisted.jk=jk;
   return i;
}
OR1KInstr* OR1KInstr_EvCheck ( Int offCounter, Int offFailAddr ) {
   OR1KInstr* i = mk(OR1Kin_EvCheck);
   i->OR1Kin.EvCheck.offCounter=offCounter; i->OR1Kin.EvCheck.offFailAddr=offFailAddr;
   return i;
}
OR1KInstr* OR1KInstr_ProfInc ( void ) {
   return mk(OR1Kin_ProfInc);
}
OR1KInstr* OR1KInstr_Call ( Addr target, RetLoc rloc, HReg cond, UChar nArgRegs ) {
   OR1KInstr* i = mk(OR1Kin_Call);
   i->OR1Kin.Call.target=target; i->OR1Kin.Call.rloc=rloc;
   i->OR1Kin.Call.cond=cond; i->OR1Kin.Call.nArgRegs=nArgRegs;
   return i;
}
OR1KInstr* OR1KInstr_CASW ( HReg old, HReg base, HReg expd, HReg data ) {
   OR1KInstr* i = mk(OR1Kin_CASW);
   i->OR1Kin.CASW.old=old; i->OR1Kin.CASW.base=base;
   i->OR1Kin.CASW.expd=expd; i->OR1Kin.CASW.data=data;
   return i;
}

/*--- pretty-print ---*/

static UInt gpr ( HReg r ) { return hregEncoding(r); }

void ppOR1KInstr ( const OR1KInstr* i ) {
   switch (i->tag) {
      case OR1Kin_Alu:
         vex_printf("alu(0x%03x) r%u,r%u,r%u", i->OR1Kin.Alu.op,
                    gpr(i->OR1Kin.Alu.dst), gpr(i->OR1Kin.Alu.srcL), gpr(i->OR1Kin.Alu.srcR));
         return;
      case OR1Kin_AluI:
         vex_printf("alui(0x%02x) r%u,r%u,0x%x", i->OR1Kin.AluI.opc,
                    gpr(i->OR1Kin.AluI.dst), gpr(i->OR1Kin.AluI.src), i->OR1Kin.AluI.imm);
         return;
      case OR1Kin_ShiftI:
         vex_printf("shifti(%u) r%u,r%u,%u", i->OR1Kin.ShiftI.type,
                    gpr(i->OR1Kin.ShiftI.dst), gpr(i->OR1Kin.ShiftI.src), i->OR1Kin.ShiftI.amt);
         return;
      case OR1Kin_MovHi:
         vex_printf("movhi r%u,0x%x", gpr(i->OR1Kin.MovHi.dst), i->OR1Kin.MovHi.imm);
         return;
      case OR1Kin_Load:
         vex_printf("load(0x%02x) r%u,%d(r%u)", i->OR1Kin.Load.opc,
                    gpr(i->OR1Kin.Load.dst), i->OR1Kin.Load.disp, gpr(i->OR1Kin.Load.base));
         return;
      case OR1Kin_Store:
         vex_printf("store(0x%02x) %d(r%u),r%u", i->OR1Kin.Store.opc,
                    i->OR1Kin.Store.disp, gpr(i->OR1Kin.Store.base), gpr(i->OR1Kin.Store.src));
         return;
      case OR1Kin_Cmp:
         vex_printf("cmp(0x%x) r%u,r%u", i->OR1Kin.Cmp.code,
                    gpr(i->OR1Kin.Cmp.srcL), gpr(i->OR1Kin.Cmp.srcR));
         return;
      case OR1Kin_CmpI:
         vex_printf("cmpi(0x%x) r%u,0x%x", i->OR1Kin.CmpI.code,
                    gpr(i->OR1Kin.CmpI.src), i->OR1Kin.CmpI.imm);
         return;
      case OR1Kin_Ext:
         vex_printf("ext(0x%03x) r%u,r%u", i->OR1Kin.Ext.op,
                    gpr(i->OR1Kin.Ext.dst), gpr(i->OR1Kin.Ext.src));
         return;
      case OR1Kin_XDirect:
         vex_printf("xdirect(%u) 0x%x -> %d(gsp)", i->OR1Kin.XDirect.cond,
                    i->OR1Kin.XDirect.dstGA, i->OR1Kin.XDirect.pcOff);
         return;
      case OR1Kin_XIndir:
         vex_printf("xindir(%u) r%u -> %d(gsp)", i->OR1Kin.XIndir.cond,
                    gpr(i->OR1Kin.XIndir.dstGA), i->OR1Kin.XIndir.pcOff);
         return;
      case OR1Kin_XAssisted:
         vex_printf("xassisted(%u) r%u -> %d(gsp) jk=%d", i->OR1Kin.XAssisted.cond,
                    gpr(i->OR1Kin.XAssisted.dstGA), i->OR1Kin.XAssisted.pcOff,
                    (Int)i->OR1Kin.XAssisted.jk);
         return;
      case OR1Kin_EvCheck:
         vex_printf("evcheck %d(gsp), fail %d(gsp)",
                    i->OR1Kin.EvCheck.offCounter, i->OR1Kin.EvCheck.offFailAddr);
         return;
      case OR1Kin_ProfInc:
         vex_printf("profinc");
         return;
      case OR1Kin_CASW:
         vex_printf("casw r%u,0(r%u),r%u,r%u", gpr(i->OR1Kin.CASW.old),
                    gpr(i->OR1Kin.CASW.base), gpr(i->OR1Kin.CASW.expd),
                    gpr(i->OR1Kin.CASW.data));
         return;
      case OR1Kin_Call:
         vex_printf("call 0x%lx [nArgRegs=%u", i->OR1Kin.Call.target,
                    i->OR1Kin.Call.nArgRegs);
         if (!hregIsInvalid(i->OR1Kin.Call.cond)) {
            vex_printf(", cond="); ppHRegOR1K(i->OR1Kin.Call.cond);
         }
         vex_printf("]");
         return;
      default:
         vpanic("ppOR1KInstr");
   }
}

/*--- emit ---*/

static UChar* emitW ( UChar* q, UInt w ) {
   q[0]=(UChar)(w>>24); q[1]=(UChar)(w>>16); q[2]=(UChar)(w>>8); q[3]=(UChar)w;
   return q+4;
}
/* materialize a 32-bit constant into reg (movhi+ori, always 2 words). */
static UChar* emitLoad32 ( UChar* q, UInt reg, UInt val ) {
   q = emitW(q, or1k_enc_movhi(reg, val >> 16));
   q = emitW(q, or1k_enc_ri(0x2a, reg, reg, val & 0xFFFF));
   return q;
}

/* branch selector to skip the exit block when the condition fails. */
#define SKIP_OPC(c) ((c)==OR1Kcc_F ? 0x03 : 0x04)   /* F: l.bnf ; NF: l.bf */

/* opcodes reused below: l.addi/l.lwz/l.sw and the signed-ge compare. */
#define OR1K_OPC_ADDI 0x27
#define OR1K_OPC_LWZ  0x21
#define OR1K_OPC_SW   0x35
#define OR1K_SF_GES   0x0b   /* l.sfges: F <- (rA >= rB), signed */

Int emit_OR1KInstr ( /*MB_MOD*/Bool* is_profInc,
                     UChar* buf, Int nbuf, const OR1KInstr* i,
                     Bool mode64,
                     const VexArchInfo* archinfo_host,
                     const void* disp_cp_chain_me_to_slowEP,
                     const void* disp_cp_chain_me_to_fastEP,
                     const void* disp_cp_xindir,
                     const void* disp_cp_xassisted )
{
   UChar* p = buf;
   vassert(nbuf >= 64);
   switch (i->tag) {
      case OR1Kin_Alu:
         p = emitW(p, or1k_enc_rrr(i->OR1Kin.Alu.op, gpr(i->OR1Kin.Alu.dst),
                                   gpr(i->OR1Kin.Alu.srcL), gpr(i->OR1Kin.Alu.srcR)));
         break;
      case OR1Kin_AluI:
         p = emitW(p, or1k_enc_ri(i->OR1Kin.AluI.opc, gpr(i->OR1Kin.AluI.dst),
                                  gpr(i->OR1Kin.AluI.src), i->OR1Kin.AluI.imm));
         break;
      case OR1Kin_ShiftI:
         p = emitW(p, or1k_enc_shifti(i->OR1Kin.ShiftI.type, gpr(i->OR1Kin.ShiftI.dst),
                                      gpr(i->OR1Kin.ShiftI.src), i->OR1Kin.ShiftI.amt));
         break;
      case OR1Kin_MovHi:
         p = emitW(p, or1k_enc_movhi(gpr(i->OR1Kin.MovHi.dst), i->OR1Kin.MovHi.imm));
         break;
      case OR1Kin_Load:
         p = emitW(p, or1k_enc_load(i->OR1Kin.Load.opc, gpr(i->OR1Kin.Load.dst),
                                    gpr(i->OR1Kin.Load.base), (UShort)i->OR1Kin.Load.disp));
         break;
      case OR1Kin_Store:
         p = emitW(p, or1k_enc_store(i->OR1Kin.Store.opc, gpr(i->OR1Kin.Store.base),
                                     gpr(i->OR1Kin.Store.src), (UShort)i->OR1Kin.Store.disp));
         break;
      case OR1Kin_Cmp:
         p = emitW(p, or1k_enc_sf(i->OR1Kin.Cmp.code, gpr(i->OR1Kin.Cmp.srcL),
                                  gpr(i->OR1Kin.Cmp.srcR)));
         break;
      case OR1Kin_CmpI:
         p = emitW(p, or1k_enc_sfi(i->OR1Kin.CmpI.code, gpr(i->OR1Kin.CmpI.src),
                                   i->OR1Kin.CmpI.imm));
         break;
      case OR1Kin_Ext:
         p = emitW(p, or1k_enc_rrr(i->OR1Kin.Ext.op, gpr(i->OR1Kin.Ext.dst),
                                   gpr(i->OR1Kin.Ext.src), 0));
         break;

      case OR1Kin_XDirect: {
         /* NB: this must stay closely coordinated with chainXDirect_OR1K()
            and unchainXDirect_OR1K() below. */
         OR1KCondCode c = i->OR1Kin.XDirect.cond;
         vassert(disp_cp_chain_me_to_slowEP != NULL);
         vassert(disp_cp_chain_me_to_fastEP != NULL);
         if (c != OR1Kcc_AL) {                 /* skip exit block (9 words) if !cond */
            p = emitW(p, or1k_enc_branch(SKIP_OPC(c), 9));
            p = emitW(p, or1k_enc_nop(0));
         }
         /* update the guest PC (r9 is a scratch for the constant) */
         p = emitLoad32(p, 9, i->OR1Kin.XDirect.dstGA);
         p = emitW(p, or1k_enc_store(OR1K_OPC_SW, 30, 9,
                                     (UShort)i->OR1Kin.XDirect.pcOff));
         /* --- PATCHABLE 16 bytes: load the chain-me address into r11 and
            call it; chainXDirect_OR1K() rewrites this to a direct jump. --- */
         const void* disp_cp_chain_me = disp_cp_chain_me_to_slowEP;
         p = emitLoad32(p, 11, (UInt)(HWord)disp_cp_chain_me);
         p = emitW(p, or1k_enc_jalr(11));
         p = emitW(p, or1k_enc_nop(0));
         break;
      }
      case OR1Kin_XIndir: {
         OR1KCondCode c = i->OR1Kin.XIndir.cond;
         vassert(disp_cp_xindir != NULL);
         if (c != OR1Kcc_AL) {                 /* skip (7 words) */
            p = emitW(p, or1k_enc_branch(SKIP_OPC(c), 7));
            p = emitW(p, or1k_enc_nop(0));
         }
         p = emitW(p, or1k_enc_store(OR1K_OPC_SW, 30, gpr(i->OR1Kin.XIndir.dstGA),
                                     (UShort)i->OR1Kin.XIndir.pcOff));
         p = emitLoad32(p, 9, (UInt)(HWord)disp_cp_xindir);
         p = emitW(p, or1k_enc_jr(9));
         p = emitW(p, or1k_enc_nop(0));
         break;
      }
      case OR1Kin_XAssisted: {
         OR1KCondCode c = i->OR1Kin.XAssisted.cond;
         vassert(disp_cp_xassisted != NULL);
         if (c != OR1Kcc_AL) {                 /* skip (9 words) */
            p = emitW(p, or1k_enc_branch(SKIP_OPC(c), 9));
            p = emitW(p, or1k_enc_nop(0));
         }
         p = emitW(p, or1k_enc_store(OR1K_OPC_SW, 30, gpr(i->OR1Kin.XAssisted.dstGA),
                                     (UShort)i->OR1Kin.XAssisted.pcOff));
         /* map the IR jump kind onto its VEX_TRC_JMP_* value in r11 */
         UInt trcval = 0;
         switch (i->OR1Kin.XAssisted.jk) {
            case Ijk_ClientReq:   trcval = VEX_TRC_JMP_CLIENTREQ;   break;
            case Ijk_Sys_syscall: trcval = VEX_TRC_JMP_SYS_SYSCALL; break;
            case Ijk_Yield:       trcval = VEX_TRC_JMP_YIELD;       break;
            case Ijk_EmWarn:      trcval = VEX_TRC_JMP_EMWARN;      break;
            case Ijk_EmFail:      trcval = VEX_TRC_JMP_EMFAIL;      break;
            case Ijk_NoDecode:    trcval = VEX_TRC_JMP_NODECODE;    break;
            case Ijk_InvalICache: trcval = VEX_TRC_JMP_INVALICACHE; break;
            case Ijk_NoRedir:     trcval = VEX_TRC_JMP_NOREDIR;     break;
            case Ijk_SigILL:      trcval = VEX_TRC_JMP_SIGILL;      break;
            case Ijk_SigTRAP:     trcval = VEX_TRC_JMP_SIGTRAP;     break;
            case Ijk_SigBUS:      trcval = VEX_TRC_JMP_SIGBUS;      break;
            case Ijk_SigFPE_IntDiv: trcval = VEX_TRC_JMP_SIGFPE_INTDIV; break;
            case Ijk_SigFPE_IntOvf: trcval = VEX_TRC_JMP_SIGFPE_INTOVF; break;
            case Ijk_Boring:      trcval = VEX_TRC_JMP_BORING;      break;
            default:
               ppIRJumpKind(i->OR1Kin.XAssisted.jk);
               vpanic("emit_OR1KInstr.XAssisted: unexpected jump kind");
         }
         vassert(trcval != 0);
         p = emitLoad32(p, 11, trcval);
         p = emitLoad32(p, 9, (UInt)(HWord)disp_cp_xassisted);
         p = emitW(p, or1k_enc_jr(9));
         p = emitW(p, or1k_enc_nop(0));
         break;
      }
      case OR1Kin_EvCheck: {
         /*    l.lwz   r9, offCounter(r30)
               l.addi  r9, r9, -1
               l.sw    offCounter(r30), r9
               l.sfges r9, r0            ; F <- (r9 >= 0)
               l.bf    +5                ; if still >= 0, skip the fail path
                l.nop                    ; (delay slot)
               l.lwz   r9, offFailAddr(r30)
               l.jr    r9
                l.nop                    ; (delay slot)
         */
         Int offC = i->OR1Kin.EvCheck.offCounter;
         Int offF = i->OR1Kin.EvCheck.offFailAddr;
         p = emitW(p, or1k_enc_load(OR1K_OPC_LWZ, 9, 30, (UShort)offC));
         p = emitW(p, or1k_enc_ri(OR1K_OPC_ADDI, 9, 9, 0xFFFF));
         p = emitW(p, or1k_enc_store(OR1K_OPC_SW, 30, 9, (UShort)offC));
         p = emitW(p, or1k_enc_sf(OR1K_SF_GES, 9, 0));
         p = emitW(p, or1k_enc_branch(0x04, 5));   /* l.bf */
         p = emitW(p, or1k_enc_nop(0));
         p = emitW(p, or1k_enc_load(OR1K_OPC_LWZ, 9, 30, (UShort)offF));
         p = emitW(p, or1k_enc_jr(9));
         p = emitW(p, or1k_enc_nop(0));
         vassert(evCheckSzB_OR1K() == (Int)(p - buf));
         break;
      }
      case OR1Kin_ProfInc: {
         /* Increment a 64-bit counter whose address is patched in later by
            patchProfInc_OR1K().  Uses only the reserved scratch regs r10/r9,
            since this runs at block entry while allocatable regs are live.
            Placeholder address 0x65557555; the r10 hi/lo halves are patched.
               l.movhi r10, 0x6555
               l.ori   r10, r10, 0x7555
               l.lwz   r9, 4(r10)        ; low word (big-endian: high addr)
               l.addi  r9, r9, 1
               l.sw    4(r10), r9
               l.sfeq  r9, r0            ; carry into high word iff low wrapped to 0
               l.lwz   r9, 0(r10)
               l.bnf   +2
                l.addi  r9, r9, 1        ; (delay slot)
               l.sw    0(r10), r9
         */
         p = emitW(p, or1k_enc_movhi(10, 0x6555));
         p = emitW(p, or1k_enc_ri(0x2a, 10, 10, 0x7555));
         p = emitW(p, or1k_enc_load(OR1K_OPC_LWZ, 9, 10, 4));
         p = emitW(p, or1k_enc_ri(OR1K_OPC_ADDI, 9, 9, 1));
         p = emitW(p, or1k_enc_store(OR1K_OPC_SW, 10, 9, 4));
         p = emitW(p, or1k_enc_sf(0x00, 9, 0));      /* l.sfeq r9,r0 */
         p = emitW(p, or1k_enc_load(OR1K_OPC_LWZ, 9, 10, 0));
         p = emitW(p, or1k_enc_branch(0x03, 2));     /* l.bnf +2 */
         p = emitW(p, or1k_enc_ri(OR1K_OPC_ADDI, 9, 9, 1));  /* delay slot */
         p = emitW(p, or1k_enc_store(OR1K_OPC_SW, 10, 9, 0));
         vassert(!*is_profInc);
         *is_profInc = True;
         break;
      }
      case OR1Kin_CASW: {
         /* A tight l.lwa/l.swa retry loop on the reserved r9, so nothing */
         /* runs between the pair and old is only written once inputs are read. */
         UInt old = gpr(i->OR1Kin.CASW.old), base = gpr(i->OR1Kin.CASW.base);
         UInt expd = gpr(i->OR1Kin.CASW.expd), data = gpr(i->OR1Kin.CASW.data);
         p = emitW(p, or1k_enc_load(0x1b, 9, base, 0));      /* 0: l.lwa r9   */
         p = emitW(p, or1k_enc_sf(0x0/*sfeq*/, 9, expd));    /* 4: r9==expd?  */
         p = emitW(p, or1k_enc_branch(0x03/*l.bnf*/, 5));    /* 8: ne -> done */
         p = emitW(p, or1k_enc_nop(0));                      /* c: delay      */
         p = emitW(p, or1k_enc_store(0x33, base, data, 0));  /* 10: l.swa     */
         p = emitW(p, or1k_enc_branch(0x03/*l.bnf*/, -5));   /* 14: retry     */
         p = emitW(p, or1k_enc_nop(0));                      /* 18: delay     */
         p = emitW(p, or1k_enc_ri(0x2a/*ori*/, old, 9, 0));  /* 1c: old = r9  */
         break;
      }

      case OR1Kin_Call: {
         /* If guarded, skip the 4-word call when the guard reg is zero. */
         UChar* skip = NULL;
         if (!hregIsInvalid(i->OR1Kin.Call.cond)) {
            p = emitW(p, or1k_enc_sf(0x0/*sfeq*/, gpr(i->OR1Kin.Call.cond), 0));
            skip = p;                              /* fill the branch in below */
            p = emitW(p, or1k_enc_nop(0));         /* placeholder for l.bf */
            p = emitW(p, or1k_enc_nop(0));         /* delay slot */
         }
         /* Load the target into r11 and call it (r9 <- return address). */
         p = emitLoad32(p, 11, (UInt)i->OR1Kin.Call.target);
         p = emitW(p, or1k_enc_jalr(11));
         p = emitW(p, or1k_enc_nop(0));            /* delay slot */
         if (skip) {                               /* branch over 4 remaining words */
            (void)emitW(skip, or1k_enc_branch(0x04/*l.bf*/,
                                              (Int)((p - skip) >> 2)));
         }
         break;
      }

      default:
         vpanic("emit_OR1KInstr");
   }
   return (Int)(p - buf);
}

/* Bytes of code emitted for an OR1Kin_EvCheck (9 instructions). */
Int evCheckSzB_OR1K ( void ) { return 36; }

/* Chain an XDirect exit: rewrite the 16-byte patchable region from
   "load chain-me addr into r11; l.jalr r11" to
   "load target addr into r11; l.jr r11". */
VexInvalRange chainXDirect_OR1K ( VexEndness endness_host,
                                  void* place_to_chain,
                                  const void* disp_cp_chain_me_EXPECTED,
                                  const void* place_to_jump_to )
{
   vassert(endness_host == VexEndnessBE);
   UChar* p = place_to_chain;
   vassert(((HWord)p & 3) == 0);
   /* verify: movhi r11,hi ; ori r11,r11,lo ; l.jalr r11 ; l.nop */
   UChar tmp[16];
   UChar* q = tmp;
   q = emitLoad32(q, 11, (UInt)(HWord)disp_cp_chain_me_EXPECTED);
   q = emitW(q, or1k_enc_jalr(11));
   q = emitW(q, or1k_enc_nop(0));
   { Int k; for (k = 0; k < 16; k++) vassert(p[k] == tmp[k]); }
   /* write the direct jump to the target block */
   q = emitLoad32(p, 11, (UInt)(HWord)place_to_jump_to);
   q = emitW(q, or1k_enc_jr(11));
   (void)emitW(q, or1k_enc_nop(0));
   VexInvalRange vir = { (HWord)p, 16 };
   return vir;
}

/* Reverse of chainXDirect_OR1K(). */
VexInvalRange unchainXDirect_OR1K ( VexEndness endness_host,
                                    void* place_to_unchain,
                                    const void* place_to_jump_to_EXPECTED,
                                    const void* disp_cp_chain_me )
{
   vassert(endness_host == VexEndnessBE);
   UChar* p = place_to_unchain;
   vassert(((HWord)p & 3) == 0);
   /* verify: movhi r11,hi ; ori r11,r11,lo ; l.jr r11 ; l.nop */
   UChar tmp[16];
   UChar* q = tmp;
   q = emitLoad32(q, 11, (UInt)(HWord)place_to_jump_to_EXPECTED);
   q = emitW(q, or1k_enc_jr(11));
   q = emitW(q, or1k_enc_nop(0));
   { Int k; for (k = 0; k < 16; k++) vassert(p[k] == tmp[k]); }
   /* write back the chain-me call */
   q = emitLoad32(p, 11, (UInt)(HWord)disp_cp_chain_me);
   q = emitW(q, or1k_enc_jalr(11));
   (void)emitW(q, or1k_enc_nop(0));
   VexInvalRange vir = { (HWord)p, 16 };
   return vir;
}

/* Patch the 64-bit counter address into a ProfInc template. */
VexInvalRange patchProfInc_OR1K ( VexEndness endness_host,
                                  void* place_to_patch,
                                  const ULong* location_of_counter )
{
   vassert(endness_host == VexEndnessBE);
   vassert(sizeof(ULong*) == 4);
   UChar* p = place_to_patch;
   vassert(((HWord)p & 3) == 0);
   /* the first two instructions are "movhi r10,0x6555 ; ori r10,r10,0x7555" */
   UChar tmp[8];
   UChar* q = tmp;
   q = emitW(q, or1k_enc_movhi(10, 0x6555));
   q = emitW(q, or1k_enc_ri(0x2a, 10, 10, 0x7555));
   { Int k; for (k = 0; k < 8; k++) vassert(p[k] == tmp[k]); }
   UInt addr = (UInt)(HWord)location_of_counter;
   q = emitW(p, or1k_enc_movhi(10, addr >> 16));
   (void)emitW(q, or1k_enc_ri(0x2a, 10, 10, addr & 0xFFFF));
   VexInvalRange vir = { (HWord)p, 8 };
   return vir;
}

/*--- register allocator interface ---*/

const RRegUniverse* getRRegUniverse_OR1K ( void )
{
   static RRegUniverse ru;
   static Bool initted = False;
   if (initted) return &ru;

   RRegUniverse__init(&ru);

   /* allocable: r3..r8, r11..r29, r31. */
   ru.allocable_start[HRcInt32] = ru.size;
   UInt n;
   for (n = 3;  n <= 8;  n++) ru.regs[ru.size++] = hregOR1K_GPR(n);
   for (n = 11; n <= 29; n++) ru.regs[ru.size++] = hregOR1K_GPR(n);
   ru.regs[ru.size++] = hregOR1K_GPR(31);
   ru.allocable_end[HRcInt32] = ru.size - 1;
   ru.allocable = ru.size;

   /* reserved: r0 (zero), r1 (sp), r2 (fp), r9 (exit scratch),
      r10, r30 (guest-state ptr). */
   ru.regs[ru.size++] = hregOR1K_GPR(0);
   ru.regs[ru.size++] = hregOR1K_GPR(1);
   ru.regs[ru.size++] = hregOR1K_GPR(2);
   ru.regs[ru.size++] = hregOR1K_GPR(9);
   ru.regs[ru.size++] = hregOR1K_GPR(10);
   ru.regs[ru.size++] = hregOR1K_GPR(30);

   initted = True;
   return &ru;
}

UInt ppHRegOR1K ( HReg r )
{
   if (hregIsVirtual(r)) { ppHReg(r); return 0; }
   vex_printf("r%u", hregEncoding(r));
   return 0;
}

void getRegUsage_OR1K ( HRegUsage* u, const OR1KInstr* i, Bool mode64 )
{
   initHRegUsage(u);
   switch (i->tag) {
      case OR1Kin_Alu:
         addHRegUse(u, HRmWrite, i->OR1Kin.Alu.dst);
         addHRegUse(u, HRmRead,  i->OR1Kin.Alu.srcL);
         addHRegUse(u, HRmRead,  i->OR1Kin.Alu.srcR); return;
      case OR1Kin_AluI:
         addHRegUse(u, HRmWrite, i->OR1Kin.AluI.dst);
         addHRegUse(u, HRmRead,  i->OR1Kin.AluI.src); return;
      case OR1Kin_ShiftI:
         addHRegUse(u, HRmWrite, i->OR1Kin.ShiftI.dst);
         addHRegUse(u, HRmRead,  i->OR1Kin.ShiftI.src); return;
      case OR1Kin_MovHi:
         addHRegUse(u, HRmWrite, i->OR1Kin.MovHi.dst); return;
      case OR1Kin_Load:
         addHRegUse(u, HRmWrite, i->OR1Kin.Load.dst);
         addHRegUse(u, HRmRead,  i->OR1Kin.Load.base); return;
      case OR1Kin_Store:
         addHRegUse(u, HRmRead, i->OR1Kin.Store.base);
         addHRegUse(u, HRmRead, i->OR1Kin.Store.src); return;
      case OR1Kin_Cmp:
         addHRegUse(u, HRmRead, i->OR1Kin.Cmp.srcL);
         addHRegUse(u, HRmRead, i->OR1Kin.Cmp.srcR); return;
      case OR1Kin_CmpI:
         addHRegUse(u, HRmRead, i->OR1Kin.CmpI.src); return;
      case OR1Kin_Ext:
         addHRegUse(u, HRmWrite, i->OR1Kin.Ext.dst);
         addHRegUse(u, HRmRead,  i->OR1Kin.Ext.src); return;
      case OR1Kin_XDirect: return;
      case OR1Kin_XIndir:
         addHRegUse(u, HRmRead, i->OR1Kin.XIndir.dstGA); return;
      case OR1Kin_XAssisted:
         addHRegUse(u, HRmRead, i->OR1Kin.XAssisted.dstGA); return;
      case OR1Kin_EvCheck:
      case OR1Kin_ProfInc:
         /* only fixed regs (r9/r11/r30) are touched. */
         return;
      case OR1Kin_CASW:
         addHRegUse(u, HRmWrite, i->OR1Kin.CASW.old);
         addHRegUse(u, HRmRead,  i->OR1Kin.CASW.base);
         addHRegUse(u, HRmRead,  i->OR1Kin.CASW.expd);
         addHRegUse(u, HRmRead,  i->OR1Kin.CASW.data); return;
      case OR1Kin_Call: {
         /* Trashes all caller-saved allocatable regs: r3-r8, r11, r12 and the
            odd r13..r31.  Even r14..r28 and r30 (GSP) are callee-saved. */
         static const UInt clob[] = { 3,4,5,6,7,8, 11,12,
                                      13,15,17,19,21,23,25,27,29,31 };
         for (UInt k = 0; k < sizeof(clob)/sizeof(clob[0]); k++)
            addHRegUse(u, HRmWrite, hregOR1K_GPR(clob[k]));
         /* Reads the argument registers r3.. and the guard, if any. */
         for (UInt a = 0; a < i->OR1Kin.Call.nArgRegs; a++)
            addHRegUse(u, HRmRead, hregOR1K_GPR(3 + a));
         if (!hregIsInvalid(i->OR1Kin.Call.cond))
            addHRegUse(u, HRmRead, i->OR1Kin.Call.cond);
         return;
      }
      default:
         vpanic("getRegUsage_OR1K");
   }
}

static void mapReg ( HRegRemap* m, HReg* r ) { *r = lookupHRegRemap(m, *r); }

void mapRegs_OR1K ( HRegRemap* m, OR1KInstr* i, Bool mode64 )
{
   switch (i->tag) {
      case OR1Kin_Alu:
         mapReg(m, &i->OR1Kin.Alu.dst); mapReg(m, &i->OR1Kin.Alu.srcL);
         mapReg(m, &i->OR1Kin.Alu.srcR); return;
      case OR1Kin_AluI:
         mapReg(m, &i->OR1Kin.AluI.dst); mapReg(m, &i->OR1Kin.AluI.src); return;
      case OR1Kin_ShiftI:
         mapReg(m, &i->OR1Kin.ShiftI.dst); mapReg(m, &i->OR1Kin.ShiftI.src); return;
      case OR1Kin_MovHi:
         mapReg(m, &i->OR1Kin.MovHi.dst); return;
      case OR1Kin_Load:
         mapReg(m, &i->OR1Kin.Load.dst); mapReg(m, &i->OR1Kin.Load.base); return;
      case OR1Kin_Store:
         mapReg(m, &i->OR1Kin.Store.base); mapReg(m, &i->OR1Kin.Store.src); return;
      case OR1Kin_Cmp:
         mapReg(m, &i->OR1Kin.Cmp.srcL); mapReg(m, &i->OR1Kin.Cmp.srcR); return;
      case OR1Kin_CmpI:
         mapReg(m, &i->OR1Kin.CmpI.src); return;
      case OR1Kin_Ext:
         mapReg(m, &i->OR1Kin.Ext.dst); mapReg(m, &i->OR1Kin.Ext.src); return;
      case OR1Kin_XDirect: return;
      case OR1Kin_XIndir:    mapReg(m, &i->OR1Kin.XIndir.dstGA); return;
      case OR1Kin_XAssisted: mapReg(m, &i->OR1Kin.XAssisted.dstGA); return;
      case OR1Kin_EvCheck:
      case OR1Kin_ProfInc:
         return;
      case OR1Kin_Call:
         if (!hregIsInvalid(i->OR1Kin.Call.cond))
            mapReg(m, &i->OR1Kin.Call.cond);
         return;
      case OR1Kin_CASW:
         mapReg(m, &i->OR1Kin.CASW.old);
         mapReg(m, &i->OR1Kin.CASW.base);
         mapReg(m, &i->OR1Kin.CASW.expd);
         mapReg(m, &i->OR1Kin.CASW.data); return;
      default:
         vpanic("mapRegs_OR1K");
   }
}

/* spill/reload go through the guest-state pointer. */
void genSpill_OR1K ( HInstr** i1, HInstr** i2, HReg r, Int offB, Bool mode64 ) {
   *i1 = (HInstr*)OR1KInstr_Store(0x35, OR1K_GSP, r, (Short)offB);
   *i2 = NULL;
}
void genReload_OR1K ( HInstr** i1, HInstr** i2, HReg r, Int offB, Bool mode64 ) {
   *i1 = (HInstr*)OR1KInstr_Load(0x21, r, OR1K_GSP, (Short)offB);
   *i2 = NULL;
}
HInstr* genMove_OR1K ( HReg from, HReg to, Bool mode64 ) {
   return (HInstr*)OR1KInstr_Alu(OR1Kalu_OR, to, from, OR1K_ZERO);
}

/*---------------------------------------------------------------*/
/*--- end                                    host_or1k_defs.c ---*/
/*---------------------------------------------------------------*/
