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

/* dispatcher-continuation addresses are wired in at M2; 0 for now. */
#define OR1K_DISP 0
/* branch selector to skip the exit block when the condition fails. */
#define SKIP_OPC(c) ((c)==OR1Kcc_F ? 0x03 : 0x04)   /* F: l.bnf ; NF: l.bf */

Int emit_OR1KInstr ( UChar* buf, Int nbuf, const OR1KInstr* i )
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
         OR1KCondCode c = i->OR1Kin.XDirect.cond;
         if (c != OR1Kcc_AL) {                 /* skip exit block (9 words) if !cond */
            p = emitW(p, or1k_enc_branch(SKIP_OPC(c), 9));
            p = emitW(p, or1k_enc_nop(0));
         }
         p = emitLoad32(p, 9, i->OR1Kin.XDirect.dstGA);
         p = emitW(p, or1k_enc_store(0x35, 30, 9, (UShort)i->OR1Kin.XDirect.pcOff));
         p = emitLoad32(p, 9, OR1K_DISP);
         p = emitW(p, or1k_enc_jr(9));
         p = emitW(p, or1k_enc_nop(0));
         break;
      }
      case OR1Kin_XIndir: {
         OR1KCondCode c = i->OR1Kin.XIndir.cond;
         if (c != OR1Kcc_AL) {                 /* skip (7 words) */
            p = emitW(p, or1k_enc_branch(SKIP_OPC(c), 7));
            p = emitW(p, or1k_enc_nop(0));
         }
         p = emitW(p, or1k_enc_store(0x35, 30, gpr(i->OR1Kin.XIndir.dstGA),
                                     (UShort)i->OR1Kin.XIndir.pcOff));
         p = emitLoad32(p, 9, OR1K_DISP);
         p = emitW(p, or1k_enc_jr(9));
         p = emitW(p, or1k_enc_nop(0));
         break;
      }
      case OR1Kin_XAssisted: {
         OR1KCondCode c = i->OR1Kin.XAssisted.cond;
         if (c != OR1Kcc_AL) {                 /* skip (9 words) */
            p = emitW(p, or1k_enc_branch(SKIP_OPC(c), 9));
            p = emitW(p, or1k_enc_nop(0));
         }
         p = emitW(p, or1k_enc_store(0x35, 30, gpr(i->OR1Kin.XAssisted.dstGA),
                                     (UShort)i->OR1Kin.XAssisted.pcOff));
         p = emitLoad32(p, 11, (UInt)i->OR1Kin.XAssisted.jk);   /* TRC value */
         p = emitLoad32(p, 9, OR1K_DISP);
         p = emitW(p, or1k_enc_jr(9));
         p = emitW(p, or1k_enc_nop(0));
         break;
      }

      default:
         vpanic("emit_OR1KInstr");
   }
   return (Int)(p - buf);
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
