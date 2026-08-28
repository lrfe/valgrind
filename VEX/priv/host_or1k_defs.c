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

/*---------------------------------------------------------------*/
/*--- end                                    host_or1k_defs.c ---*/
/*---------------------------------------------------------------*/
