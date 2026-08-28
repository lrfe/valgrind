/*---------------------------------------------------------------*/
/*--- begin                                 guest_or1k_defs.h ---*/
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

/* Only to be used within the guest-or1k directory. */

#ifndef __VEX_GUEST_OR1K_DEFS_H
#define __VEX_GUEST_OR1K_DEFS_H

#include "libvex_basictypes.h"
#include "libvex_guest_or1k.h"          /* VexGuestOR1KState */
#include "guest_generic_bb_to_IR.h"     /* DisResult */

/*--- or1k to IR conversion ---*/

/* decode one OpenRISC insn to IR (a DisOneInstrFn, see guest_generic_bb_to_IR.h). */
extern DisResult disInstr_OR1K ( IRSB*        irsb,
                                 const UChar* guest_code,
                                 Long         delta,
                                 Addr         guest_IP,
                                 VexArch      guest_arch,
                                 const VexArchInfo* archinfo,
                                 const VexAbiInfo*  abiinfo,
                                 VexEndness   host_endness,
                                 Bool         sigill_diag );

/* Used by the optimiser to specialise calls to helpers. */
extern IRExpr* guest_or1k_spechelper ( const HChar* function_name,
                                       IRExpr**     args,
                                       IRStmt**     precedingStmts,
                                       Int          n_precedingStmts );

/* Describe precise memory-exception requirements of a guest-state part. */
extern Bool guest_or1k_state_requires_precise_mem_exns (
               Int minoff, Int maxoff, VexRegisterUpdates pxControl );

extern VexGuestLayout or1kGuest_layout;

#endif /* ndef __VEX_GUEST_OR1K_DEFS_H */

/*---------------------------------------------------------------*/
/*--- end                                   guest_or1k_defs.h ---*/
/*---------------------------------------------------------------*/
