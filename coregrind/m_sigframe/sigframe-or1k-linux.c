/*--------------------------------------------------------------------*/
/*--- Create/destroy signal delivery frames.                       ---*/
/*---                                        sigframe-or1k-linux.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2026 Ali Ahmet Memis

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   The GNU General Public License is contained in the file COPYING.
*/

#if defined(VGP_or1k_linux)

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_machine.h"
#include "pub_core_options.h"
#include "pub_core_sigframe.h"
#include "pub_core_signals.h"
#include "pub_core_tooliface.h"
#include "pub_core_trampoline.h"
#include "priv_sigframe.h"

/* Extra state saved across the handler so we can restore it on return. */
struct vg_sig_private {
   UInt magicPI;
   UInt sigNo_private;
   VexGuestOR1KState vex_shadow1;
   VexGuestOR1KState vex_shadow2;
};

struct rt_sigframe {
   vki_siginfo_t      rs_info;
   struct vki_ucontext rs_uc;
   struct vg_sig_private priv;
};

#define SET_SIGNAL_GPR(zztst, zzn, zzval)                    \
   do { zztst->arch.vex.guest_r##zzn = (ULong)(zzval);       \
      VG_TRACK( post_reg_write, Vg_CoreSignal, zztst->tid,   \
                offsetof(VexGuestOR1KState, guest_r##zzn),   \
                sizeof(UWord) );                             \
   } while (0)

static void synth_sigcontext ( ThreadState* tst, struct vki_sigcontext* sc,
                               const vki_sigset_t* mask )
{
   Int i;
   for (i = 0; i < 32; i++)
      sc->regs.gpr[i] = (&tst->arch.vex.guest_r0)[i];
   sc->regs.pc = tst->arch.vex.guest_PC;
   sc->regs.sr = 0;
   sc->oldmask = mask->sig[0];
}

void VG_(sigframe_create) ( ThreadId tid,
                            Bool on_altstack,
                            Addr sp_top_of_frame,
                            const vki_siginfo_t *siginfo,
                            const struct vki_ucontext *siguc,
                            void *handler,
                            UInt flags,
                            const vki_sigset_t *mask,
                            void *restorer )
{
   ThreadState* tst = VG_(get_ThreadState)(tid);
   Addr sp;
   struct rt_sigframe* frame;
   struct vg_sig_private* priv;

   sp = sp_top_of_frame - sizeof(struct rt_sigframe);
   sp = VG_ROUNDDN(sp, 16);

   if (! ML_(sf_maybe_extend_stack)(tst, sp, sizeof(struct rt_sigframe),
                                    flags))
      return;

   frame = (struct rt_sigframe*)sp;

   VG_(memset)(frame, 0, sizeof(*frame));
   VG_(memcpy)(&frame->rs_info, siginfo, sizeof(*siginfo));
   synth_sigcontext(tst, &frame->rs_uc.uc_mcontext, mask);
   frame->rs_uc.uc_flags = 0;
   frame->rs_uc.uc_link  = 0;
   frame->rs_uc.uc_stack = tst->altstack;
   frame->rs_uc.uc_sigmask = *mask;

   priv = &frame->priv;
   priv->magicPI       = 0x31415927;
   priv->sigNo_private = siginfo->si_signo;
   priv->vex_shadow1   = tst->arch.vex_shadow1;
   priv->vex_shadow2   = tst->arch.vex_shadow2;

   VG_TRACK( post_mem_write, Vg_CoreSignal, tid, sp,
             sizeof(struct rt_sigframe) );

   /* Set up the handler's argument registers and control flow. */
   SET_SIGNAL_GPR(tst, 1, sp);                       /* new SP    */
   SET_SIGNAL_GPR(tst, 3, siginfo->si_signo);        /* arg1 = signo */
   SET_SIGNAL_GPR(tst, 4, (Addr)&frame->rs_info);    /* arg2 = &info */
   SET_SIGNAL_GPR(tst, 5, (Addr)&frame->rs_uc);      /* arg3 = &uc   */
   SET_SIGNAL_GPR(tst, 9, (Addr)&VG_(or1k_linux_SUBST_FOR_rt_sigreturn)); /* link */

   tst->arch.vex.guest_PC = (Addr)handler;

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg,
                   "sigframe_create (thread %u): next EIP=%#lx\n",
                   tid, (Addr)handler);
}

void VG_(sigframe_destroy) ( ThreadId tid, Bool isRT )
{
   ThreadState* tst = VG_(get_ThreadState)(tid);
   struct rt_sigframe* frame;
   struct vki_sigcontext* sc;
   Addr sp;
   Int i, sigNo;
   struct vg_sig_private* priv;

   sp = tst->arch.vex.guest_r1;
   frame = (struct rt_sigframe*)sp;
   priv  = &frame->priv;
   vg_assert(priv->magicPI == 0x31415927);
   sigNo = priv->sigNo_private;

   sc = &frame->rs_uc.uc_mcontext;
   for (i = 0; i < 32; i++)
      (&tst->arch.vex.guest_r0)[i] = sc->regs.gpr[i];
   tst->arch.vex.guest_PC = sc->regs.pc;

   /* the handler ran with the signal blocked; restore the caller's mask. */
   tst->sig_mask     = frame->rs_uc.uc_sigmask;
   tst->tmp_sig_mask = tst->sig_mask;

   tst->arch.vex_shadow1 = priv->vex_shadow1;
   tst->arch.vex_shadow2 = priv->vex_shadow2;

   VG_TRACK( die_mem_stack_signal, sp,
             sizeof(struct rt_sigframe) );

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg,
                   "sigframe_destroy (thread %u): isRT=%d valid magic; EIP=%#lx\n",
                   tid, isRT, (Addr)tst->arch.vex.guest_PC);

   VG_TRACK( post_deliver_signal, tid, sigNo );
}

#endif /* VGP_or1k_linux */

/*--------------------------------------------------------------------*/
/*--- end                                  sigframe-or1k-linux.c ---*/
/*--------------------------------------------------------------------*/
