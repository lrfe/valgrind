/*--------------------------------------------------------------------*/
/*--- Support for doing system calls.        syscall-or1k-linux.S ---*/
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

#include "pub_core_basics_asm.h"

#if defined(VGP_or1k_linux)

#include "pub_core_vkiscnums_asm.h"
#include "libvex_guest_offsets.h"

/* Perform a syscall for the client, running it with the client's
   per-thread signal mask.  See the nanomips/mips versions for the
   description of the interrupted-syscall protocol and the exported
   blksys_* boundary labels.

   UWord ML_(do_syscall_for_client_WRK)(
             Int syscallno,                // r3
             void* guest_state,            // r4
             const vki_sigset_t *sysmask,  // r5
             const vki_sigset_t *postmask, // r6
             Int nsigwords)                // r7
*/

#define VKI_SIG_SETMASK 2

.text
.globl ML_(do_syscall_for_client_WRK)
ML_(do_syscall_for_client_WRK):
    l.addi  r1, r1, -32
    l.sw    0(r1), r3            /* syscallno   */
    l.sw    4(r1), r4            /* guest_state */
    l.sw    8(r1), r5            /* sysmask     */
    l.sw    12(r1), r6           /* postmask    */
    l.sw    16(r1), r7           /* nsigwords   */

1:  l.ori   r11, r0, __NR_rt_sigprocmask
    l.ori   r3, r0, VKI_SIG_SETMASK
    l.lwz   r4, 8(r1)            /* sysmask   */
    l.lwz   r5, 12(r1)           /* postmask  */
    l.lwz   r6, 16(r1)           /* nsigwords */
    l.sys   1
    l.sfnei r11, 0
    l.bf    5f
     l.nop

    l.lwz   r13, 4(r1)           /* &guest_state */
    l.lwz   r11, 0(r1)           /* syscallno    */
    l.lwz   r3, OFFSET_or1k_r3(r13)
    l.lwz   r4, OFFSET_or1k_r4(r13)
    l.lwz   r5, OFFSET_or1k_r5(r13)
    l.lwz   r6, OFFSET_or1k_r6(r13)
    l.lwz   r7, OFFSET_or1k_r7(r13)
    l.lwz   r8, OFFSET_or1k_r8(r13)
2:  l.sys   1
3:  l.lwz   r13, 4(r1)
    l.sw    OFFSET_or1k_r11(r13), r11   /* store result into guest r11 */

4:  l.ori   r11, r0, __NR_rt_sigprocmask
    l.ori   r3, r0, VKI_SIG_SETMASK
    l.lwz   r4, 12(r1)           /* postmask  */
    l.ori   r5, r0, 0
    l.lwz   r6, 16(r1)           /* nsigwords */
    l.sys   1
    l.sfnei r11, 0
    l.bf    5f
     l.nop

    l.ori   r11, r0, 0           /* success */
    l.j     6f
     l.nop
5:  l.movhi r11, 0x8             /* sigprocmask failed: return 0x80000 */
6:  l.addi  r1, r1, 32
    l.jr    r9
     l.nop

.section .rodata
.globl ML_(blksys_setup)
.globl ML_(blksys_restart)
.globl ML_(blksys_complete)
.globl ML_(blksys_committed)
.globl ML_(blksys_finished)
ML_(blksys_setup):      .long 1b
ML_(blksys_restart):    .long 2b
ML_(blksys_complete):   .long 3b
ML_(blksys_committed):  .long 4b
ML_(blksys_finished):   .long 6b

#endif

/* Let the linker know we don't need an executable stack */
MARK_STACK_NO_EXEC

/*--------------------------------------------------------------------*/
/*--- end                                  syscall-or1k-linux.S ---*/
/*--------------------------------------------------------------------*/
