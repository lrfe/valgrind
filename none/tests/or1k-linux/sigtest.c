#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static sigjmp_buf jb;
static char altstack[16 * 1024];
static volatile int count, alarms;

static void on_segv(int sig, siginfo_t *si, void *ctx)
{
    char here;
    int on_alt = &here >= altstack && &here < altstack + sizeof altstack;
    printf("segv at %s, on altstack: %d\n",
           si->si_addr == (void *)16 ? "16" : "?", on_alt);
    siglongjmp(jb, 1);
}

static void on_usr1(int sig) { count++; }
static void on_alrm(int sig) { alarms++; }

int main(void)
{
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof altstack };
    struct sigaction sa;

    /* 1: a fault, handled on the alternate stack, escaped with siglongjmp */
    sigaltstack(&ss, NULL);
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);
    if (sigsetjmp(jb, 1) == 0)
        *(volatile int *)16 = 1;

    /* 2: the same handler returning many times. if the mask is not
       restored on return, only the first one arrives */
    signal(SIGUSR1, on_usr1);
    for (int i = 0; i < 1000; i++)
        raise(SIGUSR1);
    printf("usr1 delivered: %d\n", count);

    /* 3: a signal from the kernel, not from ourselves */
    signal(SIGALRM, on_alrm);
    alarm(1);
    pause();
    printf("alarm delivered: %d\n", alarms);
    return 0;
}
