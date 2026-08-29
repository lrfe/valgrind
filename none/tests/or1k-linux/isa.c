#include <stdio.h>

#define SHOW(name, val) printf("%-8s %08x\n", name, (unsigned)(val))

static unsigned muli(unsigned a)      { unsigned r; __asm__("l.muli %0,%1,100":"=r"(r):"r"(a)); return r; }
static unsigned mulu(unsigned a, unsigned b) { unsigned r; __asm__("l.mulu %0,%1,%2":"=r"(r):"r"(a),"r"(b)); return r; }
static unsigned ff1(unsigned a)       { unsigned r; __asm__("l.ff1 %0,%1":"=r"(r):"r"(a)); return r; }
static unsigned fl1(unsigned a)       { unsigned r; __asm__("l.fl1 %0,%1":"=r"(r):"r"(a)); return r; }
static unsigned ror(unsigned a, unsigned n)  { unsigned r; __asm__("l.ror %0,%1,%2":"=r"(r):"r"(a),"r"(n)); return r; }
static unsigned rori(unsigned a)      { unsigned r; __asm__("l.rori %0,%1,12":"=r"(r):"r"(a)); return r; }
static unsigned lws(unsigned *p)      { unsigned r; __asm__("l.lws %0,0(%1)":"=r"(r):"r"(p)); return r; }

/* cmov picks rA when SR[F] is set, rB otherwise. */
static unsigned cmov(unsigned a, unsigned b, int takeA)
{
   unsigned r;
   __asm__("l.sfnei %1,0\n\tl.cmov %0,%2,%3"
           : "=&r"(r) : "r"(takeA), "r"(a), "r"(b));
   return r;
}

/* 64-bit add built from l.add + l.addc, exercising the carry chain. */
static void add64(unsigned alo, unsigned ahi, unsigned blo, unsigned bhi,
                  unsigned *rlo, unsigned *rhi)
{
   unsigned lo, hi;
   __asm__("l.add %0,%2,%4\n\tl.addc %1,%3,%5"
           : "=&r"(lo), "=&r"(hi)
           : "r"(alo), "r"(ahi), "r"(blo), "r"(bhi));
   *rlo = lo; *rhi = hi;
}

/* l.addic adds an immediate plus the carry left by the preceding l.add. */
static unsigned addic(unsigned a, unsigned b)
{
   unsigned t, r;
   __asm__("l.add %0,%2,%3\n\tl.addic %1,%2,7"
           : "=&r"(t), "=&r"(r) : "r"(a), "r"(b));
   return r;
}

int main(void)
{
   unsigned mem = 0xDEADBEEF, lo, hi;

   SHOW("muli",   muli(7));
   SHOW("mulu",   mulu(0x10001, 0x10001));
   SHOW("ff1a",   ff1(0x00000180));
   SHOW("ff1b",   ff1(0));
   SHOW("ff1c",   ff1(0x80000000));
   SHOW("fl1a",   fl1(0x00000180));
   SHOW("fl1b",   fl1(0));
   SHOW("fl1c",   fl1(1));
   SHOW("ror",    ror(0x12345678, 8));
   SHOW("ror0",   ror(0x12345678, 0));
   SHOW("rori",   rori(0x12345678));
   SHOW("lws",    lws(&mem));
   SHOW("cmovA",  cmov(0xAAAA, 0xBBBB, 1));
   SHOW("cmovB",  cmov(0xAAAA, 0xBBBB, 0));

   add64(0xFFFFFFFF, 0x00000001, 0x00000002, 0x00000003, &lo, &hi);
   SHOW("a64lo",  lo);
   SHOW("a64hi",  hi);
   add64(0x00000001, 0x00000001, 0x00000002, 0x00000003, &lo, &hi);
   SHOW("b64lo",  lo);
   SHOW("b64hi",  hi);

   SHOW("addicC", addic(0xFFFFFFFF, 2));
   SHOW("addicN", addic(1, 2));

   __asm__ volatile("l.msync");
   __asm__ volatile("l.csync");
   __asm__ volatile("l.psync");
   SHOW("syncs",  0);

   printf("isa done\n");
   return 0;
}
