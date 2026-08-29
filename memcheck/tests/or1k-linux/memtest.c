#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    /* heap overflow. invalid write of size 1 */
    char *p = malloc(16);
    p[16] = 'x';

    /* uninitialised read. conditional jump on uninit value */
    int *q = malloc(sizeof(int));
    if (*q == 42)
        printf("hit 42\n");

    /* use after free. invalid read of size 4 */
    free(q);
    int v = *q;
    (void)v;

    /* leak. 64 bytes definitely lost */
    char *leak = malloc(64);
    strcpy(leak, "leak");

    free(p);
    printf("memtest done\n");
    return 0;
}
