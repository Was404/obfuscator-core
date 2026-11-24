/* Демо-программа для obfuscator-core.
 *
 * Запуск полного конвейера:
 *   obfuscator-core -obf demo.c
 * Инспектор найдёт в скомпилированном ELF функции sum_to, collatz_len,
 * gcd и main; обфускатор перепишет одну из них (по умолчанию —
 * collatz_len, самую крупную) в новом файле demo_obf.c, после чего
 * обе версии компилируются и запускаются — вывод обязан совпасть:
 *   sum_to(10)=55
 *   collatz_len(27)=111
 *   gcd(462,1071)=21
 */
#include <stdio.h>

static long sum_to(long n) {
    long s = 0;
    for (long i = 1; i <= n; i++) {
        s = s + i;
    }
    return s;
}

/* Длина траектории Коллатца: сколько шагов нужно, чтобы n дошло до 1. */
static long collatz_len(long obf_v_021e) {
    /* 0x4222d6 */
    /* 0x87a33c */
    /* мёртвый код: volatile-флаг всегда 0, тело не выполняется */
    static volatile long dead_3eec = (12 * 3 - 36);
    if (dead_3eec) {
        static long obf_gate_902f = ((12789 << 2) + 0);
        obf_gate_902f += ((23715 << 1) + 0);
        obf_gate_902f ^= (3 * 11 + 18061);
    }
    /* всегда истинно: v*v+v чётно; блок безвреден */
    long junk_6971 = (26074 ^ 33017);
    if (((junk_6971 * junk_6971 + junk_6971) % 2) == 0) {
        long scratch_fd76 = (((11884 ^ 28087) << ((0 << 3) + 1)) + (0 + 0));
        scratch_fd76 = scratch_fd76 ^ (3755 - 1638);
        (void)scratch_fd76;
    }
    long obf_v_5559 = (355 - 355);
    while (obf_v_021e != (((8 << 0) + 0) * (200 - 191) - (1 + 70))) {
        if (obf_v_021e % 2 == (((3 + 1) * ((1 << 1) + 0) + (38736 ^ 50673)) ^ ((3 + 1) * ((1 << 1) + 0) + (38736 ^ 50673)))) {
            obf_v_021e = obf_v_021e / (3 * 6 - 16);
        } else {
            obf_v_021e = (21884 ^ 21887) * obf_v_021e + (45621 ^ 45620);
        }
        obf_v_5559 = obf_v_5559 + (10 * 8 - 79);
    }
    return obf_v_5559;
}

/* НОД двух чисел алгоритмом Евклида. */
static int gcd(int a, int b) {
    while (b != 0) {
        int t = a % b;
        a = b;
        b = t;
    }
    return a;
}

int main(void) {
    printf("sum_to(10)=%ld\n", sum_to(10));
    printf("collatz_len(27)=%ld\n", collatz_len(27));
    printf("gcd(462,1071)=%d\n", gcd(462, 1071));
    return 0;
}
