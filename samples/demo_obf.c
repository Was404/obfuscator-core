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
static long collatz_len(long obf_0_f871) {
    static volatile long obf_gate_ae4c = 0; if (obf_gate_ae4c) { static long obf_sink_ae4c; obf_sink_ae4c += (0x5A5A ^ 0x1234) - (0x4B4B ^ 0x0F0F); } /* dead code: gate всегда 0 */
    long obf_1_6d14 = (1 - 1);
    while (obf_0_f871 != (2 - 1)) {
        if (obf_0_f871 % 2 == (1 - 1)) {
            obf_0_f871 = obf_0_f871 / 2;
        } else {
            obf_0_f871 = 3 * obf_0_f871 + (2 - 1);
        }
        obf_1_6d14 = obf_1_6d14 + (2 - 1);
    }
    return obf_1_6d14;
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
