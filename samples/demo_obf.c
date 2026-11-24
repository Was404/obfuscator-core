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
static long collatz_len(long var_261) {
    /* мёртвая ветвь: p*(p+1) всегда чётно, условие ложно */
    long junk_7326 = ((1442 << 3) + 3);
    if (((junk_7326 * (junk_7326 + 1)) % 2) != 0) {
        long unused_34b6 = ((9 * 2 - 15) * (1245 - 1233) + (47300 + 3091));
        unused_34b6 ^= (298 + 3460);
        (void)unused_34b6;
    }
    /* мёртвая ветвь: p*(p+1) всегда чётно, условие ложно */
    long obf_gate_3def = (25209 ^ 5132);
    if (((obf_gate_3def * (obf_gate_3def + 1)) % 2) != 0) {
        long dead_064c = (((52031 ^ 65339) << (1306 - 1305)) + ((0 << 1) + 1));
        dead_064c ^= (1395 + 2222);
        (void)dead_064c;
    }
    /* 0xe7443f */
    long wv72 = (1236 - 1236);
    while (var_261 != (4 * 12 - 47)) {
        if (var_261 % 2 == ((5514 + 4587) ^ (5514 + 4587))) {
            var_261 = var_261 / (4 * 5 - 18);
        } else {
            var_261 = 3 * var_261 + ((15303 ^ 15309) * (5 + 7) - (12 * 3 + 83));
        }
        wv72 = wv72 + (((0 << 1) + 1) + ((0 << 2) + 0));
    }
    return wv72;
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
