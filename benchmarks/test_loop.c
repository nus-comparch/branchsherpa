#include <stdio.h>
#include <stdint.h>

int main(void)
{
    uint32_t x = 123456789u;
    volatile uint64_t sum = 0;

    for (uint64_t i = 0; i < 10000000ULL; i++) {
        // xorshift pseudo-random number generator
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;

        // Approximately 50% taken / 50% not-taken
        if (x & 1)
            sum += i;
        else
            sum -= i;
    }

    printf("sum = %llu\n", (unsigned long long)sum);
    return 0;
}