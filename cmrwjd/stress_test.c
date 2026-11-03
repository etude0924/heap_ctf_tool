// stress_test.c - 오버헤드 벤치마크용
// malloc/free를 대량 반복해서 "호출 한 번당 추가 비용"을 측정 가능한
// 수준까지 끌어올린다. 인자로 반복 횟수를 받는다 (기본 100000).
//
// 사용 예:
//   ./stress_test                  (기본 10만 회)
//   ./stress_test 500000           (50만 회)
//   ./waw g2.29 -e ./stress_test   (waw로 감싸서 비교)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    long iterations = 100000;
    if (argc > 1) {
        iterations = atol(argv[1]);
    }

    // tcache 범위 안에서 여러 크기를 섞어서, 실제 프로그램의 malloc 패턴에
    // 더 가깝게 만든다 (한 크기만 반복하면 비현실적으로 단순해짐)
    size_t sizes[] = {16, 32, 64, 128, 256};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    for (long i = 0; i < iterations; i++) {
        size_t sz = sizes[i % num_sizes];
        void *p = malloc(sz);
        if (p) {
            memset(p, 0x41, sz); // 실제로 메모리를 건드려서 더 현실적으로
            free(p);
        }
    }

    printf("done: %ld iterations\n", iterations);
    return 0;
}
