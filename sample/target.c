// target.c - double-free 탐지 테스트용
// 시나리오: 같은 포인터를 두 번 free
//   ./waw g2.26 -e ./target
// 기대 결과: [WAW] CRITICAL: Use-After-Free detected... 가
//           glibc 자체 메시지(free(): double free detected in tcache 2)보다 먼저 뜸

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); // stdout 즉시 출력 (버퍼링으로 로그 순서 꼬이는 것 방지

    printf("[target] mallocing 32 bytes...\n");
    void *p = malloc(32);
    printf("[target] got pointer %p\n", p);

    printf("[target] freeing once...\n");
    free(p);

    printf("[target] freeing AGAIN (double free!)...\n");
    free(p);

    printf("[target] done\n");
    return 0;
}
