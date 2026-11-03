// poison_target.c - tcache/fastbin poisoning 탐지 테스트용
// 시나리오: free된 청크를 UAF로 직접 접근해서 fd 필드를 조작
//   (실제 CTF에서는 오버플로우/UAF 버그로 이 지점을 조작함, 여기선 직접 흉내)
//   ./waw g2.29 -e ./poison_target   (raw 값 비교만, 디코딩 없음)
//   ./waw g2.32 -e ./poison_target   (safe-linking 디코딩 로그까지 같이 뜸)
// 기대 결과: [WAW] CRITICAL: tcache/fastbin poisoning detected...

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[poison_target] malloc 32 bytes\n");
    void *a = malloc(32);
    printf("[poison_target] a = %p\n", a);

    printf("[poison_target] free(a)\n");
    free(a); // 이 시점에 glibc가 a 위치에 fd를 써넣음 (tcache/fastbin)

    // UAF를 흉내낸 조작: free된 a를 통해 fd 필드를 직접 덮어씀
    printf("[poison_target] corrupting fd field via dangling pointer...\n");
    *(unsigned long *)a = 0xdeadbeefcafebabeUL;

    printf("[poison_target] malloc 32 bytes again (should return 'a')\n");
    void *b = malloc(32);
    printf("[poison_target] b = %p (same as a? %s)\n", b, (a == b) ? "yes" : "no");

    return 0;
}
