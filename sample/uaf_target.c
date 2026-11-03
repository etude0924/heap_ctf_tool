// uaf_target.c - UAF(Use-After-Free) 쓰기 탐지 테스트용
// 시나리오: free된 청크에 다시 값을 써넣음 (함수 후킹 없이도 잡혀야 하는 경로)
//   ./waw g2.26 -e ./uaf_target
// 기대 결과: [WAW] CRITICAL: Use-After-Free write detected...
// 참고: 내용물이 fd 영역(헤더)까지 덮으면 poisoning 탐지도 같이 뜰 수 있음
//       (실제 공격에서도 흔히 같이 발생하는 패턴)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    char *buf = malloc(64);
    strcpy(buf, "original secret data");
    printf("[uaf_target] buf=%p content=%s\n", buf, buf);

    free(buf); // free 시점에 이 내용물이 스냅샷으로 저장됨

    // UAF: free된 포인터를 통해 직접 써버림
    printf("[uaf_target] writing to freed buf (UAF)...\n");
    strcpy(buf, "ATTACKER OVERWRITE!!");

    void *reused = malloc(64); // 같은 자리를 다시 할당받으면 스냅샷과 비교가 일어남
    printf("[uaf_target] reused=%p (same as buf? %s)\n", reused, reused == buf ? "yes" : "no");

    return 0;
}
