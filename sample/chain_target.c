// chain_target.c - --show-bins (tcache bin 체인 로그) 테스트용
// 시나리오: 같은 크기(32바이트) 청크 3개를 만들었다가 순서대로 free,
//          그 다음 다시 malloc해서 체인이 줄어드는 걸 관찰
//   ./waw g2.26 -e ./chain_target --show-bins
// 기대 결과 (LIFO 순서로 head가 바뀌는 걸 확인):
//   free(a): a -> NULL                       (count=1)
//   free(b): b -> a -> NULL                  (count=2)
//   free(c): c -> b -> a -> NULL             (count=3)
//   malloc(): (c가 빠져나감) b -> a -> NULL   (count=2)

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void *a = malloc(32);
    void *b = malloc(32);
    void *c = malloc(32);
    printf("[chain_target] a=%p b=%p c=%p\n", a, b, c);

    free(a);
    free(b);
    free(c);

    void *d = malloc(32); // c를 다시 꺼내감
    printf("[chain_target] d=%p (c였나? %s)\n", d, d == c ? "yes" : "no");

    return 0;
}
