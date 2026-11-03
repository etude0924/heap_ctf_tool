// 읽기 전용 UAF 테스트: free된 메모리를 "읽기만" 하고 아무것도 안 씀
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    char *secret = malloc(64);
    strcpy(secret, "super-secret-password");
    free(secret); // 여기서부턴 secret은 더 이상 유효하지 않음

    // 아무것도 안 쓰고 "읽기만" -> puts로 유출 시도
    puts(secret);

    return 0;
}
