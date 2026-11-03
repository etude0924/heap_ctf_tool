// shadow_map.c
// 섀도우 메모리 "저장" 담당 파일.
//
// [수정 이력] 처음엔 절대 힙 주소를 8로 나눠서 고정 오프셋에 매핑했는데,
// PIE+ASLR 환경에서 힙 주소가 매우 높은 곳(예: 0x5640...)에 뜨는 바람에
// 8:1로 나눠도 예약해둔 섀도우 공간 범위를 벗어나 세그폴트가 발생했다.
// → 절대주소 대신 "힙 시작점(base) 대비 상대 오프셋"으로 매핑하도록 변경.
//   힙은 base에서 시작해서 위로 자라므로, 상대 오프셋은 훨씬 작은 값이 되고
//   이 값이 예약된 섀도우 공간 범위를 벗어나면 안전하게 추적을 건너뛴다.

#include "shadow_map.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#define SHADOW_OFFSET 0x100000000000ULL
#define SHADOW_SIZE   (1ULL << 30) // 1GB 섀도우 공간 -> 힙 8GB까지 추적 가능 (1GB * 8)

static int       shadow_ready = 0;
static uintptr_t heap_base    = 0; // 이 프로세스 힙의 시작 기준점

// ---------------------------------------------------------
// 실제 주소 -> 섀도우 주소 변환
// heap_base를 기준으로 한 "상대 오프셋"을 8:1로 매핑한다.
// 범위를 벗어나면(예: mmap으로 별도 할당된 큰 청크) out_ptr에 NULL을 주고
// -1을 반환해서 "추적 대상 아님"으로 처리한다.
// ---------------------------------------------------------
static int addr_to_shadow(void *addr, uint8_t **out_ptr) {
    uintptr_t a = (uintptr_t)addr;

    if (a < heap_base) {
        return -1; // 힙 시작점보다 낮은 주소 (스택/코드 영역 등) -> 추적 대상 아님
    }

    uintptr_t rel_offset = a - heap_base;
    uintptr_t shadow_index = rel_offset >> 3; // 8바이트당 1바이트

    if (shadow_index >= SHADOW_SIZE) {
        return -1; // 예약해둔 섀도우 공간 범위 초과 (힙이 비정상적으로 커진 경우)
    }

    *out_ptr = (uint8_t *)(SHADOW_OFFSET + shadow_index);
    return 0;
}

// ---------------------------------------------------------
// 섀도우 메모리 맵 초기화
// ★ 연결 지점: aha_libc.c의 __attribute__((constructor)) 함수가
//   라이브러리 로드 시점에 이 함수를 호출한다.
// ---------------------------------------------------------
void init_shadow_map(void) {
    // 현재 프로그램 break 지점 = 이 시점 기준 힙의 시작 근처
    heap_base = (uintptr_t)sbrk(0);

    void *shadow_map = mmap(
        (void *)SHADOW_OFFSET,
        SHADOW_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE,
        -1, 0
    );

    if (shadow_map == MAP_FAILED) {
        perror("[WAW] Failed to allocate shadow memory map");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[WAW] Shadow memory map created at %p (Size: 1GB, heap_base=%p)\n",
            shadow_map, (void *)heap_base);
    shadow_ready = 1;
}

// ---------------------------------------------------------
// 특정 메모리 영역의 상태를 섀도우 맵에 기록
// ---------------------------------------------------------
void set_shadow_status(void *addr, size_t size, uint8_t status) {
    if (!shadow_ready) return;

    uint8_t *shadow_ptr;
    if (addr_to_shadow(addr, &shadow_ptr) != 0) {
        return; // 추적 범위 밖 -> 조용히 무시 (에러 아님)
    }

    size_t shadow_size = size >> 3;
    if (shadow_size == 0) shadow_size = 1;

    for (size_t i = 0; i < shadow_size; i++) {
        shadow_ptr[i] = status;
    }
}

// ---------------------------------------------------------
// 특정 주소에 접근하기 전 유효성 검사
// ★ 연결 지점: aha_libc.c의 free() 후킹부가 double-free 탐지에 사용.
// ---------------------------------------------------------
int verify_shadow_status(void *addr) {
    if (!shadow_ready) return 0;

    uint8_t *shadow_ptr;
    if (addr_to_shadow(addr, &shadow_ptr) != 0) {
        return 0; // 추적 범위 밖 -> 판단 불가, 정상으로 취급
    }

    if (*shadow_ptr == SHADOW_FREED) {
        fprintf(stderr, "[WAW] CRITICAL: Use-After-Free detected at address %p!\n", addr);
        return -1;
    } else if (*shadow_ptr == SHADOW_POISON) {
        fprintf(stderr, "[WAW] CRITICAL: Heap Overflow detected at address %p!\n", addr);
        return -1;
    }
    return 0;
}
