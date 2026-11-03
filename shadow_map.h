// shadow_map.h
// 섀도우 메모리 저장소의 공개 인터페이스.
// aha_libc.c(malloc/free 후킹부)가 이 헤더를 include해서
// shadow_map.c 안의 함수들을 가져다 쓴다.
//
// 전체 호출 체인: waw.c(LD_PRELOAD 주입) → aha_libc.c(후킹) → shadow_map.c(저장)

#ifndef SHADOW_MAP_H
#define SHADOW_MAP_H

#include <stddef.h>
#include <stdint.h>

// 섀도우 메모리 상태 코드
#define SHADOW_VALID  0x00 // 정상 (Access Allowed)
#define SHADOW_FREED  0x7F // 해제됨 (UAF / double-free 탐지용)
#define SHADOW_POISON 0xFE // 가드 영역 / 오버플로우 탐지용

// shadow_map.c가 구현하는 함수들 (aha_libc.c에서 호출)
void init_shadow_map(void);
void set_shadow_status(void *addr, size_t size, uint8_t status);
int  verify_shadow_status(void *addr);

#endif // SHADOW_MAP_H
