// aha_libc.c  (컴파일 결과물: aha_libc.so)
// "malloc/free 후킹" 담당 파일. shadow_map.c가 만든 저장소에
// 언제, 무엇을 기록할지 결정하는 역할.
//
// ★ 연결 지점: waw.c(프론트엔드)가 LD_PRELOAD 환경변수로
//   이 .so를 타겟 프로세스에 강제로 먼저 로드시킨다.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>   // getenv
#include <string.h>   // strcmp
#include <execinfo.h> // backtrace, backtrace_symbols_fd
#include <unistd.h>   // STDERR_FILENO, open/read/close
#include <fcntl.h>    // O_RDONLY
#include <gnu/libc-version.h> // gnu_get_libc_version

#include "shadow_map.h"

// ---------------------------------------------------------
// ★ 실제로 지금 로드된 glibc가 safe-linking을 쓰는지는 "사용자가 고른
//   시대(WAW_MODE)"가 아니라 "진짜 glibc 버전"에 달려있다. 이 둘을
//   섞어서 enable_safelink 하나로 쓰면, 예를 들어 실제 환경이 2.39인데
//   사용자가 g2.26을 선택했을 때 "메모리엔 인코딩된 값이 있는데 우리는
//   디코딩을 안 하는" 불일치가 생겨 bin 체인 추적이 완전히 틀어진다
//   (실제로 테스트 중 발견됨: 디코딩 안 한 raw 값을 다음 주소로 써서
//   전혀 엉뚱한 주소가 출력됨).
//
//   그래서 "실제로 디코딩이 필요한지"는 런타임에 자동 감지한 이 값
//   (actual_safelink)으로만 판단한다. enable_safelink는 별도로 남겨서
//   poisoning 탐지 로그에 "디코딩된 해석"을 보여줄지 말지에만 쓴다
//   (교육적 설명 목적 — 사용자가 g2.32를 선택했다는 건 "이 조작을
//   safe-linking 관점에서 설명해달라"는 의도로 해석).
// ---------------------------------------------------------
static int actual_safelink    = 0;
static int actual_tcache_key  = 0; // glibc 2.29+는 fd 다음 8바이트에 'key' 필드를 씀
                                    // (UAF 스냅샷 비교 시 이 영역도 헤더로 건너뛰어야 함)

static void detect_actual_glibc_features(void) {
    const char *ver = gnu_get_libc_version(); // 예: "2.39"
    int major = 0, minor = 0;
    if (sscanf(ver, "%d.%d", &major, &minor) == 2 && major == 2) {
        actual_safelink   = (minor >= 32);
        actual_tcache_key = (minor >= 29);
    }
}

// ---------------------------------------------------------
// WAW_MODE: waw.c가 "glibc 시대" 문자열(g2.26/g2.29/g2.32)을 심어서
// 넘겨주는 환경변수. 기능 단위(ddf/poison/safelink)에서 시대 단위로
// 전환되면서, 하나의 시대가 여러 탐지 기능을 동시에 켤 수 있게 됐다.
//
//   g2.26: tcache_entry에 key 필드 자체가 없음 -> double-free 무방비,
//          poisoning도 당연히 가능 (ddf + poison 둘 다 켬)
//   g2.29: key 필드로 double-free는 막히지만, tcache_get()에는 여전히
//          key 체크가 없어 poisoning은 그대로 가능 (ddf + poison 둘 다 켬,
//          내부 탐지 로직은 g2.26과 사실상 동일 — 우리 탐지는 raw 값
//          비교라서 glibc 자체 보호 유무와 무관하게 똑같이 작동한다)
//   g2.32: safe-linking(pointer mangling) 도입 (ddf + poison + safelink)
//
// waw.c 없이 이 .so를 직접 LD_PRELOAD한 경우(WAW_MODE 없음)엔
// 기본값으로 g2.29(ddf+poison)를 켠다.
// ---------------------------------------------------------
static int enable_ddf      = 1; // double-free 탐지
static int enable_poison   = 1; // tcache/fastbin poisoning 탐지
static int enable_safelink = 0; // safe-linking 우회 탐지
static int enable_uaf      = 1; // UAF(쓰기) 탐지 — tcache 보호기법 유무와 무관한
                                 // 일반적인 힙 안전성 문제라 세 시대 전부 기본으로 켠다

// ★ WAW_SHOW_BINS: WAW_MODE(필수, era)와는 별개의 독립적인 on/off 옵션.
//   era가 "이 시대엔 뭘 탐지할지"를 정한다면, 이건 "탐지 외에 bin 체인도
//   실시간으로 보여줄지"를 정하는 거라 환경변수를 분리했다.
static int show_bins_enabled = 0;

static void load_mode_from_env(void) {
    if (getenv("WAW_SHOW_BINS")) {
        show_bins_enabled = 1;
    }

    const char *era = getenv("WAW_MODE");
    if (!era) {
        return; // 기본값(ddf+poison, safelink 없음) 그대로 사용
    }

    if (strcmp(era, "g2.26") == 0 || strcmp(era, "g2.29") == 0) {
        enable_ddf = 1;
        enable_poison = 1;
        enable_safelink = 0;
        enable_uaf = 1;
    } else if (strcmp(era, "g2.32") == 0) {
        enable_ddf = 1;
        enable_poison = 1;
        enable_safelink = 1;
        enable_uaf = 1;
    } else {
        enable_ddf = 0;
        enable_poison = 0;
        enable_safelink = 0;
        enable_uaf = 0;
        fprintf(stderr, "[WAW] WARNING: unknown WAW_MODE '%s', no detection enabled\n", era);
    }
}

// ---------------------------------------------------------
// 탐지 시점의 콜스택(호출 스택)을 stderr로 출력
// ★ target 프로세스 안에서 실행되므로, target 자신의 함수 호출 흐름이
//   그대로 찍힌다. 함수 이름까지 보려면 target을 컴파일할 때
//   -rdynamic 옵션을 주는 게 좋다 (심볼 테이블을 동적 링커가 볼 수 있게 함).
// ---------------------------------------------------------
#define BACKTRACE_MAX_FRAMES 16

static void print_backtrace(void) {
    void *frames[BACKTRACE_MAX_FRAMES];
    int n = backtrace(frames, BACKTRACE_MAX_FRAMES);

    fprintf(stderr, "[WAW] --- call stack (where this free() was called) ---\n");
    // backtrace_symbols_fd는 malloc을 내부적으로 쓰지 않아서
    // 우리가 만든 malloc 후킹 안에서 재귀 호출될 걱정 없이 안전하게 쓸 수 있다.
    backtrace_symbols_fd(frames, n, STDERR_FILENO);
    fprintf(stderr, "[WAW] ----------------------------------------------\n");
}

// 원래의 libc 함수 포인터
static void  *(*original_malloc)(size_t) = NULL;
static void   (*original_free)(void *)   = NULL;
// ★ memcpy는 free() 내부(UAF 스냅샷 캡처)에서도 직접 써야 하는데,
//   이 파일 안에서 그냥 memcpy(...)라고 부르면 우리가 아래에서 정의한
//   후킹된 memcpy로 바로 연결돼버린다. 그러면 "방금 FREED로 마킹한
//   주소"를 스냅샷 뜨려고 읽는 우리 자신의 호출이 UAF로 오탐되는
//   문제가 실제로 발생했다 (free() 안에서 자기 자신을 의심하는 셈).
//   그래서 내부용으로 쓸 원본 memcpy를 미리 확보해둔다.
static void *(*original_memcpy)(void *, const void *, size_t) = NULL;

// ---------------------------------------------------------
// 크기 추적용 저장소 (오픈 어드레싱 해시테이블)
//
// shadow_map.c는 "이 주소는 VALID/FREED/POISON이다"라는 상태만 알지,
// "이 주소가 몇 바이트짜리 청크였는지"는 모른다.
// free(ptr)는 크기 인자를 안 받기 때문에, free 시점에 섀도우를
// 몇 바이트만큼 FREED로 찍어야 할지 알려면 malloc 시점에
// 저장해둔 이 크기 정보를 다시 찾아 써야 한다.
// ---------------------------------------------------------
#define SIZE_TABLE_CAPACITY 65536 // 2의 거듭제곱 (마스크 연산용)

// ★ EMPTY: 한 번도 안 쓰인 슬롯 (탐색을 여기서 멈춰도 됨)
//   USED: 지금 사용 중
//   TOMBSTONE: 한 번 쓰였다가 반납된 슬롯 (탐색은 계속 지나가야 하지만
//              삽입할 땐 재사용 가능)
// EMPTY와 TOMBSTONE을 구분 안 하고 그냥 "빈 슬롯"으로 합쳐버리면,
// free로 반납된 슬롯을 find가 "여기서 체인이 끝났다"고 오판해서
// 그 뒤에 있는 진짜 살아있는 엔트리를 못 찾는 문제가 생긴다.
typedef enum { SLOT_EMPTY = 0, SLOT_USED, SLOT_TOMBSTONE } slot_state_t;

typedef struct {
    void         *addr;
    size_t        size;
    slot_state_t  state;
} size_entry_t;

static size_entry_t size_table[SIZE_TABLE_CAPACITY];

static inline size_t hash_ptr(void *ptr) {
    uintptr_t v = (uintptr_t)ptr;
    v ^= (v >> 33);
    v *= 0xff51afd7ed558ccdULL;
    v ^= (v >> 33);
    return (size_t)(v & (SIZE_TABLE_CAPACITY - 1));
}

// ptr의 크기를 테이블에 기록 (malloc이 호출)
static void size_table_insert(void *ptr, size_t size) {
    size_t idx = hash_ptr(ptr);
    for (size_t probe = 0; probe < SIZE_TABLE_CAPACITY; probe++) {
        size_t i = (idx + probe) & (SIZE_TABLE_CAPACITY - 1);
        // TOMBSTONE 슬롯도 재사용 가능 (EMPTY랑 똑같이 취급해서 덮어씀)
        if (size_table[i].state != SLOT_USED) {
            size_table[i].addr  = ptr;
            size_table[i].size  = size;
            size_table[i].state = SLOT_USED;
            return;
        }
    }
    fprintf(stderr, "[WAW] WARNING: size table full, tracking dropped for %p\n", ptr);
}

// ptr의 크기를 조회 (free가 호출). 못 찾으면 -1
static long size_table_find(void *ptr) {
    size_t idx = hash_ptr(ptr);
    for (size_t probe = 0; probe < SIZE_TABLE_CAPACITY; probe++) {
        size_t i = (idx + probe) & (SIZE_TABLE_CAPACITY - 1);
        if (size_table[i].state == SLOT_EMPTY) {
            return -1; // 진짜 빈 슬롯을 만나야만 "더 이상 없다"고 확정
        }
        if (size_table[i].state == SLOT_USED && size_table[i].addr == ptr) {
            return (long)i;
        }
        // SLOT_TOMBSTONE이면 값은 무시하고 계속 다음 슬롯으로 탐색
    }
    return -1;
}

// ---------------------------------------------------------
// tcache poisoning / fastbin corruption 탐지용 저장소
//
// ★ tcache와 fastbin은 둘 다 "fd 하나로만 연결된 싱글 링크드 리스트"라서
//   구조가 동일하다. safe-linking 인코딩 공식도 공유한다
//   ((청크 주소 >> 12) XOR fd). 그래서 "tcache 최대 크기(0x408)" 하나만
//   기준으로 잡으면, 그보다 작은 fastbin 크기(0x90 이하)는 자동으로
//   포함된다 — bin 종류를 따로 구분할 필요가 없다.
//
// ★ 저장하는 값은 "인코딩 여부와 상관없이 메모리에 그대로 있던 값"이다.
//   디코딩을 안 해도 탐지엔 문제가 없다: 아무도 조작 안 했다면
//   같은 주소에서 같은 방식(인코딩이든 평문이든)으로 다시 계산되니
//   raw 값이 그대로 일치한다. 디코딩은 "실제로 어느 주소를 가리키는지
//   보여주고 싶을 때"(safe-linking 우회 분석)만 필요하다.
// ---------------------------------------------------------
#define TCACHE_MAX_SIZE 0x408 // 이 크기 이하면 tcache 또는 fastbin 대상으로 간주

// ★ UAF(쓰기) 탐지용 스냅샷 크기 상한. 청크 전체를 다 저장하면 fd_table이
//   너무 커지니(65536칸 * 큰 버퍼), 교육/시연 목적엔 이 정도면 충분하다고
//   보고 상한을 둔다. 헤더(fd, 2.29+는 key까지) 이후 영역만 비교 대상이다.
#define UAF_SNAPSHOT_SIZE 48

typedef struct {
    void         *addr;
    uintptr_t     original_fd; // free 시점에 읽어둔 fd 원본 값 (raw, 디코딩 안 함)
    size_t        size;        // ★ --show-bins가 "같은 크기끼리" 체인을 묶을 때 씀
    unsigned char snapshot[UAF_SNAPSHOT_SIZE]; // ★ free 시점 payload 내용물 스냅샷
    size_t        snapshot_len;                // 실제로 담은 바이트 수 (청크가 작으면 더 작을 수 있음)
    slot_state_t  state;
} fd_entry_t;

static fd_entry_t fd_table[SIZE_TABLE_CAPACITY];

// fd 원본 값 + UAF 비교용 스냅샷을 함께 기록
// (free가 호출, original_free 호출 "이후"에만 의미 있음 — fd도 스냅샷도
//  glibc가 다 써놓은 뒤의 상태를 담아야 하기 때문)
static void fd_table_insert(void *ptr, uintptr_t fd, size_t size,
                             const unsigned char *snapshot, size_t snapshot_len) {
    size_t idx = hash_ptr(ptr);
    for (size_t probe = 0; probe < SIZE_TABLE_CAPACITY; probe++) {
        size_t i = (idx + probe) & (SIZE_TABLE_CAPACITY - 1);
        if (fd_table[i].state != SLOT_USED) {
            fd_table[i].addr        = ptr;
            fd_table[i].original_fd = fd;
            fd_table[i].size        = size;
            if (snapshot && snapshot_len > 0) {
                original_memcpy(fd_table[i].snapshot, snapshot, snapshot_len);
            }
            fd_table[i].snapshot_len = snapshot_len;
            fd_table[i].state       = SLOT_USED;
            return;
        }
    }
    fprintf(stderr, "[WAW] WARNING: fd table full, tracking dropped for %p\n", ptr);
}

// fd 원본 값을 조회 (malloc이 호출). 못 찾으면 -1
static long fd_table_find(void *ptr) {
    size_t idx = hash_ptr(ptr);
    for (size_t probe = 0; probe < SIZE_TABLE_CAPACITY; probe++) {
        size_t i = (idx + probe) & (SIZE_TABLE_CAPACITY - 1);
        if (fd_table[i].state == SLOT_EMPTY) {
            return -1;
        }
        if (fd_table[i].state == SLOT_USED && fd_table[i].addr == ptr) {
            return (long)i;
        }
    }
    return -1;
}

// ---------------------------------------------------------
// Safe-linking 디코딩 (glibc 2.32+)
//
// ★ 탐지 자체는 디코딩 없이 raw 값 비교만으로 이미 동작한다.
//   이 함수는 "탐지된 값이 실제로 어느 주소를 가리키려 했는지"를
//   사람이 읽을 수 있게 해석해서 보여주는 용도일 뿐이다 (enable_safelink
//   일 때만 호출됨, g2.26/g2.29에서는 인코딩 자체가 없으므로 호출하지 않음).
//
// 공식: decode(청크주소, mangled값) = (청크주소 >> 12) XOR mangled값
//   glibc의 PROTECT_PTR/REVEAL_PTR 매크로와 동일한 연산이다.
// ---------------------------------------------------------
static inline uintptr_t safelink_decode(void *chunk_addr, uintptr_t mangled) {
    return ((uintptr_t)chunk_addr >> 12) ^ mangled;
}

// 디코딩된 주소가 "그럴듯한" 유저 공간 포인터인지 느슨하게 검사.
// 공격자가 safe-linking 공식을 고려 안 하고 값을 그냥 덮어쓴 경우
// (저희 poison_target.c 테스트처럼), 디코딩해도 의미 없는 값이 나올 수
// 있다 -- 이건 버그가 아니라 "정교하지 않은 조작이었다"는 신호이므로
// WARNING으로만 표시하고 넘어간다.
static int looks_like_plausible_pointer(uintptr_t addr) {
    return addr >= 0x1000 && addr <= 0x7fffffffffffULL;
}

// ---------------------------------------------------------
// --show-bins: 같은 크기(size)의 free 청크들이 지금 어떻게 연결되어
// 있는지 bin 체인을 복원해서 보여준다.
//
// ★ fd_table은 주소(addr) 기준으로 해시되어 있어서, "같은 size끼리"를
//   찾으려면 테이블 전체를 훑어야 한다 (주소로 분류된 걸 크기로 다시
//   묶으려는 것이므로 구조적으로 피할 수 없음). 대신 tcache 기본 한도
//   (TCACHE_FILLCOUNT=7)를 알고 있으니, "7개 찾으면 더 볼 필요 없다"는
//   조기 종료로 평균 비용을 낮춘다. 완전히 훑지 않으려면 size별 전용
//   버킷 구조가 필요한데, 이는 향후 과제로 남긴다.
//
// head(체인의 시작점) 추정: 모아놓은 엔트리들의 addr 집합과 모든
// original_fd 값을 비교해서, "그 어떤 엔트리의 fd도 자신을 안 가리키는"
// 엔트리를 head로 본다. 이건 추정이지 glibc의 실제 tcache head를 직접
// 읽는 게 아니므로(방법 B), head를 특정 못 하면 WARNING으로 알린다.
// ---------------------------------------------------------
#define TCACHE_FILLCOUNT 7
#define MAX_CHAIN_COLLECT 32 // 비정상적으로 긴 체인까지 대비한 수집 상한

static void print_bin_chain(size_t size) {
    void     *addrs[MAX_CHAIN_COLLECT];
    uintptr_t decoded_next[MAX_CHAIN_COLLECT]; // ★ raw가 아니라 디코딩된 "다음 주소"
    int       collected = 0;

    for (size_t i = 0; i < SIZE_TABLE_CAPACITY && collected < MAX_CHAIN_COLLECT; i++) {
        if (fd_table[i].state == SLOT_USED && fd_table[i].size == size) {
            addrs[collected] = fd_table[i].addr;
            // ★ 여기서 바로 디코딩해서 저장한다. head 판정도, 체인 추적도
            //   전부 이 디코딩된 값을 기준으로 비교해야 한다 — raw(인코딩된)
            //   값끼리는 애초에 주소랑 직접 비교가 안 되기 때문에, 디코딩을
            //   빼먹으면 head 판정부터 어긋난다 (실제로 테스트 중 발견된 버그:
            //   디코딩 없이 비교하니 "아무도 안 가리키는 엔트리"가 잘못 걸려서
            //   엉뚱한 주소가 head로 선택됐었음).
            uintptr_t raw = fd_table[i].original_fd;
            decoded_next[collected] = actual_safelink ? safelink_decode(addrs[collected], raw) : raw;
            collected++;

            // ★ "7개 찾으면 멈추기": tcache 기본 한도 이상은 거의 안 보일
            //   것이므로, 여기서 끊어도 대부분의 경우 전체 체인을 놓치지 않는다.
            if (collected >= TCACHE_FILLCOUNT) break;
        }
    }

    if (collected == 0) return; // 이 크기로 추적 중인 게 없음 -> 조용히 넘어감

    // head 추정: 디코딩된 기준으로, 자신을 가리키는 다른 엔트리가 없는 엔트리를 찾는다
    int head = -1;
    for (int i = 0; i < collected; i++) {
        int pointed_to = 0;
        for (int j = 0; j < collected; j++) {
            if (j != i && decoded_next[j] == (uintptr_t)addrs[i]) {
                pointed_to = 1;
                break;
            }
        }
        if (!pointed_to) { head = i; break; }
    }

    if (head == -1) {
        fprintf(stderr,
            "[WAW] WARNING: tcache[0x%zx] 체인에서 시작점을 찾지 못함 — 순환 구조 의심\n",
            size);
        return;
    }

    if (collected >= TCACHE_FILLCOUNT) {
        fprintf(stderr,
            "[WAW] WARNING: tcache[0x%zx]에 %d개 이상 연결됨 — 기본 카운트 한도 초과 가능성\n",
            size, collected);
    }

    // head부터 디코딩된 다음 주소를 따라가며 체인 출력. 다음 엔트리가
    // 우리 추적 범위 밖이면(이미 malloc으로 빠져나갔거나 추적 안 된 주소)
    // 거기서 멈춘다.
    fprintf(stderr, "[WAW][BIN] tcache[0x%zx]: ", size);
    void *cur = addrs[head];
    int steps = 0;
    while (cur != NULL && steps < collected) {
        fprintf(stderr, "%p -> ", cur);

        int found_next = 0;
        uintptr_t next_addr = 0;
        for (int i = 0; i < collected; i++) {
            if (addrs[i] == cur) { next_addr = decoded_next[i]; found_next = 1; break; }
        }
        if (!found_next) break;

        cur = (next_addr == 0) ? NULL : (void *)next_addr;
        steps++;
    }
    fprintf(stderr, "NULL (count=%d)\n", collected);
}

// ---------------------------------------------------------
// ★ waw_disabled: -p 모드에서 LD_PRELOAD가 python3 인터프리터 자신한테도
//   상속되는 문제 때문에 추가됨. LD_PRELOAD는 "이 프로세스는 적용, 저
//   자식 프로세스는 제외" 같은 선택적 적용이 원래 불가능해서, python3도
//   aha_libc.so를 그대로 로드하게 된다. 근데 CPython은 pymalloc 같은
//   내부 메모리 관리자가 저희가 전제한 단순한 malloc/free 패턴과 안 맞아서
//   size_table/fd_table 추적이 꼬이고, 실제로 python3 자체가 UAF 오탐과
//   함께 abort되는 문제가 발견됐다 (process() 호출조차 없는 스크립트로도
//   재현됨 — target과는 무관하게 python3 자체의 문제였음).
//
//   해결: /proc/self/comm으로 "지금 이 프로세스가 python3인지"를 직접
//   확인해서, 맞으면 모든 탐지 로직을 끄고 원본 함수에 그냥 통과만
//   시킨다. LD_PRELOAD 자체는 여전히 상속되지만, 나중에 pwntools가
//   ./target을 exec하는 순간 완전히 새 프로세스 이미지로 바뀌면서
//   생성자가 다시 실행되고, 그때는 comm이 "target"이라 정상적으로
//   탐지가 켜진다.
// ---------------------------------------------------------
static int waw_disabled = 0;

static void detect_python_interpreter(void) {
    // ★ fopen/fgets는 내부적으로 malloc을 쓴다. 근데 이 함수는 생성자
    //   맨 앞, original_malloc이 dlsym으로 확보되기도 전에 실행되기 때문에,
    //   여기서 malloc이 일어나면 우리 malloc() 후킹이 미확보 상태에서
    //   재귀적으로 걸려 크래시가 난다 (실제로 발생한 버그). open/read/close는
    //   힙 할당 없는 얇은 syscall 래퍼라서 이 타이밍에 안전하게 쓸 수 있다.
    int fd = open("/proc/self/comm", O_RDONLY);
    if (fd < 0) return;

    char comm[64] = {0};
    ssize_t n = read(fd, comm, sizeof(comm) - 1);
    close(fd);
    if (n <= 0) return;

    if (comm[n - 1] == '\n') comm[n - 1] = '\0'; // 끝의 개행 제거

    if (strncmp(comm, "python", 6) == 0) { // python3, python3.11 등 전부 매치
        waw_disabled = 1;
    }
}

// ---------------------------------------------------------
// 라이브러리 로드 시점에 섀도우 맵 초기화
// ---------------------------------------------------------
__attribute__((constructor))
static void aha_init(void) {
    detect_python_interpreter(); // ★ 가장 먼저 확인 — python이면 아래 전부 건너뜀
    if (waw_disabled) return;

    load_mode_from_env();       // ★ WAW_MODE를 가장 먼저 읽어서 current_mode 확정
    detect_actual_glibc_features(); // ★ 실제 glibc의 safe-linking/key 필드 여부 자동 감지
    init_shadow_map();

    // ★ free() 내부에서 UAF 스냅샷을 뜰 때 곧바로 original_memcpy를 쓸 수
    //   있도록 미리 resolve해둔다 (free가 처음 호출되는 그 순간부터 이미
    //   필요하므로, memcpy 후킹 함수의 lazy 초기화를 기다릴 수 없다).
    original_memcpy = dlsym(RTLD_NEXT, "memcpy");
}

// ---------------------------------------------------------
// malloc 후킹
// ---------------------------------------------------------
void *malloc(size_t size) {
    if (!original_malloc) {
        original_malloc = dlsym(RTLD_NEXT, "malloc");
    }

    // ★ python3 인터프리터 자신 안에서는 추적 테이블(size_table/fd_table)
    //   자체가 shadow_ready 가드를 안 타기 때문에, 여기서 명시적으로
    //   전부 건너뛰고 순수 통과만 시켜야 한다. 안 그러면 shadow 초기화만
    //   막아도 fd_table 기반 UAF/poisoning 비교 로직은 여전히 돌아서
    //   CPython의 내부 메모리 패턴을 오탐하는 문제가 그대로 남는다.
    if (waw_disabled) {
        return original_malloc(size);
    }

    void *ptr = original_malloc(size);

    if (ptr) {
        // ★ tcache poisoning 비교는 "타겟 코드가 이 메모리에 데이터를
        //   쓰기 전, malloc이 반환한 직후"에 해야 한다. 그래서 다른 어떤
        //   로직보다도 먼저 수행한다.
        if (enable_poison || enable_uaf) {
            long fd_idx = fd_table_find(ptr);
            if (fd_idx >= 0) {
                // glibc는 tcache/fastbin에서 꺼낸 청크의 fd를 지우지 않는다.
                // 그래서 반환 직후 이 위치를 읽으면 "직전까지 있던 fd"가 그대로 남아있다.
                uintptr_t current_fd = *(uintptr_t *)ptr;

                // ★ UAF(쓰기) 탐지: free 시점에 저장해둔 payload 스냅샷과
                //   지금(malloc 직후, 아직 아무도 안 쓴 시점) 실제 내용물을 비교한다.
                //   다르다면, 이 청크가 해제되어 있던 사이에 누군가 그 메모리에
                //   썼다는 뜻이다 — read/memcpy/직접 포인터 역참조 등 어떤 경로로
                //   썼든 상관없이 "결과"만으로 탐지하는 방식이라 특정 함수 후킹이
                //   필요 없다 (대신 "읽기만 하고 안 쓴" UAF는 탐지 못 하는 게 한계).
                if (enable_uaf && fd_table[fd_idx].snapshot_len > 0) {
                    size_t header_skip = actual_tcache_key ? 16 : 8;
                    unsigned char *now = (unsigned char *)ptr + header_skip;

                    if (memcmp(now, fd_table[fd_idx].snapshot, fd_table[fd_idx].snapshot_len) != 0) {
                        fprintf(stderr,
                            "[WAW] CRITICAL: Use-After-Free write detected at %p! "
                            "(payload changed while chunk was freed, %zu bytes compared)\n",
                            ptr, fd_table[fd_idx].snapshot_len);
                        print_backtrace();
                    }
                }

                if (enable_poison && current_fd != fd_table[fd_idx].original_fd) {
                    fprintf(stderr,
                        "[WAW] CRITICAL: tcache/fastbin poisoning detected at %p! "
                        "(expected fd=0x%lx, found fd=0x%lx)\n",
                        ptr, fd_table[fd_idx].original_fd, current_fd);

                    // ★ safe-linking 디코딩: raw 값만으론 사람이 읽기 어려우니,
                    //   실제로 어느 주소를 가리키려 했는지 해석해서 같이 보여준다.
                    //   사용자가 g2.32를 선택했을 때만 이 설명을 보여주지만(enable_safelink),
                    //   디코딩 계산 자체는 실제 런타임 상태(actual_safelink)를 따라야
                    //   정확하다 — 선택한 시대와 실제 환경이 다를 수 있기 때문.
                    if (enable_safelink) {
                        uintptr_t decoded_expected = actual_safelink
                            ? safelink_decode(ptr, fd_table[fd_idx].original_fd)
                            : fd_table[fd_idx].original_fd;
                        uintptr_t decoded_current = actual_safelink
                            ? safelink_decode(ptr, current_fd)
                            : current_fd;

                        fprintf(stderr,
                            "[WAW]   decoded: expected target=0x%lx, found target=0x%lx\n",
                            decoded_expected, decoded_current);

                        if (!looks_like_plausible_pointer(decoded_current)) {
                            fprintf(stderr,
                                "[WAW] WARNING: decoded target 0x%lx doesn't look like a valid pointer — "
                                "조작값이 safe-linking 공식을 고려하지 않고 작성됐을 수 있습니다\n",
                                decoded_current);
                        }
                    }

                    print_backtrace();
                }

                // ★ 비교 끝났으면 반드시 반납. 안 그러면 다음 free/malloc
                //   사이클에서 옛날 fd 값이 남아 엉뚱한 비교 기준이 된다.
                fd_table[fd_idx].state = SLOT_TOMBSTONE;
            }
        }

        // 1. 크기 기록 (free 후킹이 이 값을 꺼내 쓴다)
        size_table_insert(ptr, size);

        // 2. 섀도우 메모리에 '할당됨(VALID)' 상태 기록
        set_shadow_status(ptr, size, SHADOW_VALID);

        // 3. --show-bins: 이 malloc으로 체인에서 하나 빠져나갔으니,
        //    바뀐 상태를 바로 보여준다
        if (show_bins_enabled) {
            print_bin_chain(size);
        }
    }

    // 디버깅용
    // printf("[WAW] malloc(%zu) = %p\n", size, ptr);

    return ptr;
}

// ---------------------------------------------------------
// free 후킹 — double-free 탐지 + 섀도우 상태를 FREED로 마킹
// ---------------------------------------------------------
void free(void *ptr) {
    if (!original_free) {
        original_free = dlsym(RTLD_NEXT, "free");
    }

    // ★ malloc()과 같은 이유로 python3 안에서는 size_table/fd_table 추적을
    //   아예 건드리지 않고 순수 통과만 시킨다.
    if (waw_disabled) {
        original_free(ptr);
        return;
    }

    if (ptr == NULL) {
        original_free(ptr); // free(NULL)은 표준상 아무 일도 안 함
        return;
    }

    // 1. double-free 탐지: enable_ddf일 때만 켠다
    //    (verify_shadow_status는 shadow_map.c에 이미 구현되어 있던 함수)
    if (enable_ddf && verify_shadow_status(ptr) == -1) {
        fprintf(stderr, "[WAW] WARNING: double free detected at %p\n", ptr);
        print_backtrace(); // ★ 여기서 "어디서 일어났는지" 콜스택을 찍는다
    }

    // 2. 원래 크기를 찾아서 그 범위만큼 섀도우를 FREED로 마킹
    long idx = size_table_find(ptr);
    size_t size = (idx >= 0) ? size_table[idx].size : 8; // 못 찾으면 최소 1워드로 가정

    set_shadow_status(ptr, size, SHADOW_FREED);

    // 3. 크기 테이블에서 슬롯 반납
    //    ★ EMPTY가 아니라 TOMBSTONE으로 표시해야 다른 엔트리의 탐색 체인이
    //      안 끊긴다 (size_table_find의 SLOT_EMPTY 조건 참고)
    if (idx >= 0) {
        size_table[idx].state = SLOT_TOMBSTONE;
    }

    // 디버깅용
    // printf("[WAW] free(%p)\n", ptr);

    original_free(ptr); // ★ glibc가 바로 이 호출 안에서 ptr 위치에 fd를 쓴다

    // 4. tcache/fastbin poisoning 추적 + UAF 스냅샷 캡처
    //    ★ 반드시 original_free "다음"에 와야 한다 — glibc가 fd(와 2.29+는
    //      key까지)를 쓰기 전에 읽으면 쓰레기값을 원본으로 착각하고 저장하게 된다.
    //    ★ 크기 조건 하나(TCACHE_MAX_SIZE)로 tcache와 fastbin을 동시에 포괄한다.
    if ((enable_poison || enable_uaf) && size <= TCACHE_MAX_SIZE) {
        uintptr_t fd = *(uintptr_t *)ptr;

        unsigned char snapshot[UAF_SNAPSHOT_SIZE];
        size_t snapshot_len = 0;

        if (enable_uaf) {
            // ★ glibc가 헤더로 쓰는 영역(fd 8바이트, 2.29+는 key 8바이트 추가)은
            //   비교 대상에서 제외해야 한다 — 이건 glibc의 정상 동작이지
            //   공격이 아니라서, 포함하면 매번 "변했다"고 오탐이 난다.
            size_t header_skip = actual_tcache_key ? 16 : 8;

            if (size > header_skip) {
                size_t payload_len = size - header_skip;
                if (payload_len > UAF_SNAPSHOT_SIZE) payload_len = UAF_SNAPSHOT_SIZE;
                original_memcpy(snapshot, (unsigned char *)ptr + header_skip, payload_len);
                snapshot_len = payload_len;
            }
        }

        fd_table_insert(ptr, fd, size, snapshot, snapshot_len);
    }

    // 5. --show-bins: 이 free로 체인에 하나 새로 들어갔으니 바로 보여준다
    if (show_bins_enabled && size <= TCACHE_MAX_SIZE) {
        print_bin_chain(size);
    }
}

// ===========================================================
// 읽기 전용 UAF 탐지 (2단계)
//
// ★ 1단계(malloc 재사용 시점 내용물 비교)는 "쓰기"만 잡는다. 해제된
//   메모리를 읽기만 하고 아무것도 안 쓰면 내용물이 안 바뀌니 비교로는
//   탐지가 안 된다. 그래서 "읽기가 일어나는 그 순간"을 직접 잡아야 하는데,
//   컴파일러 계측(ASan 방식) 없이는 모든 메모리 접근을 가로챌 수 없으므로,
//   CTF 메뉴 구조(입력→읽기, 출력→쓰기)에서 실제로 자주 쓰이는 몇 개의
//   libc 함수만 후킹하는 것으로 범위를 좁힌다 (printf 계열은 포맷 문자열
//   파싱이 복잡해져서 스코프에서 제외).
//
// ★ 재진입 방지: 아래 각 후킹 함수는 탐지 로그(fprintf)나 콜스택 출력
//   과정에서 내부적으로 strlen/memcpy 등을 다시 호출할 수 있다. 그때마다
//   다시 verify_shadow_status를 타면 무한 재귀/중복 로그 위험이 있어서,
//   in_uaf_check 플래그로 "지금 검사 중이면 중첩 검사는 건너뛴다"는
//   가드를 둔다 (원본 함수 호출 자체는 항상 그대로 수행된다).
// ===========================================================
static int in_uaf_check = 0;

// original_memcpy는 파일 상단에서 이미 선언+aha_init에서 resolve됨
static void *(*original_memmove)(void *, const void *, size_t) = NULL;
static int   (*original_puts)(const char *)                    = NULL;
static ssize_t (*original_write)(int, const void *, size_t)    = NULL;
static size_t (*original_strlen)(const char *)                 = NULL;

// 공통 처리: addr이 FREED 상태면 "어느 함수에서 읽었는지" 이름을 붙여 보고한다
static void check_uaf_read(const void *addr, const char *func_name) {
    if (!enable_uaf || in_uaf_check) return;

    in_uaf_check = 1;
    if (verify_shadow_status((void *)addr) == -1) {
        // verify_shadow_status가 이미 일반 CRITICAL 메시지를 찍었으니,
        // 여기서는 "어느 함수를 통해 발생했는지"만 추가로 알려준다
        fprintf(stderr, "[WAW]   (read via %s() at %p)\n", func_name, addr);
        print_backtrace();
    }
    in_uaf_check = 0;
}

void *memcpy(void *dest, const void *src, size_t n) {
    if (!original_memcpy) original_memcpy = dlsym(RTLD_NEXT, "memcpy");
    check_uaf_read(src, "memcpy");
    return original_memcpy(dest, src, n);
}

void *memmove(void *dest, const void *src, size_t n) {
    if (!original_memmove) original_memmove = dlsym(RTLD_NEXT, "memmove");
    check_uaf_read(src, "memmove");
    return original_memmove(dest, src, n);
}

int puts(const char *s) {
    if (!original_puts) original_puts = dlsym(RTLD_NEXT, "puts");
    check_uaf_read(s, "puts");
    return original_puts(s);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!original_write) original_write = dlsym(RTLD_NEXT, "write");
    check_uaf_read(buf, "write");
    return original_write(fd, buf, count);
}

size_t strlen(const char *s) {
    if (!original_strlen) original_strlen = dlsym(RTLD_NEXT, "strlen");
    check_uaf_read(s, "strlen");
    return original_strlen(s);
}
