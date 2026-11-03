// waw.c  (컴파일 결과물: waw, CLI 프론트엔드)
// 타겟 프로그램을 실행하면서 aha_libc.so를 LD_PRELOAD로 주입한다.
//
// [수정 이력] 처음엔 "모든 파일이 같은 디렉토리에 있다"는 전제로 LD_PRELOAD를
// 그냥 "./aha_libc.so"(상대경로) 고정값으로 썼었는데, 실제로 waw를 다른
// 디렉토리에서 실행하면(예: ~/heap/sample$ ../waw ...) 그 상대경로가 "현재
// 작업 디렉토리(pwd)" 기준으로 해석되어 waw 실행 파일 자신의 위치와 어긋나는
// 버그가 실제 사용 중 발견됐다. waw가 어디서 실행되든 자기 자신과 같은
// 디렉토리의 aha_libc.so를 정확히 찾도록, /proc/self/exe로 자기 경로를
// 읽어 절대경로를 구성하는 방식으로 되돌렸다.
//
// [구조] glibc "시대" 단위로 서브커맨드를 나눈다 (기능 단위 ddf/poison/safelink에서 전환됨).
// g2.26 / g2.29 / g2.32 중 하나만 화이트리스트로 허용하고, 그 외 값은 전부 에러 처리한다.
// 선택한 시대 문자열을 WAW_MODE 환경변수에 그대로 심어서 target에 넘기면,
// aha_libc.so가 이 값을 getenv로 읽어서 "이 시대엔 어떤 탐지를 켤지" 내부적으로 결정한다.
// waw.c와 aha_libc.so는 컴파일 시점에 안 엮이니(별개 산출물),
// 실행 시점에 정보를 넘기는 유일한 통로가 환경변수다.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>

// glibc 2.26~2.28: tcache_entry에 key 필드 자체가 없음 (double-free 무방비)
// glibc 2.29~2.31: key 필드 도입, double-free는 막히지만 poisoning은 여전히 가능
// glibc 2.32+:     safe-linking(pointer mangling) 도입
#define ERA_G226 "g2.26"
#define ERA_G229 "g2.29"
#define ERA_G232 "g2.32"

void print_help(void) {
    printf("Usage: waw [COMMAND] [OPTIONS]\n");
    printf("  %s -e <path>   tcache key 필드 없음 (2.26~2.28 대상)\n", ERA_G226);
    printf("  %s -e <path>   tcache double-free 체크 있음 (2.29~2.31 대상)\n", ERA_G229);
    printf("  %s -e <path>   safe-linking 적용 (2.32 이상 대상)\n", ERA_G232);
    printf("  --show-bins     실행 중 tcache/fastbin 체인을 실시간으로 로그 출력\n");
    printf("  -n              target의 stdout을 /dev/null로 보냄 ([WAW] 로그만 보고 싶을 때)\n");
    printf("  -en <path>      -e <path> -n 을 한 번에 (타겟 지정 + stdout 억제)\n");
    printf("  -p <script.py>  pwntools 익스플로잇 스크립트를 실행 (타겟은 스크립트 안의 process()로 뜸)\n");
    printf("\n");
    printf("Note (-p 모드): [WAW] 로그는 target의 stderr로 정상적으로 찍히지만, pwntools의\n");
    printf("  process()가 자식의 stdout/stderr를 기본적으로 파이프로 가로채서 터미널에\n");
    printf("  바로 안 보일 수 있습니다. 스크립트에서 p.interactive()를 쓰면 보통 그대로\n");
    printf("  흘러나오고, 필요하면 p.recvall() 등으로 직접 받아서 출력해도 확인할 수 있습니다.\n");
}

// ---------------------------------------------------------
// -p로 넘긴 pwntools 스크립트가 waw의 환경변수 전달을 방해할 만한
// 패턴을 쓰고 있는지 미리 훑어본다 (경고만, 실행은 막지 않음).
//   - process(...) 호출이 아예 없으면: 이 스크립트가 로컬 프로세스를
//     띄우긴 하는지 자체가 의심스러움
//   - remote(...)만 있고 process(...)가 없으면: 타겟이 원격이라 애초에
//     LD_PRELOAD 상속이 적용될 프로세스가 없음
//   - env= 또는 LD_PRELOAD 문자열이 보이면: 스크립트가 process() 호출 시
//     자기만의 환경변수를 지정해서 waw가 설정한 값을 덮어쓸 수 있음
// ★ 텍스트 패턴 매칭 수준의 휴리스틱이라 한계가 있다: 메인 스크립트
//   파일 하나만 검사하므로 다른 파일에서 process()를 호출하면 놓치고,
//   주석 안의 문자열에도 반응해 오탐할 수 있다.
// ---------------------------------------------------------
static void check_script_compatibility(const char *script_path) {
    FILE *f = fopen(script_path, "r");
    if (!f) return; // 못 열면 조용히 포기 (실행 단계에서 어차피 에러가 날 것)

    char line[512];
    int has_process = 0;
    int has_remote = 0;
    int suspicious_env = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "process(")) has_process = 1;
        if (strstr(line, "remote("))  has_remote = 1;
        if (strstr(line, "env=") || strstr(line, "LD_PRELOAD")) suspicious_env = 1;
    }
    fclose(f);

    if (!has_process && has_remote) {
        fprintf(stderr,
            "[WAW] WARNING: 이 스크립트는 remote()만 사용하는 것으로 보입니다 — "
            "타겟이 로컬 프로세스가 아니라서 waw가 탐지할 수 없습니다\n");
    } else if (!has_process && !has_remote) {
        fprintf(stderr,
            "[WAW] WARNING: process() 호출이 안 보입니다 — "
            "이 스크립트가 실제로 타겟을 띄우는지 확인해주세요\n");
    }

    if (suspicious_env) {
        fprintf(stderr,
            "[WAW] WARNING: 스크립트 안에 'env=' 또는 'LD_PRELOAD' 지정이 보입니다 — "
            "이 경우 waw의 환경변수가 덮어써져서 탐지가 안 될 수 있습니다\n");
    }
}

// ---------------------------------------------------------
// 타겟이 실제로 링크된 glibc 버전을 확인해서, 사용자가 고른 시대와
// 다르면 경고만 출력한다 (실행 자체는 막지 않음).
//   1. `ldd <target>` 출력에서 libc.so.6 경로를 찾는다
//   2. 그 경로를 `<libc> --version`으로 직접 실행해서 버전 문자열을 얻는다
//   3. 버전 숫자(minor)를 파싱해서 2.26~28 / 2.29~31 / 2.32+ 구간으로 분류
//   4. 사용자가 고른 era와 다르면 경고
// ldd나 버전 파싱이 실패하면 조용히 건너뛴다 (버전 확인은 참고용이지 필수 조건이 아님).
// ---------------------------------------------------------
static void warn_if_glibc_mismatch(const char *target_path, const char *chosen_era) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ldd '%s' 2>/dev/null | grep 'libc.so.6'", target_path);

    FILE *ldd_out = popen(cmd, "r");
    if (!ldd_out) return;

    char line[512];
    char libc_path[256] = {0};
    if (fgets(line, sizeof(line), ldd_out)) {
        // 기대하는 형식: "libc.so.6 => /path/to/libc.so.6 (0x...)"
        char *arrow = strstr(line, "=>");
        if (arrow) {
            char path_buf[256];
            if (sscanf(arrow + 2, "%255s", path_buf) == 1) {
                strncpy(libc_path, path_buf, sizeof(libc_path) - 1);
            }
        }
    }
    pclose(ldd_out);

    if (libc_path[0] == '\0') return; // 파싱 실패, 정적 링크 등 -> 조용히 포기

    snprintf(cmd, sizeof(cmd), "'%s' --version 2>/dev/null | head -1", libc_path);
    FILE *ver_out = popen(cmd, "r");
    if (!ver_out) return;

    char ver_line[256] = {0};
    fgets(ver_line, sizeof(ver_line), ver_out);
    pclose(ver_out);

    int major = 0, minor = 0;
    // "GNU C Library ... 2.31" 같은 줄에서 마지막 "2.NN" 패턴을 찾는다
    char *p = ver_line;
    int found = 0;
    while (*p) {
        if (sscanf(p, "%d.%d", &major, &minor) == 2 && major == 2) {
            found = 1;
            break;
        }
        p++;
    }
    if (!found) return;

    const char *detected_era;
    if (minor < 26) detected_era = NULL; // 지원 범위 밖
    else if (minor <= 28) detected_era = ERA_G226;
    else if (minor <= 31) detected_era = ERA_G229;
    else detected_era = ERA_G232;

    if (!detected_era) {
        fprintf(stderr, "[WAW] WARNING: target uses glibc 2.%d (tcache 도입 이전, 지원 범위 밖)\n", minor);
        return;
    }

    if (strcmp(detected_era, chosen_era) != 0) {
        fprintf(stderr,
            "[WAW] WARNING: 선택한 시대(%s)와 실제 타겟 glibc 버전(2.%d, 추정 구간 %s)이 다릅니다\n",
            chosen_era, minor, detected_era);
    }
}

// ---------------------------------------------------------
// aha_libc.so의 절대경로를 만든다. waw 실행파일 자기 자신의 위치
// (/proc/self/exe)를 기준으로, 같은 디렉토리에 있는 aha_libc.so를 찾는다.
// waw를 어느 디렉토리에서(어떤 상대경로로) 실행하든 항상 올바른 .so를
// 찾을 수 있게 하기 위함이다 (실제로 ~/heap/sample$ ../waw ... 처럼
// 다른 디렉토리에서 실행했을 때 못 찾는 문제가 있었다).
// ---------------------------------------------------------
static void get_hook_lib_path(char *out_path, size_t out_size) {
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len == -1) {
        // /proc/self/exe를 못 읽는 특이 환경이면 현재 디렉토리로 fallback
        snprintf(out_path, out_size, "./aha_libc.so");
        return;
    }
    self_path[len] = '\0'; // readlink는 널 종료를 안 해주므로 직접 붙여야 함

    char *dir = dirname(self_path); // waw 실행파일이 있는 디렉토리만 추출
    snprintf(out_path, out_size, "%s/aha_libc.so", dir);
}

// ---------------------------------------------------------
// 실제 실행 로직은 서브커맨드(시대)에 상관없이 공통이다.
// 차이는 WAW_MODE에 어떤 era 문자열을 심느냐뿐이라서, 이 공통 함수 하나로
// 모든 서브커맨드를 처리한다.
// ---------------------------------------------------------
static int run_with_era(int argc, char *argv[], const char *era) {
    char *target_path = NULL; // -e로 지정한 타겟 바이너리 경로
    char *script_path = NULL; // -p로 지정한 pwntools 스크립트 경로
    int   show_bins = 0;      // ★ WAW_MODE(era)와 별개의 독립 옵션
    int   null_stdout = 0;    // ★ -n: target의 stdout을 /dev/null로 보낼지 (기본은 꺼짐)

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            target_path = argv[i + 1];
            i++; // 다음 인자(경로)는 이미 소비했으니 건너뜀
        } else if (strcmp(argv[i], "-en") == 0 && i + 1 < argc) {
            // ★ -e(타겟 경로 지정) + -n(stdout 억제)을 한 번에 켜는 합성 옵션.
            //   "-e <path> -n"을 매번 따로 쓰는 게 번거로워서 묶었다.
            target_path = argv[i + 1];
            null_stdout = 1;
            i++;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            // ★ pwntools 익스플로잇 스크립트 모드. 실제 타겟 바이너리는
            //   스크립트 안의 process()가 띄우므로, 여기선 경로만 받아둔다.
            script_path = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--show-bins") == 0) {
            show_bins = 1;
        } else if (strcmp(argv[i], "-n") == 0) {
            null_stdout = 1;
        }
    }

    if (target_path && script_path) {
        fprintf(stderr, "Error: -e and -p cannot be used together\n");
        return 1;
    }
    if (!target_path && !script_path) {
        fprintf(stderr, "Error: either -e <path> or -p <script.py> is required\n");
        return 1;
    }

    if (script_path) {
        // ldd는 .py 파일을 분석할 수 없어서 glibc 버전 불일치 경고는
        // 이 모드에서 사실상 무력화된다 (명시된 한계) — 대신 스크립트
        // 자체의 호환성을 훑어본다.
        check_script_compatibility(script_path);
    } else {
        warn_if_glibc_mismatch(target_path, era);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // 자식: LD_PRELOAD + WAW_MODE 설정 후 target 실행
        char hook_lib_path[PATH_MAX];
        get_hook_lib_path(hook_lib_path, sizeof(hook_lib_path));
        setenv("LD_PRELOAD", hook_lib_path, 1);
        setenv("WAW_MODE", era, 1); // ★ aha_libc.so가 이 값을 getenv로 읽는다
        if (show_bins) {
            setenv("WAW_SHOW_BINS", "1", 1);
        }

        // [수정 이력] 예전엔 target의 stdout을 항상 /dev/null로 막았었는데,
        // 메뉴 기반 워게임 바이너리에선 프롬프트 자체가 안 보여서 풀 수가
        // 없는 문제가 있었다. 그래서 기본값은 "안 막음"으로 바꾸고,
        // 자동화 테스트처럼 target 출력이 필요 없을 때만 -n으로 켜서
        // 선택적으로 억제하게 만들었다.
        if (null_stdout) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull != -1) {
                dup2(devnull, STDOUT_FILENO);
                close(devnull);
            }
        }

        if (script_path) {
            // ★ python3을 PATH에서 찾아 실행 (시스템마다 설치 위치가 달라서
            //   execv 대신 execvp 사용). LD_PRELOAD/WAW_MODE는 이미 위에서
            //   setenv해뒀으니 python3 -> pwntools의 process() -> 실제 타겟까지
            //   환경변수가 그대로 상속된다.
            char *py_argv[] = { "python3", script_path, NULL };
            execvp("python3", py_argv);
            perror("execvp(python3) failed");
        } else {
            char *target_argv[] = { target_path, NULL };
            execv(target_path, target_argv);
            perror("execv failed"); // execv가 실패했을 때만 도달
        }
        _exit(1);
    }

    // 부모: 자식 종료 대기
    int status;
    waitpid(pid, &status, 0);

    // ★ 자식이 정상 종료했으면 그 exit code를, 시그널로 죽었으면
    //   "128 + 시그널 번호"(셸 관례)를 waw 자신의 종료 코드로 반영한다.
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "[WAW] target terminated by signal %d (%s)\n",
                WTERMSIG(status), strsignal(WTERMSIG(status)));
        return 128 + WTERMSIG(status);
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    // ★ 화이트리스트 방식: 이 3개 문자열과 정확히 일치할 때만 실행,
    //   그 외(g0, g2.3.4, g2.34, 임의 문자열 등)는 전부 도움말 + 에러
    if (strcmp(argv[1], ERA_G226) == 0) {
        return run_with_era(argc, argv, ERA_G226);
    } else if (strcmp(argv[1], ERA_G229) == 0) {
        return run_with_era(argc, argv, ERA_G229);
    } else if (strcmp(argv[1], ERA_G232) == 0) {
        return run_with_era(argc, argv, ERA_G232);
    }

    print_help();
    return 1;
}
