#!/bin/bash
# build.sh - waw를 로컬 환경 glibc 기준으로 빌드한다.
#
# ★ 왜 이 스크립트가 필요한가: aha_libc.so는 dlsym(RTLD_NEXT, "malloc")로
#   "지금 이 시스템에 실제로 있는 libc"를 찾아서 후킹한다. 그래서 미리
#   컴파일된 바이너리를 배포하면 받는 사람의 glibc 버전과 안 맞아서
#   ("GLIBC_2.XX not found" 같은 에러로) 실행이 안 될 수 있다.
#   반드시 "실행할 그 컴퓨터에서" 직접 컴파일해야 한다.

set -e  # 중간에 하나라도 실패하면 즉시 중단

echo "[build] 현재 환경 glibc 버전:"
ldd --version | head -1

echo "[build] waw (CLI 프론트엔드) 빌드..."
gcc -o waw waw.c

echo "[build] aha_libc.so (후킹 라이브러리) 빌드..."
gcc -shared -fPIC -o aha_libc.so aha_libc.c shadow_map.c -ldl

if [ -d "sample" ]; then
    echo "[build] 샘플 테스트 바이너리 빌드..."
    cd sample
    for f in target poison_target uaf_target chain_target; do
        if [ -f "$f.c" ]; then
            gcc -o "$f" "$f.c"
        fi
    done
    cd ..
fi

echo ""
echo "[build] 완료. 사용 예시:"
echo "  ./waw g2.26 -e ./sample/chain_target --show-bins"
