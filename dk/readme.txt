# 컨테이너 내부로 접속하여 waw 도구 및 테스트 바이너리 구동 검증
# 2.26
docker run --rm -it heapsentry:g2.26 /bin/bash

docker run --rm -it -v /home/user/heap heapsentry:g2.26 /bin/bash

docker run --rm -it -v /home/user/heap:/home/user/heap heapsentry:g2.26 /bin/bash

# 2.29
docker run --rm -it heapsentry:g2.29 /bin/bash

docker run --rm -it -v /home/user/heap heapsentry:g2.29 /bin/bash

docker run --rm -it -v /home/user/heap:/home/user/heap heapsentry:g2.26 /bin/bash


# 라이브러리 버전 확인
ldd --version | head -1 

# 파일 보낼 때 사용한다.
docker cp <로컬_파일경로> <컨테이너_이름_또는_ID>:<컨테이너_내부경로>


