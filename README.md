# web-surf MCP

JS로 렌더링되는 웹페이지를 가져오는 remote MCP 서버. Claude.ai 커스텀 커넥터로 연결.
보안 핵심은 **controller–runner 격리**: 인터넷에 노출된 컨트롤러는 인증·디스패치만 하고,
실제 브라우저 렌더링은 요청마다 떴다 사라지는 ephemeral runner(gVisor)에서만 수행.

## 도구

| 도구 | 기능 |
|---|---|
| `fetch_webpage(url, include_screenshot=False, full_page=False)` | JS 렌더링 후 본문 텍스트. 로드 후 자동 스크롤로 무한스크롤·lazy-load 콘텐츠와 이미지를 실제로 채운다. 이미지 위치에 `[이미지: alt — URL]` 마커 항상 포함(최대 40개; `data-lazy-src` 등 lazy 속성까지 해석). `include_screenshot=True`면 스크린샷(JPEG, 뷰포트 1280×800)을 MCP 이미지 블록으로 동봉, `full_page=True`면 스크롤 전체(최대 4000px, 스크린샷 자동 포함) |
| `fetch_image(image_url)` | 특정 이미지를 원본 해상도로 반환 (JPEG/PNG/GIF/WebP ≤5MB, 장변 ≤8000px; SVG는 래스터라이즈). 마커에서 고른 이미지를 자세히 볼 때 |

한도: 스크린샷/이미지 raw 5MB(초과 시 품질 50 재시도 후 생략), 텍스트 1MB, 타임아웃 텍스트 40s /
스크린샷 50s(무한스크롤·lazy 처리로 무거운 페이지 여유). runner stdout은 JSON envelope(`{"v":1, ...}`).

알려진 한계: PDF·다운로드 트리거 URL은 실패(브라우저 렌더링 대상 아님).

> 참고: 상세 빌드 스펙 문서는 개인 메모라 저장소에 포함하지 않았다.

## 구성

```
controller/controller.py     # MCP 서버. WorkOS 인증 + runner 디스패치
controller/requirements.txt  # fastmcp==3.4.2
runner/render.py             # Playwright로 URL 렌더링 → stdout (SSRF 재검증 포함)
runner/Dockerfile            # mcr playwright/python v1.60.0-jammy (arm64)
deploy/docker-compose.yml    # docker-socket-proxy (raw docker.sock 대신)
deploy/koomcp.env.example    # 환경 고유값 템플릿 (→ koomcp.env 로 복사, gitignore됨)
deploy/Caddyfile.example     # 자동 TLS + 리버스 프록시 (→ Caddyfile 로 복사, gitignore됨)
deploy/koo-mcp-controller.service  # systemd 유닛 (EnvironmentFile=/etc/koomcp.env)
deploy/setup-gvisor.sh       # gVisor(runsc) 설치
deploy/setup-egress.sh       # runner 네트워크 + egress allowlist
```

## 인프라 전제 (완료됨)

- OCI ARM 2 OCPU/12GB, Ubuntu 24.04, Docker 설치, 비-root `ubuntu` 유저
- 인바운드 443/80 (OCI Security List + 호스트 iptables)
- 도메인 (예: `*.duckdns.org`) → 인스턴스 공인 IP
- WorkOS AuthKit + DCR 활성 (`registration_endpoint` 존재 확인)

> 환경 고유값(도메인·AuthKit 테넌트)은 `deploy/koomcp.env`로 분리되어 있고 커밋되지 않는다.
> 배포 전에 `deploy/koomcp.env.example`, `deploy/Caddyfile.example`을 복사해 채울 것.

## 배포 순서 (서버에서)

```bash
# 0) 코드 동기화 (로컬 → 서버) + 환경값 채우기
#    rsync -avz --exclude .venv ./ <user>@<IP>:~/koomcp/   # rsync 없으면 tar over ssh
#    cp deploy/koomcp.env.example deploy/koomcp.env        # 값 채운 뒤
#    sudo cp deploy/koomcp.env /etc/koomcp.env             # systemd가 읽는 위치

# 1) gVisor 설치
bash ~/koomcp/deploy/setup-gvisor.sh

# 2) runner 이미지 빌드
docker build -t web-surf-runner:latest ~/koomcp/runner

# 3) egress 네트워크 + 차단 규칙
bash ~/koomcp/deploy/setup-egress.sh

# 4) socket-proxy 기동
docker compose -f ~/koomcp/deploy/docker-compose.yml up -d

# 5) runner 단독 테스트 (gVisor + egress) — JSON envelope가 나와야 함
docker run --rm --runtime=runsc --network=surf-egress \
  --read-only --tmpfs /tmp --cap-drop=ALL --security-opt=no-new-privileges \
  web-surf-runner:latest https://example.com
# 스크린샷 모드 (screenshot_b64가 JPEG인지 확인)
docker run --rm --runtime=runsc --network=surf-egress \
  --read-only --tmpfs /tmp --cap-drop=ALL --security-opt=no-new-privileges \
  web-surf-runner:latest https://example.com --screenshot \
  | python3 -c "import json,sys,base64; d=json.load(sys.stdin); \
print('keys:', sorted(d), 'jpeg:', base64.b64decode(d['screenshot_b64'])[:2]==b'\xff\xd8')"

# 6) 컨트롤러 venv + 의존성
python3 -m venv ~/koomcp/controller/.venv
~/koomcp/controller/.venv/bin/pip install -r ~/koomcp/controller/requirements.txt

# 7) 컨트롤러 전용 유저 (docker 그룹 제외 — socket-proxy만 경유하도록)
sudo useradd --system --shell /usr/sbin/nologin -G ubuntu koomcp || true

# 8) systemd 등록 (유닛은 User=koomcp, EnvironmentFile=/etc/koomcp.env)
sudo cp ~/koomcp/deploy/koo-mcp-controller.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now koo-mcp-controller
sudo systemctl status koo-mcp-controller

# 9) Caddy
sudo apt-get install -y caddy   # 또는 공식 설치 스크립트
cp ~/koomcp/deploy/Caddyfile.example ~/koomcp/deploy/Caddyfile   # 도메인 채우고
sudo cp ~/koomcp/deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl restart caddy

# 10) 동작 확인 (디스커버리 체인)
curl -s https://<내도메인>/.well-known/oauth-authorization-server | head
```

## 재배포 (코드 변경 시)

**순서 중요**: runner(render.py) 변경이 포함되면 **이미지 rebuild가 먼저**, controller 재시작이 나중.
(구버전 runner + 신버전 controller 조합은 JSON 파싱 에러 — 에러 메시지에 힌트 있음)

```bash
git pull   # 또는 scp
docker build -t web-surf-runner:latest ~/koomcp/runner   # ① runner 먼저
sudo systemctl restart koo-mcp-controller                # ② controller 나중
```

## Claude.ai 커넥터 등록 (사람이 수동, 맨 마지막)

- Settings → Connectors → Add custom connector
- URL: `https://<내도메인>/mcp`
- Client ID/Secret 비움 (DCR/CIMD 자동 등록)
- 첫 사용 시 WorkOS 로그인 1회

## 보안 체크리스트 (스펙 §7)

- [x] 컨트롤러 127.0.0.1 바인딩, 외부는 Caddy(443)만
- [x] raw docker.sock 미마운트 (socket-proxy 경유)
- [x] runner 요청마다 `--rm`
- [ ] runner 런타임 gVisor (배포 5단계에서 검증)
- [x] runner non-root + read-only + tmpfs + cap-drop=ALL + no-new-privileges
- [x] SSRF: 컨트롤러 입력검증 + runner egress 차단(메타데이터/RFC1918)
- [x] JWT 검증 (AuthKitProvider)
- [x] 임의 JS 실행 도구 미노출 (fetch_webpage만)
- [x] 리소스 한도 (memory/cpus/timeout/pids)
- [x] 컨트롤러 전용 유저(`koomcp`)는 docker 그룹 비소속 → raw docker.sock 직접 접근 차단
- [x] socket-proxy 이미지 digest 핀 고정
- [x] 동시 runner 수 상한 (`MAX_CONCURRENCY`, 기본 3) — 자원 고갈 방어
- [x] runner 내 리다이렉트/sub-resource 호스트 재검증 (egress 방화벽과 이중)
- [x] SSH 패스워드 인증 비활성 + root 로그인 차단, rpcbind 리스너 mask

## 업데이트 전략

기조: **자동으로 계속 올리고, 깨지면 그때 개입해 롤백**한다(개인 박스 기준 유지비가 가장 쌈).

- **자동(핀 없음)** — OS 패키지(`-security`+`-updates`)와 **gVisor(runsc)** 까지 unattended-upgrades로 자동 설치, 04:00 자동 재부팅으로 커널 반영. 전부 **서명된 신뢰 repo**(Ubuntu, Google)라 자동화 안전. 설정: `/etc/apt/apt.conf.d/52koomcp-unattended.conf`.
- **핀 유지(유일한 예외) — socket-proxy 이미지 digest.** 이건 "최신 유지"가 아니라 **공급망 방어**다. `:latest`는 가변 태그라 tecnativa 계정/태그가 탈취되면 docker.sock 권한을 가진 악성 이미지를 자동으로 끌어오게 됨(=호스트 전체 장악). apt(서명 검증)와 달리 Docker Hub 태그는 보증이 약하고, 이 컨테이너는 가장 민감한 표적이라 staleness 비용(거의 0)보다 오염 비용(치명적)이 압도적. → digest 핀 유지, 연 몇 회 의도적으로 bump.
- **앱 의존성(`fastmcp==3.4.2`, runner Chromium 이미지)** — 재배포 때만 갱신(서버 자동 대상 아님). 재현 가능한 배포 위해 핀 유지하고 직접 bump. Chromium 렌더러 취약점은 어차피 gVisor(자동 패치됨)가 가둠.
