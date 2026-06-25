# web-surf MCP

JS로 렌더링되는 웹페이지를 가져오는 remote MCP 서버. Claude.ai 커스텀 커넥터로 연결.
보안 핵심은 **controller–runner 격리**: 인터넷에 노출된 컨트롤러는 인증·디스패치만 하고,
실제 브라우저 렌더링은 요청마다 떴다 사라지는 ephemeral runner(gVisor)에서만 수행.

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

# 5) runner 단독 테스트 (gVisor + egress)
docker run --rm --runtime=runsc --network=surf-egress \
  --read-only --tmpfs /tmp --cap-drop=ALL --security-opt=no-new-privileges \
  web-surf-runner:latest https://example.com

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
