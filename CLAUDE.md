# CLAUDE.md — koomcp (web-surf remote MCP)

이 저장소에서 작업하는 에이전트/기여자가 **지켜야 할 불변식**과 설계 의도.
저장소는 **public**이다 → 도메인·IP·AuthKit 테넌트 등 환경 고유값은 절대 여기/코드에 넣지 말 것
(전부 `deploy/koomcp.env`(gitignore)와 서버 `/etc/koomcp.env`에만 존재, `*.example`만 커밋).

## 아키텍처 한 줄

인터넷 노출 **controller**(인증·디스패치) → **socket-proxy** → 요청마다 뜨고 사라지는
**ephemeral gVisor runner**(untrusted 웹을 만지는 유일한 지점). 컨트롤러는 URL 문자열만 다루고
위험한 브라우저 렌더링은 전부 runner에 위임한다.

## 보안 불변식 (깨지면 안 되는 것들)

- **컨트롤러 서비스 유저(`koomcp`)는 `docker` 그룹에 넣지 않는다.** raw `/var/run/docker.sock`
  직접 접근 금지 — 반드시 socket-proxy(127.0.0.1:2375)만 경유. (이게 깨지면 컨트롤러 침해 = 호스트 root.)
- **socket-proxy 이미지는 digest 핀을 유지한다.** `:latest`로 떠서 자동 pull 하지 말 것 — 이 컨테이너는
  docker 제어권을 쥔 공급망 crown jewel이라, 태그 오염 시 즉시 호스트 장악. 업그레이드는 새 digest로 의도적 교체.
- **runner는 항상** `--runtime=runsc`(gVisor) + `--cap-drop=ALL` + `--read-only` + 비-root(pwuser)
  + `--security-opt=no-new-privileges` + `--network=surf-egress` + memory/cpus/pids/timeout 한도로 실행.
- **SSRF 방어는 3중**이고 순서가 의미 있다: ①컨트롤러 입력 검증 → ②runner가 **모든 http(s) 요청 호스트**
  재검증(리다이렉트·sub-resource 포함) → ③egress iptables DROP(메타데이터 169.254.169.254 / RFC1918 / CGNAT).
  **최종 backstop은 egress 방화벽**이다. app 레이어 검증만 믿지 말 것. (방화벽은 IPv4 전용 — runner 네트워크는
  IPv6 비활성 유지. IPv6 켜려면 ip6tables 미러 규칙 필수.)
- runner의 **리소스 타입 차단(image/media/font)은 메모리 최적화지 보안 경계가 아니다** — 필요 시(예:
  fetch_image) 이미지를 허용한다. 보안 경계는 위 ②호스트 재검증과 ③egress 방화벽이며, 이 둘은
  모드와 무관하게 모든 요청에 적용된다.
- 컨트롤러는 **127.0.0.1만 바인딩**, 외부 노출은 Caddy(443)만.
- **도구는 필요에 따라 계속 추가된다** (fetch_webpage가 유일하다고 가정하지 말 것; 현재 fetch_webpage,
  fetch_image). 불변식은: **임의 JS/셸 실행을 노출하는 도구 금지 — 각 도구는 고정된 기능만 노출한다.**
  runner 내부의 고정 evaluate 스니펫은 허용하되, **사용자 입력이 페이지 JS로 흘러들어서는 안 된다.**
- untrusted 콘텐츠 **디코딩/렌더링은 runner(gVisor) 안에서만**. 컨트롤러는 URL 문자열과 runner의
  JSON envelope만 다루고, 이미지 bytes는 디코딩 없이 통과만 시킨다.
- 동시 runner 수는 `MAX_CONCURRENCY`(기본 3) 세마포어로 상한 — 자원 고갈/DoS 방어.
- 이미지 접근 방식: `fetch_webpage`는 본문에 `[이미지: alt — URL]` 마커만 넣고(텍스트), 실제 픽셀은
  별도 `fetch_image(url)`가 반환한다. (페이지 전체 스크린샷은 다운스케일 판독난·원격 커넥터
  이미지블록 호환성 이슈로 노출하지 않음 — 마커→fetch_image로 대체.)
- 크기/시간 상한: 이미지 raw 5MB, 이미지 장변 8000px(초과 시 에러 — Claude API 메시지 거부 방지),
  본문 마커 40개 — 상수는 `runner/render.py` 상단. 타임아웃은 컨트롤러 env: `RENDER_TIMEOUT`(기본 40s)·
  `STDOUT_MAX_BYTES`(기본 20MB). lazy-load/무한스크롤은 runner가 자동 스크롤로 처리하되, 이미지가
  abort돼 페이지 JS가 lazy URL을 망치기 전에 **정적 마크업(data-lazy-src 등)에서 마커를 먼저 확보**한다.

## MCP 도구 description 작성 방침

도구 docstring(=description)은 **강점 긍정형을 먼저, fallback 한 줄을 뒤에** 둔다.
즉 "JS 렌더링/SPA/무한스크롤 등 이 도구가 적합한 상황"을 앞세워 모델이 선제적으로 고르게 하고,
"기본 web fetch로 본문이 안 나올 때" 같은 fallback 신호는 보조로 한 줄. (MCP 서버는 클라이언트의 다른
도구 존재/우선순위를 모르므로, "실패하면 써라"식 강제보다 강점 명시가 여러 클라이언트에서 안정적.)

추가 방침: **파라미터/자매 도구의 사용 시점도 description에 명시**한다 — 언제 켜는지(예:
include_screenshot은 "시각 정보가 필요할 때만, 토큰 비용 있음"), 어느 도구가 어떤 케이스에 적합한지
(fetch_image=특정 이미지 원본 vs include_screenshot=페이지 전체 레이아웃) 상호 참조를 넣어
모델이 도구를 겹치지 않게 고르도록 한다.

## 업데이트 전략

기조: **자동으로 계속 올리고, 깨지면 개입해 롤백**(개인 박스 기준 유지비 최소).
- 자동(핀 없음): OS `-security`+`-updates`, **gVisor(runsc)** → unattended-upgrades + 04:00 자동 재부팅.
  전부 서명된 신뢰 repo라 자동화 안전.
- 핀 유지(유일 예외): **socket-proxy digest**(위 불변식). 공급망 방어이지 staleness 문제가 아님.
- 앱 의존성(`fastmcp` 핀, runner Chromium 이미지 핀): 서버 자동 대상 아님 → 재배포 시 수동 bump.
  Chromium 렌더러 취약점은 gVisor가 가둠.

## 배포 / 환경값

git 기반(서버에서 pull 또는 scp). 상세 순서는 `README.md`. 환경 고유값은 서버 `/etc/koomcp.env`
(systemd 유닛이 `EnvironmentFile`로 읽음, 600 root). 로컬 템플릿은 `deploy/koomcp.env.example`.
