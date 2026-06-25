"""web-surf controller (MCP 서버).

- 인터넷에 노출되는 long-lived 프로세스. JWT 인증(WorkOS AuthKit)만 하고,
  실제 브라우저 렌더링은 요청마다 ephemeral runner 컨테이너에 위임한다.
- Docker는 raw socket이 아니라 docker-socket-proxy(DOCKER_HOST=tcp://127.0.0.1:2375)
  를 통해서만 호출한다. (컨트롤러가 뚫려도 호스트 root 직행을 막기 위함)
- 위험한 untrusted 렌더링은 runner 안에서만 일어난다. 여기선 URL 문자열만 다룬다.
"""
import asyncio
import ipaddress
import os
import socket
import uuid
from urllib.parse import urlparse

from fastmcp import FastMCP
from fastmcp.server.auth.providers.workos import AuthKitProvider

# --- 설정 (systemd 환경변수로 오버라이드) ---
AUTHKIT_DOMAIN = os.environ.get(
    "AUTHKIT_DOMAIN", "https://YOUR-TENANT.authkit.app"
)
BASE_URL = os.environ.get("BASE_URL", "https://your-domain.example.com")
RUNNER_IMAGE = os.environ.get("RUNNER_IMAGE", "web-surf-runner:latest")
RUNNER_RUNTIME = os.environ.get("RUNNER_RUNTIME", "runsc")   # gVisor; 불가 시 "runc"
RUNNER_NETWORK = os.environ.get("RUNNER_NETWORK", "surf-egress")
# gVisor 유저공간 netstack은 Docker 임베디드 DNS(127.0.0.11)를 지원하지 않으므로,
# 공용 DNS를 담은 resolv.conf를 직접 bind-mount해 우회한다. (surf-egress 격리는 유지)
RESOLV_CONF = os.environ.get("RUNNER_RESOLV_CONF", "/etc/web-surf-resolv.conf")
RENDER_TIMEOUT = int(os.environ.get("RENDER_TIMEOUT", "30"))
# 동시에 띄울 수 있는 runner 컨테이너 수 상한. authed 유저가 fetch를 난사해도
# 박스 자원(메모리/CPU)이 고갈되지 않게 막는다. 초과 요청은 슬롯이 날 때까지 대기.
MAX_CONCURRENCY = int(os.environ.get("MAX_CONCURRENCY", "3"))
HOST = os.environ.get("HOST", "127.0.0.1")                   # 외부 노출은 Caddy를 통해서만
PORT = int(os.environ.get("PORT", "8000"))

# asyncio.Semaphore는 import 시점에 만들면 이벤트루프 바인딩 문제가 생길 수 있어
# 첫 사용 시점에 lazy-init 한다.
_runner_semaphore: asyncio.Semaphore | None = None


def _runner_sem() -> asyncio.Semaphore:
    global _runner_semaphore
    if _runner_semaphore is None:
        _runner_semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    return _runner_semaphore

auth = AuthKitProvider(authkit_domain=AUTHKIT_DOMAIN, base_url=BASE_URL)
mcp = FastMCP(name="koo-mcp", auth=auth)


def assert_public_url(url: str) -> None:
    """SSRF 가드: 공인 IP로만 해석되는 http/https URL인지 검증."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("http/https만 허용")
    host = parsed.hostname
    if not host:
        raise ValueError("호스트 없음")
    for res in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(res[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError(f"비공인 IP 차단: {ip}")


@mcp.tool
async def fetch_webpage(url: str) -> str:
    """JavaScript로 렌더링되는 동적 웹페이지의 본문 텍스트를 반환한다.

    실제 브라우저(Chromium)로 JavaScript를 실행한 뒤의 최종 본문을 추출하므로,
    SPA·클라이언트 렌더링 페이지, 무한 스크롤로 늦게 채워지는 콘텐츠처럼
    정적 HTML만으로는 내용이 보이지 않는 페이지에 사용한다.

    정적 HTML만 읽는 기본 web fetch로 원하는 내용이 안 나올 때
    (본문이 비어 있음, "JavaScript를 켜라"는 안내 문구만 나옴 등)
    이 도구를 쓰면 된다.
    """
    assert_public_url(url)
    name = f"surf-run-{uuid.uuid4().hex[:12]}"
    args = [
        "docker", "run", "--rm",
        "--name", name,
        "--runtime", RUNNER_RUNTIME,           # gVisor 격리
        "--network", RUNNER_NETWORK,           # egress allowlist 전용 네트워크
        "-v", f"{RESOLV_CONF}:/etc/resolv.conf:ro",  # gVisor용 공용 DNS 우회
        "--read-only",                         # rootfs 읽기전용
        "--tmpfs", "/tmp:rw,size=256m",        # 쓰기는 tmpfs에만
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "1g", "--cpus", "1",       # 자원 고갈 방지
        RUNNER_IMAGE, url,
    ]
    # 동시 runner 수 제한 (자원 고갈/DoS 방어). 슬롯이 없으면 여기서 대기.
    async with _runner_sem():
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=RENDER_TIMEOUT)
        except asyncio.TimeoutError:
            # 로컬 docker CLI를 죽여도 원격(proxy) 컨테이너는 남으므로 강제 제거
            await _force_remove(name)
            raise RuntimeError("렌더링 타임아웃")
    if proc.returncode != 0:
        raise RuntimeError(f"runner 실패: {err.decode(errors='replace')[:500]}")
    return out.decode(errors="replace")


async def _force_remove(name: str) -> None:
    try:
        p = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(p.wait(), timeout=10)
    except Exception:
        pass


if __name__ == "__main__":
    # 127.0.0.1로만 바인딩 → 외부 노출은 Caddy(443)를 통해서만
    mcp.run(transport="http", host=HOST, port=PORT)
