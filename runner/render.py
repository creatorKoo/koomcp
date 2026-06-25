"""web-surf runner: URL을 받아 JS 렌더링 후 본문 텍스트를 stdout으로 반환.

이 스크립트는 ephemeral 컨테이너 안에서만 실행되며, untrusted 웹을 만지는
유일한 지점이다. 컨트롤러의 SSRF 가드에 더해, 여기서도 한 번 더 IP를
재검증한다 (DNS rebinding 방어 — 검증 시점과 fetch 시점 사이에 DNS가 바뀌는 공격).
"""
import asyncio
import ipaddress
import socket
import sys
from urllib.parse import urlparse

from playwright.async_api import async_playwright

MAX_CHARS = 1_000_000      # 출력 폭주 방지
NAV_TIMEOUT_MS = 20_000    # 페이지 로드 타임아웃


def assert_public_host(url: str) -> None:
    """공인 IP로만 해석되는 http/https URL인지 검증."""
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


async def render(url: str) -> str:
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",   # /dev/shm 작음 → 필수
                "--disable-gpu",
                "--no-sandbox",              # 컨테이너 내부 한정
            ],
        )
        try:
            ctx = await browser.new_context(ignore_https_errors=False)
            page = await ctx.new_page()

            # 메모리 절약: 이미지/미디어/폰트 차단
            async def _route(route):
                if route.request.resource_type in ("image", "media", "font"):
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", _route)
            await page.goto(url, wait_until="networkidle", timeout=NAV_TIMEOUT_MS)
            text = await page.inner_text("body")
            return text[:MAX_CHARS]
        finally:
            await browser.close()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: render.py <url>", file=sys.stderr)
        return 2
    url = sys.argv[1]
    try:
        assert_public_host(url)
    except Exception as e:
        print(f"SSRF 차단/검증 실패: {e}", file=sys.stderr)
        return 3
    try:
        text = asyncio.run(render(url))
    except Exception as e:
        print(f"렌더링 실패: {e}", file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
