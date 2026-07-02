"""web-surf runner: URL을 JS 렌더링해 JSON envelope로 stdout에 반환.

이 스크립트는 ephemeral 컨테이너 안에서만 실행되며, untrusted 웹을 만지는
유일한 지점이다. 컨트롤러의 SSRF 가드에 더해, 여기서도 **모든 http(s) 요청**
(리다이렉트·sub-resource 포함)의 호스트를 재검증한다 (DNS rebinding 방어).
리소스 타입 차단은 메모리 최적화일 뿐 보안 경계가 아니다 — 경계는 이
호스트 재검증과 egress 방화벽이다.

모드:
  render.py <url>                본문 텍스트 (+이미지 위치 마커 [이미지: alt — URL])
  render.py <url> --fetch-image  url을 이미지로 보고 원본 bytes 반환

페이지 시각 확인은 마커의 URL을 --fetch-image로 넘기는 방식(별도 도구 fetch_image).
stdout: JSON envelope {"v":1, ...}. 에러는 stderr + 종료코드(2 usage, 3 SSRF, 1 실패).
"""
import argparse
import asyncio
import base64
import ipaddress
import json
import socket
import struct
import sys
import time
from urllib.parse import urlparse

from playwright.async_api import TimeoutError as PWTimeoutError
from playwright.async_api import async_playwright

MAX_CHARS = 1_000_000        # 본문 텍스트 상한
NAV_TIMEOUT_MS = 20_000      # goto(domcontentloaded) 상한
# 초기 XHR/SPA 콘텐츠 정착 대기 상한. networkidle은 광고·분석·소켓 때문에 안 오는
# 페이지가 흔해 goto의 wait 조건으로 두면 매번 NAV_TIMEOUT을 통째로 날린다 →
# domcontentloaded로 빠르게 진입한 뒤 짧게만 networkidle을 기다린다(best-effort).
# (이미지 마커는 이 대기 *전에* 정적 마크업에서 확보하므로, 이 값은 이미지 정확도와
#  무관하고 순전히 지연/SPA-텍스트 트레이드오프다.)
IDLE_SETTLE_MS = 1_500

# 뷰포트/캡처 관련 상수는 fetch_image(SVG 래스터라이즈 폴백)에서 사용.
SHOT_VIEWPORT = {"width": 1280, "height": 800}
SHOT_QUALITY = 80
SHOT_MAX_BYTES = 5_000_000   # raw 이미지 상한 (base64 전)
SHOT_TIMEOUT_MS = 10_000     # screenshot 자체 타임아웃 (기본 30s는 예산 초과)
IMG_MARKER_MAX = 40          # 본문에 심는 이미지 마커 최대 개수

# Claude vision이 받는 포맷만 통과. 그 외는 래스터라이즈 폴백 또는 에러.
IMAGE_MIME_ALLOWED = {"image/jpeg", "image/png", "image/gif", "image/webp"}
IMAGE_MAX_EDGE_PX = 8000     # Claude API 절대 한도 — 초과 이미지는 메시지 전체를 깨뜨림

_host_public_cache: dict[str, bool] = {}


def _host_is_public(host: str) -> bool:
    """host가 공인 IP로만 해석되는지(=내부망/메타데이터가 아닌지). 결과 캐시."""
    if host in _host_public_cache:
        return _host_public_cache[host]
    ok = True
    try:
        for res in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(res[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                ok = False
                break
    except Exception:
        ok = False
    _host_public_cache[host] = ok
    return ok


def assert_public_host(url: str) -> None:
    """공인 IP로만 해석되는 http/https URL인지 검증."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("http/https만 허용")
    host = parsed.hostname
    if not host:
        raise ValueError("호스트 없음")
    if not _host_is_public(host):
        raise ValueError(f"비공인 IP 차단: {host}")


def _make_route(blocked_types: tuple[str, ...]):
    """모든 요청 가로채기: ①blocked_types 차단(최적화) ②http(s) 호스트 재검증(보안)."""
    async def _route(route):
        req = route.request
        if req.resource_type in blocked_types:
            await route.abort()
            return
        parsed = urlparse(req.url)
        if parsed.scheme in ("http", "https"):
            host = parsed.hostname
            if not host or not _host_is_public(host):
                await route.abort()
                return
        await route.continue_()
    return _route


# 마커에서 지울 placeholder alt (실제 설명이 아니라 lazy-load 안내 문구).
_PLACEHOLDER_ALTS = {"존재하지 않는 이미지입니다", "이미지", "image", "img"}

# 고정 내부 스니펫 (사용자 입력이 흘러들지 않음 — 인자는 정수 상수뿐).
# 각 <img>를 위치 그대로 텍스트 마커로 치환 → inner_text가 마커를 문맥과 함께 포함.
# URL은 폴백 체인으로 해석 — lazy-load 페이지(네이버 스마트에디터 등)는 실제
# URL이 src가 아니라 data-lazy-src/data-src 등에 들어있고, 이미지 요청이 abort된
# 텍스트 모드에서는 src가 비어있을 수 있으므로 data 속성까지 훑는다.
_IMG_MARKER_JS = """
(args) => {
  const [maxMarkers, placeholderAlts] = args;
  const http = (s) => (/^https?:/i.test(s || "") ? s : "");
  const normalize = (u) => {
    // pstatic.net(네이버)은 type= 쿼리로 리사이즈/블러 변형을 서빙한다.
    // lazy placeholder(w80_blur 등)를 판독 가능한 원본 폭으로 승격.
    try {
      if (/\\.pstatic\\.net\\//i.test(u)) {
        u = u.replace(/([?&]type=)w\\d+(_blur)?/i, "$1w800");
      }
    } catch (e) {}
    return u;
  };
  const resolve = (el) => {
    // lazy-load 사이트는 실제 원본을 data-* 속성에 두고 src엔 저해상도/블러
    // placeholder를 둔다 → data-* 를 src보다 *먼저* 본다.
    let u = http(el.getAttribute("data-lazy-src")) || http(el.getAttribute("data-src"))
         || http(el.getAttribute("data-original")) || http(el.getAttribute("data-echo"));
    if (!u) {
      const ss = el.getAttribute("srcset") || el.getAttribute("data-srcset") || "";
      u = http(ss.trim().split(/[\\s,]+/)[0]);           // srcset 첫 후보
    }
    if (!u) u = http(el.currentSrc) || http(el.getAttribute("src"));  // 최후: 실제 src
    return u ? normalize(u) : "";
  };
  const seen = new Set();
  const collected = [];
  for (const el of Array.from(document.querySelectorAll("img"))) {
    const src = resolve(el);
    if (!src) continue;                                          // data:/blob:/미해석 제외
    const wAttr = parseInt(el.getAttribute("width") || "", 10);
    const hAttr = parseInt(el.getAttribute("height") || "", 10);
    if ((wAttr && wAttr <= 2) || (hAttr && hAttr <= 2)) continue;  // 추적픽셀
    if (el.naturalWidth > 0 && el.naturalWidth <= 2) continue;
    if (seen.has(src)) continue;                                 // 반복 로고 등 dedup
    seen.add(src);
    if (collected.length >= maxMarkers) break;
    let alt = (el.getAttribute("alt") || "").trim();
    if (placeholderAlts.includes(alt.toLowerCase())) alt = "";   // lazy 안내 문구 무시
    alt = alt.slice(0, 120);
    collected.push({ src: src, alt: alt });
    const label = alt ? `[이미지: ${alt} — ${src}]` : `[이미지 — ${src}]`;
    try { el.replaceWith(document.createTextNode(" " + label + " ")); } catch (e) {}
  }
  return collected;
}
"""


SCROLL_MAX_STEPS = 8         # 무한스크롤 안전 상한(스텝 수)
SCROLL_WAIT_MS = 300         # 스텝당 lazy 로드 대기
SCROLL_BUDGET_S = 3.0        # 오토스크롤 wall-clock 상한(무거운 페이지 대비 — 스텝 비용이
                             # 페이지마다 제각각이라 스텝 수만으론 시간이 안 잡힘)


async def _autoscroll(page) -> None:
    """페이지를 아래로 훑어 lazy-load 콘텐츠/이미지 src를 트리거한 뒤 top 복귀.

    - JS로 렌더/무한스크롤되는 콘텐츠, IntersectionObserver 기반 lazy 이미지가
      실제로 채워지게 한다 (도구가 표방하는 "무한스크롤" 지원의 실체).
    - 종료 조건 3중: scrollHeight가 더 안 커지면 조기 종료 / 스텝 수 상한 /
      wall-clock 예산. 무한 append 페이지(네이버 등)에서 스텝당 비용이 커도 바운드.
    - 이미지가 abort되는 텍스트 모드에서도 스크롤은 lazy-loader의 src 대입(JS)을
      유발하므로 마커 URL 해석에 도움. 실패해도 추출은 계속(호출부에서 무시).
    """
    try:
        deadline = time.monotonic() + SCROLL_BUDGET_S
        last_h = 0
        for _ in range(SCROLL_MAX_STEPS):
            if time.monotonic() > deadline:
                break
            h = int(await page.evaluate("() => document.documentElement.scrollHeight") or 0)
            await page.evaluate("(y) => window.scrollTo(0, y)", h)
            await page.wait_for_timeout(SCROLL_WAIT_MS)
            if h <= last_h:      # 더 안 자람 → 바닥 도달
                break
            last_h = h
        await page.evaluate("() => window.scrollTo(0, 0)")
        await page.wait_for_timeout(150)
    except Exception:
        pass


async def _shoot(page, quality: int) -> bytes:
    return await page.screenshot(type="jpeg", quality=quality, timeout=SHOT_TIMEOUT_MS)


async def render(url: str) -> dict:
    notes: list[str] = []
    # 텍스트 추출만 하므로 image/media/font는 항상 차단(메모리·속도 최적화).
    # 이미지 URL은 DOM 마커에서 뽑고, 실제 픽셀은 별도 fetch_image가 담당한다.
    blocked = ("image", "media", "font")

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
            ctx = await browser.new_context(
                viewport=SHOT_VIEWPORT, ignore_https_errors=False
            )
            page = await ctx.new_page()
            await page.route("**/*", _make_route(blocked))

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            except PWTimeoutError:
                notes.append("페이지 로드 타임아웃 — 부분 렌더링 상태에서 추출")

            async def _collect_markers():
                # 각 <img>를 위치 그대로 텍스트 마커로 치환하고 URL 목록을 반환.
                try:
                    return await page.evaluate(
                        _IMG_MARKER_JS, [IMG_MARKER_MAX, sorted(_PLACEHOLDER_ALTS)]
                    )
                except Exception:
                    return []

            async def _settle():
                # SPA가 XHR로 본문을 채울 시간을 짧게만 준다 (networkidle은 안 오는
                # 페이지가 흔해 상한만 둠). 이어서 무한스크롤/lazy 콘텐츠를 채운다.
                try:
                    await page.wait_for_load_state("networkidle", timeout=IDLE_SETTLE_MS)
                except PWTimeoutError:
                    pass
                await _autoscroll(page)

            # 이미지가 abort되는 상태에서 페이지 JS가 lazy <img>를 에러 placeholder로
            # 바꿔 URL을 날리기 *전에*, 정적 마크업(data-lazy-src 등)에서 먼저 마커를
            # 확보한다. 그 뒤 정착·스크롤로 무한스크롤/lazy 텍스트를 채운다.
            images = await _collect_markers()
            await _settle()

            try:
                text = await page.inner_text("body")
            except Exception:
                text = ""
                notes.append("본문(body) 요소 없음")

            return {
                "v": 1,
                "text": text[:MAX_CHARS],
                "images": images,
                "notes": notes,
            }
        finally:
            await browser.close()


def _image_dims(mime: str, data: bytes) -> tuple[int, int] | None:
    """디코딩 없이 헤더만 파싱해 (w, h) 추출. 실패 시 None (치명 아님)."""
    try:
        if mime == "image/png" and len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
            w, h = struct.unpack(">II", data[16:24])
            return (w, h)
        if mime == "image/gif" and len(data) >= 10:
            w, h = struct.unpack("<HH", data[6:10])
            return (w, h)
        if mime == "image/jpeg":
            i = 2
            while i + 9 < len(data):
                if data[i] != 0xFF:
                    i += 1
                    continue
                marker = data[i + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seglen = struct.unpack(">H", data[i + 2:i + 4])[0]
                if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return (w, h)
                i += 2 + seglen
        if mime == "image/webp" and len(data) >= 30 and data[8:12] == b"WEBP":
            fmt = data[12:16]
            if fmt == b"VP8X":
                w = int.from_bytes(data[24:27], "little") + 1
                h = int.from_bytes(data[27:30], "little") + 1
                return (w, h)
            if fmt == b"VP8 ":
                w = struct.unpack("<H", data[26:28])[0] & 0x3FFF
                h = struct.unpack("<H", data[28:30])[0] & 0x3FFF
                return (w, h)
            if fmt == b"VP8L" and len(data) >= 25:
                bits = int.from_bytes(data[21:25], "little")
                return ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
    except Exception:
        pass
    return None


async def fetch_image(url: str) -> dict:
    """이미지 URL을 goto로 로드해 원본 bytes 회수 (라우팅이 리다이렉트 홉까지 재검증).

    디코딩(렌더링)은 Chromium=gVisor 안에서만 일어나고, 여기서는 bytes를
    통과시키기만 한다. 지원 포맷 외(SVG 등)는 뷰포트 스크린샷으로 래스터라이즈.
    """
    notes: list[str] = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-dev-shm-usage", "--disable-gpu", "--no-sandbox"],
        )
        try:
            ctx = await browser.new_context(
                viewport=SHOT_VIEWPORT, ignore_https_errors=False
            )
            page = await ctx.new_page()
            await page.route("**/*", _make_route(("media",)))

            resp = await page.goto(url, wait_until="load", timeout=NAV_TIMEOUT_MS)
            if resp is None:
                raise RuntimeError("응답 없음")
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}")
            mime = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()

            if mime in IMAGE_MIME_ALLOWED:
                body = await resp.body()
                if len(body) > SHOT_MAX_BYTES:
                    raise RuntimeError(f"이미지 {len(body)}B > {SHOT_MAX_BYTES}B 상한")
                dims = _image_dims(mime, body)
                if dims and max(dims) > IMAGE_MAX_EDGE_PX:
                    raise RuntimeError(f"이미지 {dims[0]}x{dims[1]}px — 장변 {IMAGE_MAX_EDGE_PX}px 초과")
                return {
                    "v": 1,
                    "image_b64": base64.b64encode(body).decode(),
                    "image_mime": mime,
                    "dims": list(dims) if dims else None,
                    "notes": notes,
                }

            if mime in ("image/svg+xml",) or mime.startswith("image/"):
                # Claude vision 미지원 포맷 — 렌더된 화면을 래스터라이즈해 대체
                shot = await _shoot(page, SHOT_QUALITY)
                notes.append(f"{mime}는 직접 전달 불가 — 뷰포트 래스터라이즈로 대체")
                return {
                    "v": 1,
                    "image_b64": base64.b64encode(shot).decode(),
                    "image_mime": "image/jpeg",
                    "dims": [SHOT_VIEWPORT["width"], SHOT_VIEWPORT["height"]],
                    "notes": notes,
                }

            raise RuntimeError(f"이미지가 아님 (content-type: {mime or '알 수 없음'})")
        finally:
            await browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="render.py", add_help=False)
    parser.add_argument("url")
    parser.add_argument("--fetch-image", action="store_true", dest="fetch_image")
    try:
        args = parser.parse_args()
    except SystemExit:
        print("usage: render.py <url> | render.py <url> --fetch-image", file=sys.stderr)
        return 2

    try:
        assert_public_host(args.url)
    except Exception as e:
        print(f"SSRF 차단/검증 실패: {e}", file=sys.stderr)
        return 3

    try:
        if args.fetch_image:
            envelope = asyncio.run(fetch_image(args.url))
        else:
            envelope = asyncio.run(render(args.url))
    except Exception as e:
        print(f"렌더링 실패: {e}", file=sys.stderr)
        return 1

    sys.stdout.write(json.dumps(envelope, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
