"""web-surf runner: URL을 JS 렌더링해 JSON envelope로 stdout에 반환.

이 스크립트는 ephemeral 컨테이너 안에서만 실행되며, untrusted 웹을 만지는
유일한 지점이다. 컨트롤러의 SSRF 가드에 더해, 여기서도 **모든 http(s) 요청**
(리다이렉트·sub-resource 포함)의 호스트를 재검증한다 (DNS rebinding 방어).
리소스 타입 차단은 메모리 최적화일 뿐 보안 경계가 아니다 — 경계는 이
호스트 재검증과 egress 방화벽이다.

모드:
  render.py <url>                            본문 텍스트 (+이미지 위치 마커)
  render.py <url> --screenshot               + 뷰포트 스크린샷(JPEG)
  render.py <url> --screenshot --full-page   + 전체 페이지(높이 캡)
  render.py <url> --fetch-image              url을 이미지로 보고 원본 bytes 반환

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
from urllib.parse import urlparse

from playwright.async_api import TimeoutError as PWTimeoutError
from playwright.async_api import async_playwright

MAX_CHARS = 1_000_000        # 본문 텍스트 상한
NAV_TIMEOUT_MS = 20_000      # 페이지 로드 타임아웃

SHOT_VIEWPORT = {"width": 1280, "height": 800}
SHOT_QUALITY = 80
SHOT_RETRY_QUALITY = 50      # 5MB 초과 시 1회 재시도 품질
SHOT_MAX_BYTES = 5_000_000   # raw JPEG 상한 (base64 전)
FULLPAGE_MAX_PX = 4000       # full_page 캡처 높이 캡 (메모리/토큰 폭주 방지)
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


# 고정 내부 스니펫 (사용자 입력이 흘러들지 않음 — 인자는 정수 상수뿐).
# 각 <img>를 위치 그대로 텍스트 마커로 치환 → inner_text가 마커를 문맥과 함께 포함.
_IMG_MARKER_JS = """
(maxMarkers) => {
  const seen = new Set();
  const collected = [];
  for (const el of Array.from(document.querySelectorAll("img"))) {
    const src = el.currentSrc || el.src || "";
    if (!/^https?:/i.test(src)) continue;                       // data:/blob: 제외
    const wAttr = parseInt(el.getAttribute("width") || "", 10);
    const hAttr = parseInt(el.getAttribute("height") || "", 10);
    if ((wAttr && wAttr <= 2) || (hAttr && hAttr <= 2)) continue;  // 추적픽셀
    if (el.naturalWidth > 0 && el.naturalWidth <= 2) continue;
    if (seen.has(src)) continue;                                 // 반복 로고 등 dedup
    seen.add(src);
    if (collected.length >= maxMarkers) break;
    const alt = (el.getAttribute("alt") || "").trim().slice(0, 120);
    collected.push({ src: src, alt: alt });
    const label = alt ? `[이미지: ${alt} — ${src}]` : `[이미지 — ${src}]`;
    try { el.replaceWith(document.createTextNode(" " + label + " ")); } catch (e) {}
  }
  return collected;
}
"""


async def _shoot(page, quality: int, *, clip=None, full_page=False) -> bytes:
    kwargs = dict(type="jpeg", quality=quality, timeout=SHOT_TIMEOUT_MS)
    if clip:
        kwargs["clip"] = clip
    if full_page:
        kwargs["full_page"] = True
    return await page.screenshot(**kwargs)


async def _capture_screenshot(page, full_page: bool, notes: list[str]) -> bytes | None:
    """뷰포트/전체 스크린샷. 실패 시 뷰포트 폴백, 초과 시 품질 재시도, 최후엔 None."""
    clip = None
    use_full = False
    if full_page:
        # lazy-load 이미지가 아래쪽에서 빈칸으로 찍히는 것 방지: 프리스크롤
        try:
            await page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
            await page.wait_for_timeout(800)
            await page.evaluate("() => window.scrollTo(0, 0)")
        except Exception:
            pass
        try:
            doc_h = int(await page.evaluate("() => document.documentElement.scrollHeight") or 0)
        except Exception:
            doc_h = 0
        if doc_h > FULLPAGE_MAX_PX:
            # clip과 full_page는 배타 — 긴 문서는 상단만 절단 캡처
            clip = {"x": 0, "y": 0, "width": SHOT_VIEWPORT["width"], "height": FULLPAGE_MAX_PX}
            notes.append(f"문서 높이 {doc_h}px — 상단 {FULLPAGE_MAX_PX}px만 캡처")
        else:
            use_full = True

    try:
        shot = await _shoot(page, SHOT_QUALITY, clip=clip, full_page=use_full)
    except Exception as e:
        try:
            shot = await _shoot(page, SHOT_QUALITY)
            notes.append(f"전체 캡처 실패({type(e).__name__}) — 뷰포트만 캡처")
            clip, use_full = None, False
        except Exception as e2:
            notes.append(f"스크린샷 실패: {type(e2).__name__}")
            return None

    if len(shot) > SHOT_MAX_BYTES:
        try:
            shot = await _shoot(page, SHOT_RETRY_QUALITY, clip=clip, full_page=use_full)
            notes.append(f"용량 초과로 품질 {SHOT_RETRY_QUALITY}로 재캡처")
        except Exception:
            pass
    if len(shot) > SHOT_MAX_BYTES:
        notes.append(f"스크린샷 {len(shot)}B > {SHOT_MAX_BYTES}B — 첨부 생략")
        return None
    return shot


async def render(url: str, screenshot: bool = False, full_page: bool = False) -> dict:
    notes: list[str] = []
    # 스크린샷 모드: 페이지가 제대로 보여야 하므로 이미지·폰트 허용(media만 차단).
    # 텍스트 모드: 기존대로 image/media/font 차단(메모리 절약).
    blocked = ("media",) if screenshot else ("image", "media", "font")

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
                await page.goto(url, wait_until="networkidle", timeout=NAV_TIMEOUT_MS)
            except PWTimeoutError:
                # 광고/분석 스크립트가 많은 페이지는 networkidle에 도달 못함 —
                # DOM은 대개 완성돼 있으므로 best-effort로 계속 진행.
                notes.append("페이지 로드 타임아웃(networkidle 미도달) — 부분 렌더링 상태에서 추출")

            shot = None
            if screenshot:
                shot = await _capture_screenshot(page, full_page, notes)

            # 마커 삽입은 스크린샷 캡처 *후* (마커가 화면에 찍히면 안 됨)
            try:
                images = await page.evaluate(_IMG_MARKER_JS, IMG_MARKER_MAX)
            except Exception:
                images = []

            try:
                text = await page.inner_text("body")
            except Exception:
                text = ""
                notes.append("본문(body) 요소 없음")

            return {
                "v": 1,
                "text": text[:MAX_CHARS],
                "images": images,
                "screenshot_b64": base64.b64encode(shot).decode() if shot else None,
                "screenshot_mime": "image/jpeg",
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
    parser.add_argument("--screenshot", action="store_true")
    parser.add_argument("--full-page", action="store_true", dest="full_page")
    parser.add_argument("--fetch-image", action="store_true", dest="fetch_image")
    try:
        args = parser.parse_args()
    except SystemExit:
        print("usage: render.py <url> [--screenshot] [--full-page] | <url> --fetch-image",
              file=sys.stderr)
        return 2
    if args.fetch_image and (args.screenshot or args.full_page):
        print("--fetch-image는 --screenshot/--full-page와 함께 쓸 수 없음", file=sys.stderr)
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
            # full_page는 screenshot을 함의
            envelope = asyncio.run(render(
                args.url,
                screenshot=args.screenshot or args.full_page,
                full_page=args.full_page,
            ))
    except Exception as e:
        print(f"렌더링 실패: {e}", file=sys.stderr)
        return 1

    sys.stdout.write(json.dumps(envelope, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
