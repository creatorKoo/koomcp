# Playwright 공식 베이스 (Chromium 포함, arm64 지원). 버전 핀 고정.
# 업그레이드는 체인지로그 보고 의도적으로 태그를 올릴 것.
FROM mcr.microsoft.com/playwright/python:v1.60.0-jammy

# read-only rootfs에서 Chromium이 쓸 임시 경로를 /tmp(tmpfs)로 강제
ENV HOME=/tmp \
    TMPDIR=/tmp \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# 이 베이스 이미지(v1.60.0)는 브라우저(/ms-playwright)만 포함하고 playwright
# pip 패키지는 없음 → 이미지 버전과 동일하게 설치 (브라우저는 이미 있어 재다운로드 X)
RUN pip install --no-cache-dir playwright==1.60.0

# 베이스 이미지에 비-root 유저 pwuser가 이미 존재 → 그대로 사용
USER pwuser
WORKDIR /home/pwuser

COPY --chown=pwuser:pwuser render.py .

# url을 인자로 받아 렌더링 (stdout으로 본문 텍스트 반환)
ENTRYPOINT ["python", "render.py"]
