#!/usr/bin/env bash
# gVisor(runsc) 설치 + Docker 런타임 등록 (arm64 지원).
# OCI VM 내부라 Firecracker/Kata(nested virt 필요)는 불가 → gVisor가 현실적 최대 격리.
# gVisor는 VM 위에서 systrap/ptrace 플랫폼으로 동작하므로 KVM 없이도 OK.
set -euo pipefail

ARCH="$(dpkg --print-architecture)"   # arm64
echo "[*] arch=$ARCH"

# gVisor apt 저장소 등록
curl -fsSL https://gvisor.dev/archive.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null

sudo apt-get update
sudo apt-get install -y runsc

# Docker daemon에 runsc 런타임 등록 (/etc/docker/daemon.json 갱신)
sudo runsc install
sudo systemctl restart docker

echo "[*] 확인:"
docker info 2>/dev/null | grep -i runtimes || true
echo "[*] 테스트: docker run --rm --runtime=runsc hello-world"
docker run --rm --runtime=runsc hello-world | grep -i hello || {
  echo "!! runsc로 컨테이너 실행 실패 — fallback(runc + cap-drop/read-only/seccomp) 검토 필요"; exit 1;
}
echo "[+] gVisor 준비 완료"
