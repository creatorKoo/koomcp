#!/usr/bin/env bash
# runner 전용 도커 네트워크 + egress allowlist(최소: 메타데이터/RFC1918/링크로컬 차단).
# 목적: 페이지가 SSRF를 시도해도 클라우드 메타데이터(169.254.169.254)나 내부망에
#       도달하지 못하게 한다. 공인 인터넷으로의 NAT 아웃바운드는 허용(dest가 공인이라).
set -euo pipefail

NET=surf-egress
SUBNET=172.31.250.0/24
RESOLV=/etc/web-surf-resolv.conf

# 전용 네트워크 (이미 있으면 통과)
docker network create --subnet "$SUBNET" "$NET" 2>/dev/null || echo "[*] $NET 이미 존재"

# runner용 공용 DNS resolv.conf (gVisor가 Docker 임베디드 DNS 127.0.0.11을
# 지원하지 않아, 이 파일을 컨테이너에 bind-mount해서 우회한다)
printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\n' | sudo tee "$RESOLV" >/dev/null
echo "[+] $RESOLV 생성"

# DOCKER-USER 체인에 차단 규칙 삽입 (forward 트래픽에 적용).
# 주의: 172.16.0.0/12 차단에 게이트웨이/내부가 포함되지만, 인터넷 NAT는 dest가
#       공인이라 영향 없음. 오히려 runner→호스트 접근까지 막혀 SSRF 방어에 유리.
BLOCK_DESTS=(
  169.254.169.254/32   # 클라우드 메타데이터
  169.254.0.0/16       # 링크로컬
  10.0.0.0/8           # RFC1918
  172.16.0.0/12        # RFC1918 (게이트웨이/호스트 포함)
  192.168.0.0/16       # RFC1918
  100.64.0.0/10        # CGNAT
)
for dst in "${BLOCK_DESTS[@]}"; do
  if ! sudo iptables -C DOCKER-USER -s "$SUBNET" -d "$dst" -j DROP 2>/dev/null; then
    sudo iptables -I DOCKER-USER -s "$SUBNET" -d "$dst" -j DROP
    echo "[+] DROP $SUBNET -> $dst"
  fi
done

sudo netfilter-persistent save
echo "[+] egress allowlist 적용 완료 (재부팅 후에도 유지)"
echo "[*] 검증 예시(차단되어야 정상):"
echo "    docker run --rm --network=$NET curlimages/curl -s -m 5 http://169.254.169.254/  # 실패해야 함"
