#!/bin/bash
# ApexMail iptables Baseline Rules — July 2026
# Apply:   sudo bash deploy/hardening/iptables/apply-iptables.sh
# Persist: netfilter-persistent save (iptables-persistent package)
# Verify:  sudo iptables -L -n -v
set -euo pipefail

IPT=/sbin/iptables
IP6T=/sbin/ip6tables

echo "=== ApexMail iptables baseline hardening ==="

# ── IPv4 ─────────────────────────────────────────────────────
# Flush existing rules
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

# Default policy: DROP input/forward, ACCEPT output
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT ACCEPT

# Allow loopback unconditionally
$IPT -A INPUT -i lo -j ACCEPT

# Allow established/related connections
$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from management network (restrict in production)
$IPT -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
$IPT -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
$IPT -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP/HTTPS (nginx reverse proxy)
$IPT -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow SMTP for inbound mail delivery
$IPT -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A INPUT -p tcp --dport 465 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A INPUT -p tcp --dport 587 -m conntrack --ctstate NEW -j ACCEPT

# Rate limit ICMP (allow ping but prevent flood)
$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s --limit-burst 20 -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-request -j DROP

# Drop common attack/recon packets
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP

# Drop fragments
$IPT -A INPUT -f -j DROP

# Log and drop the rest (limit logging rate)
$IPT -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: " --log-level 4
$IPT -A INPUT -j DROP

# ── IPv6 ─────────────────────────────────────────────────────
$IP6T -F
$IP6T -X
$IP6T -P INPUT DROP
$IP6T -P FORWARD DROP
$IP6T -P OUTPUT ACCEPT

$IP6T -A INPUT -i lo -j ACCEPT
$IP6T -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow IPv6 ICMP (essential for IPv6 operation — neighbor discovery etc.)
$IP6T -A INPUT -p ipv6-icmp -j ACCEPT

# Allow SSH, HTTP, HTTPS, SMTP over IPv6
$IP6T -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
$IP6T -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
$IP6T -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A INPUT -p tcp --dport 465 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A INPUT -p tcp --dport 587 -m conntrack --ctstate NEW -j ACCEPT

# Drop invalid TCP flag combos over IPv6
$IP6T -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IP6T -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Log and drop remaining IPv6 traffic
$IP6T -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ip6tables-dropped: " --log-level 4
$IP6T -A INPUT -j DROP

echo "=== iptables hardening applied ==="
