import argparse
import ipaddress
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1
    import socket
except ImportError:
    print("Instale scapy: sudo apt install python3-scapy")
    exit(1)

PORTAS_COMUNS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                 389, 443, 445, 636, 3306, 3389, 8080, 8443]

SERVICOS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 636: "LDAPS", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

RISCO = {
    21:   "CRITICO - FTP, credenciais em texto puro",
    23:   "CRITICO - Telnet, sem criptografia",
    25:   "CRITICO - SMTP aberto, risco de relay",
    110:  "CRITICO - POP3, credenciais em texto puro",
    143:  "CRITICO - IMAP, credenciais em texto puro",
    389:  "CRITICO - LDAP sem criptografia",
    135:  "AVISO - RPC, vetor comum de ataque",
    139:  "AVISO - NetBIOS, enumeração de rede",
    445:  "AVISO - SMB, histórico de exploits",
    3306: "AVISO - MySQL exposto",
    3389: "AVISO - RDP exposto, alvo de brute force",
    8080: "AVISO - HTTP alternativo, frequentemente sem TLS",
}


def arp_scan(rede, iface=None):
    print(f"\n[*] ARP scan em {rede}\n")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(rede))
    resultado, _ = srp(pkt, timeout=2, verbose=False, iface=iface)

    hosts = []
    for _, recv in resultado:
        hosts.append({"ip": recv.psrc, "mac": recv.hwsrc})
        print(f"    {recv.psrc:<18} {recv.hwsrc}")

    print(f"\n    {len(hosts)} host(s) encontrado(s)")
    return hosts


def syn_scan(ip, portas):
    abertas = []
    for porta in portas:
        pkt  = IP(dst=ip) / TCP(dport=porta, flags="S")
        resp = sr1(pkt, timeout=0.5, verbose=False)

        if resp and resp.haslayer(TCP):
            # 0x12 = SYN+ACK, porta aberta
            if resp[TCP].flags == 0x12:
                abertas.append(porta)
                sr1(IP(dst=ip) / TCP(dport=porta, flags="R"), timeout=0.3, verbose=False)

    return abertas


def banner_grab(ip, porta, timeout=2):
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            if porta in [80, 8080, 8443, 443]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner_raw = s.recv(256).decode(errors="replace").strip()
                banner = ''.join(c for c in banner_raw if c.isprintable())
            return banner[:80] if banner else None
    except Exception:
        return None


def exibir_resultados(resultados):
    total_criticos = 0
    total_avisos   = 0

    print(f"  RELATORIO — {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    for host in resultados:
        print(f"\n  HOST: {host['ip']}  ({host['mac']})")

        if not host["portas"]:
            print("    sem portas abertas nas comuns.")
            continue

        for p in host["portas"]:
            servico = SERVICOS.get(p, "desconhecido")
            alerta  = RISCO.get(p, "")
            banner  = host["banners"].get(p, "")

            if "CRITICO" in alerta:
                flag = "[!]"
                total_criticos += 1
            elif "AVISO" in alerta:
                flag = "[?]"
                total_avisos += 1
            else:
                flag = "[ ]"

            print(f"    {flag}  :{p:<6} {servico:<12} {alerta}")
            if banner:
                print(f"           {banner}")

    print(f"  {total_criticos} critico(s)  |  {total_avisos} aviso(s)")

def main():
    parser = argparse.ArgumentParser(description="net_recon - ARP . SYN . Banner")
    parser.add_argument("rede",        help="ex: 192.168.1.0/24")
    parser.add_argument("--portas",    nargs="+", type=int)
    parser.add_argument("--iface",     help="interface de rede (ex: br-a1131ff3806e)")
    args = parser.parse_args()

    print("\nnet_recon.py | ARP . SYN Scan . Banner Grab")
    print("-" * 30)
    print("  uso restrito a ambientes autorizados.")
    print("-" * 30)

    try:
        rede = ipaddress.ip_network(args.rede, strict=False)
    except ValueError as e:
        print(f"rede invalida: {e}")
        return

    hosts  = arp_scan(rede, iface=args.iface)
    portas = args.portas or PORTAS_COMUNS

    resultados = []
    for host in hosts:
        ip = host["ip"]
        print(f"\n[*] escaneando {ip}...")
        abertas = syn_scan(ip, portas)

        banners = {}
        for p in abertas:
            b = banner_grab(ip, p)
            if b:
                banners[p] =b

        resultados.append({**host, "portas": abertas, "banners": banners})

    exibir_resultados(resultados)


if __name__ == "__main__":
    main()
