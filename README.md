# net_recon

Script Python para reconhecimento de rede, desenvolvido como projeto prático de estudo em Blue Team e análise de superfície de ataque.

Faz ARP scan para descobrir hosts ativos, SYN scan para identificar portas abertas e banner grab para coletar informações de serviços - tudo em um único comando.

---

## O que detecta

| Serviço | Porta | Severidade |
|---|---|---|
| FTP | 21/TCP | Crítico |
| Telnet | 23/TCP | Crítico |
| SMTP aberto | 25/TCP | Crítico |
| POP3 | 110/TCP | Crítico |
| IMAP | 143/TCP | Crítico |
| LDAP sem criptografia | 389/TCP | Crítico |
| RPC | 135/TCP | Aviso |
| NetBIOS | 139/TCP | Aviso |
| SMB | 445/TCP | Aviso |
| MySQL exposto | 3306/TCP | Aviso |
| RDP exposto | 3389/TCP | Aviso |
| HTTP alternativo | 8080/TCP | Aviso |

---

## Requisitos

```bash
sudo apt install python3-scapy
```

---

## Uso

```bash
# Varrer rede completa com portas padrão
sudo python3 net_recon.py 192.168.1.0/24

# Portas específicas
sudo python3 net_recon.py 192.168.1.0/24 --portas 21 22 23 80 3306

# Definir interface de rede
sudo python3 net_recon.py 192.168.1.0/24 --iface eth0
```

---

## Exemplo de output

```
[*] ARP scan em 172.20.0.0/24

    172.20.0.10        7e:71:09:ad:83:62
    172.20.0.30        d6:5a:0e:d2:33:b2

    2 host(s) encontrado(s)

[*] escaneando 172.20.0.10...
[*] escaneando 172.20.0.30...

  RELATORIO — 01/05/2026 17:07

  HOST: 172.20.0.10  (7e:71:09:ad:83:62)
    [ ]  :2222   desconhecido
           SSH-2.0-OpenSSH_10.2

  HOST: 172.20.0.30  (d6:5a:0e:d2:33:b2)
    [!]  :21     FTP          CRITICO - FTP, credenciais em texto puro
           220 FTP Server

  2 critico(s)  |  0 aviso(s)
```

---

## Limitações conhecidas

- O SYN scan exige privilégios de root para envio de pacotes raw.
- Banner grab pode falhar em serviços que não respondem imediatamente ou que exigem handshake específico.
- Desenvolvido e testado em ambiente de lab local. Não substitui ferramentas de reconhecimento em produção (Nmap, Masscan, etc.).

---

## Aviso legal

Use apenas em redes e dispositivos que você tem autorização para monitorar. A captura e o envio de pacotes sem autorização podem violar leis locais.
