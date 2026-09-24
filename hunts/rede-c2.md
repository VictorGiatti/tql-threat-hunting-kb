# Rede / C2 · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Beaconing · hosts muito falantes

**MITRE ATT&CK:** `T1071`

Hosts com muitas conexões de rede por hora (possível C2).

> **Limitação:** `bin()` só aceita 1s, 1m, 1h, 1d, 7d e 30d. O balde de 5 a 10 min, onde o beacon aparece, não existe; em 1h o beacon se dilui. Veja também "Beaconing · presença constante e baixo volume".

```text
datasource("xdr")
| where eventCategory == "DeviceNetworkEvents"
| where eventTime > ago(1d)
| summarize conexoes = count() by endpointHostName, hora = bin(eventTime, 1h)
| top 50 by conexoes desc
```

---

## Túnel / anonymizer (processos)

**MITRE ATT&CK:** `T1090 / T1572`

ngrok, frpc, chisel, cloudflared: túneis usados pra exfil/C2.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(ngrok|frpc|chisel|psiphon|cloudflared|localtonet)"
| sort by eventTime desc
| take 100
```

---

## Ferramentas de acesso remoto (RMM)

**MITRE ATT&CK:** `T1219`

AnyDesk, TeamViewer, ScreenConnect, Atera: abuso de RMM pra C2.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|logmein)"
| sort by eventTime desc
| take 100
```

---

## Reverse shell (one-liner)

**MITRE ATT&CK:** `T1059`

nc/ncat, /dev/tcp, TcpClient, bash -i: shell reverso.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)((^|[^a-z0-9])(nc|ncat|netcat)([.]exe)? |/dev/tcp/|tcpclient|bash +-i|reverse.?shell)"
| sort by eventTime desc
| take 100
```

---

## Download por linha de comando

**MITRE ATT&CK:** `T1105`

curl/wget/Invoke-WebRequest/certutil urlcache puxando payload por HTTP.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(curl|wget|invoke-webrequest|certutil.*urlcache).*http"
| sort by eventTime desc
| take 100
```

---

## DNS suspeito (TXT/tunnel)

**MITRE ATT&CK:** `T1071.004`

nslookup pedindo TXT, indício de C2/exfil por DNS.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)nslookup.*(-type=txt|-q=txt)"
| sort by eventTime desc
| take 100
```

---

## Conexões de saída por host

**MITRE ATT&CK:** `T1071`

Total de conexões por host em 24h, ranking de quem mais fala com a rede.

```text
datasource("xdr")
| where eventCategory == "DeviceNetworkEvents"
| where eventTime > ago(1d)
| summarize conexoes = count() by endpointHostName
| top 50 by conexoes desc
```

---

## Proxy / port forwarding

**MITRE ATT&CK:** `T1090`

netsh portproxy, plink -R, ssh -R: pivô/encaminhamento de porta.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(netsh.*portproxy|plink.*-r|ssh.*-r +|socks)"
| sort by eventTime desc
| take 100
```

---

## Start-BitsTransfer (download PS)

**MITRE ATT&CK:** `T1105`

Download via módulo BITS do PowerShell.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(start-bitstransfer|import-module bitstransfer)"
| sort by eventTime desc
| take 100
```

---

## Beaconing · presença constante e baixo volume

**MITRE ATT&CK:** `T1071`

Host que fala com a rede quase todo minuto, mas com poucas conexões por minuto: assinatura de beacon (presença constante, volume baixo).

> **Limitação:** a contagem é por host, não por destino, e 1 min é o menor balde útil que o `bin()` aceita (5 min não existe). Agentes de monitoramento também aparecem: compare com a baseline antes de escalar.

```text
datasource("xdr")
| where eventCategory == "DeviceNetworkEvents"
| where eventTime > ago(1d)
| summarize hits = count() by endpointHostName, minuto = bin(eventTime, 1m)
| summarize minutosAtivos = count(), mediaHits = avg(hits) by endpointHostName
| where minutosAtivos >= 60 and mediaHits <= 3
| top 50 by minutosAtivos desc
```
