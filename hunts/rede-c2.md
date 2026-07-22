# Rede / C2 · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## Beaconing · hosts muito falantes

**MITRE ATT&CK:** `T1071`

Hosts com muitas conexões de rede por hora (possível C2).

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
| where processCmd matches regex "(?i)(nc.exe|ncat|/dev/tcp|tcpclient|reverse.*shell|bash -i)"
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

