# Exfiltração — Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## Upload para nuvem (rclone/aws/az)

**MITRE ATT&CK:** `T1567`

rclone, megacmd, aws s3 cp, az storage upload — exfil pra storage em nuvem.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(rclone|megacmd|aws s3 cp|az storage blob upload|gsutil cp|dropbox)"
| sort by eventTime desc
| take 100
```

---

## Transferência via FTP/SFTP/SCP

**MITRE ATT&CK:** `T1048`

ftp put, WinSCP, pscp, curl -T — envio de arquivos pra fora.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(ftp.*put|winscp|pscp|sftp.*put|curl.*-t )"
| sort by eventTime desc
| take 100
```

---

## Envio via HTTP POST/PUT com arquivo

**MITRE ATT&CK:** `T1041`

Invoke-WebRequest/curl mandando arquivo no corpo da requisição.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(invoke-webrequest|invoke-restmethod|curl).*(-method +(post|put)|-infile|--data-binary|-d @)"
| sort by eventTime desc
| take 100
```

---

## Sites de compartilhamento anônimo

**MITRE ATT&CK:** `T1567.002`

transfer.sh, pastebin, anonfiles, wetransfer, 0x0.st — dropzones de exfil.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(transfer.sh|pastebin|anonfiles|file.io|temp.sh|0x0.st|wetransfer)"
| sort by eventTime desc
| take 100
```

---

## Exfil por DNS (subdomínios longos)

**MITRE ATT&CK:** `T1048.003`

nslookup/Resolve-DnsName com rótulos longos codificados.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(nslookup|resolve-dnsname).*[a-z0-9]{20,}"
| sort by eventTime desc
| take 100
```

