# Coleta · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## Compactação para exfil (archive)

**MITRE ATT&CK:** `T1560.001`

rar/7z/WinRAR/Compress-Archive juntando dados antes de sair.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(rar +a|7z +a|winrar|makecab|compress-archive)"
| sort by eventTime desc
| take 100
```

---

## Archive protegido por senha

**MITRE ATT&CK:** `T1560.001`

rar/7z com -hp/-p: compacta com senha pra dificultar inspeção.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(rar|7z|winrar).*(-hp|-p)"
| sort by eventTime desc
| take 100
```

---

## Captura de tela

**MITRE ATT&CK:** `T1113`

Ferramentas/comandos de screenshot (nircmd, Get-Screen, snippingtool).

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(screenshot|get-screen|nircmd.*savescreenshot|snippingtool)"
| sort by eventTime desc
| take 100
```

---

## Acesso à área de transferência

**MITRE ATT&CK:** `T1115`

Get-Clipboard, clip.exe: roubo de conteúdo copiado.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(get-clipboard|clip.exe|pbpaste)"
| sort by eventTime desc
| take 100
```

---

## Staging em pasta temporária

**MITRE ATT&CK:** `T1074`

Cópia de dados pra Recycle/Temp/ProgramData antes da exfil.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(copy|move|xcopy|robocopy)"
| where processCmd has_any ("Recycle", "Temp", "ProgramData")
| sort by eventTime desc
| take 100
```

