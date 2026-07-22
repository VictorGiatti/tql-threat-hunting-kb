# Execução — Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## PowerShell codificado (-enc)

**MITRE ATT&CK:** `T1059.001`

Comando PowerShell ofuscado em base64 — evasão clássica de defesa.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "powershell" and processCmd contains "-enc"
| sort by eventTime desc
| take 100
```

---

## PowerShell download cradle

**MITRE ATT&CK:** `T1059.001`

Baixa e executa payload da rede (IEX, DownloadString, WebClient).

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd has_any ("DownloadString", "Invoke-WebRequest", "IEX", "Net.WebClient")
| sort by eventTime desc
| take 100
```

---

## LOLBins (binários confiáveis abusados)

**MITRE ATT&CK:** `T1218`

certutil, mshta, rundll32, regsvr32 usados pra baixar/executar.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd has_any ("certutil", "mshta", "rundll32", "regsvr32", "installutil")
| sort by eventTime desc
| take 100
```

---

## Abuso de WMI

**MITRE ATT&CK:** `T1047`

Execução remota/lateral via wmic ou Invoke-WmiMethod.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd has_any ("wmic ", "wmiprvse", "Invoke-WmiMethod")
| sort by eventTime desc
```

---

## Office gerando shell (macro)

**MITRE ATT&CK:** `T1059 / T1566.001`

Word/Excel/Outlook iniciando powershell/cmd/wscript — assinatura de macro maliciosa.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, parentCmd, processCmd
| where parentCmd matches regex "(?i)(winword|excel|powerpnt|outlook|mspub)"
| where processCmd matches regex "(?i)(powershell|cmd|wscript|cscript|mshta)"
| sort by eventTime desc
| take 100
```

---

## Script rodando de pasta temporária

**MITRE ATT&CK:** `T1059`

Scripts (.ps1/.vbs/.js/.hta/.bat) executados a partir de AppData — típico de dropper.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "AppData"
| where processCmd has_any (".ps1", ".vbs", ".js", ".hta", ".bat")
| sort by eventTime desc
| take 100
```

---

## Limpeza de logs de evento

**MITRE ATT&CK:** `T1070.001`

wevtutil cl / Clear-EventLog — apagar rastros.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd has_any ("wevtutil cl", "Clear-EventLog", "wevtutil clear-log")
| sort by eventTime desc
```

---

## mshta executando script remoto

**MITRE ATT&CK:** `T1218.005`

mshta chamando http/javascript/vbscript — execução de HTA malicioso.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "mshta"
| where processCmd has_any ("http", "javascript:", "vbscript:", ".hta")
| sort by eventTime desc
| take 100
```

---

## rundll32 suspeito

**MITRE ATT&CK:** `T1218.011`

rundll32 chamando JavaScript, url.dll ou RunHTMLApplication.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "rundll32"
| where processCmd has_any ("javascript:", "url.dll", "RunHTMLApplication", "shell32.dll,Control_RunDLL")
| sort by eventTime desc
| take 100
```

---

## regsvr32 scriptlet (Squiblydoo)

**MITRE ATT&CK:** `T1218.010`

regsvr32 com /i: apontando pra scrobj.dll ou URL — bypass de whitelisting.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "regsvr32"
| where processCmd has_any ("/i:", "scrobj.dll", "http")
| sort by eventTime desc
| take 100
```

---

## WScript/CScript rodando script

**MITRE ATT&CK:** `T1059.005 / T1059.007`

Windows Script Host executando .vbs/.js/.wsf — dropper comum.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(wscript|cscript)"
| where processCmd has_any (".vbs", ".js", ".vbe", ".jse", ".wsf")
| sort by eventTime desc
| take 100
```

---

## bitsadmin transferindo arquivo

**MITRE ATT&CK:** `T1197`

Download furtivo via BITS (bitsadmin /transfer).

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "bitsadmin"
| where processCmd has_any ("/transfer", "/create", "/addfile")
| sort by eventTime desc
| take 100
```

---

## Proxy de execução via dev tools

**MITRE ATT&CK:** `T1127`

msbuild, installutil, regasm, regsvcs usados pra rodar código.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(msbuild|installutil|regasm|regsvcs)"
| sort by eventTime desc
| take 100
```

---

## cmd encadeado (one-liner)

**MITRE ATT&CK:** `T1059.003`

cmd /c chamando powershell/certutil/curl em cadeia — loader.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)cmd.*(/c|/k).*(powershell|certutil|bitsadmin|curl|wget|mshta)"
| sort by eventTime desc
| take 100
```

