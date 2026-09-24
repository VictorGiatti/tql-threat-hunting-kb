# Execução · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## PowerShell codificado (-enc)

**MITRE ATT&CK:** `T1059.001`

Comando PowerShell com payload em base64 (`-e`, `-ec`, `-enc`, `-EncodedCommand`), evasão clássica de defesa.

> **Limitação:** o TQL não decodifica base64 nem extrai substring (`base64_decode`/`extract` não existem). O hunt acha o blob; o conteúdo tem que ser lido fora (ex.: CyberChef).

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "powershell" or processCmd contains "pwsh"
| where processCmd matches regex "(?i) [-/]e[a-z]* +.?[a-z0-9+/=]{20,}"
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
| where processCmd matches regex "(?i)(downloadstring|downloadfile|invoke-webrequest|iwr |net[.]webclient|iex|invoke-expression)"
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
| where processCmd matches regex "(?i)(certutil|mshta|rundll32|regsvr32|installutil)"
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
| where processCmd matches regex "(?i)(wmic([.]exe)? |wmiprvse|invoke-wmimethod|invoke-cimmethod)"
| sort by eventTime desc
| take 100
```

---

## Office gerando shell (macro)

**MITRE ATT&CK:** `T1059 / T1566.001`

Word/Excel/Outlook iniciando powershell/cmd/wscript: assinatura de macro maliciosa.

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

Scripts (.ps1/.vbs/.js/.hta/.bat) executados de AppData, Temp, ProgramData ou Users\Public: típico de dropper.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(appdata|programdata|users.public|windows.temp|%temp%)"
| where processCmd matches regex "(?i)[.](ps1|vbs|vbe|js|jse|hta|bat|cmd|wsf)([^a-z0-9]|$)"
| sort by eventTime desc
| take 100
```

---

## Limpeza de logs de evento

**MITRE ATT&CK:** `T1070.001`

wevtutil cl / Clear-EventLog: apagar rastros.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(wevtutil([.]exe)? +(cl|clear-log) |clear-eventlog|remove-eventlog)"
| sort by eventTime desc
| take 100
```

---

## mshta executando script remoto

**MITRE ATT&CK:** `T1218.005`

mshta chamando http/javascript/vbscript: execução de HTA malicioso.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "mshta"
| where processCmd matches regex "(?i)(http|javascript:|vbscript:|[.]hta)"
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
| where processCmd matches regex "(?i)(javascript:|url[.]dll|runhtmlapplication|shell32[.]dll,control_rundll)"
| sort by eventTime desc
| take 100
```

---

## regsvr32 scriptlet (Squiblydoo)

**MITRE ATT&CK:** `T1218.010`

regsvr32 com /i: apontando pra scrobj.dll ou URL: bypass de whitelisting.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "regsvr32"
| where processCmd matches regex "(?i)([-/]i:|scrobj[.]dll|http)"
| sort by eventTime desc
| take 100
```

---

## WScript/CScript rodando script

**MITRE ATT&CK:** `T1059.005 / T1059.007`

Windows Script Host executando .vbs/.js/.wsf: dropper comum.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(wscript|cscript)"
| where processCmd matches regex "(?i)[.](vbs|vbe|js|jse|wsf)([^a-z0-9]|$)"
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
| where processCmd matches regex "(?i)[-/](transfer|create|addfile)"
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

cmd /c chamando powershell/certutil/curl em cadeia: loader.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)cmd.*(/c|/k).*(powershell|certutil|bitsadmin|curl|wget|mshta)"
| sort by eventTime desc
| take 100
```

