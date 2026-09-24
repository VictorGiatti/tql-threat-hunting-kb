# Evasão de defesa · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Desabilitar Defender (realtime)

**MITRE ATT&CK:** `T1562.001`

Set-MpPreference desligando proteção em tempo real / antispyware.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(set-mppreference.*disable|disablerealtimemonitoring|disableantispyware)"
| sort by eventTime desc
| take 100
```

---

## Exclusão adicionada no Defender

**MITRE ATT&CK:** `T1562.001`

Add-MpPreference -ExclusionPath/Process: criando ponto cego.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)add-mppreference.*exclusion"
| sort by eventTime desc
| take 100
```

---

## Parar serviço de segurança

**MITRE ATT&CK:** `T1562.001`

net stop / sc stop / taskkill contra EDR/AV conhecidos.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(net stop|sc.*stop|taskkill).*(defender|sense|sophos|crowdstrike|mcafee|symantec|trend|falcon|sentinel|cylance)"
| sort by eventTime desc
| take 100
```

---

## Desabilitar firewall do Windows

**MITRE ATT&CK:** `T1562.004`

netsh advfirewall set ... off, abrindo a máquina.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(netsh.*advfirewall.*off|netsh firewall set opmode disable)"
| sort by eventTime desc
| take 100
```

---

## UAC bypass (LOLBins conhecidos)

**MITRE ATT&CK:** `T1548.002`

fodhelper, computerdefaults, eventvwr, sdclt, slui: bypass de UAC.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(fodhelper|computerdefaults|eventvwr|sdclt|slui)"
| sort by eventTime desc
| take 100
```

---

## Bypass de AMSI

**MITRE ATT&CK:** `T1562.001`

Padrões de bypass do AMSI (amsiInitFailed, amsiUtils).

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(amsiinitfailed|amsiutils|amsi.*bypass)"
| sort by eventTime desc
| take 100
```

---

## Ocultar arquivos (attrib +h +s)

**MITRE ATT&CK:** `T1564.001`

attrib marcando arquivos como oculto/sistema.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "attrib"
| where processCmd matches regex "(?i)[+][hs]"
| sort by eventTime desc
| take 100
```

---

## Timestomp (alterar timestamps)

**MITRE ATT&CK:** `T1070.006`

Set-ItemProperty mudando CreationTime/LastWriteTime.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)set-itemproperty.*(creationtime|lastwritetime|lastaccesstime)"
| sort by eventTime desc
| take 100
```

---

## Apagar histórico do PowerShell

**MITRE ATT&CK:** `T1070`

Clear-History / remoção do ConsoleHost_history / PSReadLine.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(clear-history|consolehost_history|remove-item.*psreadline)"
| sort by eventTime desc
| take 100
```

---

## Desabilitar logging (ETW/logman)

**MITRE ATT&CK:** `T1562.006`

logman stop, wevtutil sl /e:false, Set-EtwTraceProvider.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(logman.*stop|wevtutil sl.*/e:false|set-etwtraceprovider)"
| sort by eventTime desc
| take 100
```

---

## Reg desabilitando Defender/Tamper

**MITRE ATT&CK:** `T1562.001`

reg add mexendo em DisableAntiSpyware / TamperProtection.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "reg add"
| where processCmd matches regex "(?i)(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection|tamperprotection)"
| sort by eventTime desc
| take 100
```

---

## Remoção de Mark-of-the-Web

**MITRE ATT&CK:** `T1553.005`

Unblock-File / remoção de Zone.Identifier: tira o aviso de arquivo baixado.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(unblock-file|remove-item.*zone.identifier|:zone.identifier)"
| sort by eventTime desc
| take 100
```

