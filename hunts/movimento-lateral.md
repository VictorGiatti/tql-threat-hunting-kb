# Movimento lateral · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## PsExec / execução remota

**MITRE ATT&CK:** `T1021.002 / T1570`

PsExec e similares para rodar comandos em outra máquina.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(psexec|paexec|psexesvc|-accepteula)"
| sort by eventTime desc
| take 100
```

---

## WinRM / execução remota PowerShell

**MITRE ATT&CK:** `T1021.006`

winrs, Enter-PSSession, Invoke-Command -ComputerName, wsmprovhost.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(winrs|enter-pssession|invoke-command .*-computername|wsmprovhost)"
| sort by eventTime desc
| take 100
```

---

## RDP interativo / hijack de sessão

**MITRE ATT&CK:** `T1021.001`

mstsc /v, tscon, qwinsta: uso de RDP e sequestro de sessão.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(mstsc.*/v|tscon .*/dest|qwinsta)"
| sort by eventTime desc
| take 100
```

---

## Cópia para share administrativo

**MITRE ATT&CK:** `T1021.002`

copy/robocopy para C$, ADMIN$, IPC$: staging em host remoto.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(copy|xcopy|robocopy|move)"
| where processCmd has_any ("c$", "admin$", "ipc$")
| sort by eventTime desc
| take 100
```

---

## WMIC remoto (/node)

**MITRE ATT&CK:** `T1047`

wmic /node executando em máquina remota.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)wmic +/node"
| sort by eventTime desc
| take 100
```

---

## Execução via DCOM

**MITRE ATT&CK:** `T1021.003`

MMC20.Application, Excel.Application, ShellWindows: lateral por DCOM.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(mmc20.application|excel.application|shellwindows|invoke-dcom)"
| sort by eventTime desc
| take 100
```

---

## Tarefa agendada remota

**MITRE ATT&CK:** `T1053.005`

schtasks /s <host>: cria/roda tarefa em máquina remota.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)schtasks.*/s +"
| sort by eventTime desc
| take 100
```

---

## Instalação de serviço (Evento 7045)

**MITRE ATT&CK:** `T1543.003`

Novo serviço instalado, artefato clássico de PsExec/execução remota.

```text
datasource("xdr") with (log_type="systemevent")
| where eventTime > ago(7d)
| where winEventId == 7045
| project eventTime, endpointHostName, eventName, eventSubName
| sort by eventTime desc
| take 100
```

