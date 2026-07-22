# Escalonamento de privilégio — Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## PrintNightmare (spoolsv gerando processo)

**MITRE ATT&CK:** `T1068`

spoolsv.exe como pai de cmd/powershell/rundll32 — exploração do spooler.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, parentCmd, processCmd
| where parentCmd contains "spoolsv"
| where processCmd matches regex "(?i)(cmd|powershell|rundll32|wscript)"
| sort by eventTime desc
| take 100
```

---

## Exploits 'Potato'

**MITRE ATT&CK:** `T1134.001`

JuicyPotato, PrintSpoofer, RoguePotato, GodPotato — abuso de privilégio.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(juicypotato|printspoofer|roguepotato|sweetpotato|godpotato|efspotato)"
| sort by eventTime desc
| take 100
```

---

## Manipulação de token

**MITRE ATT&CK:** `T1134`

Invoke-TokenManipulation, AdjustTokenPrivileges, SeDebugPrivilege.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(invoke-tokenmanipulation|adjusttokenprivileges|sedebugprivilege)"
| sort by eventTime desc
| take 100
```

---

## runas com credencial alternativa

**MITRE ATT&CK:** `T1078`

runas /user ou /savecred — execução com outra identidade.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)runas.*(/user|/savecred)"
| sort by eventTime desc
| take 100
```

---

## Serviço criado como SYSTEM

**MITRE ATT&CK:** `T1543.003`

sc create com binPath pra cmd/powershell — executa como SYSTEM.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)sc.*create.*binpath.*(cmd|powershell)"
| sort by eventTime desc
| take 100
```

---

## Tarefa agendada como SYSTEM

**MITRE ATT&CK:** `T1053.005`

schtasks /create /ru system — persistência/execução privilegiada.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)schtasks.*/create.*/ru +system"
| sort by eventTime desc
| take 100
```

