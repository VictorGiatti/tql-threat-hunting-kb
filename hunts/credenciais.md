# Credenciais — Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## Acesso ao LSASS (dump de credencial)

**MITRE ATT&CK:** `T1003.001`

Tentativa de ler a memória do LSASS pra roubar credenciais.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd contains "lsass"
| sort by eventTime desc
```

---

## Ferramentas de dump conhecidas

**MITRE ATT&CK:** `T1003.001`

mimikatz, comsvcs MiniDump, procdump, nanodump — extração de credencial.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(mimikatz|comsvcs|minidump|procdump|nanodump|sekurlsa)"
| sort by eventTime desc
| take 100
```

---

## Acesso ao NTDS.dit / shadow copy

**MITRE ATT&CK:** `T1003.003`

Cópia do banco do AD ou criação de shadow copy pra extrair hashes.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(ntds|ntdsutil|vssadmin create|create shadow|diskshadow)"
| sort by eventTime desc
| take 100
```

---

## Logons falhos / brute force (gráfico)

**MITRE ATT&CK:** `T1110`

Picos de falha de autenticação por hora (4625/4771/4776/4740).

```text
datasource("xdr") with (log_type="telemetry", product_code=["sao", "xes"])
| where eventTime > ago(1d)
| where winEventId in (4625, 4771, 4776, 4740)
| summarize tentativas = count() by hora = bin(eventTime, 1h), winEventId
| render linechart with (xtitle="Hora", ytitle="Tentativas")
```

---

## Dump do SAM/SYSTEM via reg save

**MITRE ATT&CK:** `T1003.002`

reg save das hives SAM/SYSTEM/SECURITY pra extrair hashes locais.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)reg.*save.*(sam|system|security)"
| sort by eventTime desc
| take 100
```

---

## Kerberoasting

**MITRE ATT&CK:** `T1558.003`

Rubeus, GetUserSPNs, kerberoast, asreproast — abuso de tickets Kerberos.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(rubeus|getuserspns|kerberoast|asktgt|asreproast)"
| sort by eventTime desc
| take 100
```

---

## DCSync

**MITRE ATT&CK:** `T1003.006`

lsadump::dcsync / drsuapi — replicação maliciosa pra roubar hashes do DC.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(dcsync|lsadump|drsuapi)"
| sort by eventTime desc
| take 100
```

---

## Acesso a cofres de credencial

**MITRE ATT&CK:** `T1555`

vaultcmd, cmdkey /list, DPAPI — extração de segredos armazenados.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(vaultcmd|cmdkey /list|get-vaultcredential|dpapi)"
| sort by eventTime desc
| take 100
```

---

## Busca por senhas em arquivos

**MITRE ATT&CK:** `T1552.001`

findstr/Select-String por 'password', unattend.xml, arquivos de credencial.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(findstr.*pass|select-string.*password|type.*unattend|get-content.*(password|cred))"
| sort by eventTime desc
| take 100
```

---

## Habilitar WDigest (creds em claro)

**MITRE ATT&CK:** `T1112 / T1003`

reg add UseLogonCredential=1 pra forçar credencial em texto no LSASS.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "reg add"
| where processCmd has_any ("UseLogonCredential", "WDigest")
| sort by eventTime desc
| take 100
```

