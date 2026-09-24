# Impacto / Ransomware · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Deleção de shadow copies

**MITRE ATT&CK:** `T1490`

vssadmin/wmic apagando cópias de sombra: impede recuperação.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(vssadmin.*delete.*shadow|wmic shadowcopy delete)"
| sort by eventTime desc
| take 100
```

---

## Desabilitar recuperação do Windows

**MITRE ATT&CK:** `T1490`

bcdedit (recoveryenabled no), wbadmin delete, Disable-ComputerRestore.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(wbadmin delete|bcdedit.*(recoveryenabled +no|ignoreallfailures)|disable-computerrestore)"
| sort by eventTime desc
| take 100
```

---

## Limpar journal USN

**MITRE ATT&CK:** `T1070`

fsutil usn deletejournal, apaga trilha de alterações de arquivo.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)fsutil.*(usn.*deletejournal|deletejournal)"
| sort by eventTime desc
| take 100
```

---

## Wipe de dados (cipher /w)

**MITRE ATT&CK:** `T1485`

cipher /w sobrescreve espaço livre: destruição de dados.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(cipher +/w|sdelete|format .*/)"
| sort by eventTime desc
| take 100
```

---

## Parar serviços críticos (pré-ransom)

**MITRE ATT&CK:** `T1489`

net stop/Stop-Service em SQL, Exchange, Veeam, backup: antes de criptografar.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(net stop|sc.*stop|stop-service).*(sql|exchange|veeam|backup|oracle|vss)"
| sort by eventTime desc
| take 100
```

---

## Indícios de nota de resgate

**MITRE ATT&CK:** `T1486`

Comandos citando readme/decrypt/restore-files ou extensões .locked/.encrypted.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(readme|decrypt|[.]locked|[.]encrypted|restore-my-files|how_to)"
| sort by eventTime desc
| take 100
```

---

## Alteração de papel de parede

**MITRE ATT&CK:** `T1491`

reg add mexendo em Control Panel\Desktop Wallpaper, comum em ransomware.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "reg add"
| where processCmd contains "Wallpaper"
| sort by eventTime desc
| take 100
```

