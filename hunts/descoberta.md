# Descoberta · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## Reconhecimento (discovery)

**MITRE ATT&CK:** `T1087 / T1016 / T1082`

whoami, net view, ipconfig, nltest, systeminfo em sequência.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(1d)
| project eventTime, endpointHostName, processCmd
| where processCmd has_any ("whoami", "net view", "ipconfig /all", "nltest", "systeminfo")
| sort by eventTime desc
```

---

## Reconhecimento de Active Directory

**MITRE ATT&CK:** `T1087.002`

AdFind, SharpHound/BloodHound, dsquery, nltest: mapeamento do domínio.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd matches regex "(?i)(adfind|sharphound|bloodhound|dsquery|nltest|net group .*domain)"
| sort by eventTime desc
| take 100
```

---

## Descoberta de compartilhamentos/rede

**MITRE ATT&CK:** `T1135 / T1049`

net view/share/use, sessions, arp: mapeando o que dá pra alcançar.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(1d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(net view|net share|net use|net sessions|arp -a)"
| sort by eventTime desc
| take 100
```

---

## Enumeração de processos e serviços

**MITRE ATT&CK:** `T1057 / T1007`

tasklist, sc query, Get-Process/Get-Service: mapeando o que roda.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(1d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(tasklist|sc query|get-process|get-service|wmic process)"
| sort by eventTime desc
| take 100
```

---

## Enumeração de segurança (AV/firewall)

**MITRE ATT&CK:** `T1518.001`

Procura por soluções de segurança instaladas antes de agir.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(netsh advfirewall show|antivirusproduct|get-mpcomputerstatus|sc query win)"
| sort by eventTime desc
| take 100
```

---

## Descoberta de trusts de domínio

**MITRE ATT&CK:** `T1482`

nltest /domain_trusts, Get-ADTrust: mapear relações entre domínios.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(domain_trusts|get-adtrust|trusteddomain)"
| sort by eventTime desc
| take 100
```

---

## Política de senha / contas

**MITRE ATT&CK:** `T1201`

net accounts, net user, política de senha do domínio.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(net accounts|net user |defaultdomainpasswordpolicy)"
| sort by eventTime desc
| take 100
```

---

## Descoberta de sistemas remotos

**MITRE ATT&CK:** `T1018`

Ping sweep, nmap, Test-Connection: mapeando hosts na rede.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(1d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(for.*ping|nmap|test-connection|net view /domain)"
| sort by eventTime desc
| take 100
```

---

## Descoberta de arquivos e pastas

**MITRE ATT&CK:** `T1083`

dir /s, tree, Get-ChildItem -Recurse: varredura do disco.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(1d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(dir /s|tree |get-childitem -recurse|where /r)"
| sort by eventTime desc
| take 100
```

---

## Enumeração de tarefas agendadas

**MITRE ATT&CK:** —

schtasks /query, Get-ScheduledTask: inventário de agendamentos.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(1d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(schtasks.*/query|get-scheduledtask)"
| sort by eventTime desc
| take 100
```

