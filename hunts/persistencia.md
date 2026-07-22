# Persistência · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## Persistência via Registry Run

**MITRE ATT&CK:** `T1547.001`

Escrita em chave Run pra rodar no boot (via reg add).

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "reg add" and processCmd contains "Run"
| sort by eventTime desc
```

---

## Tarefa agendada / serviço novo

**MITRE ATT&CK:** `T1053.005`

Criação de scheduled task ou serviço pra persistir/executar.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd, parentCmd
| where processCmd has_any ("schtasks /create", "sc create", "New-ScheduledTask")
| sort by eventTime desc
```

---

## Criação de conta / grupo admin

**MITRE ATT&CK:** `T1136 / T1098`

net user /add e adição ao grupo Administradores.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd has_any ("net user /add", "net localgroup administrators", "net group")
| sort by eventTime desc
```

---

## Assinatura de evento WMI (persistência)

**MITRE ATT&CK:** `T1546.003`

__EventFilter / EventConsumer: persistência furtiva via WMI.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd has_any ("__EventFilter", "CommandLineEventConsumer", "ActiveScriptEventConsumer", "__EventConsumer")
| sort by eventTime desc
```

---

## Drop na pasta Startup

**MITRE ATT&CK:** `T1547.001`

Cópia de atalho/binário/script pra pasta Startup do usuário.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "Startup"
| where processCmd has_any (".lnk", ".vbs", ".bat", ".exe", ".ps1")
| sort by eventTime desc
| take 100
```

---

## Serviço com binPath suspeito

**MITRE ATT&CK:** `T1543.003`

sc create/config apontando binPath pra cmd/powershell/script.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)sc.*(create|config).*binpath"
| sort by eventTime desc
| take 100
```

---

## Winlogon/Userinit alterado

**MITRE ATT&CK:** `T1547.004`

reg add em Userinit/Shell/Winlogon: execução no logon.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "reg add"
| where processCmd has_any ("Userinit", "Winlogon", "Shell")
| sort by eventTime desc
| take 100
```

---

## IFEO Debugger (sequestro de imagem)

**MITRE ATT&CK:** `T1546.012`

Image File Execution Options com Debugger, dispara binário no lugar de outro.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "Image File Execution Options"
| where processCmd contains "Debugger"
| sort by eventTime desc
| take 100
```

---

## Netsh helper DLL

**MITRE ATT&CK:** `T1546.007`

netsh add helper carregando DLL persistente.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)netsh.*add helper"
| sort by eventTime desc
| take 100
```

---

## Accessibility features (sethc/utilman)

**MITRE ATT&CK:** `T1546.008`

Substituição/depurador de sethc.exe/utilman.exe: backdoor na tela de logon.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd has_any ("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe")
| where processCmd matches regex "(?i)(reg add|copy|debugger|cmd.exe)"
| sort by eventTime desc
| take 100
```

---

## BITS job com notify (persistência)

**MITRE ATT&CK:** `T1197`

bitsadmin SetNotifyCmdLine, reexecuta comando quando o job completa.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)bitsadmin.*(setnotifycmdline|setnotifyflags)"
| sort by eventTime desc
| take 100
```

