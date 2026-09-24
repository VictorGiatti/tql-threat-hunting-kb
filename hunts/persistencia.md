# Persistência · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Persistência via Registry Run

**MITRE ATT&CK:** `T1547.001`

Escrita em chave Run/RunOnce (reg add ou PowerShell) pra rodar no logon.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd contains "currentversion"
| where processCmd matches regex "(?i)(reg([.]exe)? +add|new-itemproperty|set-itemproperty).*currentversion.(run|runonce|runservices|policies.explorer.run)"
| sort by eventTime desc
| take 100
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
| where processCmd matches regex "(?i)(schtasks([.]exe)? .*/create|sc([.]exe)? +([^ ]+ +)?create |new-scheduledtask|register-scheduledtask|new-service)"
| sort by eventTime desc
| take 100
```

---

## Criação de conta / grupo admin

**MITRE ATT&CK:** `T1136 / T1098`

net user ... /add, adição a grupo de administradores (net ou PowerShell).

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, processCmd
| where processCmd matches regex "(?i)(net1?([.]exe)? +user +.*/add|net1?([.]exe)? +(localgroup|group) +.*(admin|/add)|new-localuser|add-localgroupmember|add-adgroupmember)"
| sort by eventTime desc
| take 100
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
| where processCmd matches regex "(?i)(__eventfilter|commandlineeventconsumer|activescripteventconsumer|__eventconsumer|__filtertoconsumerbinding)"
| sort by eventTime desc
| take 100
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
| where processCmd contains "startup"
| where processCmd matches regex "(?i)(programs.startup|shell:(common )?startup)"
| where processCmd matches regex "(?i)[.](lnk|vbs|vbe|js|bat|cmd|exe|ps1|hta)([^a-z0-9]|$)"
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
| where processCmd contains "winlogon"
| where processCmd matches regex "(?i)(reg([.]exe)? +add|set-itemproperty|new-itemproperty).*(userinit|shell|taskman|appsetup)"
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
| where processCmd matches regex "(?i)(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)[.]exe"
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

---

## Servidor web ou SQL gerando shell (webshell)

**MITRE ATT&CK:** `T1505.003`

IIS (w3wp), Apache, nginx, Tomcat ou SQL Server (xp_cmdshell) iniciando shell ou recon: webshell ou exploração de aplicação exposta.

```text
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where eventTime > ago(7d)
| project eventTime, endpointHostName, parentCmd, processCmd
| where parentCmd matches regex "(?i)(w3wp|httpd|nginx|tomcat|catalina|php-cgi|sqlservr)"
| where processCmd matches regex "(?i)(cmd[.]exe|powershell|pwsh|whoami|net1?[.]exe|certutil|bitsadmin|rundll32|/bin/(ba)?sh)"
| sort by eventTime desc
| take 100
```
