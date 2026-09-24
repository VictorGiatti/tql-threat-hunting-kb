# Nuvem · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## CloudTrail: ações sensíveis de IAM

**MITRE ATT&CK:** `T1078.004`

Criação de usuário/chave/policy: possível criação de acesso persistente. Valide os campos de nuvem no editor.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(1d)
| where eventName in ("CreateUser", "CreateAccessKey", "CreateLoginProfile", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy")
| summarize total = count() by eventName
| sort by total desc
```

---

## CloudTrail: logging desabilitado

**MITRE ATT&CK:** `T1562.008`

StopLogging/DeleteTrail/DeleteFlowLogs: cegando a auditoria da nuvem.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(7d)
| where eventName in ("StopLogging", "DeleteTrail", "UpdateTrail", "DeleteFlowLogs")
| take 100
```

---

## CloudTrail: mudança em security group

**MITRE ATT&CK:** `T1098`

Abertura/alteração de regras de rede na AWS.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(1d)
| where eventName in ("AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "ModifyInstanceAttribute")
| take 100
```

---

## CloudTrail: S3 exposto

**MITRE ATT&CK:** `T1530`

PutBucketPolicy/PutBucketAcl/remoção de PublicAccessBlock: dados públicos.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(7d)
| where eventName in ("PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock", "DeleteBucketPolicy")
| take 100
```

---

## CloudTrail: uso da conta root

**MITRE ATT&CK:** `T1078.004`

Atividade atribuída ao root, deve ser rara e vigiada.

> **Limitação:** `userIdentity` é um objeto; `contains "root"` também casa ARNs e roles com "root" no nome. Confira o tipo de identidade no resultado.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(7d)
| where tostring(userIdentity) contains "root"
| project eventTime, eventName
| take 100
```

---

## CloudTrail: logins de console por hora

ConsoleLogin ao longo do tempo, picos e horários incomuns.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(1d)
| where eventName == "ConsoleLogin"
| summarize total = count() by hora = bin(eventTime, 1h)
| sort by hora asc
| render columnchart with (xtitle="Hora", ytitle="Logins")
```

---

## CloudTrail: chamadas mais frequentes

Baseline das APIs mais chamadas, anomalias saltam à vista.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(1d)
| summarize total = count() by eventName
| top 40 by total desc
```

---

## CloudTrail: mudança em compute

**MITRE ATT&CK:** `T1578`

RunInstances/TerminateInstances/CreateSnapshot/CreateFunction: manipulação de recursos.

```text
datasource("xdr") with (log_type="cloudtrail", product_code="scm")
| where eventTime > ago(1d)
| where eventName in ("RunInstances", "TerminateInstances", "CreateFunction", "CreateSnapshot", "ModifySnapshotAttribute")
| take 100
```

