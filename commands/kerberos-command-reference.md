# Kerberos Investigation — PowerShell Command Reference

**Scope:** DC02 / `lab.local` in an isolated, authorized Active Directory lab. These are commands used or reviewed during the Kerberos service-ticket investigation. Screenshots document observed outcomes; not every command's original execution is independently timestamped.

## Account and SPN

```powershell
Get-ADUser svc-kerberos-lab -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes |
  Select-Object Name,Enabled,ServicePrincipalName,msDS-SupportedEncryptionTypes
```

**Purpose:** Inspect the service account and its Kerberos service principal. `HTTP/kerberos-test.lab.local` was the test SPN. The encryption attribute showed **24 decimal**, or `0x18`, indicating AES-128 and AES-256 support. This attribute does not, alone, prove the encryption type actually used in issued tickets.

```powershell
Get-ADUser svc-kerberos-lab -Properties msDS-SupportedEncryptionTypes |
  Select-Object Name,msDS-SupportedEncryptionTypes
```

**Expected observed result:** `svc-kerberos-lab  24`.

## Auditing and Tickets

```powershell
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

**Purpose:** Check and enable domain-controller auditing of service-ticket requests. Use organizational GPO in managed environments rather than relying on local configuration.

```powershell
klist purge
klist get HTTP/kerberos-test.lab.local
klist
```

**Purpose:** Clear cached tickets, request a fresh ticket for the test SPN, and inspect issued tickets. **Observed later:** AES-256 service ticket.

## Event 4769 Hunting

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 10 |
  Format-List TimeCreated,Message
```

`fl` is an alias for `Format-List`, useful when manually typing commands.

**Quick triage only:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 30 |
  Where-Object {$_.Message -match '0x17'} |
  Format-List TimeCreated,Message
```

This matches `0x17` **anywhere** in message text. It is **not** precise enough to serve as a production RC4 detection rule.

**Field-specific validation:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} |
  Where-Object {
    $eventXml = [xml]$_.ToXml()
    @($eventXml.Event.EventData.Data | Where-Object {
      $_.Name -eq 'TicketEncryptionType' -and $_.'#text' -eq '0x17'
    }).Count -gt 0
  } | Select-Object TimeCreated,Id,MachineName
```

This reads the named `TicketEncryptionType` XML field rather than searching the full message. Field availability can vary by Windows version and event schema; inspect a sample XML event before relying on automation.

## Interpreting Results

| Field | Meaning |
|---|---|
| `Event ID 4769` | Kerberos service ticket request |
| `Ticket Encryption Type 0x17` | RC4-HMAC |
| `Ticket Encryption Type 0x12` | AES-256 |
| `Failure Code 0x0` | Successful request |
| `Client Address ::1` | Loopback / locally originated request |
| `msDS-SupportedEncryptionTypes 24` | Decimal `24` = `0x18`, AES-128 + AES-256 support |

**Lab results:** RC4 at **9:20:12 PM** on October 17, 2026; AES-256 at **10:16:40 PM** after the scoped change and fresh ticket request. Both requests succeeded. Neither alone proves Kerberoasting or a compromise.

## Troubleshooting

- `Get-ADUser` **reads** AD objects; `Set-ADUser` **modifies** them.
- `-MaxEvents` must be spelled exactly; `fl` shortens `Format-List`.
- If no 4769 events appear, verify the Security log on the **domain controller**, auditing configuration, event retention, and that a new service ticket was actually requested.
- If the ticket still shows RC4, check account settings, the requesting client, service/SPN mapping, domain policy, and cached tickets; avoid changing domain-wide encryption settings without compatibility testing.
- Windows Server evaluation licensing issues are separate from Kerberos configuration. Use valid licensing or supported evaluation renewal.

## Interview Questions

1. Why is `0x17` a security-hardening lead rather than proof of Kerberoasting?
2. What distinguishes account-supported encryption (`0x18`) from actual ticket encryption (`0x12`)?
3. Why purge the cache before retesting?
4. How would you avoid false positives when detecting RC4 ticket requests?
5. What evidence would you need before claiming a domain-wide RC4 elimination?

**Related:** [Kerberos investigation report](../reports/IR-002-kerberos-rc4-aes256-hardening.md) · [Detection engineering guide](../docs/kerberos-detection-engineering.md)
