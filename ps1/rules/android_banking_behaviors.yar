// CyberShield PS1 — behavioral triage rules for Android banking trojans.
//
// Scope: BEHAVIORAL rules only (permission/API combinations documented across
// Indian banking-trojan campaigns). Family rules (SpyNote/SpyMax, Drinik,
// SOVA, Axbanker) are deliberately deferred until real MalwareBazaar samples
// are in hand — single-sample (or zero-sample) family rules are brittle.
//
// Operational note: these rules scan DEX bytecode. The triage pipeline
// unzips the APK and scans every classes*.dex member (multi-dex apps split
// code across several DEX files).
//
// FP design: each rule requires a COMBINATION of behaviors, never a single
// permission/API — legitimate banking apps legitimately request SMS and
// overlay capabilities (ARCHITECTURE.md §3.2). Validate against the benign
// corpus (BOI Mobile, YONO, iMobile, BHIM) before deployment.

import "dex"

rule MAL_Android_OverlaySmsCombo_Jun26 {
  meta:
    description = "Detects the overlay + SMS-interception combination characteristic of Indian banking trojans: an AccessibilityService implementation or overlay windows, together with SMS capture and a network exfiltration channel"
    author      = "CyberShield team (BOI Hackathon)"
    reference   = "https://attack.mitre.org/techniques/T1417/002/ (Input Capture: GUI Input Capture), T1582 (SMS Control)"
    date        = "2026-06-10"
    score       = 80

  condition:
    dex.is_dex and

    // SMS capture: broadcast registration or PDU parsing
    (
      dex.contains_string("android.provider.Telephony.SMS_RECEIVED") or
      dex.contains_method("createFromPdu") or
      dex.contains_method("getMessageBody")
    ) and

    // Screen takeover: accessibility-service subclass or overlay window type
    (
      for any c in dex.class_defs: (
        c.superclass contains "AccessibilityService"
      ) or
      dex.contains_string("TYPE_APPLICATION_OVERLAY") or
      dex.contains_string("SYSTEM_ALERT_WINDOW")
    ) and

    // Exfiltration channel
    (
      dex.contains_class("Ljava/net/HttpURLConnection;") or
      dex.contains_class("Lokhttp3/OkHttpClient;") or
      dex.contains_class("Ljava/net/Socket;")
    )
}

rule SUSP_Android_TelegramBotExfil_Jun26 {
  meta:
    description = "Detects Telegram-bot exfiltration plumbing (api.telegram.org bot endpoints plus send methods) combined with access to sensitive data sources - the dominant exfil channel in Indian banking-trojan smishing campaigns"
    author      = "CyberShield team (BOI Hackathon)"
    reference   = "https://attack.mitre.org/techniques/T1639/ (Exfiltration Over Alternative Protocol)"
    date        = "2026-06-10"
    score       = 75

  strings:
    $tg_api     = "api.telegram.org" ascii
    $tg_send1   = "/sendMessage" ascii
    $tg_send2   = "/sendDocument" ascii
    // bot<digits>:<35-char token> embedded in URLs
    $tg_bot_url = /bot[0-9]{8,10}:[A-Za-z0-9_\-]{35}/

  condition:
    dex.is_dex and
    ($tg_api or $tg_bot_url) and
    ($tg_bot_url or any of ($tg_send*)) and

    // must also touch a sensitive source: SMS, contacts, or telephony ids
    (
      dex.contains_string("content://sms") or
      dex.contains_string("android.provider.Telephony.SMS_RECEIVED") or
      dex.contains_string("content://com.android.contacts") or
      dex.contains_method("getDeviceId") or
      dex.contains_method("getSubscriberId")
    )
}

rule SUSP_Android_DropperPattern_Jun26 {
  meta:
    description = "Detects the dropper pattern: runtime package-install capability (REQUEST_INSTALL_PACKAGES / package-archive intents) combined with payload download or dynamic code loading - tiny installer fetches the real banking trojan post-install"
    author      = "CyberShield team (BOI Hackathon)"
    reference   = "https://attack.mitre.org/techniques/T1407/ (Download New Code at Runtime)"
    date        = "2026-06-10"
    score       = 70

  strings:
    $install1 = "android.permission.REQUEST_INSTALL_PACKAGES" ascii
    $install2 = "application/vnd.android.package-archive" ascii
    $install3 = "android.content.pm.action.SESSION_DETAILS" ascii

  condition:
    dex.is_dex and
    any of ($install*) and

    // payload acquisition: network download or dynamic dex loading
    (
      dex.contains_class("Ldalvik/system/DexClassLoader;") or
      dex.contains_class("Ldalvik/system/InMemoryDexClassLoader;") or
      (
        dex.contains_class("Ljava/net/HttpURLConnection;") and
        dex.contains_method("openConnection")
      )
    )
}

rule SUSP_Android_HardcodedUpiBeneficiary_Jun26 {
  meta:
    description = "Detects hardcoded UPI beneficiary handles inside DEX code combined with SMS interception - trojans that route stolen funds to fixed mule accounts; extracted handles feed the PS2 mule-account watchlist"
    author      = "CyberShield team (BOI Hackathon)"
    reference   = "CyberShield ARCHITECTURE.md fusion layer; https://attack.mitre.org/techniques/T1582/"
    date        = "2026-06-10"
    score       = 75

  strings:
    // handle@psp for the common Indian PSP suffixes; bounded, anchored by '@'
    $upi = /[a-z0-9._\-]{3,40}@(ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|apl|ibl|axl|jio|barodampay|boi|upi)/

  condition:
    dex.is_dex and
    $upi and
    (
      dex.contains_string("android.provider.Telephony.SMS_RECEIVED") or
      dex.contains_method("createFromPdu") or
      dex.contains_string("content://sms")
    )
}
