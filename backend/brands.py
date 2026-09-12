"""Brand + lexicon reference data used by the typosquatting and impersonation checks.

Kept deliberately small and offline: a hackathon demo should never block a page
render on a network lookup. `BRANDS` maps a brand token to the registrable
domains that legitimately own it.
"""

from __future__ import annotations

BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google": {"google.com", "google.co.uk", "googlemail.com", "youtube.com", "goo.gl"},
    "gmail": {"google.com", "googlemail.com", "gmail.com"},
    "youtube": {"youtube.com", "youtu.be", "google.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "msn.com", "azure.com"},
    "office365": {"microsoft.com", "office.com", "microsoftonline.com"},
    "outlook": {"microsoft.com", "live.com", "outlook.com", "hotmail.com"},
    "onedrive": {"microsoft.com", "live.com", "onedrive.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "icloud": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com", "amazonaws.com"},
    "netflix": {"netflix.com", "nflxext.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com", "messenger.com"},
    "instagram": {"instagram.com", "facebook.com", "meta.com"},
    "whatsapp": {"whatsapp.com", "facebook.com", "meta.com"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "github": {"github.com", "githubusercontent.com", "github.io"},
    "gitlab": {"gitlab.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"},
    "adobe": {"adobe.com", "adobelogin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "steam": {"steampowered.com", "steamcommunity.com", "valvesoftware.com"},
    "discord": {"discord.com", "discordapp.com", "discord.gg"},
    "spotify": {"spotify.com", "scdn.co"},
    "slack": {"slack.com", "slack-edge.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebayimg.com"},
    "shopify": {"shopify.com", "myshopify.com"},
    "stripe": {"stripe.com", "stripe.network"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com", "binance.us"},
    "metamask": {"metamask.io", "consensys.net"},
    "kraken": {"kraken.com"},
    "blockchain": {"blockchain.com", "blockchain.info"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citi.com", "citibank.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "santander": {"santander.co.uk", "santander.com"},
    "lloyds": {"lloydsbank.com", "lloydsbank.co.uk"},
    "natwest": {"natwest.com"},
    "revolut": {"revolut.com"},
    "wise": {"wise.com", "transferwise.com"},
    "venmo": {"venmo.com", "paypal.com"},
    "cashapp": {"cash.app", "squareup.com", "block.xyz"},
    "zelle": {"zellepay.com"},
    "usps": {"usps.com", "usps.gov"},
    "ups": {"ups.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "royalmail": {"royalmail.com"},
    "irs": {"irs.gov"},
    "hmrc": {"hmrc.gov.uk", "gov.uk"},
    "dvla": {"dvla.gov.uk", "gov.uk"},
    "nhs": {"nhs.uk", "nhs.net"},
    "walmart": {"walmart.com"},
    "target": {"target.com"},
    "costco": {"costco.com"},
    "att": {"att.com"},
    "verizon": {"verizon.com"},
    "tmobile": {"t-mobile.com", "tmobile.com"},
    "vodafone": {"vodafone.com", "vodafone.co.uk"},
    "roblox": {"roblox.com"},
    "epicgames": {"epicgames.com", "unrealengine.com"},
    "battlenet": {"battle.net", "blizzard.com"},
    "twitch": {"twitch.tv", "twitchcdn.net"},
    "telegram": {"telegram.org", "t.me"},
    "signal": {"signal.org"},
    "booking": {"booking.com"},
    "airbnb": {"airbnb.com"},
    "uber": {"uber.com"},
    "doordash": {"doordash.com"},
    "aliexpress": {"aliexpress.com", "alibaba.com"},
    "wechat": {"wechat.com", "qq.com", "tencent.com"},
    "alipay": {"alipay.com", "antgroup.com"},
}

# Registrable domains we treat as trusted infrastructure (never typosquat-flagged
# against themselves, and legitimate hosts for brand content).
KNOWN_GOOD_DOMAINS: set[str] = {d for owned in BRANDS.values() for d in owned} | {
    "wikipedia.org",
    "mozilla.org",
    "cloudflare.com",
    "python.org",
    "fastapi.tiangolo.com",
    "stackoverflow.com",
    "reddit.com",
    "bbc.co.uk",
    "nytimes.com",
    "duckduckgo.com",
    "bing.com",
    "yahoo.com",
    "npmjs.com",
    "pypi.org",
    "developer.mozilla.org",
}

# Words that show up in credential-harvesting hostnames far more than in real ones.
CREDENTIAL_KEYWORDS: set[str] = {
    "login", "signin", "logon", "log-in", "sign-in", "auth", "authenticate",
    "verify", "verification", "verified", "validate", "confirm", "confirmation",
    "secure", "security", "safety", "protect", "account", "accounts", "myaccount",
    "update", "updating", "renew", "recovery", "recover", "reset", "unlock",
    "billing", "invoice", "payment", "payments", "pay", "refund", "credit",
    "banking", "bank", "wallet", "seed", "mnemonic", "restore", "keystore",
    "support", "helpdesk", "service", "customer", "alert", "notice", "suspend",
    "suspended", "limited", "locked", "expire", "expired", "webmail", "portal",
    "sso", "mfa", "otp", "2fa", "token", "id", "identity", "kyc", "claim",
    "giveaway", "bonus", "prize", "winner", "reward", "airdrop", "gift",
}

# TLDs with historically high abuse ratios / free registration.
HIGH_RISK_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "click", "link", "work",
    "loan", "zip", "mov", "review", "country", "kim", "cricket", "science",
    "party", "gdn", "stream", "download", "racing", "win", "bid", "date",
    "faith", "rest", "quest", "cyou", "sbs", "icu", "monster", "wang", "cam",
    "surf", "casa", "beauty", "makeup", "hair", "skin", "autos", "boats",
    "duckdns.org", "ngrok.io", "trycloudflare.com", "serveo.net", "loca.lt",
    "repl.co", "glitch.me", "vercel.app", "netlify.app", "pages.dev", "web.app",
    "firebaseapp.com", "r2.dev", "workers.dev", "onrender.com", "github.io",
    "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com",
}

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
    "s.id", "gg.gg", "shorte.st", "adf.ly", "t.ly", "lnkd.in", "trib.al",
}

# Visual/keyboard confusables used to normalise a hostname before distance scoring.
HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
    "8": "b", "9": "g", "$": "s", "@": "a", "!": "i", "|": "l", "£": "e",
    "à": "a", "á": "a", "â": "a", "ä": "a", "å": "a", "ã": "a", "ā": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e", "ē": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i", "ı": "i", "ī": "i",
    "ò": "o", "ó": "o", "ô": "o", "ö": "o", "õ": "o", "ø": "o", "ō": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u", "ū": "u",
    "ç": "c", "ć": "c", "ñ": "n", "ń": "n", "ş": "s", "ś": "s", "š": "s",
    "ý": "y", "ÿ": "y", "ž": "z", "ź": "z", "ł": "l", "đ": "d", "ţ": "t",
    "ρ": "p", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "μ": "m",
    "ν": "v", "τ": "t", "υ": "u", "χ": "x", "һ": "h", "ѕ": "s", "і": "i",
    "ј": "j", "ԁ": "d", "ɑ": "a", "ｇ": "g", "ⅼ": "l", "ѵ": "v", "ԛ": "q",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ь": "b", "т": "t", "к": "k", "м": "m", "н": "h",
}

# Multi-character confusables applied before single-char mapping.
DIGRAPH_HOMOGLYPHS: list[tuple[str, str]] = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"), ("ii", "u"),
]

# Input field name/id fragments that indicate high-value data capture.
SENSITIVE_FIELD_HINTS: dict[str, str] = {
    "password": "password",
    "passwd": "password",
    "pwd": "password",
    "pass": "password",
    "passcode": "passcode",
    "pin": "PIN",
    "otp": "one-time code",
    "mfa": "MFA code",
    "2fa": "2FA code",
    "totp": "authenticator code",
    "seedphrase": "wallet seed phrase",
    "seed_phrase": "wallet seed phrase",
    "mnemonic": "wallet seed phrase",
    "privatekey": "private key",
    "private_key": "private key",
    "keystore": "wallet keystore",
    "cardnumber": "card number",
    "card_number": "card number",
    "cardno": "card number",
    "ccnum": "card number",
    "creditcard": "card number",
    "cvv": "card CVV",
    "cvc": "card CVC",
    "securitycode": "card security code",
    "expiry": "card expiry",
    "exp_date": "card expiry",
    "ssn": "social security number",
    "socialsecurity": "social security number",
    "sortcode": "bank sort code",
    "accountnumber": "bank account number",
    "routingnumber": "bank routing number",
    "iban": "IBAN",
    "dateofbirth": "date of birth",
    "dob": "date of birth",
    "mothersmaiden": "security answer",
    "securityanswer": "security answer",
    "nationalinsurance": "national insurance number",
}

# Urgency/scare copy typical of harvesting pages.
URGENCY_PHRASES: list[str] = [
    "your account has been suspended", "account has been limited",
    "unusual sign-in activity", "unusual signin activity",
    "verify your identity", "verify your account", "confirm your identity",
    "your account will be closed", "will be permanently deleted",
    "immediate action required", "action required", "final warning",
    "within 24 hours", "within 48 hours", "failure to verify",
    "we detected unusual", "suspicious activity detected",
    "re-enter your password", "reconfirm your password",
    "update your billing", "payment could not be processed",
    "your session has expired", "you have won", "claim your reward",
    "connect your wallet", "validate your wallet", "sync your wallet",
    "import seed phrase", "recovery phrase",
]


# Correct display casing for brand names. `str.title()` mangles most of these
# ("Paypal", "Github", "Hsbc"), and the brand name is the most prominent string
# in the blocking overlay, so it needs to look right.
BRAND_DISPLAY: dict[str, str] = {
    "paypal": "PayPal", "google": "Google", "gmail": "Gmail", "youtube": "YouTube",
    "microsoft": "Microsoft", "office365": "Office 365", "outlook": "Outlook",
    "onedrive": "OneDrive", "apple": "Apple", "icloud": "iCloud", "amazon": "Amazon",
    "netflix": "Netflix", "facebook": "Facebook", "instagram": "Instagram",
    "whatsapp": "WhatsApp", "linkedin": "LinkedIn", "twitter": "Twitter/X",
    "github": "GitHub", "gitlab": "GitLab", "dropbox": "Dropbox", "adobe": "Adobe",
    "docusign": "DocuSign", "steam": "Steam", "discord": "Discord",
    "spotify": "Spotify", "slack": "Slack", "zoom": "Zoom", "ebay": "eBay",
    "shopify": "Shopify", "stripe": "Stripe", "coinbase": "Coinbase",
    "binance": "Binance", "metamask": "MetaMask", "kraken": "Kraken",
    "blockchain": "Blockchain.com", "chase": "Chase", "wellsfargo": "Wells Fargo",
    "bankofamerica": "Bank of America", "citibank": "Citibank", "hsbc": "HSBC",
    "barclays": "Barclays", "santander": "Santander", "lloyds": "Lloyds Bank",
    "natwest": "NatWest", "revolut": "Revolut", "wise": "Wise", "venmo": "Venmo",
    "cashapp": "Cash App", "zelle": "Zelle", "usps": "USPS", "ups": "UPS",
    "fedex": "FedEx", "dhl": "DHL", "royalmail": "Royal Mail", "irs": "IRS",
    "hmrc": "HMRC", "dvla": "DVLA", "nhs": "NHS", "walmart": "Walmart",
    "target": "Target", "costco": "Costco", "att": "AT&T", "verizon": "Verizon",
    "tmobile": "T-Mobile", "vodafone": "Vodafone", "roblox": "Roblox",
    "epicgames": "Epic Games", "battlenet": "Battle.net", "twitch": "Twitch",
    "telegram": "Telegram", "signal": "Signal", "booking": "Booking.com",
    "airbnb": "Airbnb", "uber": "Uber", "doordash": "DoorDash",
    "aliexpress": "AliExpress", "wechat": "WeChat", "alipay": "Alipay",
}


def brand_label(key: str | None) -> str:
    """Human-facing brand name for `key`, falling back to title case."""
    if not key:
        return ""
    return BRAND_DISPLAY.get(key.lower(), key.replace("-", " ").title())
