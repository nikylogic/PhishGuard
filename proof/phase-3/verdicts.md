# Verdict matrix: every fake attack page through the real sandbox

| Fake page | Phishing | Malware | Tracking | Tricks | Stamp | Main reasons |
|---|---:|---:|---:|---:|---|---|
| Normal page | 0 | 0 | 0 | 0 | **CLEAR** | - |
| Fake bank login | 65 | 0 | 0 | 0 | **DANGER** | This page asks for a password on an unencrypted (http) connection.<br>This page asks for your password but sends it to another website (collect.test). |
| invoice.pdf.exe download | 10 | 100 | 0 | 0 | **DANGER** | The page tried to download a program or script (invoice.pdf.exe).<br>The download is disguised: 'invoice.pdf.exe' is really a windows program.<br>The page started a download by itself, without any click. |
| Fingerprinting page | 0 | 0 | 40 | 0 | **CLEAR** | The page fingerprints your device (audio, canvas, fonts, hardware, webgl).<br>The page opened a WebRTC connection, which can reveal your local IP address. |
| IP-logger link | 10 | 0 | 60 | 0 | **DANGER** | This is an IP-logger link: opening it records your IP address and device.<br>The link bounced through 1 hop(s) and ended on a different website (grabify.link). |
| ClickFix fake CAPTCHA | 0 | 0 | 0 | 70 | **DANGER** | The page secretly copied a command to your clipboard and wants you to run it. |
| ms-msdt launcher | 0 | 0 | 0 | 60 | **DANGER** | The page tried to launch a Windows app through a 'ms-msdt:' link. |
| Fake virus alert | 0 | 0 | 0 | 55 | **DANGER** | The page shows a fake security alert and tries to trap you on it.<br>The page immediately asks for permission to use notifications. |
| Crypto-miner | 0 | 0 | 0 | 65 | **DANGER** | The page runs a crypto-miner that would use your computer's power.<br>The page hides what its code does (heavy obfuscation). |
| Open redirect from a trusted site | 10 | 0 | 0 | 35 | **CAUTION** | A trusted website (trusted.test) was used to bounce you to evil.test.<br>The link carries another website's address inside it (evil.test).<br>The link bounced through 1 hop(s) and ended on a different website (evil.test). |
