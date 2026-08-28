# Privacy policy

Quimera processes HTTP requests, responses, cookies, authentication material and optional browser
snapshots locally inside Burp Suite. This data is used only to produce the analysis requested by
the user. It is not transmitted to the author or any third party, and there is no telemetry,
analytics, advertising or remote code.

Settings and custom rules are stored through Burp's extension persistence. Findings remain in the
current Burp project/UI according to Burp's own project retention. The optional browser bridge is
disabled by default and listens only on loopback after the user enables it. Its authenticated scope
endpoint can return bounded hostnames observed by Quimera and currently accepted by Burp scope; no
request/response bodies or scope-rule configuration are returned by that endpoint. Users control the
project file, browser data and exports and may remove them using Burp/browser controls.

The current release does not use or declare Burp AI and does not submit prompts or data to an AI
service.
