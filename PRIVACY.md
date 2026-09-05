# Privacy policy

Quimera processes HTTP requests, responses, cookies, authentication material and optional browser
snapshots locally inside Burp Suite. This data is used only to produce the analysis requested by
the user. It is not transmitted to the author or any third party, and there is no telemetry,
analytics, advertising or remote code.

Settings, custom rules, and findings (with the specific request/response that produced each one,
capped per host and finding type to avoid unbounded project growth) are stored through Burp's own
extension persistence, so they are available again after reopening the same project. This data
lives inside the Burp project file like everything else Burp itself stores, is never sent
anywhere, and is removed by clearing the Logger or by Burp's own project file controls.

The optional browser bridge is disabled by default and listens only on loopback after the user enables it. Its authenticated scope
endpoint can return bounded hostnames observed by Quimera and currently accepted by Burp scope; no
request/response bodies or scope-rule configuration are returned by that endpoint. Users control the
project file, browser data and exports and may remove them using Burp/browser controls.

Quimera declares Burp's `AI_FEATURES` capability, so Burp shows its own consent prompt the first
time the extension loads, before anything AI-related can run. The Advisory panel has an opt-in
"AI Analysis" button that uses Burp's own AI API (`api.ai()`) to explain a finding or summarize a
URL's findings. It only runs when the user clicks it, is disabled with a message if Burp AI is
not enabled in Burp Suite, and sends the
URL, the relevant finding(s) (header name/value, severity, evidence, description) and the
detected technology fingerprint as the prompt. That data goes through Burp's own AI feature,
governed by Burp's own AI settings and data-handling terms, not a separate third-party service
Quimera talks to directly. No other part of Quimera uses AI, and nothing is sent to any AI
service unless the user explicitly clicks that button.
