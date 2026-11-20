# External evidence archive: manual release gate

Run this checklist against the release JAR in a real Burp Suite project on Windows, macOS and
Linux before publishing. The automated suite verifies the archive format and failure paths; these
steps verify Montoya's live request/response reconstruction and Burp UI integration.

## Setup

1. Start with a saved project containing no Quimera external-archive configuration.
2. Open **Quimera → Settings** and confirm that **Store full finding evidence in a local external
   archive** is disabled.
3. Generate a finding and confirm Quimera's existing request/response behavior is unchanged.
4. Choose an empty local folder, enable the option and apply settings.

## Capture and reopen

1. Generate a passive finding with a response body and, where available, an active finding with
   probe evidence.
2. Confirm `<chosen folder>/quimera-evidence/<project-id-hash>/objects/` contains compressed
   evidence objects, with no `.tmp` files left behind.
3. Close and reopen the same Burp project.
4. Confirm project opening is immediate while archive evidence warms progressively in the
   background, without blocking the UI or loading an unbounded amount into memory.
5. Select the restored row. It must show the persisted advisory/excerpt, not another row's
   request/response.
6. Confirm its exact request and response load automatically, the expected marker/evidence is
   highlighted, and **Retest** is enabled for an HTTP finding.
7. For a multi-exchange active finding, confirm the probe-evidence selector contains every saved
   exchange after loading.

## Failure and safety paths

1. With Burp closed, rename or disconnect the selected archive folder. Reopen the project and
   select a row with an archived reference.
2. Confirm a clear unavailable message and a **Retry archived evidence load** button are shown;
   the finding, advisory and archived excerpt must remain visible.
3. Restore the folder, click retry and verify the same row loads successfully without recreating
   findings.
4. Make the archive folder read-only (or select a non-writable location), capture a new finding,
   and confirm Quimera logs one concise external-archive error and retains normal project
   evidence rather than silently dropping the result.
5. Corrupt one `.qev.gz` object. Confirm loading rejects it rather than rendering partial data;
   other archive objects must still load.
6. Use Quimera **Clear** and accept its destructive-action confirmation. Confirm project findings
   clear and `<chosen folder>/quimera-evidence/<project-id-hash>/` is removed. Confirm the chosen
   folder, its `quimera-evidence` parent and another project's archive (if present) are untouched.

## Performance and unload

1. Capture several large finding-bearing responses while ordinary browsing continues. Confirm no
   visible HTTP-handler or Swing freeze and no repeating archive-error log flood.
2. Disable the archive and confirm subsequent findings use the normal bounded project evidence
   behavior.
3. Reload and unload Quimera. Confirm Burp reports no uncaught exceptions and no archive-related
   threads or file handles remain.
