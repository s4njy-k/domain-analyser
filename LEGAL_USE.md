# Legal Use Guidance

This repository produces investigative intelligence outputs and evidentiary artefacts for analyst review. It does not issue legal conclusions automatically.

## Chain of custody

1. Preserve the original input list used for the batch.
2. Retain the generated HTML report, JSON data file, evidence ZIP, and GitHub Actions run URL together as the evidence package.
3. Record SHA-256 hashes from the evidence manifest before transferring or sharing any file.
4. If evidence is exported outside GitHub, store it in a controlled evidence register and note the analyst, date/time, and purpose of access.

## Review requirement

The AI legal analysis is an analytical aid only. A designated legal officer must validate the cited provisions, offence descriptions, and blocking recommendations before the material is used in official notices, blocking requests, FIR drafting, or court-facing documentation.

## Operational handling

- Use `unlisted` visibility for URLScan submissions to reduce discoverability.
- Do not submit internal or classified URLs to third-party services.
- Treat screenshots and page text as potentially harmful content and review in a controlled environment.
