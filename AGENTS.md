# Project maintenance instructions

- `docs/HIST_EV_ANALYSIS.md` is the persistent reverse-engineering record for `HIST_EV.CDS` and the shared event interpreter.
- Whenever a HIST_EV condition, body command, part flow, EXE handler, or previously unknown byte sequence is analyzed, update that document in the same change.
- Keep confirmed, partially confirmed, inferred, and unknown findings clearly separated. Do not promote context-based guesses to confirmed behavior without EXE or runtime evidence.
- When parser or UI terminology changes, update the matching encoding table, part notes, remaining-work list, and change log in the analysis document.
- Preserve unresolved bytes verbatim and record the exact raw bytes and part/slot location before changing their parser behavior.
