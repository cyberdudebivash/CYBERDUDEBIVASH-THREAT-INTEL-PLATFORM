# Phase 0 — PDS Mirror Package (Item 0.2)
## Mirroring the PDS to `CYBERDUDEBIVASH-ENTERPRISE-CONFIG`

The canonical cross-repository home for this specification is
`CYBERDUDEBIVASH-ENTERPRISE-CONFIG/docs/ENTERPRISE-OPERATING-SPEC/`
(Vol. 7 §1 repository charters). The copy in the production repo
(`docs/enterprise-storage-os/`) remains for platform-team visibility.

## Why this isn't automated yet

This Claude session is scoped to the production repository only.
Cross-repo automation (the drift-checked mirror) is a Phase 1 deliverable;
for Phase 0 a manual mirror is sufficient and safer.

## Option A — Manual mirror (5 minutes)

```bash
git clone git@github.com:cyberdudebivash/CYBERDUDEBIVASH-ENTERPRISE-CONFIG.git
cd CYBERDUDEBIVASH-ENTERPRISE-CONFIG
mkdir -p docs/ENTERPRISE-OPERATING-SPEC
# from a clone of the production repo:
cp -r ../CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/docs/enterprise-storage-os/* \
      docs/ENTERPRISE-OPERATING-SPEC/
git add docs/ENTERPRISE-OPERATING-SPEC
git commit -m "Mirror Enterprise Storage OS PDS v1.0 from production repo (Phase 0 item 0.2)"
git push origin main
```

Then record the mirror commit SHA in `PHASE-0-EXECUTION-PLAN.md` item 0.2.

## Option B — Have Claude do it

In a Claude Code session, say:
*"add repo cyberdudebivash/CYBERDUDEBIVASH-ENTERPRISE-CONFIG"* — then ask it
to mirror `docs/enterprise-storage-os/` into
`docs/ENTERPRISE-OPERATING-SPEC/` and update the Phase 0 tracker.

## Sync rule until automation exists (Phase 1)

The production-repo copy is the **editing** copy; the ENTERPRISE-CONFIG copy
is the **canonical published** copy. Any PR that changes
`docs/enterprise-storage-os/` must state in its description whether the
mirror was refreshed. Phase 1's drift check makes this mechanical.
