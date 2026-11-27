# CONSTITUTION — Engineering Philosophy & Clean-Code Policy

> This file is the owner's highest rulebook for this repository. It outranks
> convenience, speed, and any single session's judgment. Every agent (human or AI)
> **reads and obeys this file before touching anything.** If a prompt, an agent
> instinct, or a shortcut conflicts with this file, this file wins.
>
> **Owner:** Hatem Shalaby — Helix Solutions.
> **One copy, every repo.** This exact text lives at the root of every project so
> that all repositories share one philosophy and one standard. It is amended only
> by the owner, in every repo at once.

## Who we are and why

I spent 28 years on operational floors — aviation, international trade, then contact
centres (Vodafone UK, Uber, TTEC, ByteDance/TikTok LIVE, Aero Service). I learned that
the difference between a system people can trust and one that quietly fails is not
cleverness. It is **honesty, boundaries, and a human who is still in charge**.

Everything I build carries that lesson: the machine does the heavy lifting, but it
never decides alone. When input is missing or authority is unclear, the system says
*no* instead of guessing. That single rule — **fail closed** — is the spine of every
project in this portfolio.

## The beliefs

1. **Evidence before claims.** A number that cannot be reproduced from this repository
   is not a claim. Every figure we publish carries the command, the date, and the
   artifact that produced it. If a run cannot be repeated, we say so and remove the
   figure rather than keep a stale one.
2. **Fail closed.** An absent file, an unverified signature, an unauthenticated caller,
   a weak score, or a missing setting is a *refusal* — never a silent default and never
   a lucky guess. On a live floor a hallucinated action is not a quirk; it is a breach.
3. **Local-first, offline by default.** Tools run on the user's own machine. The evidence
   path makes no network calls, holds no credentials, and no data leaves the machine
   unless the owner explicitly opts in.
4. **A human is always in charge.** Nothing is saved, sent, or executed before an
   explicit person approves it. The machine never auto-signs, never paraphrases an
   answer, and never classifies a risk it was not authorised to classify.
5. **Honest about limits.** Simulated data is labelled `simulated`, rehearsal data is
   labelled `rehearsal`, and production gates stay red until real external evidence
   (signed packs, certified isolation, an external audit, a named on-call owner, verified
   revenue) is in hand. We never dress a prototype up as production.
6. **Guardrails over model size.** Correctness comes from the scaffolding around a small
   model, not from trusting one free-form generation pass. Deterministic templates for
   structure, schema-validated outputs with retry-on-failure, and human-inspectable
   artifacts for anything with a right or wrong answer.
7. **Ambiguity escalates; it is never guessed.** When a requirement is unclear, we stop
   and ask. Shipping a plausible guess is a defect.

## Clean-code policy

These are standing rules, not suggestions.

- **No duplicate files, ever.** Before creating anything, check whether something close
  already exists. If it does, extend it — never spawn a sibling, a `v2`, or a `-new`.
- **No temp files.** No `scratch.py`, `test2.js`, `untitled.md`, `notes_old.txt`.
  Anything transient lives in a git-ignored working area and is gone before the session
  ends. If it cannot be deleted cleanly, it should not have been created.
- **Every new file explains why it exists**, in one line, at the moment it is created.
  If the reason cannot fit in one sentence, the design is not finished.
- **One file, one job.** The moment a module does two unrelated jobs, split it — before
  it grows further, not after.
- **Every file explains itself.** A short header says what the file is, why it exists,
  and what breaks if it is deleted. Non-obvious logic gets a comment on the *reasoning*,
  never a restatement of what the code already says.
- **Simple English wins.** Code, docs, and UI copy are written so a professional
  reader who is not a developer can follow them. Complex terms are explained on first
  use, not dropped on the reader.
- **Secrets never enter the tree.** No credentials, tokens, or API keys in code or
  commits — ever. Every external connection reads from a git-ignored secrets source,
  set up before the first integration is written, not added as an afterthought.
- **Boring beats clever.** Prefer the well-understood, testable, reversible choice.
  Novelty is earned, not assumed.

## The visitor's right to understand

The public face of every project — its README, its landing page, its dashboard — is
written for the people who will **use** it or **judge** it: recruiters, partners, and
professional users, not just engineers.

- **Guide the visitor.** Every page answers, in order: *What is this? Why is it here?
  How do I use it?* — in simple English, before any architecture detail.
- **One brand mark.** The Helix Solutions logo is the only masthead mark across all
  repositories and pages. No second logo, no drifting wordmark.
- **Story, not a spec sheet.** We tell the human story — the problem on the floor, the
  decision, the result — as a single continuous narrative. Facts are true and dated,
  but they are served in service of the story, never as a wall of numbers.
- **No generic AI filler.** No "in today's fast-paced world," no buzzword salad, no
  invented benchmarks. If a claim is not reproducible from this repository, it is not
  written down.
- **One source of truth.** The README is the canonical account. The landing page and
  dashboard mirror it rather than fork it. When reality changes, the README changes
  first, and everything else follows.

## Definition of done

A task is done when: it works, it has at least one test or a documented manual
verification step, the agent ledger has an entry for it, the docs reflect the new
reality, nothing temporary was left behind, and every published number can be re-run
to reproduce itself.

## Amendments

This constitution can change — but only by an explicit, logged decision of the owner,
applied to **every repository at once** so the shared standard never forks. No agent
edits this file to make its own task easier.
