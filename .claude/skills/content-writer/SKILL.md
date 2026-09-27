---
name: content-writer
description: |
  Researches and writes threat hunting and detection engineering content for Chris Scott,
  producing a long-form blog post (for carrietheroberts.com / Medium) and a companion
  LinkedIn short post in a single run. Always searches the web for recent, relevant
  material before writing, produces a research summary first, then generates both
  outputs. Use this skill whenever Chris asks to write a blog post, article, LinkedIn
  post, or any content on threat hunting, detection engineering, or related
  cybersecurity topics. Also trigger when Chris says "write something about X",
  "draft a post on X", "create content about X", or "I want to publish something
  on X" - even if he doesn't explicitly say blog or LinkedIn. Finishes by committing
  the blog post to the SentinelHunt repo on a new branch and opening a pull request
  against main for Chris to review.
---

# content-writer

Produces research-backed blog and LinkedIn content for Chris Scott on threat hunting
and detection engineering topics. Accessible but authoritative tone - written for a
mixed audience of practitioners and security leadership.

## Workflow

Work through these five phases in order. Do not skip the research summary - it is a
checkpoint before any writing begins.

---

### Phase 1 - Clarify (only if topic is missing)

If Chris has supplied a topic or angle in his prompt, skip this phase entirely and
proceed to Phase 2.

If no topic has been provided, ask one question only:

> "What topic or angle do you want to cover?"

Wait for the answer before continuing.

---

### Phase 2 - Research

Search the web for recent, relevant material on the topic. Aim for a minimum of
**five distinct sources**. Prioritise:

- Threat intelligence reports and vendor research (last 12 months preferred)
- ATT&CK technique pages or MITRE updates where relevant
- Detection engineering practitioner blogs (e.g. Sigma, Elastic, Microsoft Sentinel
  community posts)
- News coverage of recent incidents that relate to the topic
- Academic or conference papers (SANS, Black Hat, BSides) where applicable

**Search strategy:** run multiple queries with different angles. Example queries for
a topic like "LSASS credential dumping detection":

- `LSASS credential dumping detection 2025`
- `LSASS memory access threat hunting KQL Sentinel`
- `credential dumping ATT&CK T1003 recent incidents`
- `LSASS bypass detection evasion 2025`

Write results to a scratch list internally - do not dump raw search output into the
conversation.

---

### Phase 3 - Research Summary

Before writing any content, present Chris with a structured research summary.
This is a hard checkpoint - wait for his go-ahead before proceeding to Phase 4.

Format the summary as follows:

```
## Research Summary: [Topic]

### Key Findings
- [3–5 bullet points covering the most relevant, recent, and interesting findings]

### Interesting Angles
- [2–3 potential content angles or hooks worth building the post around]

### Sources
| # | Title | Source | Date |
|---|-------|--------|------|
| 1 | ...   | ...    | ...  |
...

Ready to write - which angle would you like to lead with, or should I pick the
strongest one?
```

If Chris approves without specifying an angle, select the most compelling one and
proceed.

If the run is unattended (a scheduled task, or nobody is there to reply), do not stop
at this checkpoint. Pick the strongest angle, carry the research summary and the
chosen angle into the pull request description in Phase 5, and keep going. The pull
request review becomes the checkpoint instead.

---

### Phase 4 - Write Both Outputs

Produce the blog post and LinkedIn post sequentially in the same response.

Before writing, load and apply the `chris-voice` skill (invoke it with the Skill tool).

This skill governs tone, language, and structure for both outputs. Its voice reference,
`references/voice-reference.md` inside the chris-voice skill's base directory, must
also be read - do not rely on memory. Key principles that apply to the blog post as well as the
LinkedIn post: direct and conversational, no AI-sounding phrases, UK English, technical
specifics retained, no corporate-speak, opens with a personal observation not a
headline claim.

---

#### Blog Post (carrietheroberts.com / Medium)

**Author:** Chris Scott  
**Audience:** Mixed - practitioners and security leadership  
**Tone:** Accessible but authoritative. No unnecessary jargon without explanation.
Not dry or academic. Reads like it was written by a practitioner who also knows
how to communicate upwards.

**Structure:**

```
# [Title]

*[Strapline - one sentence that captures the hook]*

## Introduction
[2–3 paragraphs. Open with a real-world hook - an incident, a trend, a question
practitioners are asking. Establish why this matters now.]

## [Section 1 - Context / the problem]
[What is happening in the threat landscape that makes this topic relevant?
Ground this in the research findings.]

## [Section 2 - The detection or hunting angle]
[The practical meat. What should defenders be doing? Include specifics -
data sources, query logic concepts, ATT&CK references, tooling - but explain
them accessibly. This is where Chris's practitioner voice comes through.]

## [Section 3 - Considerations / caveats / maturity]
[What are the limits of this approach? What does a team need to have in place
to do this well? What are the common failure modes?]

## Closing Thoughts
[1–2 paragraphs. Forward-looking. What should the reader do next or think about?
Avoid generic calls to action.]

---

## References
[Numbered list matching the research summary sources, with full URLs]
```

**Length:** 800–1,200 words for the body. References sit outside that count.  
**Do not:** use bullet-heavy formatting in the main body. Write in prose. Lists are
acceptable in Section 2 for query components or step-by-step logic, but should not
dominate.

---

#### LinkedIn Short Post

Produce this using the `chris-voice` skill in full - follow its output format,
structure, tone checklist, and post-output editorial note exactly.

The LinkedIn post must not mirror the blog post opening. It should feel like Chris
sharing a reaction or a key takeaway, not a summary of the article. Pick the single
most shareable insight from the blog and build the post around that.

---

### Phase 5 - Publish via Pull Request

Commit the blog post to the SentinelHunt repository (`rustedroberts/sentinelhunt`)
and open a pull request against `main` for Chris to review. Never push to `main` and
never merge the pull request yourself: merging deploys the site to GitHub Pages and
publishes the post, so that call is Chris's.

**1. Branch.** Run `git fetch origin main`. If the environment assigns you a working
branch (as Claude Code on the web does), use that. Otherwise create
`content/<slug>` from `origin/main`. One post per branch and per pull request.

**2. Blog file.** Save the post to `content/blog/<slug>.md`. The slug is the title in
lowercase kebab-case, trimmed to roughly eight words. Convert the Phase 4 draft into
the site's format:

```
---
title: "<title>"
date: <today, YYYY-MM-DD>
author: Chris Scott
summary: <the strapline, or one or two sentences on the hook>
tags:
  - <3-6 lowercase kebab-case tags; reuse tags already used in content/blog where they fit>
published: true
---

<introduction paragraphs, with no heading>

## <Section 1>
...

## Closing Thoughts
...

## References

1. [<Title> - <Source>](<url>)
```

- Drop the `# Title` heading and the italic strapline, because the site renders the
  title and summary from the frontmatter.
- Drop the `## Introduction` heading and the `---` rule before References.
- Write references as numbered markdown links.
- Do not commit the LinkedIn post or the research summary. They go in the pull
  request description.

**3. Validate.** Check that the file has no em dashes (`grep -n $'\xe2\x80\x94' <file>`
returns nothing). Run `npm ci && npm run build`, because the build parses every post's
frontmatter and fails on a malformed one. If the build can't run in the environment,
say so in the pull request description.

**4. Commit and push.** Stage only `content/blog/<slug>.md`, commit with the message
`blog: <title>`, then run `git push -u origin <branch>`.

**5. Open the pull request** against `main`, ready for review (not a draft). Use the
GitHub MCP tools if they're available, otherwise `gh`. Title: `Blog: <title>`. Body:

```
## Summary
New blog post: **<title>** (`content/blog/<slug>.md`), about <n> words.
Angle: <one line>. <If unattended: "Angle picked automatically on an unattended
run - redirect in review if needed.">
Merging to `main` publishes the post via the GitHub Pages deploy.

## Research summary
<Phase 3 key findings and sources table>

## Review checklist
- [ ] Claims match the cited sources
- [ ] KQL snippets run in your environment
- [ ] Voice and tone
- [ ] Title, summary and tags

## LinkedIn post (not committed)
<the LinkedIn post, followed by its editorial note>
```

If an open pull request already exists for the same slug, push to its branch rather
than opening a second one. If the run is unattended, include the pull request URL in
the notification.

---

## Output Format

Present the output in this order:

1. A single line confirming the chosen angle
2. `---`
3. The full blog post (including References)
4. `---`
5. `### LinkedIn Post`
6. The LinkedIn post
7. `---`
8. The pull request URL

---

## Notes

- Never use em dashes (-) anywhere in any output. Use hyphens (-) instead. This overrides any other instruction, including chris-voice.
- UK English throughout (colour, defence, authorise, etc.)
- ATT&CK technique IDs should be referenced in full on first use:
  e.g. `Credential Dumping (T1003)`
- Do not fabricate statistics or incidents. If a claim needs a source and one
  wasn't found in research, flag it rather than invent it.
- KQL or query snippets in the blog post should be in fenced code blocks with
  the language tag: ` ```kql `
- Do not include a generic author bio at the end - Chris will add this manually.
