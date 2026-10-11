"""Editable task starters, separate from persistent workspace instructions.

Builtin text is copied into settings, never dynamically overlaid on authored
content. Upgrades append only new IDs once; deleted templates stay deleted.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

CATEGORIES = (
    'Project work', 'Software development', 'Engineering & systems',
    'Research & analysis', 'Writing & communication', 'Planning & decisions',
    'Learning', 'Summarising & organising', 'Creative work',
)
LEGACY_TEMPLATE_IDS = frozenset({'continue', 'review', 'debug', 'handover'})


def _template(key: str, name: str, category: str, description: str, text: str) -> dict[str, str]:
    return dict(id=key, name=name, category=category, description=description, text=text.strip())


DEFAULT_CHAT_TEMPLATES = [
    # Keep the original four IDs, names and prompts for upgrade compatibility.
    _template('continue', 'Continue work', 'Project work', 'Resume from the actual current state.',
              'Continue from where we left off. Inspect the current project state first, then proceed with the next pending work.'),
    _template('review', 'Review project', 'Project work', 'Read-only project review and next steps.',
              'Review the current project and tell me what you find, including important issues, regressions, and recommended next steps. Do not modify anything yet.'),
    _template('debug', 'Debug issue', 'Software development', 'Investigate first and propose a fix without applying it.',
              'Investigate this issue carefully. Reproduce or trace it where possible, identify the root cause, then propose the smallest safe fix before changing behavior.'),
    _template('handover', 'Create handover', 'Project work', 'Capture the baseline, decisions and remaining work.',
              'Create a concise handover of the current project state: completed work, decisions, current baseline, known issues, pending work, and what should happen next.'),
    _template('implement-feature', 'Implement a feature', 'Software development', 'Turn a requirement into a tested, focused change.', '''Implement the following feature.
Feature and expected behaviour: [describe]
Constraints and acceptance criteria: [add details]

Inspect the relevant implementation and project conventions first. Identify affected interfaces and data compatibility. Implement a focused change, add appropriate tests, and verify the acceptance criteria. Avoid unrelated refactoring. Report changes, actual test results and remaining limits.'''),
    _template('fix-bug', 'Investigate and fix a bug', 'Software development', 'Find the cause, fix it and add regression coverage.', '''Investigate and fix the following bug.
Observed behaviour: [describe]
Expected behaviour: [describe]
Reproduction steps, files or logs: [provide]

Inspect the relevant code and reproduce or trace the failure where practical. Establish the root cause before making a focused fix. Add regression coverage and run relevant checks, followed by broader tests where practical. Preserve unrelated behaviour. Report what changed, what was actually tested and any remaining uncertainty.'''),
    _template('code-review', 'Review code', 'Software development', 'Prioritised, evidence-based review without edits.', '''Review this code without modifying it.
Code or change to review: [provide files or scope]
Concerns and expected behaviour: [describe]

Trace relevant callers, state transitions and failure paths. Prioritise correctness, regressions, resource handling and maintainability over cosmetic preferences. For each finding, give the location, triggering conditions, impact and a concrete remedy. Separate confirmed defects from hypotheses; state coverage limits and useful tests.'''),
    _template('refactor-safely', 'Refactor without changing behaviour', 'Software development', 'Improve structure while preserving observable behaviour.', '''Refactor the following area.
Scope and desired improvement: [describe]
Behaviour and interfaces that must stay unchanged: [list]

Establish the existing behaviour and tests first. Make small, coherent structural changes without adding features or changing saved formats. Add characterisation tests where needed and compare behaviour before and after. Report the changes, verification and any compatibility risks.'''),
    _template('build-failure', 'Diagnose a build failure', 'Software development', 'Trace the first meaningful error before changing dependencies.', '''Diagnose and resolve this build failure.
Build command and environment: [provide]
Error output and relevant files: [provide]

Identify the first meaningful failure rather than downstream noise. Check toolchain versions, configuration, paths and dependencies against project requirements. Apply the smallest relevant correction; do not perform blanket upgrades. Rerun the failing command and report the result, or the exact remaining blocker.'''),
    _template('test-coverage', 'Add tests and regression coverage', 'Software development', 'Cover real behaviour, boundaries and failure paths.', '''Add useful tests for this area.
Files or behaviour: [specify]
Known bugs or critical cases: [provide]

Inspect existing test conventions. Identify gaps in normal behaviour, boundaries, errors and lifecycle/concurrency where relevant. Prefer tests that exercise production code and would fail for the defect they target. Keep test data isolated. Run the tests and report coverage achieved, limitations and any failures without weakening assertions to hide defects.'''),
    _template('circuit-review', 'Review a circuit or schematic', 'Engineering & systems', 'Check supplies, interfaces, components and bring-up risks.', '''Review this circuit or schematic without changing it.
Schematic and exact component/panel references: [provide]
Supply ranges, loads and operating conditions: [provide]

Trace power, grounds, interfaces and startup/reset behaviour. Check ratings, pin mapping, decoupling and signal levels against the supplied datasheets, or identified manufacturer sources when accessible. Do not assume an unspecified supply or module pinout. Separate confirmed issues from missing information and give prioritised corrections and a practical bring-up checklist.'''),
    _template('firmware-review', 'Review embedded firmware', 'Engineering & systems', 'Inspect lifecycles, resource budgets and hardware interactions.', '''Review the embedded firmware in this scope without editing it.
Target hardware, toolchain and relevant code: [provide]
Main concerns: [describe]

Trace initialisation, task/interrupt interactions, allocation ownership, failure cleanup and shutdown. Check timing assumptions, shared resources, persistent data and hardware interfaces. Ground findings in call paths and platform requirements. Distinguish host-test evidence from target-build and hardware validation; recommend focused fixes and regression tests.'''),
    _template('reverse-engineer', 'Analyse a binary or firmware image', 'Engineering & systems', 'Evidence-led analysis while preserving the original.', '''Analyse the following binary or firmware image within the established project scope.
Input files and target architecture/device, if known: [provide]
Question to answer: [describe]

Preserve the original and work on copies. Start with file format, hashes, sections, strings and likely architecture, then follow evidence into disassembly or controlled execution where appropriate. Record offsets, addresses, commands and supporting observations. Distinguish demonstrated behaviour from hypotheses. Do not patch or flash hardware unless separately requested.'''),
    _template('network-diagnosis', 'Diagnose a network or service problem', 'Engineering & systems', 'Trace the failure by layer using bounded checks.', '''Diagnose this network or service problem.
Topology, endpoints and permitted scope: [provide]
Symptoms, expected behaviour and logs: [provide]

Work through the relevant layers: link, addressing/routing, name resolution, transport and application. Use bounded, targeted checks and correlate timestamps. Identify evidence for each hypothesis. Start read-only; propose disruptive changes with their impact and rollback rather than applying them without approval. Report the likely cause and what would confirm it.'''),
    _template('performance-analysis', 'Investigate performance', 'Engineering & systems', 'Measure bottlenecks before optimising.', '''Investigate this performance problem.
Workload, environment and expected performance: [provide]
Observed timings, resource use or traces: [provide]

Establish a repeatable baseline. Separate startup, input processing, execution and I/O where relevant. Profile or instrument the likely bottleneck with bounded overhead. Change one relevant factor at a time and compare using the same workload. Report measurements, trade-offs and uncertainty; do not claim an improvement without a comparable result.'''),
    _template('configuration-rollout', 'Plan a configuration change and rollback', 'Engineering & systems', 'Prepare a staged change without executing it.', '''Plan this configuration or deployment change; do not execute it yet.
Current state and proposed change: [provide]
Availability, compatibility and access constraints: [provide]

Identify prerequisites, affected services and data. Give ordered steps, pre-change checks, a backup/recovery approach, validation criteria and clear rollback triggers. Distinguish reversible operations from irreversible ones. Keep secrets out of the plan and identify any unknowns that block safe execution.'''),
    _template('research-topic', 'Research a topic', 'Research & analysis', 'Answer a focused question with attributable evidence.', '''Research the following question.
Question and scope: [provide]
Required depth, timeframe and source constraints: [provide]

Prioritise relevant primary or authoritative sources when accessible. Compare evidence, explain disagreements and distinguish facts from inference. Cite the sources actually consulted and their dates where relevant. Do not invent browsing or citations; identify unavailable evidence and limits. End with the main conclusions and open questions.'''),
    _template('compare-options', 'Compare options', 'Research & analysis', 'Compare like-for-like against explicit criteria.', '''Compare the following options.
Options: [list]
Use case, constraints and decision criteria: [provide]

Use comparable assumptions and units. Separate verified attributes, estimates and missing information. Explain the trade-offs that matter for this use case, not just feature counts. Identify what would change the recommendation and give a reasoned choice or shortlist. Use current sources for changing facts when available.'''),
    _template('evaluate-claim', 'Evaluate a claim', 'Research & analysis', 'Check what evidence supports, contradicts or leaves unresolved.', '''Evaluate this claim.
Claim and source/context: [provide]

State precisely what would need to be true. Examine the supporting evidence, counterevidence, assumptions and alternative explanations. Distinguish correlation from causation where relevant. Use the supplied material as the starting point and identify any outside sources separately. Conclude with a calibrated assessment, not a forced yes/no when evidence is insufficient.'''),
    _template('analyse-data', 'Analyse supplied data', 'Research & analysis', 'Validate data and explain reproducible findings.', '''Analyse the supplied dataset.
Data and question to answer: [provide]
Units, definitions and constraints: [provide]

Inspect schema, missing values, duplicates and obvious quality issues before calculating. State cleaning choices and keep original data intact. Use appropriate summaries and comparisons; distinguish observed patterns from causal claims. Provide reproducible steps, results with units, caveats and useful next checks. Do not fill gaps with invented values.'''),
    _template('draft-email', 'Draft an email or message', 'Writing & communication', 'Communicate an outcome in the right tone.', '''Draft a message using the following details.
Recipient and desired outcome: [provide]
Key facts and requested action: [provide]
Tone and length: [provide]

Make the purpose clear early, include only supported facts, and end with a specific next step where appropriate. Do not invent promises, deadlines or commitments. Provide a ready-to-edit draft and an appropriate subject line if this is an email.'''),
    _template('rewrite-clarity', 'Rewrite for clarity', 'Writing & communication', 'Improve readability while preserving meaning.', '''Rewrite the following text for clarity.
Text: [paste]
Audience, tone and length constraints: [provide]

Preserve the meaning, important qualifications and factual claims. Remove repetition and organise the argument logically. Do not silently add facts or strengthen uncertain claims. Return the revised text; flag only ambiguities that materially affect the meaning.'''),
    _template('adapt-audience', 'Explain to a specific audience', 'Writing & communication', 'Translate complexity without losing important caveats.', '''Explain the following material to this audience.
Material or topic: [provide]
Audience and what they need to understand or do: [provide]
Format and length: [provide]

Use appropriate vocabulary and concrete examples. Define necessary terms and preserve important limitations. Distinguish supplied facts from illustrative examples. Avoid condescension, unsupported simplifications and unnecessary detail.'''),
    _template('document-review', 'Review a document', 'Writing & communication', 'Check structure, consistency and evidential gaps.', '''Review this document without rewriting it yet.
Document and intended purpose: [provide]
Audience and review priorities: [provide]

Assess structure, clarity, internal consistency, missing context and whether conclusions follow from the evidence. Point to specific sections and prioritise actionable changes. Separate editorial suggestions from factual questions requiring verification. Preserve the author's intended meaning and terminology.'''),
    _template('project-plan', 'Build a project plan', 'Planning & decisions', 'Turn a goal into milestones with acceptance criteria.', '''Build a practical plan for this project.
Goal and deliverables: [provide]
Resources, constraints and target dates: [provide]

Break work into milestones with dependencies and clear completion criteria. Identify the critical uncertainties, risks and early validation steps. Use explicit assumptions for estimates; do not invent available people or resources. Include a sensible first step and checkpoints for revising the plan.'''),
    _template('task-breakdown', 'Break down a complex task', 'Planning & decisions', 'Find the smallest useful sequence of work.', '''Break this task into manageable steps.
Task and desired result: [provide]
Constraints and current progress: [provide]

Identify prerequisites, dependencies and unknowns. Separate discovery from implementation and verification. Make each step concrete, with an observable output. Avoid unnecessary process and suggest the smallest useful next action without beginning execution.'''),
    _template('risk-assessment', 'Assess risks and trade-offs', 'Planning & decisions', 'Identify credible failure modes and mitigations.', '''Assess the risks of this proposal.
Proposal and operating context: [provide]
Priorities and unacceptable outcomes: [provide]

Identify credible failure modes, their causes and consequences. Distinguish evidence-based assessments from rough estimates; do not invent probabilities. Suggest proportionate prevention, detection and recovery measures, residual risks and decisions needing human approval.'''),
    _template('decision-note', 'Write a decision note', 'Planning & decisions', 'Record why a choice fits the available evidence.', '''Prepare a decision note.
Decision to make and options: [provide]
Evidence, constraints and priorities: [provide]

Summarise the context, criteria, viable alternatives and trade-offs. Recommend a choice with explicit assumptions, uncertainties and consequences. State what new evidence would justify revisiting it. Keep the distinction between proposed and already-approved decisions clear.'''),
    _template('practical-checklist', 'Create a practical checklist', 'Planning & decisions', 'Make repeatable checks and failure actions explicit.', '''Create a checklist for this activity.
Activity and intended user: [provide]
Inputs, constraints and completion standard: [provide]

Organise checks in execution order. Make each item observable and unambiguous, with expected results and stop/escalation conditions where needed. Distinguish mandatory checks from optional improvements. Keep the checklist usable during the actual task rather than turning it into a long essay.'''),
    _template('explain-concept', 'Explain a concept', 'Learning', 'Build understanding with examples and limits.', '''Explain this concept.
Concept and my current understanding: [provide]
What I need to use it for: [provide]

Start with the central idea, then build the mechanism step by step. Use a concrete example and explain where analogies stop being accurate. Address common misconceptions and connect the explanation to my goal. Finish with a small check of understanding.'''),
    _template('guided-learning', 'Teach me step by step', 'Learning', 'Interactive instruction rather than a full answer dump.', '''Teach me this topic step by step.
Topic, current level and goal: [provide]

Start with a short roadmap and the first essential idea. Give one manageable explanation or exercise at a time, then wait for my response before advancing. Adapt to my answers, explain mistakes constructively and keep examples relevant to the goal.'''),
    _template('study-plan', 'Create a study plan', 'Learning', 'Schedule practice and checks against a learning goal.', '''Create a study plan.
Topic and target capability: [provide]
Starting knowledge, available time and deadline: [provide]

Identify prerequisites and sequence the key ideas. Balance explanation, practice and spaced review. Define achievable checkpoints and a way to measure understanding. Do not assume access to paid resources; distinguish known resources from suggestions that still need checking.'''),
    _template('quiz-material', 'Quiz me on supplied material', 'Learning', 'Source-grounded questions with feedback.', '''Quiz me using only the supplied material.
Material: [provide]
Difficulty and question style: [provide]

Ask one question at a time and wait for my answer. Check it against the material, explain corrections with a section reference where possible, and adapt the next question. Do not add outside facts as though they appeared in the source. Track areas that need review.'''),
    _template('summarise-document', 'Summarise a document', 'Summarising & organising', 'Preserve source claims, framing and qualifications.', '''Summarise the supplied document.
Document and desired length/detail: [provide]

Preserve its terminology, organisation, central claims and important qualifications. Distinguish the author's findings from proposals or speculation. Do not silently correct or supplement it with outside knowledge. Note missing or unclear passages and give section/page references when available.'''),
    _template('extract-actions', 'Extract decisions and action items', 'Summarising & organising', 'Turn notes into attributable follow-up work.', '''Extract decisions and action items from these notes or this transcript.
Material: [provide]

Separate confirmed decisions, proposed ideas, action items and unresolved questions. Preserve named owners and deadlines exactly when stated; otherwise mark them unspecified. Link each important item to its supporting passage where practical. Do not turn suggestions into commitments.'''),
    _template('notes-to-docs', 'Turn notes into documentation', 'Summarising & organising', 'Organise rough material without inventing missing steps.', '''Turn these notes into usable documentation.
Notes and intended audience: [provide]
Desired document type: [guide, reference, runbook or other]

Organise the supplied information around the reader's needs. Preserve commands, names and constraints. Distinguish verified procedures from draft ideas; mark missing prerequisites or steps rather than inventing them. Include a short overview and clear headings, with examples only when supported or explicitly labelled illustrative.'''),
    _template('brainstorm', 'Brainstorm ideas', 'Creative work', 'Explore distinct directions against real constraints.', '''Brainstorm ideas for the following goal.
Goal, audience and constraints: [provide]

Offer a varied set of genuinely different approaches rather than minor variations. Explain the appeal and main trade-off of each. Separate imaginative possibilities from feasibility claims. Select a few promising directions and describe a low-cost way to explore each without executing anything yet.'''),
    _template('develop-concept', 'Develop a concept', 'Creative work', 'Turn an early idea into a coherent proposal.', '''Develop this concept.
Initial idea, audience and purpose: [provide]
Constraints and desired format: [provide]

Clarify the central proposition and build out the experience, structure or story around it. Keep the parts consistent and explain the important choices. Identify weak assumptions and unanswered questions. Provide a concrete example or outline and a practical next experiment.'''),
    _template('critique-idea', 'Critique and improve an idea', 'Creative work', 'Useful criticism without losing the original goal.', '''Critique and improve this idea.
Idea, intended goal and audience: [provide]
Non-negotiable constraints: [provide]

Identify what works, what is unclear and what is likely to fail, with reasons. Do not mistake personal taste for fact. Suggest specific improvements that preserve the goal, then show a revised version and explain the most consequential changes.'''),
    _template('alternative-approaches', 'Explore alternative approaches', 'Creative work', 'Challenge the assumed solution while preserving the goal.', '''Explore alternatives to this approach.
Goal and current approach: [provide]
Constraints and concerns: [provide]

Identify the assumptions built into the current solution. Propose meaningfully different approaches, including a simpler option where plausible. Compare benefits, costs and limitations without pretending unknowns are settled. Recommend what to test before choosing.'''),
]

_BY_ID = {row['id']: row for row in DEFAULT_CHAT_TEMPLATES}


def template_category(template: dict[str, Any]) -> str:
    explicit = str(template.get('category') or '').strip()
    if explicit:
        return explicit
    builtin = _BY_ID.get(str(template.get('id') or ''))
    return builtin['category'] if builtin else 'Custom'


def template_categories(templates: list[dict[str, Any]]) -> list[str]:
    present = {template_category(row) for row in templates}
    return [name for name in CATEGORIES if name in present] + sorted(present - set(CATEGORIES), key=str.casefold)


def filter_templates(templates: list[dict[str, Any]], query: str = '', category: str = '') -> list[dict[str, Any]]:
    words = str(query or '').casefold().split()
    return [row for row in templates if (not category or template_category(row) == category) and all(
        word in ' '.join(str(row.get(k) or '') for k in ('name', 'description', 'text')).casefold() + ' ' + template_category(row).casefold()
        for word in words)]


def append_new_templates(existing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One-time v9 migration; don't replace edits, reorder originals or restore old deletions."""
    result = deepcopy(existing)
    ids = {str(row.get('id') or '') for row in result if isinstance(row, dict)}
    names = {str(row.get('name') or '').strip().casefold() for row in result if isinstance(row, dict)}
    for template in DEFAULT_CHAT_TEMPLATES:
        if template['id'] in LEGACY_TEMPLATE_IDS or template['id'] in ids or template['name'].casefold() in names:
            continue
        result.append(deepcopy(template))
    return result
