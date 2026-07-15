"""Prompt construction for the triage reasoner (Build Reference 4.3).

- System prompt: skeptical Tier-3 SOC analyst persona; reason strictly on
  provided data; never invent CVEs/IPs/domains/hashes; state what is
  missing instead.
- Few-shot: contrast a true positive with a complex false positive
  (mimikatz is a TP from a standard user, an FP from an authorized
  scanner's known directory).
- Chain-of-Thought mandatory: benign hypothesis AND malicious hypothesis,
  weigh evidence, then conclude the schema enforces the ordering.
- Candidate injection: the retrieved ATT&CK candidates (with strict
  definitions) are the ONLY techniques the model may return.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from engine.ai.retriever import Candidate

SYSTEM_PROMPT = """\
You are an expert Tier 3 SOC analyst. You analyze correlated clusters of
security alerts, evaluate the provided threat intelligence, and determine
whether the activity is a true positive, a false positive, or needs
escalation.

Rules you must follow without exception:
- Base your reasoning STRICTLY on the provided log data and context.
- Do NOT invent, hallucinate, or recall CVEs, IPs, domains, hashes,
  usernames, or timestamps that are not explicitly present in the input.
- If evidence is missing, state what is missing in missing_context and
  recommend gathering it as a next investigation step.
- MITRE ATT&CK technique IDs may ONLY be chosen from the
  <attack_technique_candidates> list provided with the cluster. If none of
  the candidates fits, return an empty technique list and explain why.
- critical_evidence_fields must be field keys that appear verbatim in the
  provided <alert_cluster> evidence.
- Always form a benign hypothesis AND a malicious hypothesis first, weigh
  the evidence for each, and only then decide the verdict.

Calibration example (contrast):
- A mimikatz style credential dumping detection executed by an ordinary
  user account on a workstation, followed by lateral movement, is a TRUE
  POSITIVE: standard users have no legitimate reason to dump LSASS.
- The same mimikatz style detection originating from an authorized
  vulnerability scanner's service account, running from the scanner's
  known installation directory during a scheduled scan window, is a FALSE
  POSITIVE: the tooling is expected, provided the surrounding evidence
  (source host, account, path, schedule) supports it.
The same indicator can be either the surrounding, provided evidence
decides, not the indicator alone. This tool only recommends; a human acts.
"""


def render_candidates(candidates: list[Candidate]) -> str:
    """The retrieved ATT&CK candidates with strict definitions, as XML."""
    if not candidates:
        return (
            "<attack_technique_candidates>\n"
            "  (no candidates retrieved return an empty technique list)\n"
            "</attack_technique_candidates>"
        )
    lines = ["<attack_technique_candidates>"]
    for candidate in candidates:
        technique = candidate.technique
        description = technique.description.strip().replace("\n", " ")
        if len(description) > 600:
            description = description[:600] + "…"
        lines.append(
            f'  <technique id="{escape(technique.uid)}" '
            f'name="{escape(technique.name)}" '
            f'tactics="{escape(", ".join(technique.tactics))}">'
        )
        lines.append(f"    {escape(description)}")
        lines.append("  </technique>")
    lines.append("</attack_technique_candidates>")
    return "\n".join(lines)


USER_INSTRUCTIONS = """\
Triage the attack chain above.

1. Write the benign hypothesis, then the malicious hypothesis, then weigh
   them step by step in investigation_chain_of_thought.
2. Decide: True Positive, False Positive, or Needs Escalation, with a
   0-100 confidence score.
3. mitre_attack_techniques: only IDs from <attack_technique_candidates>
   whose definition matches the observed behaviour.
4. critical_evidence_fields: only field keys that appear in <alert_cluster>.
5. missing_context: every fact you wanted but was not provided.
6. remediation_recommendations: concrete steps a human analyst should take.
"""


def build_messages(payload_xml: str,
                   candidates: list[Candidate]) -> list[dict[str, str]]:
    """The chat messages for one triage call."""
    user_content = "\n\n".join(
        [payload_xml, render_candidates(candidates), USER_INSTRUCTIONS]
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
