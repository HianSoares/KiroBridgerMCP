"""Reviewable closing reason and note proposals. No offense mutation is exposed.

Each closing reason of the live QRadar catalog maps to the requirements it needs. A reason
is recommended only when every one of its requirements is met; requirements the bridge
cannot observe (authorization, CRE tuning, remediation, policy) can be met only by a cited
analyst-supplied record, which the report labels as such. A gap blocks only the reasons
that need it. The bridge never closes, assigns or annotates the offense.
"""
from __future__ import annotations

from .ariel_collection import BudgetExhausted
from .decision import STATUSES, evaluate, requirement

# Requirements per standard reason text (normalized). Custom reasons are never auto-eligible.
REASON_REQUIREMENTS = {
    "non-issue": ["authorization", "relevant_collection_complete"],
    "not an issue": ["authorization", "relevant_collection_complete"],
    "false-positive, tuned": ["detection_error", "active_cre_reviewed", "tuning_applied", "relevant_collection_complete"],
    "policy violation": ["policy_confirmed", "relevant_collection_complete"],
    "duplicate": ["primary_offense"],
    "misconfiguration": ["misconfiguration_confirmed"],
    "resolved": ["remediation_verified"],
    "unresolved": ["administrative_decision"],
}
ANALYST_REQUIREMENTS = {
    "authorization": "owner/change/inventory record showing the activity was authorized and expected",
    "active_cre_reviewed": "active CRE tests and responses reviewed against the trigger",
    "detection_error": "positive evidence that the rule matched something that is not the described behavior",
    "tuning_applied": "corrective tuning applied and verified",
    "policy_confirmed": "applicable policy and the violation confirmed by the response workflow",
    "misconfiguration_confirmed": "misconfiguration demonstrated by configuration evidence and agreed with the owner",
    "remediation_verified": "remediation and post-remediation verification evidenced",
    "primary_offense": "same incident established with a referenced primary offense",
    "administrative_decision": "explicit analyst decision to close administratively with remaining risk recorded",
}


def validate_confirmations(confirmations: list | None, offense_id: int | None = None) -> list[dict]:
    """Analyst-supplied records: requirement id, source and reference are mandatory and kept verbatim."""
    out = []
    for item in confirmations or []:
        if not isinstance(item, dict):
            raise ValueError("each confirmation must be an object")
        rid = item.get("requirement")
        if rid not in ANALYST_REQUIREMENTS:
            raise ValueError(f"requirement must be one of {sorted(ANALYST_REQUIREMENTS)}; collection coverage "
                             "is measured by the bridge and cannot be confirmed manually")
        fields = {}
        for key in ("source", "reference", "summary"):
            value = item.get(key, "")
            if not isinstance(value, str) or len(value) > 300 or (key != "summary" and not value.strip()):
                raise ValueError(f"confirmation {key} must be a non-empty string up to 300 characters")
            fields[key] = value.strip()
        if rid == "primary_offense":
            if not fields["reference"].isdigit() or int(fields["reference"]) == offense_id:
                raise ValueError("primary_offense reference must be another offense ID")
        out.append({"requirement": rid, **fields})
    return out

CONDITIONS = {
    "non-issue": "Authorization and expected behavior confirmed, relevant collection complete, no unresolved contradictory evidence",
    "not an issue": "Local definition confirmed by analyst; authorized expected behavior evidenced",
    "false-positive, tuned": "Detection error confirmed against active CRE tests; corrective tuning already applied and verified",
    "policy violation": "Applicable policy and the observed violation confirmed; closure approved by the response workflow",
    "duplicate": "Same incident established with a referenced primary offense; ownership and evidence transferred",
    "misconfiguration": "Misconfiguration demonstrated by configuration evidence; disposition agreed with the owner",
    "resolved": "Remediation and relevant post-remediation verification evidenced",
    "unresolved": "Explicit analyst decision to close administratively with limitations and remaining risk recorded",
}


async def closing_catalog(qradar, budget) -> dict:
    """Optional read; unknown/deleted/reserved reasons are never suggested as valid IDs."""
    try:
        data = await budget.run(lambda: qradar.call("list_offense_closing_reasons", {
            "include_deleted": False, "include_reserved": False, "limit": 100}), "closing reason catalog")
        if not isinstance(data, list):
            return {"state": "unparsed", "reasons": []}
        valid = [dict(id=r["id"], text=r["text"]) for r in data if isinstance(r, dict)
                 and isinstance(r.get("id"), int) and not isinstance(r["id"], bool) and r["id"] >= 0
                 and isinstance(r.get("text"), str) and 0 < len(r["text"]) <= 200
                 and r.get("is_deleted") is False and r.get("is_reserved") is False]
        return {"state": "collected" if len(data) < 100 else "limited", "reasons": valid[:100],
                "source": "QRadar list_offense_closing_reasons (read only)",
                "note": "Live names/IDs; local workflow definitions still require analyst validation"}
    except BudgetExhausted:
        return {"state": "not_read_time_budget", "reasons": []}
    except Exception:
        return {"state": "unavailable", "reasons": [],
                "note": "Optional catalog unavailable; no closing reason ID invented"}


def propose(result: dict, confirmations: list | None = None) -> dict:
    """Collection-only decision: cite facts, scope and why closure is still unsupported.

    Kiro may revise the proposal with cited analyst/owner evidence following the
    steering; it must not turn the collection-only flag true without that review.
    """
    assessment = result["assessment"]
    queries = result["queries"]
    evidence = [{"query": name, "search_id": q.get("search_id"), "outcome": q.get("outcome"),
                 "rows": q.get("returned_rows"), "scope": q.get("scope")}
                for name, q in queries.items()]
    linux = result.get("linux", {})
    linked = linux.get("offense", {})
    ssh = linux.get("ssh_window", {})
    sudo = linked.get("kind_counts", {}).get("sudo_command_record", 0)
    root = ssh.get("accepted_root_ssh_count", 0)
    findings = []
    if sudo:
        findings.append(f"{sudo} sudo command records parsed over the collected offense rows; "
                        "authorization and command outcome not established")
    if ssh:
        if root:
            findings.append(f"{root} accepted root SSH messages observed in the strict query window; authorization unverified")
        elif ssh.get("recognized_message_census_complete"):
            findings.append("No accepted root SSH message parsed in the strict sources/filters/window; this is not proof of complete logging")
        else:
            findings.append("SSH coverage or parsing incomplete; no negative SSH conclusion supported")
    incomplete = [name for name, q in queries.items() if not q.get("result_set_complete")]
    # Do not let an irrelevant flow census prevent reporting Linux authentication facts.
    relevant_names = {"events", "linux_ssh_window", "linux_identity_window"} if linux.get("detected") else {"events", "flows"}
    relevant = [n for n in incomplete if n in relevant_names]
    confirmed = validate_confirmations(confirmations, result.get("offense_id"))
    blockers = [{"id": f"coverage:{n}", "summary": f"Relevant collection incomplete: {n}"} for n in relevant]
    if result.get("count_comparison", {}).get("events", {}).get("status") == "unresolved":
        blockers.append({"id": "event_snapshot", "summary": "Event count/window/snapshot difference not reconciled"})
    if linked.get("unparsed_daemon_rows") or linked.get("truncated_payload_rows"):
        blockers.append({"id": "linux_content", "summary": "Some Linux daemon records were unparsed or cut"})
    # Carry conclusion-specific gaps into the decision; a draft must not hide
    # DHCP attribution, a rejected SELECT, or missing record content.
    known = {b["id"] for b in blockers}
    secondary_linux = {"count:flows", "query:flows", "truncation:flows"}
    for item in result.get("gap_details", []):
        if ("benign_verdict" in item.get("relevance", {}).get("blocks", []) and item["id"] not in known
                and not (linux.get("detected") and item["id"] in secondary_linux)):
            blockers.append({"id": item["id"], "summary": item["summary"],
                             "next_action": item.get("next_action"), "source": item.get("evidence")})
            known.add(item["id"])
    outside_ids = {g["id"] for g in result.get("gap_details", []) if g.get("state") == "outside_bridge"}
    # Bridge-measured gaps; outside_bridge gaps are what the authorization record must address.
    technical = [b for b in blockers if b["id"] not in outside_ids]
    req = {}
    outside = [g["id"] for g in result.get("gap_details", []) if g.get("state") == "outside_bridge"]
    for rid, text in ANALYST_REQUIREMENTS.items():
        cited = [c for c in confirmed if c["requirement"] == rid]
        req[rid] = (requirement(rid, text, "confirmed", cited, source="analyst-supplied record (not verified by the bridge)")
                    if cited else requirement(rid, text, "unverified",
                                              {"bridge_gaps_it_must_address": outside} if rid == "authorization" else None,
                                              "Cite the record with qradar_assess_closure (requirement, source, reference)"))
    req["relevant_collection_complete"] = requirement(
        "relevant_collection_complete", "collection relevant to a benign closure complete, reconciled and parsed",
        "confirmed" if not technical else "unverified", [b["id"] for b in technical] or None,
        "Resume the listed searches/pages or resolve the listed gaps")
    available = result.get("closing_reasons", {}).get("reasons", [])
    metadata = result.get("metadata", {})
    existing_id = metadata.get("closing_reason_id")
    existing = {"status": metadata.get("status"), "reason_id": existing_id,
                "reason_text": next((r["text"] for r in available if r["id"] == existing_id), None),
                "close_time": metadata.get("close_time"),
                "meaning": "Observed metadata, not evidence that the original closure was justified"}
    conclusions = [{"id": r["id"], "label": r["text"], "requires": REASON_REQUIREMENTS[r["text"].strip().lower()]}
                   for r in available if r["text"].strip().lower() in REASON_REQUIREMENTS]
    matrix = evaluate(conclusions, req)
    by_id = {m["id"]: m for m in matrix}
    options = [{**r, "condition": CONDITIONS.get(r["text"].strip().lower(),
                "Custom reason: obtain its local definition and supporting evidence before selecting it"),
                "eligible_now": by_id.get(r["id"], {}).get("sufficiency") == "sustained",
                "unmet": [b["id"] for b in by_id.get(r["id"], {}).get("blocking", [])] if r["id"] in by_id else ["custom_reason_definition"]}
               for r in available]
    sustained = [o for o in options if o["eligible_now"]]
    already_closed = metadata.get("status") == "CLOSED"
    recommended = sustained[0] if len(sustained) == 1 else None
    if recommended and not already_closed:
        primary = f"Fechar com o motivo '{recommended['text']}' (ID {recommended['id']}) após revisão humana"
        confidence = "Sustentada: todos os requisitos do motivo atendidos (ver matriz e fontes citadas)"
    elif already_closed:
        primary = "Revisar justificativa do fechamento já registrado"
        confidence = "Insuficiente para uma classificação final" if not sustained else "Requisitos do motivo atendidos"
    else:
        primary = "Manter aberta / pendente de validação do analista"
        confidence = "Insuficiente para uma classificação final"
        if len(sustained) > 1:
            confidence = "Mais de um motivo atende aos requisitos; escolha do analista necessária"
    # Blocking list for the reason closest to being met (benign closure by default).
    target = (by_id.get(recommended["id"]) if recommended else
              min((m for m in matrix if m["sufficiency"] != "contradicted"),
                  key=lambda m: (len(m["blocking"]), "authorization" not in REASON_REQUIREMENTS[m["label"].strip().lower()]),
                  default=None))
    for item in (target or {}).get("blocking", []):
        if item["id"] != "relevant_collection_complete" and item["id"] not in {b["id"] for b in blockers}:
            blockers.insert(0, {"id": item["id"], "summary": item["requirement"], "next_action": item["next_check"]})
    if not matrix:
        blockers.insert(0, {"id": "authorization", "summary": ANALYST_REQUIREMENTS["authorization"],
                            "next_action": "Closing-reason catalog unavailable or custom-only; no reason can be evaluated"})
    interval = result.get("metadata_interval", {})
    note_facts = []
    if sudo:
        note_facts.append(f"{sudo} registros de invocação sudo identificados nas linhas coletadas da offense; "
                          "autorização e resultado dos comandos não comprovados")
    if ssh:
        if root:
            note_facts.append(f"{root} registros Accepted de autenticação SSH como root na busca restrita; autorização não verificada")
        elif ssh.get("recognized_message_census_complete"):
            note_facts.append("não foram identificadas mensagens Accepted de SSH como root nas fontes, filtros e janela restrita consultados; "
                              "isso não comprova completude do logging")
        else:
            note_facts.append("cobertura ou interpretação SSH incompleta; não é possível excluir autenticação root")
    lockout = result.get("lockout", {})
    if lockout.get("detected"):
        note_facts.append(f"{lockout['event_id_counts'].get(4740, 0)} registros 4740 de bloqueio nas linhas coletadas; "
                          "o DC registrador não é automaticamente a origem; causa e remediação não comprovadas")
        for group in lockout.get("groups", [])[:5]:
            note_facts.append(f"conta-alvo={group.get('target_domain') or 'domínio não observado'}\\"
                              f"{group.get('target_user') or 'não observada'}, "
                              f"caller informado={group.get('caller_computer') or 'não observado'}, "
                              f"fonte registradora={group.get('log_source') or 'não observada'}, "
                              f"linhas 4740={group.get('rows')}; identidade/origem do processo não confirmadas")
        if len(lockout.get("groups", [])) > 5 or lockout.get("groups_omitted"):
            note_facts.append("outros grupos de conta/caller estão detalhados ou limitados no relatório")
        note_facts.append(f"{len(lockout.get('authentication_candidates', []))} relações candidatas com falhas "
                          "4625/4771/4776 por conta e horário de recepção; vínculo causal não comprovado")
    if linux.get("strict_window"):
        win = linux["strict_window"]
        note_facts.append(f"janela SSH/su sem margem: {win.get('start_utc')} até {win.get('end_utc')}, relógio starttime")
    processes = result.get("processes", {})
    if processes.get("process_creations"):
        note_facts.append(f"{len(processes['process_creations'])} criações de processo no resumo coletado e "
                          f"{len(processes.get('links', []))} vínculos pai/filho por GUID e host; propósito não comprovado")
    if processes.get("script_blocks"):
        note_facts.append(f"{len(processes['script_blocks'])} registros PowerShell de conteúdo de sessão identificados")
    if result.get("integrity", {}).get("integrity_events"):
        note_facts.append(f"{len(result['integrity']['integrity_events'])} registros de integridade de arquivo "
                          "identificados; vínculo com a cadeia e causa exigem avaliação separada")
    pt = {"authorization": "autorização da atividade pelo responsável não apresentada",
          "active_cre_reviewed": "testes ativos da CRE e vínculo com o gatilho não verificados",
          "detection_error": "erro de detecção não demonstrado", "tuning_applied": "tuning não aplicado/verificado",
          "policy_confirmed": "política e violação não confirmadas", "primary_offense": "offense primária não referenciada",
          "misconfiguration_confirmed": "configuração incorreta não demonstrada",
          "remediation_verified": "remediação não verificada", "administrative_decision": "decisão administrativa não registrada"}
    blockers_pt = [pt[b["id"]] for b in blockers if b["id"] in pt]
    blockers_pt += [f"coleta relevante incompleta: {n}" for n in relevant]
    if any(b["id"] == "event_snapshot" for b in blockers):
        comparison = result["count_comparison"]["events"]
        blockers_pt.append(f"contagens de eventos não reconciliadas: metadados={comparison.get('metadata_count')}, "
                           f"linhas Ariel={comparison.get('collected_ariel_rows')}; unidade/janela/snapshot sem causa atribuída")
    if any(b["id"] == "linux_content" for b in blockers):
        blockers_pt.append("há registros Linux não interpretados ou payloads cortados")
    carried = [b["id"] for b in blockers if b["id"] in {g["id"] for g in result.get("gap_details", [])}]
    if carried:
        blockers_pt.append("pendências técnicas relevantes detalhadas no relatório: " + ", ".join(carried))
    note = [f"Offense {result['offense_id']} — investigação preliminar.",
            f"Intervalo dos metadados (UTC, sem margem): {interval.get('start')} até {interval.get('end')}.",
            "Evidências: " + ("; ".join(note_facts) if note_facts else
                              "registros coletados; classificação final não estabelecida") + ".",
            "Consultas: " + "; ".join(f"{e['query']} [{e['search_id'] or 'não iniciada'}]: {e['outcome']}, "
                                     f"{e['rows']} linhas, escopo={e['scope']}" for e in evidence) + ".",
            ("Fechamento já registrado nos metadados; a justificativa ainda requer validação. " if already_closed else
             (f"Decisão sugerida: fechar com o motivo '{recommended['text']}' (ID {recommended['id']}), sujeita a revisão humana. "
              if recommended else "Decisão sugerida: manter pendente. ")) + "; ".join(blockers_pt) + ".",
            *([f"Registros citados pelo analista (não verificados pela ponte): " +
               "; ".join(f"{c['requirement']} — {c['source']} [{c['reference']}]" for c in confirmed) + "."] if confirmed else []),
            ("Motivo de fechamento selecionado a partir do catálogo real do QRadar." if recommended else
             "Motivo de fechamento ainda não selecionado.") + " Nenhum fechamento, tuning ou contenção executado."]
    return {"decision": "review_existing_closure" if already_closed else "recommend_closure" if recommended else "keep_open",
            "recommendation": primary, "ready_to_close": bool(recommended) and not already_closed,
            "existing_closure": existing,
            "recommended_reason": {"id": recommended["id"], "text": recommended["text"]} if recommended else None,
            "reason_catalog_state": result.get("closing_reasons", {}).get("state"),
            "decision_matrix": matrix, "requirements": req, "analyst_confirmations": confirmed,
            "evidence_status_vocabulary": STATUSES,
            "conditional_reason_options": options, "justification": findings,
            "confidence": confidence,
            "confidence_explanation": ("Sem pontuação numérica: um motivo é recomendado somente quando todos os seus requisitos "
                                       "estão atendidos; lacunas irrelevantes para o motivo não o bloqueiam."),
            "blocking_requirements": blockers, "secondary_collection_pending": [n for n in incomplete if n not in relevant],
            "evidence": evidence, "suggested_note": "\n".join(note),
            "observed_facts": assessment.get("confirmed_facts", []),
            "note_status": "draft_for_analyst_review", "human_review_required": True,
            "executed_actions": [], "numeric_risk_score": None,
            "scope_note": "This is a note draft and reason guidance, never an instruction to mutate QRadar"}
