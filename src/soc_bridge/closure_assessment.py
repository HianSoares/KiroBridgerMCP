"""Reviewable closing reason and note proposals. No offense mutation is exposed."""
from __future__ import annotations

from .ariel_collection import BudgetExhausted

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


def propose(result: dict) -> dict:
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
    blockers = [{"id": "authorization", "summary": "Owner/change/inventory evidence of authorized activity not supplied"},
                {"id": "active_cre", "summary": "Full active CRE tests and the actual trigger not verified"}]
    blockers.extend({"id": f"coverage:{n}", "summary": f"Relevant collection incomplete: {n}"} for n in relevant)
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
    available = result.get("closing_reasons", {}).get("reasons", [])
    metadata = result.get("metadata", {})
    existing_id = metadata.get("closing_reason_id")
    existing = {"status": metadata.get("status"), "reason_id": existing_id,
                "reason_text": next((r["text"] for r in available if r["id"] == existing_id), None),
                "close_time": metadata.get("close_time"),
                "meaning": "Observed metadata, not evidence that the original closure was justified"}
    options = [{**r, "condition": CONDITIONS.get(r["text"].strip().lower(),
                "Custom reason: obtain its local definition and supporting evidence before selecting it"),
                "eligible_now": False} for r in available]
    already_closed = metadata.get("status") == "CLOSED"
    primary = "Revisar justificativa do fechamento já registrado" if already_closed else "Manter aberta / pendente de validação do analista"
    confidence = "Insuficiente para uma classificação final"
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
    blockers_pt = ["autorização da atividade pelo responsável não apresentada",
                   "testes ativos da CRE e vínculo com o gatilho não verificados"]
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
             "Decisão sugerida: manter pendente. ") + "; ".join(blockers_pt) + ".",
            "Motivo de fechamento ainda não selecionado. Nenhum fechamento, tuning ou contenção executado."]
    return {"decision": "review_existing_closure" if already_closed else "keep_open",
            "recommendation": primary, "ready_to_close": False, "existing_closure": existing,
            "recommended_reason": None, "reason_catalog_state": result.get("closing_reasons", {}).get("state"),
            "conditional_reason_options": options, "justification": findings,
            "confidence": confidence, "confidence_explanation": "Comportamento observado e cobertura não comprovam autorização nem o gatilho da CRE",
            "blocking_requirements": blockers, "secondary_collection_pending": [n for n in incomplete if n not in relevant],
            "evidence": evidence, "suggested_note": "\n".join(note),
            "observed_facts": assessment.get("confirmed_facts", []),
            "note_status": "draft_for_analyst_review", "human_review_required": True,
            "executed_actions": [], "numeric_risk_score": None,
            "scope_note": "This is a note draft and reason guidance, never an instruction to mutate QRadar"}
