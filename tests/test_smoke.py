"""Offline smoke tests — deterministic, no network. Run: python -m tests.test_smoke"""
import sys

def check(name, cond):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    return cond

def main():
    ok = True

    # 1. all modules import
    import autoasm.config, autoasm.models, autoasm.core, autoasm.discovery
    import autoasm.assessment, autoasm.correlation, autoasm.scoring
    import autoasm.orchestrator, autoasm.reporting, autoasm.cli, autoasm.dashboard
    ok &= check("all modules import", True)

    # 2. scope guard
    from autoasm.core import ScopeGuard
    sg = ScopeGuard(["example.com"])
    ok &= check("scope: in-scope subdomain", sg.in_scope("api.example.com"))
    ok &= check("scope: in-scope root", sg.in_scope("https://example.com/x"))
    ok &= check("scope: out-of-scope rejected", not sg.in_scope("evil.com"))
    ok &= check("scope: lookalike rejected", not sg.in_scope("notexample.com"))

    # 3. breach corpus loads + matches
    from autoasm.correlation import load_breach_corpus, corpus_match
    corpus = load_breach_corpus()
    ok &= check("corpus loads patterns", len(corpus.get("patterns", [])) >= 10)
    m = corpus_match("exposed-admin-panel")
    ok &= check("corpus matches exposed-admin-panel", m is not None)

    # 4. scoring: breach-weighting actually changes ranking
    from autoasm.scoring import score_one, rank, breach_relevance
    # exposure A: default creds (corpus critical_ratio 1.0) ; B: same CVSS, no corpus
    cors_creds = [{"source": "CORPUS", "breach_tag": "default_credentials",
                   "weight": 0.011 * (1 + 1.0)}]
    a = score_one(5, 7.0, cors_creds, "a.example.com", "default-login", "default creds")
    b = score_one(5, 7.0, [], "b.example.com", "misc", "no corpus")
    ok &= check("breach_relevance >1 with corpus", a.breach_relevance > 1.0)
    ok &= check("breach_relevance ==1 without", b.breach_relevance == 1.0)
    ok &= check("corpus exposure outranks equal-CVSS one",
                a.composite_score > b.composite_score)

    # 5. KEV uplift
    kev_cor = [{"source": "KEV", "cve_id": "CVE-2024-0001", "kev_flag": True,
                "weight": 0.9}]
    br = breach_relevance(kev_cor)
    ok &= check("KEV raises breach relevance", br > 1.0)

    # 6. ranking assigns sequential ranks
    ranked = rank([a, b])
    ok &= check("rank 1 is highest score", ranked[0].rank == 1 and
                ranked[0].composite_score >= ranked[1].composite_score)

    # 7. DB round-trip in a temp db
    import os, tempfile
    os.environ["AUTOASM_DB_URL"] = "sqlite:///" + tempfile.mktemp(suffix=".db")
    # re-import models with new URL
    import importlib, autoasm.models as M
    importlib.reload(M)
    M.init_db()
    s = M.get_session()
    org = M.Organisation(name="T", root_domains="example.com")
    s.add(org); s.commit()
    ok &= check("db round-trip", org.id is not None)
    s.close()

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
