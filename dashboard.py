"""SecureCharge research dashboard: python -m streamlit run dashboard.py."""

from __future__ import annotations
import json
from pathlib import Path
import secrets
import pandas as pd
import streamlit as st
from securecharge import collision, collision_lab, riskanalysis
from securecharge.backend import Mode, SecureCsms
from securecharge.clock import FakeClock
from securecharge.gateway import MigrationGateway
from securecharge.keys import Keyring
from securecharge.legacy import CHECKSUM_LABELS, add_legacy_integrity
from securecharge.messages import example_start, example_stop, format_inr
from securecharge.scenarios import TITLES, Attack, Lab, run, run_all
from securecharge.storage import Store

st.set_page_config(page_title="SecureCharge Research Lab", page_icon="⚡", layout="wide")
st.markdown(
    """<style>
.block-container {padding-top:2rem; max-width:1440px;}
[data-testid="stMetric"] {border:1px solid #22394b; border-radius:12px; padding:16px;}
[data-testid="stSidebar"] {border-right:1px solid #22394b;}
.eyebrow {font:600 12px monospace;letter-spacing:.18em;color:#2dd4bf;margin-bottom:.6rem;}
.hero {font-size:46px;font-weight:750;letter-spacing:-.04em;line-height:1.1;margin:0;}
.subtitle {color:#94a3b8;font-size:17px;max-width:900px;line-height:1.6;margin-top:12px;}
</style>""",
    unsafe_allow_html=True,
)


def verdict_box(lane):
    if not lane.applicable:
        st.info("Not applicable: " + lane.note)
    elif lane.fooled:
        st.error("Forgery accepted — " + lane.note)
    elif lane.accepted:
        st.success("Accepted — " + lane.note)
    else:
        st.info("Rejected — " + lane.note)
    st.caption(lane.detail)


def attack_tab(lab):
    st.subheader("Watch an integrity decision change the bill")
    attack = st.selectbox("Scenario", list(Attack), format_func=lambda a: TITLES[a])
    result = run(attack, lab)
    a, b, c = st.columns(3)
    a.metric("Honest session", format_inr(result.honest_paise), "12.5 kWh delivered")
    b.metric("Forgery target", format_inr(result.forged_paise), "Checksum recomputation experiment")
    c.metric("Secure outcome", result.secure.reason)
    left, right = st.columns(2)
    with left:
        st.markdown(f"**Legacy · {CHECKSUM_LABELS[lab.algorithm]} checksum**")
        verdict_box(result.legacy)
    with right:
        st.markdown("**SC2 · HMAC-SHA3-256**")
        verdict_box(result.secure)
    st.caption(
        "Attack is applied after gateway signing. A forged measurement before a trusted gateway is outside this defense."
    )
    with st.expander("Inspect original and delivered transport envelopes"):
        x, y = st.columns(2)
        x.code(json.dumps(result.secure.honest, indent=2), language="json")
        y.code(json.dumps(result.secure.delivered, indent=2), language="json")
    rows = run_all(lab)
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Scenario": r.title,
                    "Legacy": r.legacy.reason,
                    "Legacy fooled": r.legacy.fooled,
                    "Secure": r.secure.reason,
                    "Secure fooled": r.secure.fooled,
                }
                for r in rows
            ]
        ),
        hide_index=True,
        width="stretch",
    )


def collision_tab():
    st.subheader("A genuine collision, carried by valid OCPP messages")
    st.warning(
        "MVR-128 is an explicit research model of vendor binary meter records. This is not a discovered vulnerability in real charger firmware."
    )
    r = collision_lab.report()
    a, b, c = st.columns(3)
    a.metric("MD5 of both decoded records", r["pinned_md5"][:12] + "…")
    b.metric("Meter reading difference", f"{r['honest_meter_stop'] - r['substituted_meter_stop']} Wh")
    c.metric("Secure substitution", r["secure_substitution_reason"])
    st.write(
        "The legacy verifier pins the MD5 of a 128-byte decoded record. The attacker substitutes the published colliding record without changing that pinned digest. Both records encode different meter counters and travel in schema-valid OCPP 1.6 SignedData samples."
    )
    st.info(
        "Hash boundary: decoded binary meter record. The base64 values and full JSON messages do not share the same MD5."
    )
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Input": "Honest A",
                    "meterStop": r["honest_meter_stop"],
                    "Bill": format_inr(r["honest_bill_paise"]),
                    "Pinned MD5 accepted": True,
                },
                {
                    "Input": "Substituted B",
                    "meterStop": r["substituted_meter_stop"],
                    "Bill": format_inr(r["substituted_bill_paise"]),
                    "Pinned MD5 accepted": True,
                },
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    report = collision.analyse()
    st.dataframe(
        pd.DataFrame(
            [
                {"Algorithm": name, "Digest A": a, "Digest B": b, "Equal on this pair": a == b}
                for name, (a, b) in report.digests.items()
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    left, right = st.columns(2)
    left.download_button("Download collision input A", report.a, "md5_collision_a.bin")
    right.download_button("Download collision input B", report.b, "md5_collision_b.bin")
    with st.expander("Schema-valid OCPP fixtures"):
        st.code(
            json.dumps({"honest": r["honest_ocpp"], "substitution": r["substituted_ocpp"]}, indent=2), language="json"
        )


def fleet_tab(mode):
    st.subheader("Migrate a mixed fleet without losing enforcement")
    if "fleet_store" not in st.session_state:
        st.session_state.fleet_store = Store()
        st.session_state.fleet_keys = {cp: Keyring.generate(f"{cp}-v1", cp) for cp in ("CP-01", "CP-02")}
        st.session_state.fleet_tx = {}
    s = st.session_state.fleet_store
    cp = st.selectbox("Charge point", ["CP-01", "CP-02"])
    k = st.session_state.fleet_keys[cp]
    clock = FakeClock(1_790_000_900)
    b = SecureCsms(k, s, clock=clock, mode=mode)
    g = MigrationGateway(k, clock=clock)
    a, c, d = st.columns(3)
    a.metric("Charger policy", "Signed only" if s.security_required(cp) else "Awaiting migration")
    c.metric("Retained replay nonces", s.nonce_count())
    d.metric("Bills committed", len(s.ledger_rows()))
    buttons = st.columns(3)
    if buttons[0].button("Send signed start", width="stretch"):
        msg = add_legacy_integrity(example_start(unique_id=secrets.token_hex(8)))
        v = b.receive(g.process(msg.to_frame(), cp).frame, cp)
        if v.accepted:
            st.session_state.fleet_tx[cp] = v.facts["transaction_id"]
        st.session_state.fleet_last = v
        st.rerun()
    if buttons[1].button("Send unsigned start", width="stretch"):
        msg = add_legacy_integrity(example_start(unique_id=secrets.token_hex(8)))
        v = b.receive(msg.to_frame(), cp)
        if v.accepted:
            st.session_state.fleet_tx[cp] = v.facts["transaction_id"]
        st.session_state.fleet_last = v
        st.rerun()
    if buttons[2].button("Close current session", width="stretch"):
        tx = st.session_state.fleet_tx.get(cp)
        if tx is None:
            st.info("Open a session first.")
        else:
            msg = add_legacy_integrity(example_stop(transaction_id=tx, unique_id=secrets.token_hex(8)))
            v = b.receive(g.process(msg.to_frame(), cp).frame, cp)
            st.session_state.fleet_last = v
            if v.accepted:
                st.session_state.fleet_tx.pop(cp, None)
            st.rerun()
    last = st.session_state.get("fleet_last")
    if last:
        if last.accepted and last.legacy:
            st.warning("Accepted WITHOUT authentication: " + last.detail)
        elif last.accepted:
            st.success(last.label + ": " + last.detail)
        else:
            st.info(last.label + ": " + last.detail)
    st.caption(
        "A first accepted signed request enrolls its charger. Monitor/warn can accept only chargers that have not enrolled. Enrollment and billing are committed together."
    )
    st.dataframe(pd.DataFrame(s.audit_rows()), hide_index=True, width="stretch")
    st.download_button("Download fleet audit", json.dumps(s.audit_rows(), indent=2), "fleet-audit.json")


def protocol_tab():
    st.subheader("Parser compatibility has a precise boundary")
    st.code(
        "Legacy OCPP charger → trusted local adapter → SC2 authenticated transport\n                                                     ↓\n                  legacy OCPP parser ← unchanged CALL ← secure CSMS adapter",
        language="text",
    )
    call = example_start()
    from securecharge import security

    envelope = security.attach(add_legacy_integrity(call), Keyring.generate(), ts=1_790_000_900)
    left, right = st.columns(2)
    left.markdown("**The OCPP 1.6 parser receives**")
    left.code(json.dumps(call.to_frame(), indent=2), language="json")
    right.markdown("**The upgraded transport adapter receives**")
    right.code(json.dumps(envelope.to_frame(), indent=2), language="json")
    st.success("The unwrapped CALL is identical and independently schema-validated. No customData field is added.")
    st.caption(
        "The outer protocol is proprietary SC2. Both transport endpoints need adapters. Legacy parsers do not verify tags or gain protection on their own."
    )
    if st.button("Run real localhost WebSocket walkthrough"):
        import asyncio
        from securecharge.network import loopback

        with st.spinner("Starting isolated loopback endpoints…"):
            st.session_state.network_result = asyncio.run(loopback())
    if "network_result" in st.session_state:
        st.json(st.session_state.network_result)


def evidence_tab():
    st.subheader("Raw measurements, provenance and research scope")
    root = Path(__file__).resolve().parent / "artifacts"
    result_files = sorted(root.glob("*/results.json")) if root.exists() else []
    if not result_files:
        st.info("Generate evidence: python -m securecharge research --out artifacts/run-01 --samples 200")
        return
    chosen = st.selectbox("Recorded experiment", result_files, format_func=lambda p: p.parent.name)
    r = json.loads(chosen.read_text(encoding="utf-8"))
    env = r["environment"]
    st.caption(f"{env['hardware_class']} · Python {env['python']} · {env['measured_at_utc']}")
    a, b, c = st.columns(3)
    a.metric("Request median", f"{r['pipeline_summary']['total_ns']['median_ns'] / 1e6:.3f} ms")
    b.metric("Request p95", f"{r['pipeline_summary']['total_ns']['p95_ns'] / 1e6:.3f} ms")
    c.metric("Envelope overhead", f"{r['message_overhead_bytes']} bytes")
    st.caption(r["methods"]["latency_scope"])
    for name in ("hash_latency.png", "pipeline_latency.png"):
        if (chosen.parent / name).exists():
            st.image(str(chosen.parent / name), width="stretch")
    with st.expander("Methods, environment and claim boundaries"):
        st.json({"methods": r["methods"], "environment": env, "claims": r["claims"]})
    for name in ("results.json", "hash_samples.csv", "pipeline_samples.csv", "scenarios.csv", "manifest.json"):
        path = chosen.parent / name
        if path.exists():
            st.download_button("Download " + name, path.read_bytes(), name, key=str(path))


def risk_tab():
    st.subheader("Threat inventory and migration rationale")
    st.caption("Hypothetical legacy CSMS inventory; no vendor firmware was audited. Severity ratings are qualitative.")
    report = riskanalysis.summary()
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Severity": i.severity,
                    "Area": i.area,
                    "Mechanism": i.weakness,
                    "Threat": i.threat,
                    "Replacement": i.replacement,
                }
                for i in report.sorted_items()
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    st.info(
        "SHA-256 and SHA3-256 remain unkeyed checksums. Message authenticity requires a MAC or signature. HMAC-SHA-256 is a secure comparison baseline; SHA-3 is selected to meet this project's migration target."
    )
    with st.expander("References"):
        for ref in report.references:
            st.write(ref)


def pilot_tab():
    st.subheader("The charging black box: recover the bill and its evidence")
    st.markdown(
        "The Pi records a request before forwarding it. A network outage leaves it pending. "
        "If the CSMS commits a bill but its reply disappears, a fresh authenticated retry recovers "
        "the response without billing again. Only a verified CSMS response reaches the charger."
    )
    st.code(
        "Charger → sealed custody journal → mutual TLS + SC2 → CSMS\n                    ↑                         ↓\n             retained request ← authenticated receipt",
        language="text",
    )
    st.info(
        "Disconnecting the backend never produces an invented success response. Charger offline authorization remains vendor behavior."
    )
    root = Path(__file__).resolve().parent / "artifacts"
    runs = sorted(root.glob("*/pilot-results.json"))
    if runs:
        chosen = st.selectbox("Pilot fault experiment", runs, index=len(runs) - 1, format_func=lambda p: p.parent.name)
        result = json.loads(chosen.read_text(encoding="utf-8"))
        a, b, c = st.columns(3)
        a.metric("Bills after lost reply + recovery", result["ledger_rows_after_recovery"])
        b.metric("Authenticated custody events", result["journal_events"])
        c.metric("Altered journal refused", "Yes" if result["tampered_custody_record_rejected_at_startup"] else "No")
        st.json(result)
        st.download_button("Download pilot fault evidence", chosen.read_bytes(), "pilot-results.json")
    else:
        st.code("python -m securecharge pilot-demo --out artifacts/pilot-run-01")
    st.caption(
        "A protected external anchor detects journal rollback. HMAC evidence assumes protected symmetric keys and is not third-party non-repudiation. Real Pi/charger and physical power-cut validation are separate measurements."
    )


st.markdown(
    '<div class="eyebrow">OCPP 1.6 · SHA-3 MIGRATION · REPRODUCIBLE SECURITY EXPERIMENTS</div>', unsafe_allow_html=True
)
st.markdown('<h1 class="hero">SecureCharge Research Lab</h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="subtitle">Retrofitting legacy charging integrity with an authenticated outer wrapper, durable migration policy, and evidence you can inspect.</p>',
    unsafe_allow_html=True,
)
st.sidebar.title("Experiment policy")
mode = st.sidebar.radio("Migration mode", list(Mode), index=2, format_func=lambda m: m.value)
algo = st.sidebar.selectbox("Legacy checksum", list(CHECKSUM_LABELS), format_func=lambda a: CHECKSUM_LABELS[a])
ttl = st.sidebar.slider("Signing lifetime (seconds)", 10, 600, 120, 10)
skew = st.sidebar.slider("Clock skew (seconds)", 0, 120, 30, 5)
st.sidebar.caption(
    "Signing freshness is separate from the original meter-event timestamp. Desktop evidence is never labeled as a Pi measurement."
)
lab = Lab(mode=mode, algorithm=algo, ttl_seconds=ttl, max_skew_seconds=skew)
tabs = st.tabs(
    [
        "Attack simulator",
        "Collision substitution",
        "Migration fleet",
        "OCPP compatibility",
        "Research evidence",
        "Pi black box",
        "Risk model",
    ]
)
with tabs[0]:
    attack_tab(lab)
with tabs[1]:
    collision_tab()
with tabs[2]:
    fleet_tab(mode)
with tabs[3]:
    protocol_tab()
with tabs[4]:
    evidence_tab()
with tabs[5]:
    pilot_tab()
with tabs[6]:
    risk_tab()
