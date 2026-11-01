"""Generate vectors.json: fixed inputs -> exact canonical bytes and hashes.

Any implementation of AIngram hashing must reproduce every field of this file.
Inputs deliberately exercise: NFC normalisation (decomposed é in), keyword
sort/dedupe/trim, refs, supersedes, pinned, untrusted_ctx, non-ASCII text,
control characters, and a redaction.
"""

import json
import sys
from pathlib import Path

import aingram_core as core

T = ["2026-11-01T12:00:00.000001Z", "2026-11-01T12:00:01.000002Z",
     "2026-11-01T12:00:02.000003Z", "2026-11-01T12:00:03.000004Z"]
S = ["00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100",
     "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"]


def build():
    conn = core.connect(":memory:")
    core.add_key(conn, key_id="k_brain_01", voice="brain", created_at=T[0])
    core.add_key(conn, key_id="k_code_01", voice="code", created_at=T[0])

    inputs = [
        dict(key_id="k_brain_01", subject="people/ada", kind="fact",
             excerpt="Ada goes by Ada. Caf\u0065\u0301 regular.",  # decomposed é
             keywords=["ada", " identity ", "ada", "Café"],
             body="Line one.\nLine two with a tab\tand a \"quote\".",
             pinned=True, ts=T[0], salt=S[0]),
        dict(key_id="k_code_01", subject="project/docs", kind="gotcha",
             excerpt="\\text breaks in some formula renderers; use \\mathrm.",
             keywords=["docs", "latex"], body="Seen 2026-10-26. 🐌",
             untrusted_ctx="web", half_life_days=180.0, ts=T[1], salt=S[1]),
    ]
    out = []
    ids = []
    for inp in inputs:
        r = core.append(conn, **inp)
        ids.append(r["id"])
    third = dict(key_id="k_brain_01", subject="people/ada", kind="correction",
                 excerpt="Ada moved to Lisbon.", keywords=[], body="",
                 supersedes=ids[0], refs=[ids[1], ids[0]], ts=T[2], salt=S[2])
    r = core.append(conn, **third)
    ids.append(r["id"])
    inputs.append({**third, "supersedes": "<entry 1 id>", "refs": ["<entry 2 id>", "<entry 1 id>"]})

    for i, row in enumerate(conn.execute("SELECT * FROM entries ORDER BY seq")):
        content = core.content_object(row["excerpt"], json.loads(row["keywords"]), row["body"], row["salt"])
        header = core.header_object(
            seq=row["seq"], prev_hash=row["prev_hash"], ts=row["ts"], voice=row["voice"],
            key_id=row["key_id"], subject=row["subject"], kind=row["kind"],
            supersedes=row["supersedes"], refs=json.loads(row["refs"]), pinned=row["pinned"],
            untrusted_ctx=row["untrusted_ctx"], content_hash=row["content_hash"])
        out.append({
            "input": {k: v for k, v in inputs[i].items() if k != "half_life_days"},
            "canonical_content": core.canonical(content).decode(),
            "content_hash": row["content_hash"],
            "canonical_header": core.canonical(header).decode(),
            "entry_hash": row["id"],
        })

    red = core.redact(conn, target_id=ids[1], by_key_id="k_brain_01",
                      reason="vector test", ts=T[3], salt=S[3])
    tomb = conn.execute("SELECT * FROM entries WHERE id = ?", (red["tombstone"],)).fetchone()
    tomb_header = core.header_object(
        seq=tomb["seq"], prev_hash=tomb["prev_hash"], ts=tomb["ts"], voice=tomb["voice"],
        key_id=tomb["key_id"], subject=tomb["subject"], kind=tomb["kind"],
        supersedes=tomb["supersedes"], refs=json.loads(tomb["refs"]), pinned=tomb["pinned"],
        untrusted_ctx=tomb["untrusted_ctx"], content_hash=tomb["content_hash"])
    assert core.verify(conn) == []
    return {
        "version": core.V,
        "genesis_prev_hash": core.GENESIS,
        "notes": "Inputs are as passed to append(); <entry N id> means the entry_hash of entry N. "
                 "Entry 2 is redacted by the tombstone; its header and entry_hash are unchanged.",
        "entries": out,
        "redaction": {
            "target": ids[1],
            "tombstone_canonical_header": core.canonical(tomb_header).decode(),
            "tombstone_entry_hash": tomb["id"],
            "final_head": tomb["id"],
        },
    }


if __name__ == "__main__":
    data = build()
    text = json.dumps(data, indent=2, ensure_ascii=True) + "\n"
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        same = Path("vectors.json").read_text(encoding="utf-8") == text
        print("vectors match" if same else "VECTORS DIFFER")
        sys.exit(0 if same else 1)
    Path("vectors.json").write_text(text, encoding="utf-8")
    print("wrote vectors.json")
