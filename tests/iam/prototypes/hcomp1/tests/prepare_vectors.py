#!/usr/bin/env python3
"""Extract only public verification fields from the approved local JSON vectors."""

import json
from pathlib import Path

here = Path(__file__).resolve().parent
iam_tests = Path(__file__).resolve().parents[3]
public = iam_tests / "fixtures" / "trust04c_public_vectors"

rfc = json.loads((public / "rfc8032-section7_1-verification-only.json").read_text())
assert len(rfc["records"]) == 3
with (here / "rfc8032.tsv").open("w") as out:
    for row in rfc["records"]:
        out.write("\t".join((row["vector_id"], row["source_expected_result"], "ACCEPT",
                             row["public_key_hex"], row["message_hex"] or "-", row["signature_hex"])) + "\n")

wycheproof = json.loads((public / "wycheproof-ed25519-a3d5d142.json").read_text())
rows = sorted(((test, group["publicKey"]["pk"])
               for group in wycheproof["testGroups"] for test in group["tests"]),
              key=lambda item: item[0]["tcId"])
assert len(rows) == 210
with (here / "wycheproof.tsv").open("w") as out:
    for test, public_key in rows:
        flags = set(test.get("flags", []))
        if flags & {"SmallOrderPublicKey", "MixedOrderPublicKey"} or test["result"] == "invalid":
            expected = "REJECT"
        elif test["result"] == "valid":
            expected = "ACCEPT"
        else:
            expected = "REVIEW_REQUIRED"
        out.write("\t".join((str(test["tcId"]), test["result"], expected,
                             ",".join(test.get("flags", [])), public_key or "-",
                             test["msg"] or "-", test["sig"] or "-")) + "\n")
print(f"extracted RFC={len(rfc['records'])} Wycheproof={len(rows)}")
