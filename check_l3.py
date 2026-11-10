import sys
sys.path.insert(0, "scripts")
from deduplicate_dataset import analyze

rows = [
    {"text": 'api_key = "abcdef1234567890abcdef"', "language": "python",
     "file_ext": ".py", "file_type": "python", "context_label": "REAL_SECRET",
     "category": "API_KEY", "leak_group": "g1"},
    {"text": 'api_key = "abcdef1234567890abcdeg"', "language": "python",
     "file_ext": ".py", "file_type": "python", "context_label": "REAL_SECRET",
     "category": "API_KEY", "leak_group": "g2"},
    {"text": "completely different documentation sentence about vault usage patterns",
     "language": "markdown", "file_ext": ".md", "file_type": "markdown",
     "context_label": "DOCUMENTATION_EXAMPLE", "category": "GENERIC_SECRET",
     "leak_group": "g3"},
]
r = analyze(rows)
print("l1:", len(r["l1_dup_idx"]), "l3:", len(r["l3_dup_idx"]), "groups:", len(r["groups"]))
assert len(r["l1_dup_idx"]) == 0
assert len(r["l3_dup_idx"]) == 1, "near-duplicate pair should be flagged"
print("L3 sanity check PASSED")
