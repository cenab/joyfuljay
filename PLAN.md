Below is a coding-agent-ready implementation plan, with exact files, exact functions, exact JSON formats, exact CLI flags, and acceptance tests. It assumes your library is imported as joyfuljay as jj and you have a CLI executable jj. If names differ, the agent should map accordingly.

⸻

0) Feature Freeze (policy + optional CI)

0.1 Add policy doc

Create file: docs/FEATURE_FREEZE.md

Content requirements:
	•	Header: “JoyfulJay v1.0 Feature Freeze”
	•	List allowed changes: bugfix, docs, schema, tests, ci
	•	List forbidden changes: new extractors, new features, feature semantic changes in CORE

0.2 Optional CI guard (only if GitHub Actions exists)

Create file: .github/workflows/feature_freeze.yml

Behavior:
	•	On PR, if any file changed under:
	•	src/joyfuljay/extractors/
	•	src/joyfuljay/features/
then PR title must contain one of:
	•	[bugfix], [schema], [docs], [tests]

Acceptance:
	•	PR touching feature code without tag fails CI.

⸻

Phase 1) Standardize

1) Profiles (JJ-CORE / JJ-EXTENDED / JJ-EXPERIMENTAL)

Objective

Create stable, named feature sets that users can cite.

⸻

1.1 Decide canonical Feature ID format

Hard rule: Every feature must have a stable ID string.

Use this format:
{extractor_name}.{feature_name}

Examples:
	•	flow_meta.duration_s
	•	timing.iat_mean_ms
	•	tls.ja3
	•	quic.alpn
	•	padding.tor_cell_score

⸻

1.2 Add profile definition files

Create directory: profiles/

Create files:
	•	profiles/JJ-CORE.txt
	•	profiles/JJ-EXTENDED.txt
	•	profiles/JJ-EXPERIMENTAL.txt

File format rules:
	•	UTF-8 text
	•	One feature ID per line
	•	# starts a comment
	•	Empty lines allowed
	•	Lines must be sorted lexicographically

Agent task:
	•	Enumerate all current features from current extractor registry (see 1.3), then assign each to exactly one file.

⸻

1.3 Implement feature registry (single source of truth)

1.3.1 Add extractor interface requirements

Every extractor must implement:
	•	name: str (stable extractor ID, e.g. "tls")
	•	feature_ids() -> list[str] returning stable IDs prefixed by name.
	•	feature_meta() -> dict[str, FeatureMeta] metadata per feature

If you already have extractor classes, add these methods.

1.3.2 Create registry module

Create file: src/joyfuljay/schema/registry.py

Implement:

from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Optional

DType = Literal["float32","float64","int64","bool","string","categorical"]
Scope = Literal["flow","direction","burst","packet_seq"]
Privacy = Literal["safe","sensitive","high"]

@dataclass(frozen=True)
class FeatureMeta:
    id: str
    dtype: DType
    shape: list[int] | Literal["variable"]
    units: str
    scope: Scope
    direction: Literal["bidir","src_to_dst","dst_to_src","both"]
    direction_semantics: str
    missing_policy: Literal["nan","zero","empty","sentinel"]
    missing_sentinel: Optional[float | int | str]
    dependencies: list[str]
    privacy_level: Privacy
    description: str

def get_extractors() -> list[object]:
    """
    Return instantiated extractor objects in deterministic order.
    Must be stable across runs.
    """
    ...

def all_feature_ids() -> set[str]:
    ids = set()
    for ex in get_extractors():
        for fid in ex.feature_ids():
            if fid in ids:
                raise ValueError(f"Duplicate feature id: {fid}")
            ids.add(fid)
    return ids

def all_feature_meta() -> dict[str, FeatureMeta]:
    meta: dict[str, FeatureMeta] = {}
    for ex in get_extractors():
        m = ex.feature_meta()
        for fid, fmeta in m.items():
            if fid in meta:
                raise ValueError(f"Duplicate feature meta id: {fid}")
            meta[fid] = fmeta
    # ensure meta covers all ids
    missing = all_feature_ids() - set(meta.keys())
    if missing:
        raise ValueError(f"Missing meta for feature ids: {sorted(missing)}")
    return meta

Acceptance:
	•	Running python -c "from joyfuljay.schema.registry import all_feature_ids; print(len(all_feature_ids()))" prints your full feature count.
	•	No duplicates.
	•	Every ID has metadata.

⸻

1.4 Implement profile loader + validation

Create file: src/joyfuljay/schema/profiles.py

Implement:

from __future__ import annotations
from pathlib import Path
from .registry import all_feature_ids

PROFILES_DIR = Path(__file__).resolve().parents[3] / "profiles"  # adjust if needed

def list_profiles() -> list[str]:
    return ["JJ-CORE","JJ-EXTENDED","JJ-EXPERIMENTAL"]

def load_profile(profile: str) -> list[str]:
    path = PROFILES_DIR / f"{profile}.txt"
    if not path.exists():
        raise FileNotFoundError(f"Profile file not found: {path}")
    ids = []
    seen = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            raise ValueError(f"Duplicate feature id in {profile}: {line}")
        seen.add(line)
        ids.append(line)
    return ids

def validate_profile(profile: str) -> None:
    defined = set(load_profile(profile))
    available = all_feature_ids()
    missing = defined - available
    extra = available - defined  # only for “exactly one tier” checks later
    if missing:
        raise ValueError(f"{profile} contains unknown feature ids: {sorted(missing)[:20]}")

“Exactly one tier” validation

Create file: src/joyfuljay/schema/tiering.py

Implement:

from .profiles import load_profile, list_profiles
from .registry import all_feature_ids

def validate_tiering_complete() -> None:
    all_ids = all_feature_ids()
    tiered = set()
    overlap = set()
    for p in list_profiles():
        ids = set(load_profile(p))
        overlap |= (tiered & ids)
        tiered |= ids
    missing = all_ids - tiered
    if overlap:
        raise ValueError(f"Features present in multiple profiles: {sorted(overlap)[:20]}")
    if missing:
        raise ValueError(f"Features not assigned to any profile: {sorted(missing)[:20]}")

Acceptance:
	•	validate_tiering_complete() passes.

⸻

1.5 Wire profiles into extraction output

Wherever you currently produce outputs (DataFrame/NumPy/JSONL), add a profile parameter.

Required API signature:
	•	jj.extract(..., profile="JJ-CORE", schema_version="v1.0", backend="scapy", capture_mode="offline", config={...})

Implementation rules:
	1.	After computing the full feature dict per flow, filter keys:
	•	Keep only features in load_profile(profile)
	2.	If a feature is in profile but missing (protocol not present), populate with missing policy from schema (Step 2).
	3.	Ensure output column order is deterministic:
	•	Sort feature IDs lexicographically or use profile file order.
	•	Prefer profile file order.

Acceptance:
	•	Running extraction with different profiles changes columns but not code paths.

⸻

1.6 CLI additions for profiles

Add commands:
	•	jj profiles list
	•	jj profiles show JJ-CORE

And flags for existing commands:
	•	jj extract --profile JJ-CORE
	•	jj live --profile JJ-CORE

Acceptance:
	•	jj profiles list prints 3 profiles.
	•	jj profiles show JJ-CORE prints feature IDs.

⸻

2) Canonical schema v1.0

2.1 Create schema directory and files

Create:
	•	schema/v1.0/feature_schema.json
	•	schema/v1.0/feature_schema.md

2.2 Implement schema generator

Create file: src/joyfuljay/schema/generate.py

Required behavior:
	•	Read all feature metadata from registry.all_feature_meta()
	•	Determine tier for each feature:
	•	If ID in JJ-CORE => CORE
	•	else if in JJ-EXTENDED => EXTENDED
	•	else => EXPERIMENTAL
	•	Emit JSON with stable ordering

Exact JSON format:

{
  "schema_version": "v1.0",
  "joyfuljay_version": "1.0.0",
  "generated_at": "2026-01-06T00:00:00Z",
  "profiles": {
    "JJ-CORE": ["flow_meta.duration_s", "..."],
    "JJ-EXTENDED": ["..."],
    "JJ-EXPERIMENTAL": ["..."]
  },
  "features": [
    {
      "id": "timing.iat_mean_ms",
      "tier": "CORE",
      "dtype": "float64",
      "shape": [1],
      "units": "ms",
      "scope": "flow",
      "direction": "bidir",
      "direction_semantics": "Client is SYN-sender for TCP else first-sender; direction computed relative to client",
      "missing_value": {"policy": "nan", "sentinel": null},
      "dependencies": ["ip","tcp"],
      "privacy_level": "safe",
      "description": "Mean inter-arrival time across packets in the flow in milliseconds."
    }
  ]
}

Also generate: schema/v1.0/core_schema_hash.txt
	•	Compute hash of:
	•	all CORE feature objects sorted by id, JSON minified
	•	sha256 hex string

2.3 Schema guard (hard rule enforcement)

Add CI job:
	•	Regenerate schema + core hash
	•	Fail if core_schema_hash.txt changes without major version bump

Major version bump rule:
	•	If current version is 1.x.y, changing CORE hash requires bump to 2.0.0.

Implementation approach:
	•	Store version in src/joyfuljay/__init__.py or version.py
	•	CI reads it.

⸻

3) Provenance metadata everywhere

3.1 Provenance module

Create file: src/joyfuljay/provenance.py

Implement:
	•	compute_config_hash(config: dict) -> str (stable JSON sort + sha256)
	•	build_provenance(...) -> dict returning exactly:

{
  "jj_version": "1.0.0",
  "schema_version": "v1.0",
  "profile": "JJ-CORE",
  "backend": "scapy",
  "capture_mode": "offline",
  "config_hash": "sha256:...",
  "timestamp_generated": "2026-01-06T00:00:00Z",
  "privacy": {
    "ip_anonymization": true,
    "port_redaction": false
  }
}

3.2 Output embedding rules (must implement)
	•	If exporting to file: always write sidecar *.provenance.json
	•	If DataFrame return: attach df.attrs["joyfuljay_provenance"] = provenance AND include a sidecar on export
	•	If JSONL streaming: write a first metadata line:
	•	{"type":"metadata","provenance":{...}}

3.3 API + CLI
	•	jj.provenance(...) -> dict
	•	CLI: jj info --provenance prints JSON

⸻

Phase 2) Determinism

4) Determinism guarantees and enforcement

4.1 Implement deterministic rules in code

Create:
	•	src/joyfuljay/flows/key.py canonical flow key ordering
	•	src/joyfuljay/flows/direction.py client/server rule
	•	src/joyfuljay/output/rounding.py float rounding and dtype casting

Rules that must be encoded:
	•	Flow key: always canonicalize endpoint order
	•	Direction: client is SYN sender for TCP else first sender
	•	Timestamps: relative to first packet, rounded to 1e-6
	•	Floats: cast to float32 or float64 consistently per schema dtype
	•	Hashing: anonymization uses stable seed and documented hashing algorithm

4.2 Write doc

Create file:
	•	docs/determinism.md
Must list the exact rules above.

⸻

5) Golden conformance tests

5.1 Add golden PCAPs

Directory:
	•	tests/data/pcaps/
Files:
	•	tls_small.pcap
	•	quic_small.pcap
	•	ssh_small.pcap
	•	tor_like_small.pcap
	•	optional doh_small.pcap

If you do not have them, the agent must generate them (capture small sessions) or add minimal placeholders and mark TODO. Prefer real pcaps.

5.2 Golden outputs directory
	•	tests/golden/v1.0/JJ-CORE/

For each pcap:
	•	NAME.parquet
	•	NAME.provenance.json
	•	NAME.schema_hash.txt
	•	NAME.config.json

5.3 Script to generate golden outputs

Create:
	•	scripts/generate_golden.py

It runs:
	•	extract(pcap, profile=JJ-CORE, schema=v1.0, backend=scapy)
	•	Writes parquet + provenance + hash + config

5.4 Tests

Create:
	•	tests/integration/test_golden_scapy.py
	•	tests/integration/test_golden_dpkt.py
	•	tests/integration/test_golden_remote.py

Comparison rules:
	•	Sort rows by stable key (flow key + start time)
	•	Column order must match profile file order
	•	Floats compare within tolerance:
	•	float64 tolerance 1e-9
	•	float32 tolerance 1e-6
	•	Strings/bools/ints must match exactly

Remote test:
	•	Replay pcap through remote streaming client into server
	•	Compare extracted output to golden

5.5 CLI validate

Implement command:
	•	jj validate --pcap X --profile JJ-CORE --schema v1.0 --backend scapy
Behavior:
	•	Runs extraction
	•	Validates output conforms to schema types/shapes
	•	If --golden-dir passed, compares to golden

⸻

Phase 3) Citation plumbing

6) CITATION + cite command + changelog

Files:
	•	CITATION.cff
	•	CHANGELOG.md
	•	docs/versioning.md
	•	src/joyfuljay/cli/cite.py (or equivalent)

CLI:
	•	jj cite prints:
	•	BibTeX block
	•	APA line

Zenodo:
	•	Add docs/releasing.md describing enabling Zenodo GitHub integration
	•	Add .zenodo.json metadata file

⸻

Phase 4) Benchmark protocol (decoupled)

8) Dataset adapters

Create module:
	•	src/joyfuljay/ml/dataset.py
Functions:
	•	to_sklearn(df, label_col="label") -> (X, y, feature_names)
	•	to_torch(df, label_col="label") -> torch.utils.data.Dataset

Bench scripts:
	•	benchmarks/run_baselines.py
	•	fixed splits: hash-based split on flow key
	•	baselines: logistic regression, random forest

Hard rule:
	•	No jj.train() in core package.

⸻

What to implement first (exact order)
	1.	schema/registry.py + extractor feature_ids() + feature_meta() implemented everywhere
	2.	profiles/*.txt + profiles.py + tiering.py validation
	3.	Profile filtering in extraction outputs
	4.	schema/generate.py + committed schema/v1.0/feature_schema.json
	5.	provenance.py + embed provenance in exports
	6.	Golden PCAPs + generate_golden.py + jj validate

⸻

Acceptance criteria checklist (agent must verify)
	•	validate_tiering_complete() passes
	•	jj profiles show JJ-CORE prints stable list
	•	schema/v1.0/feature_schema.json generated and committed
	•	jj extract --profile JJ-CORE outputs only CORE columns
	•	Every export writes *.provenance.json
	•	pytest -q passes golden tests on scapy backend
	•	jj validate --pcap tests/data/pcaps/tls_small.pcap --profile JJ-CORE --schema v1.0 exits 0

If you paste your actual repo tree (top-level folders + where extractors live + current CLI entrypoint), I can rewrite all paths to match your exact structure so the agent has zero ambiguity.