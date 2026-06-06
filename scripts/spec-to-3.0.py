#!/usr/bin/env python3
"""Convert OpenAPI 3.1 spec to 3.0 for oapi-codegen compatibility.

Huma v2 emits 3.1 specs. oapi-codegen does not support 3.1 yet.
This script converts the two incompatible patterns we actually use:
  - type: [array, null]  →  type: array + nullable: true
  - openapi: 3.1.0       →  openapi: 3.0.3
"""

import json
import sys


def downconvert(obj):
    if isinstance(obj, dict):
        if "type" in obj and isinstance(obj["type"], list):
            types = [t for t in obj["type"] if t != "null"]
            nullable = "null" in obj["type"]
            obj["type"] = types[0] if len(types) == 1 else types
            if nullable:
                obj["nullable"] = True
        return {k: downconvert(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [downconvert(v) for v in obj]
    return obj


with open(sys.argv[1]) as f:
    spec = json.load(f)

spec["openapi"] = "3.0.3"
spec = downconvert(spec)

print(json.dumps(spec, indent=2))
