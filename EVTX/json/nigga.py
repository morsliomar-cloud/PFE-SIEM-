import json
import os
import re

# === CONFIGURE THIS ===
input_dir  = r'C:\Users\ss\Downloads\EVTX\json'
# ======================

output_dir = os.path.join(input_dir, 'converted')
if not os.path.exists(output_dir):
    os.makedirs(output_dir)


def transform_attributes(obj):
    """
    Recursively convert evtx_dump #attributes pattern to key_attributes.
    e.g. {"Event": {"#attributes": {"xmlns": "..."}, "System": {...}}}
      -> {"Event_attributes": {"xmlns": "..."}, "Event": {"System": {...}}}
    Already-converted files (web app format) pass through unchanged.
    """
    if not isinstance(obj, dict):
        return obj
    result = {}
    for key, value in obj.items():
        if isinstance(value, dict) and '#attributes' in value:
            result[f'{key}_attributes'] = value['#attributes']
            remaining = {k: v for k, v in value.items() if k != '#attributes'}
            if remaining:
                result[key] = transform_attributes(remaining)
            # If nothing left besides #attributes, key itself is dropped (e.g. Provider)
        elif isinstance(value, dict):
            result[key] = transform_attributes(value)
        elif isinstance(value, list):
            result[key] = [transform_attributes(i) if isinstance(i, dict) else i for i in value]
        else:
            result[key] = value
    return result


def clean_strings(obj):
    """Strip trailing whitespace/newlines from all string values (matches web-app output)."""
    if isinstance(obj, dict):
        return {k: clean_strings(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_strings(i) for i in obj]
    elif isinstance(obj, str):
        return obj.rstrip()
    return obj


def load_events(file_path):
    """
    Auto-detect and load events from either:
      - evtx_dump NDJSON  : one JSON per line, prefixed with 'Record N' header lines
      - Web-app JSON array: a single JSON array [...]
    Returns a list of raw event dicts (before any transformation).
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read().strip()

    # Web-app / already-converted format → JSON array
    if content.startswith('['):
        return json.loads(content)

    # evtx_dump NDJSON format → skip 'Record N' lines, parse the rest
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line or re.match(r'^Record \d+$', line):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # silently skip malformed lines
    return events


# ── Main loop ──────────────────────────────────────────────────────────────────
total = 0
for filename in sorted(os.listdir(input_dir)):
    if not filename.endswith('.json'):
        continue

    file_path   = os.path.join(input_dir, filename)
    output_path = os.path.join(output_dir, f'converted_{filename}')

    events = load_events(file_path)

    with open(output_path, 'w', encoding='utf-8') as f:
        for entry in events:
            entry = transform_attributes(entry)   # #attributes  → key_attributes
            entry = clean_strings(entry)           # strip trailing whitespace
            f.write(json.dumps(entry) + '\r\n')

    print(f'Done: {filename}  ({len(events)} events)')
    total += len(events)

print(f'\nAll done — {total} total events saved to: {output_dir}')