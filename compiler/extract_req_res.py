#!/usr/bin/env python3

import re
import sys
from pathlib import Path


def extract_req_res_pairs(log_file_path):
    """Extract all request/response pairs from the log file."""
    with open(log_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    pairs = []
    current_req = None

    req_pattern = re.compile(r'req -> (TL_\S+)\s*:\s*(\{.*\})')
    res_pattern = re.compile(r'res -> (\S+)\s*:\s*(\{.*\})')

    for line in lines:
        req_match = req_pattern.search(line)
        if req_match:
            current_req = {
                'method': req_match.group(1),
                'params': req_match.group(2)
            }
            continue

        res_match = res_pattern.search(line)
        if res_match and current_req:
            pairs.append({
                'req': current_req,
                'res': {
                    'type': res_match.group(1),
                    'data': res_match.group(2)
                }
            })
            current_req = None

    return pairs


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python extract_req_res.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    if not Path(log_file).exists():
        print(f"Error: File not found: {log_file}")
        sys.exit(1)

    pairs = extract_req_res_pairs(log_file)

    for i, pair in enumerate(pairs, 1):
        print(f"\n--- Pair {i} ---")
        print(f"REQ: {pair['req']['method']} : {pair['req']['params']}")
        print(f"RES: {pair['res']['type']} : {pair['res']['data']}")
