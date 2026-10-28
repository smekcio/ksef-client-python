"""Bound JSON structure before allocating the decoder's object graph.

This is a lexical preflight, not a replacement JSON parser. Strings are skipped
without decoding or copying them; json.loads still validates grammar and UTF-8.
Keys count towards the token budget as well as containers and scalar values.
"""

from __future__ import annotations

import re

_ATOM = re.compile(rb'[^ \t\r\n{}\[\],:"]+')


def check_json_structure(body: bytes, *, max_nodes: int, max_depth: int) -> None:
    if b"\x00" in body:
        raise ValueError("JSON response must use UTF-8")
    index = nodes = 0
    stack: list[int] = []
    while index < len(body):
        byte = body[index]
        if byte in b" \t\r\n,:]}":
            if byte in b"]}":
                expected = 91 if byte == 93 else 123
                if not stack or stack.pop() != expected:
                    raise ValueError("Unbalanced JSON container")
            index += 1
            continue
        nodes += 1
        if nodes > max_nodes:
            raise ValueError("JSON node budget exceeded")
        if byte in b"[{":
            stack.append(byte)
            if len(stack) > max_depth:
                raise ValueError("JSON depth budget exceeded")
            index += 1
        elif byte == 34:
            end = index
            while True:
                end = body.find(b'"', end + 1)
                if end == -1:
                    raise ValueError("Unterminated JSON string")
                slash = end - 1
                while slash > index and body[slash] == 92:
                    slash -= 1
                if (end - slash) % 2 == 1:
                    break
            index = end + 1
        else:
            atom = _ATOM.match(body, index)
            assert atom is not None
            index = atom.end()
    if stack:
        raise ValueError("Unterminated JSON container")
