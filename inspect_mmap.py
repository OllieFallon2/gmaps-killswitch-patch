"""
inspect_mmap.py - read-only mitmproxy addon for exploring /glm/mmap responses.

Use this first on a version other than 9.0.0. It changes nothing. For each
response it prints the framing and finds gzip streams, reports where the
kill-switch URL sits inside them, and shows the bytes around it so you can
check that the tag in front of the URL is what killswitch.py expects (0x12).

Run:
  mitmdump -s inspect_mmap.py
"""
import logging
import zlib

from mitmproxy import http

MARK = b"gmm/upgrades"


def gz_streams(body):
    pos = 0
    while True:
        i = body.find(b"\x1f\x8b\x08", pos)
        if i < 0:
            return
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            raw = d.decompress(body[i:])
        except Exception:
            pos = i + 3
            continue
        if not d.eof:
            pos = i + 3
            continue
        used = len(body) - i - len(d.unused_data)
        yield i, used, raw
        pos = i + max(used, 1)


def response(flow: http.HTTPFlow):
    if flow.request.path != "/glm/mmap":
        return
    body = flow.response.content or b""
    logging.info("== mmap response: %d bytes, first 12: %s", len(body), body[:12].hex())
    if MARK in body:
        logging.info("URL found in RAW (uncompressed) body at offset %d", body.find(MARK))
    n = 0
    for i, used, raw in gz_streams(body):
        n += 1
        if n > 30:
            logging.info("... more streams not shown")
            break
        j = raw.find(MARK)
        logging.info("gzip@%d used=%d raw=%d url_at=%d before=%s after=%s",
                     i, used, len(raw), j,
                     body[max(0, i - 7):i].hex(),
                     body[i + used:i + used + 8].hex())
        if j >= 0:
            ctx = raw[max(0, j - 8): j + 60]
            logging.info("URL context hex:  %s", ctx.hex())
            logging.info("URL context text: %r", ctx)