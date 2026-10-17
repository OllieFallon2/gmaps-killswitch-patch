import logging, zlib
from mitmproxy import http

MARK = b"gmm/upgrades"
NEW_TAG = 0x7A  # field 15, wire type 2: unknown to the app's parser

def patch_payload(raw: bytes):
    i = raw.find(MARK)
    if i < 0:
        return None
    start = raw.rfind(b"http", 0, i)
    if start < 2:
        logging.warning("URL found but no room for tag/length")
        return None
    tag, length = raw[start - 2], raw[start - 1]
    if tag != 0x12 or MARK not in raw[start:start + length]:
        logging.warning("unexpected bytes before URL: %s",
                        raw[max(0, start - 6):start].hex())
        return None
    out = bytearray(raw)
    out[start - 2] = NEW_TAG
    return bytes(out)

def response(flow: http.HTTPFlow):
    if flow.request.path != "/glm/mmap":
        return
    body = flow.response.content or b""
    if len(body) < 7:
        return
    out = bytearray(body[:2])
    pos, changed = 2, False
    while pos < len(body):
        if pos + 5 > len(body):
            logging.warning("truncated record header; leaving response alone")
            return
        rtype = body[pos]
        length = int.from_bytes(body[pos + 1:pos + 5], "big", signed=True)
        size = abs(length)
        payload = body[pos + 5:pos + 5 + size]
        if len(payload) != size:
            logging.warning("record overruns body; leaving response alone")
            return
        if length < 0:
            try:
                raw = zlib.decompress(payload, 16 + zlib.MAX_WBITS)
            except zlib.error as e:
                logging.warning("gunzip failed: %s", e)
                return
            patched = patch_payload(raw)
            if patched is not None:
                c = zlib.compressobj(9, zlib.DEFLATED, 31)
                payload = c.compress(patched) + c.flush()
                length = -len(payload)
                changed = True
        else:
            patched = patch_payload(payload)
            if patched is not None:
                payload = patched
                changed = True
        out += bytes([rtype]) + length.to_bytes(4, "big", signed=True) + payload
        pos += 5 + size
    if changed:
        flow.response.content = bytes(out)
        logging.info("kill-switch field neutralised")