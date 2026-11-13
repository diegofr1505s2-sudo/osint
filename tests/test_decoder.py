import base64
import bz2
import gzip
import lzma
import zlib

import pytest

from catexe.app import decoders


def _decoded(name, payload):
    return [value for format_name, value in decoders(payload) if name in format_name]


def test_base85_and_ascii85_decode_text():
    message = b"CAT EXE decoder test"
    assert "CAT EXE decoder test" in _decoded("Base85", base64.b85encode(message).decode())
    ascii85 = base64.a85encode(message, adobe=True).decode()
    assert "CAT EXE decoder test" in _decoded("ASCII85", ascii85)
    plain_ascii85 = base64.a85encode(b"Hello, world!").decode()
    assert "Hello, world!" in _decoded("ASCII85", plain_ascii85)


def test_rot47_is_available_for_printable_ascii():
    encoded = "%96  D64C6E  `abP"
    assert "The  secret  123!" in _decoded("ROT47", encoded)


def test_idna_punycode_domain_decodes():
    assert "bücher.example" in _decoded("IDNA / Punycode", "xn--bcher-kva.example")


def test_unicode_codepoint_sequence_decodes():
    assert "Salut" in _decoded("Codepoints Unicode U+", "U+0053 U+0061 U+006C U+0075 U+0074")
    assert "A" in _decoded("Codepoints Unicode U+", "U+41")


def test_base64_wrapped_bz2_stream_is_decompressed():
    payload = base64.b64encode(bz2.compress(b"compressed payload")).decode()
    results = decoders(payload)
    assert any("Base64 + décompression bz2" == name and value == "compressed payload" for name, value in results)


@pytest.mark.parametrize("compressor,label", [
    (gzip.compress, "gzip"),
    (zlib.compress, "zlib"),
    (lzma.compress, "xz"),
])
def test_other_bounded_compression_formats(compressor, label):
    payload = base64.b64encode(compressor(b"another compressed payload")).decode()
    assert any(name == f"Base64 + décompression {label}" and value == "another compressed payload"
               for name, value in decoders(payload))


def test_decompression_output_is_bounded():
    payload = base64.b64encode(bz2.compress(b"A" * 1_100_000)).decode()
    assert all(len(value) <= 1_000_000 for _, value in decoders(payload))
