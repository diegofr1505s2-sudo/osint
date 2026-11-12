from pathlib import Path

from PIL import Image

from catexe.modules.metadata import cardinal, dms_to_decimal, read_exif


def test_metadata_primitives_are_deterministic():
    assert abs(dms_to_decimal((48, 51, 23.8)) - 48.85661111111111) < 1e-12
    assert dms_to_decimal(("bad", 1, 2)) is None
    assert cardinal(0) == "nord"
    assert cardinal(90) == "est"
    assert cardinal(225) == "sud-ouest"


def test_read_exif_returns_stable_contract(tmp_path):
    path = Path(tmp_path) / "sample.jpg"
    Image.new("RGB", (40, 20), "white").save(path, "JPEG")
    image, info, gps, camera = read_exif(path)
    assert image.size == (40, 20)
    assert info["Taille"] == "40×20"
    assert gps is None
    assert isinstance(camera, dict)
