"""Extraction déterministe de métadonnées image pour CAT.EXE."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any


def dms_to_decimal(value: Any) -> float | None:
    try:
        return float(value[0]) + float(value[1]) / 60 + float(value[2]) / 3600
    except Exception:
        return None


def cardinal(degrees: float) -> str:
    return ["nord", "nord-est", "est", "sud-est", "sud", "sud-ouest", "ouest", "nord-ouest"][int((degrees % 360 + 22.5) // 45) % 8]


def read_exif(path: str | Path):
    """Renvoie image redressée, infos lisibles, GPS (lat, lon) et infos caméra."""
    from PIL import Image, ImageOps

    info: dict[str, str] = {}
    gps = None
    camera: dict[str, float] = {}
    raw = Image.open(path)
    exif = raw.getexif()
    for key, label in {271: "Appareil (marque)", 272: "Modèle", 305: "Logiciel", 270: "Description", 315: "Auteur", 33432: "Copyright",
                       0x9C9C: "Commentaire", 0x9C9F: "Sujet", 0x9C9D: "Auteur (Windows)", 0x9C9E: "Mots-clés"}.items():
        value = exif.get(key)
        if value:
            if isinstance(value, (bytes, tuple)):
                try:
                    value = bytes(value).decode("utf-16-le")
                except Exception:
                    value = str(value)
            info[label] = str(value).strip("\x00 ")
    try:
        sub = exif.get_ifd(0x8769)
        if sub.get(36867):
            info["Prise le"] = str(sub.get(36867))
        if sub.get(42036):
            info["Objectif"] = str(sub.get(42036))
        comment = sub.get(0x9286)
        if comment:
            comment = comment[8:] if isinstance(comment, bytes) and comment[:8] in (b"ASCII\x00\x00\x00", b"UNICODE\x00", b"\x00" * 8) else comment
            info["Commentaire utilisateur"] = (comment.decode("utf-8", "ignore") if isinstance(comment, bytes) else str(comment)).strip("\x00 ")
        if sub.get(41989):
            camera["f35"] = float(sub.get(41989))
        elif sub.get(37386):
            info["Focale réelle"] = f"{float(sub.get(37386)):.1f} mm"
    except Exception:
        pass
    try:
        geo = exif.get_ifd(0x8825)
        if geo and 2 in geo and 4 in geo:
            lat, lon = dms_to_decimal(geo[2]), dms_to_decimal(geo[4])
            if lat is not None and lon is not None:
                lat = -lat if str(geo.get(1, "N")).upper().startswith("S") else lat
                lon = -lon if str(geo.get(3, "E")).upper().startswith("W") else lon
                gps = (lat, lon)
                if 6 in geo:
                    info["Altitude"] = f"{float(geo[6]):.0f} m"
                if 17 in geo:
                    camera["dir"] = float(geo[17]) % 360
    except Exception:
        pass
    image = ImageOps.exif_transpose(raw)
    info["Taille"] = f"{image.width}×{image.height}"
    if camera.get("f35"):
        side = 36 if image.width >= image.height else 24
        camera["hfov"] = round(math.degrees(2 * math.atan(side / (2 * camera["f35"]))), 1)
        info["Focale éq. 35 mm"] = f"{camera['f35']:.0f} mm · champ ≈ {camera['hfov']}°"
    if camera.get("dir") is not None:
        info["Direction de visée"] = f"{camera['dir']:.0f}° ({cardinal(camera['dir'])})"
    return image, info, gps, camera
