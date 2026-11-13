#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAT.EXE // OSINT TOOL
Outil d'audit d'exposition : géoloc photo, pseudos, domaine/IP, dorks, entreprises.
A utiliser sur tes propres comptes, domaines et photos, ou avec l'accord de la personne concernee.
"""
import os
import sys
import re
import io
import json
import ssl
import socket
import base64
import time
import math
import datetime
import webbrowser
import random
import hashlib
import concurrent.futures as cf
from pathlib import Path
from .config import load_config
from .core_utils import clean_path, haversine, parse_json, stamp
from .diagnostics import collect_checks
from .http_client import create_session
from .modules.geolocation import GeoHypothesis, confidence_text, limitation_text, rank_hypotheses
from .modules.financial_identifiers import decode_vin, validate_iban
from .modules.ai_router import AI_PROFILES, configured_model, profile_for
from .modules.search import APPROX, EXACT
from .modules.cyber_catalog import categories as cyber_categories, load_catalog, platforms as cyber_platforms, risk_label, search_tools
from .modules.ip_attribution import summarize_ip_sources
from .modules.geoint.elevation import MAX_POINTS_PER_REQUEST, fetch_open_meteo_elevations, great_circle_profile
from .modules.geoint.line_of_sight import analyze_sightline
from .modules.geoint.triangulation import BearingObservation, intersect_bearings
from .modules.username_utils import normalize_username
from .modules.menu_registry import KEYW, build_sections
from .modules.metadata import cardinal, read_exif
from .modules.secure_store import SecretStore
from .modules.sources.results import SourceResult, result_from_probe, source_error
from .modules.ui import UIContext, ask_num as ui_ask_num, ask_text as ui_ask_text, ask_yes as ui_ask_yes, read_key as ui_read_key, select as ui_select

try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn
    from rich.markup import escape
    from rich.live import Live
    from rich.text import Text
    from rich import box
except ImportError:
    print("Modules manquants. Lance : pip install -r requirements.txt")
    sys.exit(1)

if sys.version_info < (3, 11):
    print(f"CAT.EXE a besoin de Python 3.11 minimum (tu as {sys.version_info.major}.{sys.version_info.minor}).")
    print("Installe Python 3.11 ou plus récent depuis python.org (ou : winget install Python.Python.3.11), puis relance.")
    input("Entrée pour quitter… ")
    sys.exit(1)

HEIF_OK = False
try:
    from PIL import Image
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
        HEIF_OK = True
    except Exception:
        pass
except ImportError:
    Image = None
try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier, geocoder as pn_geo, timezone as pn_tz
except ImportError:
    phonenumbers = None

VERSION = "6.3"

if os.name == "nt":
    os.system("")
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
OUT = BASE / "resultats"
OUT.mkdir(exist_ok=True)
CFG_FILE = BASE / "config.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
HTTP = create_session()
con = Console(highlight=False)
G, P, Y, R, B, M = "bold #00e5ff", "bold #b388ff", "#ffc861", "bold #ff5c7a", "#7aa2ff", "#7480a8"

CFG = load_config(CFG_FILE)
SECRETS_FILE = BASE / "secrets.json"
SECRETS = SecretStore(SECRETS_FILE)
_legacy_secret_keys = dict(CFG.get("keys") or {})
_migrated_secrets = False
for _key_name, _key_value in _legacy_secret_keys.items():
    if _key_value and not SECRETS.get("api_" + _key_name):
        SECRETS.set("api_" + _key_name, str(_key_value))
        _migrated_secrets = True
if _legacy_secret_keys:
    CFG.pop("keys", None)
    _migrated_secrets = True
if _migrated_secrets:
    CFG_FILE.write_text(json.dumps(CFG, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    try:
        os.chmod(CFG_FILE, 0o600)
    except OSError:
        pass
REPORT = []
AI_CALLS = 0


def secret_get(name, default=""):
    return SECRETS.get(name, default)

# ============================================================ LANGUES
LANGS = [("fr", "Français"), ("en", "English"), ("es", "Español"), ("de", "Deutsch"), ("it", "Italiano"), ("pt", "Português"), ("nl", "Nederlands"),
         ("pl", "Polski"), ("tr", "Türkçe"), ("ru", "Русский"), ("ar", "العربية"), ("ja", "日本語"), ("zh-CN", "中文")]
LANG_EN = {"fr": "French", "en": "English", "es": "Spanish", "de": "German", "it": "Italian", "pt": "Portuguese", "nl": "Dutch", "pl": "Polish",
           "tr": "Turkish", "ru": "Russian", "ar": "Arabic", "ja": "Japanese", "zh-CN": "Chinese"}
LANG = {"code": "fr", "tr": {}, "rx": None}
LANG_DIR = BASE / "lang"


def lang_load(code):
    LANG.update(code=code, tr={}, rx=None)
    if code == "fr":
        return True
    try:
        d = json.loads((LANG_DIR / f"{code}.json").read_text(encoding="utf-8"))
    except Exception:
        return False
    d = {k: v for k, v in d.items() if v and v != k}
    LANG["tr"] = d
    LANG["rx"] = re.compile("(?<![A-Za-zÀ-ÿ])(" + "|".join(re.escape(k) for k in sorted(d, key=len, reverse=True)) + ")(?![A-Za-zÀ-ÿ])") if d else None
    return True


def tr(s):
    if not isinstance(s, str) or not LANG["rx"]:
        return s
    return LANG["rx"].sub(lambda m: LANG["tr"].get(m.group(1), m.group(1)), s)


def _tr_obj(o):
    if isinstance(o, str):
        return tr(o)
    if isinstance(o, Table):
        if isinstance(o.title, str):
            o.title = tr(o.title)
        for c in o.columns:
            if isinstance(c.header, str):
                c.header = tr(c.header)
            c._cells = [_tr_obj(x) for x in c._cells]
    elif isinstance(o, Panel):
        o.renderable = _tr_obj(o.renderable)
        for a in ("title", "subtitle"):
            if isinstance(getattr(o, a), str):
                setattr(o, a, tr(getattr(o, a)))
    return o


_con_print, _con_rule, _con_status, _prompt_ask = con.print, con.rule, con.status, Prompt.ask
con.print = lambda *a, **k: _con_print(*[_tr_obj(x) for x in a], **k)
con.rule = lambda title="", *a, **k: _con_rule(tr(title), *a, **k)
con.status = lambda status="", *a, **k: _con_status(tr(status), *a, **k)
Prompt.ask = lambda prompt="", *a, **k: _prompt_ask(tr(prompt), *a, **k)


def ai_lang(prompt):
    """Les consignes « en français » données à l'IA suivent la langue choisie."""
    if LANG["code"] == "fr":
        return prompt
    nm = LANG_EN.get(LANG["code"], "English")
    return re.sub(r"(?i)\b(en français|in french)\b", f"in {nm}", tr(prompt)) + f"\n(Answer in {nm}.)"


def lang_download(code):
    """Traduit tous les textes de l'outil dans une nouvelle langue (une seule fois, gratuit)."""
    base = LANG_DIR / "textes.json"
    try:
        frags = list(json.loads(base.read_text(encoding="utf-8")))
    except Exception:
        con.print(f"[{R}]Fichier lang/textes.json manquant.")
        return False
    out, batch, size = {}, [], 0

    def flush(pr, t):
        nonlocal batch, size
        if not batch:
            return
        res = None
        try:
            r = HTTP.post("https://translate.googleapis.com/translate_a/single", params={"client": "gtx", "sl": "fr", "tl": code, "dt": "t"},
                          data={"q": "\n".join(batch)}, timeout=40)
            res = "".join(x[0] for x in r.json()[0] if x and x[0]).split("\n")
        except Exception:
            pass
        if res and len(res) == len(batch):
            out.update({a: b.strip() for a, b in zip(batch, res) if b.strip()})
        pr.update(t, advance=len(batch))
        batch, size = [], 0
    with Progress(TextColumn(f"[{G}]Traduction"), BarColumn(complete_style="#00e5ff"), TaskProgressColumn(), console=con) as pr:
        t = pr.add_task("", total=len(frags))
        for f in frags:
            if size + len(f) > 3000:
                flush(pr, t)
            batch.append(f)
            size += len(f) + 1
        flush(pr, t)
    if len(out) < len(frags) * .5:
        con.print(f"[{R}]Traduction incomplète (connexion ?).")
        return False
    LANG_DIR.mkdir(exist_ok=True)
    (LANG_DIR / f"{code}.json").write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    return True


lang_load(CFG.get("lang", "fr"))


def log(msg, style=M):
    con.print(f"[{M}]{datetime.datetime.now():%H:%M:%S}[/] [{style}]{escape(str(msg))}[/]")


# ============================================================ 🎨 THÈMES DE COULEURS
# Toutes les couleurs du code sont écrites dans le thème « Cyber » ; un autre thème les remplace à l'affichage
# (terminal via rich.Color.parse, pages HTML via theme_html()).
def _hx(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def _mix(a, b, t):
    a, b = _hx(a), _hx(b)
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


THEMES = {  # nom : (couleur principale, accent, fond, description)
    "graphite": ("#d9dce1", "#e0a83a", "#111315", "gris / ambre, sobre · par défaut"),
    "cyber": ("#00e5ff", "#b388ff", "#07081a", "cyan / violet néon"),
    "nord": ("#88c0d0", "#b48ead", "#1c2029", "bleu polaire / mauve (Nord)"),
    "tokyo": ("#7aa2f7", "#bb9af7", "#16161e", "bleu nuit / lilas (Tokyo Night)"),
    "gruvbox": ("#fabd2f", "#fe8019", "#1d2021", "jaune rétro / orange (Gruvbox)"),
    "monokai": ("#a6e22e", "#f92672", "#1e1f1c", "vert / rose (Monokai)"),
    "solarized": ("#2aa198", "#b58900", "#002b36", "sarcelle / or (Solarized)"),
    "catppuccin": ("#89dceb", "#f5c2e7", "#181825", "pastel bleu / rose"),
    "rosepine": ("#ebbcba", "#c4a7e7", "#191724", "rose poudré / iris"),
    "forest": ("#8fbc8f", "#d9c27e", "#0e1410", "vert forêt / sable"),
    "lava": ("#ff6b35", "#ffd23f", "#140a06", "orange lave / jaune"),
    "cobalt": ("#4d9de0", "#ffc600", "#0b1a2b", "bleu cobalt / jaune"),
    "wine": ("#c9485b", "#e8c39e", "#160a0e", "bordeaux / crème"),
    "paper": ("#f5f0e6", "#c97b4a", "#1a1815", "papier / terre cuite"),
    "matrix": ("#39ff14", "#00c853", "#020a04", "vert terminal façon Matrix"),
    "synthwave": ("#ff2bd6", "#7c4dff", "#0d0221", "rose néon / violet années 80"),
    "blood": ("#ff3b3b", "#ff9e3b", "#0d0505", "rouge sang / orange"),
    "ocean": ("#00d4c8", "#2f80ed", "#021014", "turquoise / bleu profond"),
    "gold": ("#ffd166", "#ff9f1c", "#0c0904", "or / ambre"),
    "ice": ("#e0f7ff", "#7ab8ff", "#060a10", "blanc glacé / bleu"),
    "dracula": ("#bd93f9", "#ff79c6", "#15161e", "violet / rose (Dracula)"),
    "toxic": ("#c6ff00", "#00e676", "#070a02", "vert acide"),
    "sakura": ("#ff8fab", "#ffd6e0", "#120a0e", "rose cerisier"),
    "amber": ("#ffb000", "#ff6a00", "#0a0600", "vieux terminal ambre"),
    "mono": ("#ffffff", "#9e9e9e", "#0a0a0a", "noir et blanc"),
    "sunset": ("#ff7e5f", "#feb47b", "#120806", "coucher de soleil"),
    "aurora": ("#00ffa3", "#dc1fff", "#05040f", "aurore boréale"),
}
DEFAULT_THEME = "graphite"
_BASE = {"p": "#00e5ff", "a": "#b388ff", "bg": "#07081a"}
THEME_MAP = {}


def theme_colors(name):
    p, a, bg, _ = THEMES.get(name, THEMES["cyber"])
    tx = _mix("#ffffff", p, .1)
    return {  # couleur « Cyber » → couleur du thème
        "#00e5ff": p, "#b388ff": a,
        "#33ccff": _mix(p, a, .2), "#66b3ff": _mix(p, a, .4), "#8c9eff": _mix(p, a, .6), "#a78bfa": _mix(p, a, .8), "#c084fc": _mix(a, "#ffffff", .15),
        "#00b8d4": _mix(p, bg, .2), "#3f7fd9": _mix(p, a, .5) if name != "mono" else "#bdbdbd", "#4a3fa0": _mix(a, bg, .45), "#2a2266": _mix(a, bg, .7),
        "#e4e9ff": tx, "#7480a8": _mix(tx, bg, .45), "#a3acd1": _mix(tx, bg, .25), "#2b3158": _mix(a, bg, .72), "#343a66": _mix(a, bg, .65),
        "#22305a": _mix(p, bg, .75), "#1a1f40": _mix(a, bg, .82), "#14173a": _mix(a, bg, .86), "#0e1028": _mix(a, bg, .92), "#0b0d22": _mix(a, bg, .94),
        "#07081a": bg, "#050816": _mix(bg, "#000000", .3), "#03040e": _mix(bg, "#000000", .5), "#000d1a": _mix(p, bg, .93),
        "#3a1f5a": _mix(a, bg, .6), "#0b1630": _mix(p, bg, .88), "#1a0b30": _mix(a, bg, .88), "#7aa2ff": _mix(p, "#7aa2ff", .5),
    }


def apply_theme(name=None):
    """Active un thème dans le terminal (sans redémarrer)."""
    from rich.color import Color
    from rich.style import Style
    name = name or CFG.get("theme", DEFAULT_THEME)
    THEME_MAP.clear()
    if name != "cyber":
        THEME_MAP.update({k: v for k, v in theme_colors(name).items() if k != v})
    if not hasattr(Color, "_cat_orig"):
        Color._cat_orig = Color.parse

        def _parse(cls, color):
            c = color.strip().lower()
            return Color._cat_orig(THEME_MAP.get(c, color) if c.startswith("#") else color)
        Color.parse = classmethod(_parse)
    for obj in (Style.__dict__.get("parse"), Style.__dict__.get("normalize"), Style.__dict__.get("_add")):
        f = getattr(obj, "__func__", obj)
        if hasattr(f, "cache_clear"):
            f.cache_clear()
    try:
        con._style_cache.clear() if hasattr(con, "_style_cache") else None
    except Exception:
        pass


# ============================================================ STYLE SOBRE (sans emojis dans le terminal)
_EMO = re.compile("(?:[\U0001F000-\U0001FAFF☀-⛿✀-➿⌀-⏿⬀-⯿₿〰〽ℹ™Ⓜ]"
                  "(?<![✔✘✓✗⚠✚❯➜✦★☆•])️?(?:‍[\U0001F000-\U0001FAFF☀-➿]️?)*)+[ \t]*")


def _desemo(s):
    return _EMO.sub("", s) if "️" in s or any(ord(c) > 0x20A0 for c in s) else s


def sober_patch():
    """Mode sobre : les emojis sont retirés à l'affichage (menus, titres, tableaux, tutos). Réglable dans Réglages → Style."""
    from rich.text import Text as _T
    if getattr(_T, "_cat_sober", False):
        return
    oi, oa = _T.__init__, _T.append

    def __init__(self, text="", *a, **k):
        oi(self, _desemo(text) if CFG.get("sobre", True) and isinstance(text, str) and text else text, *a, **k)

    def append(self, text, style=None):
        if CFG.get("sobre", True) and isinstance(text, str) and text:
            text = _desemo(text)
        return oa(self, text, style)
    _T.__init__, _T.append, _T._cat_sober = __init__, append, True


sober_patch()
try:
    from rich.theme import Theme as _Th
    con.push_theme(_Th({"rule.line": "#2b3158"}))
except Exception:
    pass


def theme_html(s):
    """Applique le thème aux pages web générées (cartes, graphe, rapports)."""
    if not THEME_MAP:
        return s
    return re.sub(r"#[0-9a-fA-F]{6}(?![0-9a-fA-F])", lambda m: THEME_MAP.get(m.group(0).lower(), m.group(0)), s)


try:
    apply_theme()
except Exception:
    pass


def get(url, timeout=12, **kw):
    return HTTP.get(url, timeout=timeout, **kw)


def get_json(url, timeout=12, **kw):
    r = get(url, timeout, **kw)
    r.raise_for_status()
    return r.json()


def add_report(mod, title, text):
    safe_title = SECRETS.redact(title)
    safe_text = SECRETS.redact(text)
    REPORT.append({"mod": mod, "title": safe_title, "text": safe_text, "t": datetime.datetime.now().strftime("%d/%m/%Y %H:%M")})
    graph_feed(mod, safe_title, safe_text)


def pause():
    Prompt.ask(f"\n[{M}]Entrée pour revenir au menu[/]", default="", show_default=False)


_SRV = {}


def local_server():
    """Petit serveur web local (127.0.0.1) : les pages s'ouvrent en http:// et plus en file://,
    ce qui évite les cartes grises (tuiles refusées sans « Referer ») et les recherches bloquées."""
    if "port" not in _SRV:
        import http.server
        import threading
        import functools

        class H(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def end_headers(self):
                self.send_header("Cache-Control", "no-store")
                super().end_headers()

            def do_POST(self):
                if self.path == "/api/transform":
                    try:
                        q = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                        added, msg = graph_transform(q.get("e"), q.get("id"), q.get("t"))
                        out = {"ok": True, "added": added, "msg": msg}
                    except Exception as e:
                        out = {"ok": False, "error": sl_err(e) if "sl_err" in globals() else str(e)}
                    body = json.dumps(out, ensure_ascii=False).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                m = re.fullmatch(r"/api/enquete/([\w-]{1,40})", self.path)
                try:
                    data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                    assert m and isinstance(data.get("nodes"), dict)
                    d = OUT / "enquetes"
                    d.mkdir(parents=True, exist_ok=True)
                    (d / f"{m.group(1)}.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
                    if _G.get("name") == m.group(1):
                        _G.clear()
                    self.send_response(204)
                except Exception:
                    self.send_response(400)
                self.end_headers()
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(H, directory=str(OUT.resolve())))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        _SRV["port"] = srv.server_address[1]
    return _SRV["port"]


def open_file(path):
    p = Path(path).resolve()
    if THEME_MAP and p.suffix.lower() in (".html", ".htm"):
        try:
            p.write_text(theme_html(p.read_text(encoding="utf-8")), encoding="utf-8")
        except Exception:
            pass
    url = p.as_uri()
    try:
        if p.suffix.lower() in (".html", ".htm") and p.is_relative_to(OUT.resolve()):
            url = f"http://127.0.0.1:{local_server()}/" + "/".join(requests.utils.quote(x) for x in p.relative_to(OUT.resolve()).parts)
    except Exception:
        pass
    try:
        webbrowser.open(url)
    except Exception:
        pass
    return url


# ============================================================ IA
_AI_ASKED = {}


def ask_ai(prompt, img_b64=None, on_token=None, task="text"):
    """IA 100 % locale routée par tâche ; ``on_token`` reçoit le texte au fil de l'eau."""
    prompt = ai_lang(prompt)
    profile = profile_for(task, image=bool(img_b64))
    want = configured_model(task, CFG, image=bool(img_b64))
    m = ollama_setup(interactive=False, m=want)
    if not m and not _AI_ASKED.get(want):
        _AI_ASKED[want] = True
        m = ollama_setup(interactive=True, m=want)
    if not m:
        raise RuntimeError(f"IA locale indisponible : installe Ollama et le profil {profile.label} ({want}) via le menu Réglages → IA locale")
    msg = {"role": "user", "content": prompt}
    if img_b64:
        msg["images"] = [img_b64]
    out = []
    with OLL.post(OLLAMA + "/api/chat", json={"model": m, "messages": [msg], "stream": True, "options": {"num_ctx": 8192}}, stream=True, timeout=1800) as r:
        r.raise_for_status()
        for line in r.iter_lines():
            if not line:
                continue
            j = json.loads(line)
            if j.get("error"):
                raise RuntimeError(j["error"])
            t = j.get("message", {}).get("content", "")
            if t:
                out.append(t)
                if on_token:
                    on_token("".join(out))
            if j.get("done"):
                break
    return "".join(out)


def ai_print(prompt, title="Analyse IA", img=None, task="text"):
    global AI_CALLS
    AI_CALLS += 1
    from rich.markdown import Markdown

    def box_(text):
        return Panel(Markdown(text) if text else Text(tr("L'IA locale réfléchit…"), style=M), title=f"[{P}]{escape(tr(title))}", border_style=P, box=box.ROUNDED, padding=(1, 2))

    try:
        with Live(box_(""), console=con, refresh_per_second=12, transient=True) as live:
            t = ask_ai(prompt, img, on_token=lambda x: live.update(box_(x[-6000:])), task=task)
    except Exception as e:
        if "IA locale indisponible" in str(e) or isinstance(e, requests.ConnectionError):
            con.print(Panel(tr("L'IA locale n'est pas encore installée : le reste du module marche sans elle.\nPour l'activer : menu Réglages → IA locale (gratuit, tourne sur ton PC)."),
                            title="🤖 IA locale", border_style=Y))
        else:
            con.print(Panel(escape(str(e)), title="Erreur IA", border_style=R))
        return None
    con.print(box_(t))
    return t


# ============================================================ MENUS AUX FLÈCHES
# Les implémentations vivent dans catexe.modules.ui ; ces façades préservent
# les signatures historiques utilisées par les modules existants.
ARROWS = sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("CATEXE_NOARROW")
SEL_STYLE = "bold #050816 on #00e5ff"
_UI = UIContext(
    con=con,
    tr=tr,
    escape=escape,
    colors={"G": G, "P": P, "Y": Y, "M": M},
    arrows=ARROWS,
    sel_style=SEL_STYLE,
)


def read_key():
    return ui_read_key()


def select(title, items, default=None, back=True, side=None, height=None, echo=True, hint=None, side_min=96, paged=False, keys=()):
    return ui_select(_UI, title, items, default, back, side, height, echo, hint, side_min, paged, keys)


def ask_yes(q, default=False):
    return ui_ask_yes(_UI, q, default, LANG["code"])


def ask_num(q, default="0"):
    return ui_ask_num(_UI, q, default)


def ask_text(q, default=None, password=False):
    return ui_ask_text(_UI, q, default, password)


# ============================================================ 1. GÉOLOC PHOTO
NOMI = {"User-Agent": "CatExe-OSINT/2.1 (outil d'audit)"}


def img_b64(img, maxs=1280):
    im = img.convert("RGB")
    im.thumbnail((maxs, maxs))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=85)
    return base64.b64encode(buf.getvalue()).decode()


def escape_html(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def place_name(lat, lon, zoom=14):
    try:
        j = get_json("https://nominatim.openstreetmap.org/reverse", 10, headers=NOMI,
                     params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": zoom, "accept-language": "fr"})
        a = j.get("address", {})
        parts = [" ".join(x for x in (a.get("house_number"), a.get("road")) if x) if zoom >= 17 else None,
                 a.get("neighbourhood"), a.get("quarter"), a.get("suburb"),
                 a.get("city") or a.get("town") or a.get("village") or a.get("municipality"), a.get("state"), a.get("country")]
        return ", ".join(dict.fromkeys(x for x in parts if x and not re.search(r"community board|arrondissement municipal", x, re.I)))
    except Exception:
        return ""


def geocode(q, near=None):
    params = {"format": "jsonv2", "limit": 1, "q": q, "accept-language": "fr"}
    if near:
        params["viewbox"] = f"{near[1] - .4},{near[0] + .4},{near[1] + .4},{near[0] - .4}"
    try:
        j = get_json("https://nominatim.openstreetmap.org/search", 10, headers=NOMI, params=params)
        return (float(j[0]["lat"]), float(j[0]["lon"])) if j else None
    except Exception:
        return None


# --- IA locale sans clé : GeoCLIP (prédit la position GPS d'où la photo a été prise)
_GEOCLIP = None


def geoclip_ready():
    try:
        import geoclip  # noqa
        return True
    except Exception:
        return False


def geoclip_install():
    import subprocess
    if getattr(sys, "frozen", False):
        log("Dans la version .exe, l'IA GeoCLIP ne peut pas s'installer : lance l'outil avec LANCER.bat pour l'avoir.", Y)
        return False
    cmds = [[sys.executable, "-m", "pip", "install", "torch", "torchvision", "--index-url", "https://download.pytorch.org/whl/cpu"],
            [sys.executable, "-m", "pip", "install", "geoclip"]]
    for c in cmds:
        log("$ pip " + " ".join(c[3:]), B)
        if subprocess.run(c).returncode != 0:
            log("Installation échouée.", R)
            return False
    return geoclip_ready()


def free_geoclip():
    """Libère la RAM de GeoCLIP (laisse la place à l'IA de vision)."""
    global _GEOCLIP
    _GEOCLIP = None
    import gc
    gc.collect()


def geoclip_predict(img, k=5):
    global _GEOCLIP
    import warnings
    warnings.filterwarnings("ignore")
    from geoclip import GeoCLIP
    if _GEOCLIP is None:
        _GEOCLIP = GeoCLIP()
    tmp = OUT / ".geoclip_tmp.jpg"
    img.convert("RGB").save(tmp, "JPEG", quality=92)
    gps, prob = _GEOCLIP.predict(str(tmp), top_k=k)
    try:
        tmp.unlink()
    except Exception:
        pass
    out, seen = [], set()
    for g, p in zip(gps, prob):
        key = (round(float(g[0]), 3), round(float(g[1]), 3))
        if key not in seen:
            seen.add(key)
            out.append((float(g[0]), float(g[1]), float(p)))
    tot = sum(p for *_, p in out) or 1
    return [(a, b, p / tot) for a, b, p in out]


def vantage_html(img, layers, prefill, gps, cam, center):
    data = {"layers": layers, "prefill": prefill, "gps": list(gps) if gps else None, "exifDir": cam.get("dir"), "fov": cam.get("hfov"),
            "f35": cam.get("f35"), "center": list(center) if center else None}
    return VANTAGE_TPL.replace("__LEAFLET__", LEAFLET_HEAD).replace("__IMG__", img_b64(img, 1600)).replace("__DATA__", json.dumps(data))


VANTAGE_TPL = r"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cat.exe · Position du photographe</title>
__LEAFLET__
<style>
:root{--bg:#07081a;--p:#0e1028;--l:#2b3158;--t:#e4e9ff;--m:#7480a8;--g:#00e5ff;--k:#b388ff;--y:#ffc861}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font-family:system-ui,-apple-system,sans-serif}
header{padding:12px 16px;border-bottom:1px solid var(--l);display:flex;gap:14px;align-items:baseline;flex-wrap:wrap}
header b{font-family:monospace;color:var(--g);font-size:16px}header span{color:var(--m);font-size:13px}header a{margin-left:auto;color:#8a8cff;font:13px monospace}
.wrap{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;padding:12px}
@media(max-width:900px){.wrap{grid-template-columns:1fr}}
.card{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:12px;min-width:0}
#ph{position:relative;cursor:crosshair;user-select:none}#ph img{width:100%;display:block;border-radius:8px}
.vl{position:absolute;top:0;bottom:0;width:2px;margin-left:-1px;background:var(--k);pointer-events:none;box-shadow:0 0 6px var(--k)}
.vl i{position:absolute;top:6px;left:5px;background:var(--k);color:#fff;font:700 11px monospace;padding:2px 6px;border-radius:4px;font-style:normal;white-space:nowrap}
.vl.pend{background:var(--y);box-shadow:0 0 6px var(--y)}.vl.pend i{background:var(--y);color:#000}
#map{height:560px;border-radius:8px}
.steps{font-size:13px;color:var(--m);line-height:1.6}.steps b{color:var(--g)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
input,select{background:#14173a;border:1px solid var(--l);color:var(--t);padding:8px 10px;border-radius:8px;font:13px monospace}
button{background:var(--g);color:#000d1a;border:0;padding:9px 14px;border-radius:8px;font-weight:700;cursor:pointer}
button.gh{background:transparent;color:var(--t);border:1px solid var(--l)}
#lm div{display:flex;justify-content:space-between;gap:8px;padding:6px 8px;border:1px solid var(--l);border-radius:8px;margin-top:6px;font:12px monospace}
#lm a{color:#ff5c7a;text-decoration:none}
#sr div{padding:7px 8px;border-bottom:1px solid var(--l);cursor:pointer;font-size:13px}#sr div:hover{color:var(--g)}
#out{font-size:14px;line-height:1.65;margin-top:6px}#out a{color:var(--g)}
#out .big{font-size:20px;font-weight:700;color:var(--k);font-family:monospace}
#out .note{color:var(--y);font-size:13px}
.st{font:13px monospace;color:var(--y);margin-top:8px}
.leg{font:12px monospace;color:var(--m);margin-top:6px;display:flex;gap:12px;flex-wrap:wrap}
</style></head><body>
<header><b>CAT.exe // POSITION DU PHOTOGRAPHE</b><span>où se tenait la personne qui a pris la photo</span></header>
<div class="wrap">
 <div class="card">
  <div id="ph"><img id="img" src="data:image/jpeg;base64,__IMG__" alt=""></div>
  <div class="st" id="st"></div>
  <div class="steps" style="margin-top:8px">
   <b>1.</b> Clique le sommet d'un repère reconnaissable dans la photo (tour, clocher, antenne…).<br>
   <b>2.</b> Indique où il se trouve : cherche son nom à droite, ou clique dessus sur la carte.<br>
   <b>3.</b> 3 repères minimum (4 c'est mieux), bien répartis de gauche à droite, puis <b>Calculer</b>.
  </div>
  <div id="lm"></div>
  <div class="row"><span style="font-size:13px;color:var(--m)">Focale</span>
   <select id="fovm"><option value="auto">inconnue (calcul auto)</option><option value="fix">je la connais</option></select>
   <input id="f35" type="number" min="8" max="800" placeholder="mm éq. 35 mm" style="width:140px"></div>
  <div class="row"><button id="calc">📷 Calculer la position</button><button class="gh" id="reset">Effacer les repères</button></div>
  <div id="out"></div>
 </div>
 <div class="card">
  <div class="row"><input id="q" placeholder="chercher un repère (ex. Tour Eiffel)" style="flex:1"><button class="gh" id="go">Chercher</button></div>
  <div id="sr"></div>
  <div id="map"></div>
  <div class="leg"><span style="color:#00e5ff">● GPS du fichier</span><span style="color:#b388ff">● GeoCLIP n°1</span><span style="color:#ffc861">● autres pistes</span><span style="color:#b388ff">▦ zone du photographe</span></div>
 </div>
</div>
<script>
const D=__DATA__;
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const R2D=180/Math.PI, D2R=Math.PI/180;
const wrap=a=>{a=(a+Math.PI)%(2*Math.PI);if(a<0)a+=2*Math.PI;return a-Math.PI;};
const CARD=d=>['nord','nord-est','est','sud-est','sud','sud-ouest','ouest','nord-ouest'][Math.floor(((d%360+360)%360+22.5)/45)%8];
const img=$('#img'), ph=$('#ph');
let pts=(D.prefill||[]).slice(), pend=null;
const map=catMap('map',{center:D.center||[46.6,2.4],zoom:D.center?13:5,clickCoords:false});
const base=L.featureGroup().addTo(map), lmL=L.layerGroup().addTo(map), resL=L.layerGroup().addTo(map);
(D.layers||[]).forEach(p=>{L.circleMarker([p.lat,p.lon],{radius:7,color:p.c,fillOpacity:.85}).bindPopup(esc(p.label)).addTo(base);if(p.r)L.circle([p.lat,p.lon],{radius:p.r,color:p.c,fillOpacity:.05,weight:1,dashArray:'4 4'}).addTo(base);});
if(D.gps&&D.exifDir!=null)cone(D.gps[0],D.gps[1],D.exifDir*D2R,(D.fov||60)*D2R,700,'#00e5ff',base);
const fitAll=()=>{const g=L.featureGroup([...base.getLayers(),...lmL.getLayers()]);if(g.getLayers().length)map.fitBounds(g.getBounds(),{padding:[40,40],maxZoom:15});else if(D.center)map.setView(D.center,13);else map.setView([46.6,2.4],5);};
if(D.f35){$('#fovm').value='fix';$('#f35').value=Math.round(D.f35);}

function cone(lat,lon,h,f,len,color,layer){const kx=111320*Math.cos(lat*D2R),ky=110540,P=[[lat,lon]];
 for(let a=h-f/2;a<=h+f/2+1e-9;a+=f/24)P.push([lat+Math.cos(a)*len/ky,lon+Math.sin(a)*len/kx]);
 L.polygon(P,{color,weight:1,fillOpacity:.12}).addTo(layer);}
function draw(){
 ph.querySelectorAll('.vl').forEach(e=>e.remove());
 pts.forEach((p,i)=>vline(p.x,String(i+1),false));
 if(pend!=null)vline(pend,'? → place-le sur la carte',true);
 lmL.clearLayers();
 pts.forEach((p,i)=>L.marker([p.lat,p.lon],{icon:L.divIcon({className:'',iconSize:null,html:`<div style="background:#b388ff;color:#fff;font:700 11px monospace;padding:2px 6px;border-radius:5px;white-space:nowrap;transform:translate(-50%,-50%)">${i+1} ${esc((p.name||'').split(',')[0])}</div>`})}).addTo(lmL));
 $('#lm').innerHTML=pts.map((p,i)=>`<div><span>${i+1}. ${esc((p.name||'repère').split(',')[0])} · x ${(p.x*100).toFixed(1)}% · ${p.lat.toFixed(5)}, ${p.lon.toFixed(5)}</span><a href="#" data-del="${i}">✕</a></div>`).join('');
 document.querySelectorAll('[data-del]').forEach(a=>a.onclick=e=>{e.preventDefault();pts.splice(+a.dataset.del,1);draw();});
 $('#st').textContent=pend!=null?'→ Indique maintenant ce repère sur la carte : recherche son nom ou clique dessus':pts.length<3?`→ Clique un repère dans la photo (${pts.length}/3 minimum)`:`✓ ${pts.length} repères : clique sur Calculer (ou ajoute-en un autre)`;
}
function vline(x,label,pending){const d=document.createElement('div');d.className='vl'+(pending?' pend':'');d.style.left=(x*100)+'%';d.innerHTML=`<i style="${x>.7?'left:auto;right:5px':''}">${esc(label)}</i>`;ph.appendChild(d);}
ph.addEventListener('click',e=>{const r=img.getBoundingClientRect();pend=Math.min(1,Math.max(0,(e.clientX-r.left)/r.width));draw();$('#q').focus();});
map.on('click',e=>{if(pend==null)return;pts.push({x:pend,lat:e.latlng.lat,lon:e.latlng.lng,name:$('#q').value.trim()||('repère '+(pts.length+1))});pend=null;$('#q').value='';draw();});
async function search(){const q=$('#q').value.trim();if(!q)return;$('#sr').innerHTML='<div>Recherche…</div>';
 const b=map.getBounds(),vb=[b.getWest(),b.getNorth(),b.getEast(),b.getSouth()].join(',');
 try{const j=await catGeocode(q,vb);
  $('#sr').innerHTML=j.length?j.map((x,i)=>`<div data-i="${i}">📍 ${esc(x.name)}</div>`).join(''):'<div>Aucun résultat : clique directement sur la carte.</div>';
  document.querySelectorAll('#sr [data-i]').forEach(el=>el.onclick=()=>{const x=j[+el.dataset.i],lat=+x.lat,lon=+x.lon;
   if(pend!=null){pts.push({x:pend,lat,lon,name:q});pend=null;$('#q').value='';draw();}else map.setView([lat,lon],16);$('#sr').innerHTML='';});
 }catch(e){$('#sr').innerHTML='<div>Recherche indisponible : clique sur la carte.</div>';}}
$('#go').onclick=search;$('#q').addEventListener('keydown',e=>{if(e.key==='Enter')search();});
$('#reset').onclick=()=>{pts=[];pend=null;resL.clearLayers();$('#out').innerHTML='';draw();};

// ---- résolution : trouve le point d'où les repères apparaissent à ces positions dans l'image
function solve(P,fovFix){
 const n=P.length,lat0=P.reduce((s,p)=>s+p.lat,0)/n,lon0=P.reduce((s,p)=>s+p.lon,0)/n,kx=111320*Math.cos(lat0*D2R),ky=110540;
 const Lm=P.map(p=>({X:(p.lon-lon0)*kx,Y:(p.lat-lat0)*ky,x:p.x}));
 let spread=0;Lm.forEach(a=>Lm.forEach(b=>spread=Math.max(spread,Math.hypot(a.X-b.X,a.Y-b.Y))));
 const Rm=Math.min(40000,Math.max(2500,spread*14));
 const mk=fs=>fs.map(f=>({f,a:Lm.map(l=>Math.atan((l.x-.5)*2*Math.tan(f*D2R/2)))}));
 const coarseF=mk(fovFix?[fovFix]:Array.from({length:52},(_,i)=>8+i*2));
 function ev(cx,cy,FS){const be=[];for(const l of Lm){if(Math.hypot(l.X-cx,l.Y-cy)<60)return null;be.push(Math.atan2(l.X-cx,l.Y-cy));}
  let best=null;for(const F of FS){let s=0,c=0;for(let i=0;i<n;i++){const d=be[i]-F.a[i];s+=Math.sin(d);c+=Math.cos(d);}const h=Math.atan2(s,c);let e=0;for(let i=0;i<n;i++){const r=wrap(be[i]-F.a[i]-h);e+=r*r;}e=Math.sqrt(e/n);if(!best||e<best.e)best={e,h,f:F.f};}return best;}
 const N=150,step=2*Rm/N,cells=[];let best=null;
 for(let i=0;i<=N;i++)for(let j=0;j<=N;j++){const cx=-Rm+i*step,cy=-Rm+j*step,r=ev(cx,cy,coarseF);if(!r)continue;r.cx=cx;r.cy=cy;cells.push(r);if(!best||r.e<best.e)best=r;}
 if(!best)return null;
 let s=step;for(let k=0;k<3;k++){const FS=fovFix?coarseF:mk(Array.from({length:25},(_,i)=>Math.max(4,best.f-3+i*.25)));const b0=best,M=24,st=2*s/M;
  for(let i=0;i<=M;i++)for(let j=0;j<=M;j++){const cx=b0.cx-s+i*st,cy=b0.cy-s+j*st,r=ev(cx,cy,FS);if(r&&r.e<best.e){r.cx=cx;r.cy=cy;best=r;}}s=st*2;}
 const thr=Math.max(best.e*2.5,.006*best.f*D2R),zone=cells.filter(c=>c.e<=thr);
 const toLL=(x,y)=>[lat0+y/ky,lon0+x/kx];
 const d95=zone.map(c=>Math.hypot(c.cx-best.cx,c.cy-best.cy)).sort((a,b)=>a-b);
 return{best,ll:toLL(best.cx,best.cy),zone:zone.map(c=>({b:[toLL(c.cx-step/2,c.cy-step/2),toLL(c.cx+step/2,c.cy+step/2)],w:1-c.e/thr})),
  prec:d95.length?d95[Math.floor(d95.length*.9)]:0,step,dist:Lm.map(l=>Math.hypot(l.X-best.cx,l.Y-best.cy)),Rm};
}
$('#calc').onclick=async()=>{
 if(pts.length<3){$('#out').innerHTML='<span class="note">Il faut au moins 3 repères.</span>';return;}
 const fix=$('#fovm').value==='fix'&&+$('#f35').value?2*Math.atan(((img.naturalWidth>=img.naturalHeight)?36:24)/(2*+$('#f35').value))*R2D:null;
 $('#out').innerHTML='Calcul…';await new Promise(r=>setTimeout(r,30));
 const R=solve(pts,fix);resL.clearLayers();
 if(!R){$('#out').innerHTML='<span class="note">Pas de solution : vérifie les repères.</span>';return;}
 R.zone.slice(0,5000).forEach(z=>L.rectangle(z.b,{stroke:false,fillColor:'#b388ff',fillOpacity:.08+.35*z.w}).addTo(resL));
 const [la,lo]=R.ll,h=(R.best.h*R2D+360)%360,f=R.best.f,f35=18/Math.tan(f*D2R/2),far=Math.max(...R.dist);
 cone(la,lo,R.best.h,f*D2R,far*1.15,'#b388ff',resL);
 pts.forEach(p=>L.polyline([[la,lo],[p.lat,p.lon]],{color:'#ffc861',weight:1,dashArray:'3 5'}).addTo(resL));
 L.marker([la,lo],{icon:L.divIcon({className:'',iconSize:null,html:'<div style="font-size:26px;transform:translate(-50%,-50%);filter:drop-shadow(0 0 4px #000)">📷</div>'})}).addTo(resL);
 map.fitBounds(L.featureGroup([...resL.getLayers()]).getBounds(),{padding:[30,30]});
 const errD=R.best.e*R2D,prec=Math.max(R.prec,R.step/2),amb=pts.length===3&&!fix;
 let adr='';try{const a=await catReverse(la,lo)||{};adr=[[a.house_number,a.road].filter(Boolean).join(' '),a.neighbourhood,a.quarter,a.suburb,a.city||a.town||a.village].filter(x=>x&&!/community board/i.test(x)).filter((x,i,A)=>A.indexOf(x)===i).join(', ');}catch(e){}
 $('#out').innerHTML=`<div class="big">📷 ${la.toFixed(5)}, ${lo.toFixed(5)}</div>
 ${adr?`<div>Le photographe était vers : <b>${esc(adr)}</b></div>`:''}
 <div>Regard vers : <b>${h.toFixed(0)}° (${CARD(h)})</b> · champ ≈ <b>${f.toFixed(0)}°</b> (≈ ${f35.toFixed(0)} mm éq.)</div>
 <div>Précision : ± ${prec<1000?Math.round(prec)+' m':(prec/1000).toFixed(1)+' km'} · erreur angulaire ${errD.toFixed(2)}° · ${pts.length} repères</div>
 <div>Distances : ${pts.map((p,i)=>`${i+1}. ${esc((p.name||'').split(',')[0])} ${R.dist[i]<1000?Math.round(R.dist[i])+' m':(R.dist[i]/1000).toFixed(2)+' km'}`).join(' · ')}</div>
 ${errD>1.5?'<div class="note">⚠ Erreur élevée : un repère est peut-être mal placé (photo ou carte).</div>':''}
 ${amb?'<div class="note">Avec 3 repères et une focale inconnue, plusieurs positions collent (zone rose). Ajoute un 4e repère ou la focale pour trancher.</div>':''}
 <div style="margin-top:6px">Vérifier : <a target="_blank" href="https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${la},${lo}&heading=${h.toFixed(0)}">Street View dans cette direction</a> · <a target="_blank" href="https://earth.google.com/web/@${la},${lo},60a,0d,35y,${h.toFixed(0)}h,88t,0r">Google Earth 3D</a> · <a target="_blank" href="https://www.google.com/maps?q=${la},${lo}">Google Maps</a></div>`;
};
draw();fitAll();
if(pts.length>=3)setTimeout(()=>$('#calc').click(),300);
</script></body></html>"""


# ============================================================ 2. PSEUDOS
def SC(st, b, u):
    return 1 if st == 200 else 0 if st in (404, 410) else None


def J(b):
    try:
        return json.loads(b)
    except Exception:
        return None


SITES = [
    # (nom, catégorie, url profil, url de vérification ou None, fonction(status, body, pseudo) -> 1/0/None, headers)
    ("GitHub", "dev", "https://github.com/{u}", "https://api.github.com/users/{u}", SC, None),
    ("GitLab", "dev", "https://gitlab.com/{u}", "https://gitlab.com/api/v4/users?username={u}", lambda s, b, u: (1 if J(b) else 0) if isinstance(J(b), list) else None, None),
    ("Codeberg", "dev", "https://codeberg.org/{u}", "https://codeberg.org/api/v1/users/{u}", SC, None),
    ("Bitbucket", "dev", "https://bitbucket.org/{u}/", None, SC, None),
    ("npm", "dev", "https://www.npmjs.com/~{u}", "https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=1", lambda s, b, u: (1 if (J(b) or {}).get("objects") else 0) if J(b) else None, None),
    ("PyPI", "dev", "https://pypi.org/user/{u}/", None, SC, None),
    ("Docker Hub", "dev", "https://hub.docker.com/u/{u}", "https://hub.docker.com/v2/users/{u}/", SC, None),
    ("Dev.to", "dev", "https://dev.to/{u}", "https://dev.to/api/users/by_username?url={u}", SC, None),
    ("Hacker News", "dev", "https://news.ycombinator.com/user?id={u}", "https://hacker-news.firebaseio.com/v0/user/{u}.json", lambda s, b, u: None if s != 200 else (0 if b.strip() == "null" else 1), None),
    ("Replit", "dev", "https://replit.com/@{u}", None, SC, None),
    ("Kaggle", "dev", "https://www.kaggle.com/{u}", None, SC, None),
    ("HackerOne", "cyber", "https://hackerone.com/{u}", None, SC, None),
    ("TryHackMe", "cyber", "https://tryhackme.com/p/{u}", "https://tryhackme.com/api/user/exist/{u}", lambda s, b, u: 1 if re.search(r'"exists"\s*:\s*true', b) else 0 if re.search(r'"exists"\s*:\s*false', b) else None, None),
    ("Root-Me", "cyber", "https://www.root-me.org/{u}", None, SC, None),
    ("Keybase", "cyber", "https://keybase.io/{u}", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", lambda s, b, u: (1 if (J(b) or {}).get("them") and J(b)["them"][0] else 0) if J(b) else None, None),
    ("Instagram", "social", "https://www.instagram.com/{u}/", "https://i.instagram.com/api/v1/users/web_profile_info/?username={u}", lambda s, b, u: 1 if s == 200 and '"user"' in b else 0 if s == 404 else None, {"x-ig-app-id": "936619743392459"}),
    ("TikTok", "social", "https://www.tiktok.com/@{u}", None, lambda s, b, u: 0 if s == 404 else 1 if re.search('"uniqueId":"' + re.escape(u) + '"', b, re.I) else 0 if re.search(r"couldn.t find this account|statusCode\":10221", b, re.I) else None, None),
    ("Reddit", "social", "https://www.reddit.com/user/{u}", "https://www.reddit.com/user/{u}/about.json", lambda s, b, u: 1 if s == 200 and '"name"' in b else 0 if s == 404 else None, None),
    ("YouTube", "social", "https://www.youtube.com/@{u}", None, SC, None),
    ("Telegram", "social", "https://t.me/{u}", None, lambda s, b, u: None if s != 200 else (1 if "tgme_page_title" in b else 0), None),
    ("Snapchat", "social", "https://www.snapchat.com/add/{u}", None, SC, None),
    ("Threads", "social", "https://www.threads.net/@{u}", None, lambda s, b, u: 0 if s == 404 else None, None),
    ("Bluesky", "social", "https://bsky.app/profile/{u}.bsky.social", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", lambda s, b, u: 1 if s == 200 else 0 if s == 400 else None, None),
    ("Mastodon", "social", "https://mastodon.social/@{u}", "https://mastodon.social/api/v1/accounts/lookup?acct={u}", SC, None),
    ("Pinterest", "social", "https://www.pinterest.com/{u}/", None, lambda s, b, u: 0 if s == 404 else (1 if f'"username":"{u}"'.lower() in b.lower() else None), None),
    ("Tumblr", "social", "https://{u}.tumblr.com", None, SC, None),
    ("Linktree", "social", "https://linktr.ee/{u}", None, SC, None),
    ("Medium", "social", "https://medium.com/@{u}", None, SC, None),
    ("VK", "social", "https://vk.com/{u}", None, SC, None),
    ("Twitch", "gaming", "https://www.twitch.tv/{u}", None, lambda s, b, u: None, None),
    ("Kick", "gaming", "https://kick.com/{u}", "https://kick.com/api/v2/channels/{u}", SC, None),
    ("Chess.com", "gaming", "https://www.chess.com/member/{u}", "https://api.chess.com/pub/player/{u}", SC, None),
    ("Lichess", "gaming", "https://lichess.org/@/{u}", "https://lichess.org/api/user/{u}", SC, None),
    ("Steam", "gaming", "https://steamcommunity.com/id/{u}", None, lambda s, b, u: SC(s, b, u) if s != 200 else (0 if "specified profile could not be found" in b.lower() else 1 if ("profile_header" in b or "persona_name" in b) else None), None),
    ("Roblox", "gaming", "https://www.roblox.com/search/users?keyword={u}", "https://users.roblox.com/v1/users/search?keyword={u}&limit=10", lambda s, b, u: (1 if any(x.get("name", "").lower() == u.lower() for x in (J(b) or {}).get("data", [])) else 0) if s == 200 and J(b) else None, None),
    ("Scratch", "gaming", "https://scratch.mit.edu/users/{u}/", "https://api.scratch.mit.edu/users/{u}", SC, None),
    ("Duolingo", "autre", "https://www.duolingo.com/profile/{u}", "https://www.duolingo.com/2017-06-30/users?username={u}&fields=users%7Bid%7D", lambda s, b, u: (1 if (J(b) or {}).get("users") else 0) if J(b) else None, None),
    ("Wikipédia", "autre", "https://fr.wikipedia.org/wiki/Utilisateur:{u}", "https://fr.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&format=json", lambda s, b, u: (0 if "missing" in ((J(b) or {}).get("query", {}).get("users") or [{}])[0] else 1) if J(b) else None, None),
    ("SoundCloud", "créa", "https://soundcloud.com/{u}", None, SC, None),
    ("Patreon", "créa", "https://www.patreon.com/{u}", None, SC, None),
    ("Behance", "créa", "https://www.behance.net/{u}", None, SC, None),
    ("Dribbble", "créa", "https://dribbble.com/{u}", None, SC, None),
    ("Vimeo", "créa", "https://vimeo.com/{u}", None, SC, None),
    ("Flickr", "créa", "https://www.flickr.com/people/{u}", None, SC, None),
    ("DeviantArt", "créa", "https://www.deviantart.com/{u}", None, SC, None),
    ("Gravatar", "autre", "https://gravatar.com/{u}", "https://en.gravatar.com/{u}.json", SC, None),
    ("About.me", "autre", "https://about.me/{u}", None, SC, None),
    ("Minecraft", "gaming", "https://namemc.com/profile/{u}", "https://api.mojang.com/users/profiles/minecraft/{u}", lambda s, b, u: 1 if s == 200 and '"id"' in b else 0 if s in (204, 404) else None, None),
    ("Speedrun.com", "gaming", "https://www.speedrun.com/users/{u}", "https://www.speedrun.com/api/v1/users/{u}", SC, None),
    ("osu!", "gaming", "https://osu.ppy.sh/users/{u}", None, SC, None),
    ("Itch.io", "gaming", "https://{u}.itch.io", None, SC, None),
    ("Pastebin", "autre", "https://pastebin.com/u/{u}", None, SC, None),
    ("Imgur", "créa", "https://imgur.com/user/{u}", "https://api.imgur.com/account/v1/accounts/{u}?client_id=546c25a59c58ad7", SC, None),
    ("Last.fm", "créa", "https://www.last.fm/user/{u}", None, SC, None),
    ("Letterboxd", "autre", "https://letterboxd.com/{u}/", None, SC, None),
    ("MyAnimeList", "autre", "https://myanimelist.net/profile/{u}", "https://api.jikan.moe/v4/users/{u}", SC, None),
    ("Wattpad", "créa", "https://www.wattpad.com/user/{u}", "https://www.wattpad.com/api/v3/users/{u}", SC, None),
    ("Discogs", "autre", "https://www.discogs.com/user/{u}", "https://api.discogs.com/users/{u}", SC, None),
    ("Trello", "pro", "https://trello.com/{u}", "https://trello.com/1/Members/{u}", SC, None),
    ("Hashnode", "dev", "https://hashnode.com/@{u}", None, SC, None),
    ("CodePen", "dev", "https://codepen.io/{u}", None, SC, None),
    ("Gitee", "dev", "https://gitee.com/{u}", None, SC, None),
    ("Ko-fi", "créa", "https://ko-fi.com/{u}", None, SC, None),
    ("Buy Me a Coffee", "créa", "https://buymeacoffee.com/{u}", None, SC, None),
    ("Bandcamp", "créa", "https://{u}.bandcamp.com", None, SC, None),
    ("Gumroad", "créa", "https://{u}.gumroad.com", None, SC, None),
    ("Instructables", "créa", "https://www.instructables.com/member/{u}/", None, SC, None),
    ("Product Hunt", "pro", "https://www.producthunt.com/@{u}", None, SC, None),
    ("Fiverr", "pro", "https://www.fiverr.com/{u}", None, SC, None),
    ("X / Twitter", "social", "https://x.com/{u}", None, None, None),
    ("Facebook", "social", "https://www.facebook.com/{u}", None, None, None),
    ("Ask.fm", "social", "https://ask.fm/{u}", None, SC, None),
    ("Mixcloud", "créa", "https://www.mixcloud.com/{u}/", None, SC, None),
    ("Dailymotion", "créa", "https://www.dailymotion.com/{u}", None, SC, None),
    ("Hackaday.io", "dev", "https://hackaday.io/{u}", None, SC, None),
    ("Substack", "social", "https://{u}.substack.com", None, SC, None),
    ("Quora", "social", "https://www.quora.com/profile/{u}", None, None, None),
    ("Spotify", "social", "https://open.spotify.com/user/{u}", None, None, None),
    ("Pixiv", "créa", "https://www.pixiv.net/en/users/{u}", None, None, None),
    ("500px", "créa", "https://500px.com/p/{u}", None, None, None),
    ("Unsplash", "créa", "https://unsplash.com/@{u}", None, None, None),
    ("Rumble", "social", "https://rumble.com/user/{u}", None, None, None),
    ("Odysee", "social", "https://odysee.com/@{u}", None, None, None),
    ("Myspace", "social", "https://myspace.com/{u}", None, None, None),
    ("Goodreads", "autre", "https://www.goodreads.com/{u}", None, None, None),
    ("Strava", "autre", "https://www.strava.com/athletes/{u}", None, None, None),
    ("Codeforces", "dev", "https://codeforces.com/profile/{u}", None, None, None),
    ("LeetCode", "dev", "https://leetcode.com/u/{u}/", None, None, None),
    ("Exercism", "dev", "https://exercism.org/profiles/{u}", None, None, None),
    ("Fandom", "gaming", "https://{u}.fandom.com", None, None, None),
    ("Faceit", "gaming", "https://www.faceit.com/en/players/{u}", None, None, None),
    ("Thingiverse", "créa", "https://www.thingiverse.com/{u}", None, None, None),
    ("Etsy", "pro", "https://www.etsy.com/shop/{u}", None, None, None),
    ("Wikipédia EN", "autre", "https://en.wikipedia.org/wiki/User:{u}", "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&format=json", lambda s, b, u: (0 if "missing" in ((J(b) or {}).get("query", {}).get("users") or [{}])[0] else 1) if J(b) else None, None),
    ("LinkedIn", "pro", "https://www.linkedin.com/in/{u}", None, None, None),
]


def check_site(site, u):
    name, cat, url, api, fn, hdr = site
    if fn is None:
        return SourceResult(name, "unknown", "none", url.replace("{u}", u), "Parser non disponible : vérification manuelle nécessaire")
    target = (api or url).replace("{u}", u)
    for essai in range(2):
        try:
            r = get(target, timeout=12 if essai == 0 else 20, headers=hdr or {}, allow_redirects=True)
            if r.status_code in (429, 503) and essai == 0:
                time.sleep(2)
                continue
            v = fn(r.status_code, r.text[:400000], u)
            return result_from_probe(source=name, url=r.url, http_status=r.status_code, value=v)
        except requests.RequestException as exc:
            time.sleep(1)
            last_error = exc
    return source_error(source=name, url=target, reason=str(last_error))


def variants(u):
    b = re.sub(r"[._-]", "", u)
    v = [u, b, u.replace(".", "_"), re.sub(r"[_-]", ".", u), re.sub(r"(\D)(\d)", r"\1_\2", b, count=1)]
    return list(dict.fromkeys(x for x in v if x and re.fullmatch(r"[A-Za-z0-9._-]+", x)))


def mod_user():
    con.rule(f"[{G}]👤 RECHERCHE DE PSEUDO")
    raw_u = Prompt.ask(f"[{G}]Pseudo")
    u = normalize_username(raw_u)
    if u != raw_u.strip().lstrip("@"):
        con.print(f"[{M}]Pseudo Unicode normalisé :[/] {escape(u)}")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", u):
        con.print(f"[{R}]Pseudo invalide.")
        return pause()
    names = variants(u) if ask_yes("Tester aussi les variantes (_ . -) ?") else [u]
    jobs = [(s, n) for n in names for s in SITES]
    res = []
    with Progress(TextColumn(f"[{G}]Scan"), BarColumn(complete_style="#00e5ff"), TaskProgressColumn(), TextColumn("{task.description}"), console=con) as pr:
        task = pr.add_task("", total=len(jobs))
        with cf.ThreadPoolExecutor(16) as ex:
            futs = {ex.submit(check_site, s, n): (s, n) for s, n in jobs}
            for f in cf.as_completed(futs):
                s, n = futs[f]
                st, code = f.result()
                res.append((s, n, st, code))
                found = sum(1 for x in res if x[2] == "trouvé")
                pr.update(task, advance=1, description=f"[{M}]trouvés : [{G}]{found}")
    order = {"trouvé": 0, "à vérifier": 1, "manuel": 2, "injoignable": 3, "absent": 4}
    res.sort(key=lambda x: (order[x[2]], x[0][0]))
    t = Table(title=f"Résultats pour {escape(', '.join(names))}", box=box.ROUNDED, border_style="#2b3158")
    for c in ("Site", "Cat.", "Statut", "Lien"):
        t.add_column(c)
    col = {"trouvé": G, "à vérifier": Y, "manuel": B, "injoignable": M, "absent": M}
    for s, n, st, code in res:
        if st in ("absent", "injoignable"):
            continue
        t.add_row(s[0], s[1], f"[{col[st]}]{st}{'' if st in ('trouvé', 'manuel') or not code else f' ({code})'}", escape(s[2].replace("{u}", n)))
    con.print(t)
    cnt = {k: sum(1 for x in res if x[2] == k) for k in order}
    con.print(f"[{G}]{cnt['trouvé']} trouvés[/] · [{Y}]{cnt['à vérifier'] + cnt['manuel']} à vérifier[/] · [{M}]{cnt['absent']} absents")
    inj = sorted({s[0] for s, n, st, _ in res if st == "injoignable"})
    if inj:
        con.print(f"[{M}]{len(inj)} site(s) n'ont pas répondu (site lent, anti-robot ou bloqué par ton réseau / VPN), à vérifier à la main si besoin : {escape(', '.join(inj))}")
    found = [f"{s[0]} ({s[1]}) → {s[2].replace('{u}', n)}" for s, n, st, _ in res if st == "trouvé"]
    add_report("Pseudos", ", ".join(names), f"Trouvés ({len(found)}) :\n" + ("\n".join(found) or "aucun"))
    f = OUT / f"pseudo_{u}_{stamp()}.txt"
    f.write_text("\n".join(f"{st}\t{s[0]}\t{s[2].replace('{u}', n)}" for s, n, st, _ in res), encoding="utf-8")
    log(f"Résultats enregistrés : {f}", G)
    if found and ask_yes("Analyse IA de l'empreinte ?"):
        ai_print(f"Tu es analyste OSINT et conseiller en vie privée. Voici l'empreinte du pseudo \"{', '.join(names)}\" (audit de ma propre exposition). Comptes trouvés :\n" + "\n".join(found) +
                 "\n\nEn français, donne : 1) un niveau d'exposition (faible/moyen/élevé) justifié, 2) ce qu'un attaquant pourrait recouper, 3) une checklist concrète pour réduire l'exposition. Concis, avec des puces.")
    if ask_yes("Chercher les anciens pseudos et traces archivées (prevname) ?"):
        prevname_core(u)
    pause()


# ============================================================ 3. DOMAINE / IP
TT = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
RISKY = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 445: "SMB", 1433: "MSSQL", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
         5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
SENS_SUB = re.compile(r"^(dev|test|staging|stage|preprod|pre|beta|admin|vpn|jenkins|git|gitlab|old|backup|bak|internal|intranet|dashboard|panel|db|sql|phpmyadmin|demo|uat|qa|ftp|webmail|cpanel|remote|portal)\b", re.I)
TECH = [("WordPress", r"wp-content|wp-includes"), ("Shopify", r"cdn\.shopify\.com"), ("Wix", r"wix\.com|_wixCIDX"), ("Squarespace", r"squarespace"), ("Webflow", r"webflow"),
        ("PrestaShop", r"prestashop"), ("Joomla", r"joomla"), ("Drupal", r"drupal"), ("Next.js", r"__NEXT_DATA__|_next/static"), ("Nuxt", r"__NUXT__"),
        ("React", r"react(-dom)?(\.production)?(\.min)?\.js|data-reactroot"), ("Vue", r"vue(\.min)?\.js|data-v-[0-9a-f]{6}"), ("Angular", r"ng-version"),
        ("jQuery", r"jquery[.-]?(\d[\d.]*)?(\.min)?\.js"), ("Bootstrap", r"bootstrap(\.min)?\.(css|js)"), ("Google Analytics", r"gtag\(|google-analytics\.com"),
        ("Google Tag Manager", r"googletagmanager\.com/gtm"), ("Meta Pixel", r"fbevents\.js"), ("reCAPTCHA", r"recaptcha"), ("Matomo", r"matomo|piwik"),
        ("Hotjar", r"hotjar"), ("Stripe", r"js\.stripe\.com"), ("Elementor", r"elementor"), ("WooCommerce", r"woocommerce")]
SEC_HEADERS = {"strict-transport-security": "HSTS", "content-security-policy": "CSP", "x-frame-options": "X-Frame-Options",
               "x-content-type-options": "X-Content-Type-Options", "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy"}


def dns(name, typ):
    j = get_json("https://dns.google/resolve", 10, params={"name": name, "type": typ})
    out = []
    for a in j.get("Answer", []):
        if a.get("type") == TT[typ]:
            d = a["data"]
            d = re.sub(r'"\s*"', "", d.strip('"')) if typ == "TXT" else d.rstrip(".")
            out.append(d)
    return out


def ip_info(ip):
    v = {}
    try:
        g = get_json(f"https://ipwho.is/{ip}", 10)
        if g.get("success") is not False:
            c = g.get("connection") or {}
            v["geo"] = {"country": g.get("country"), "city": g.get("city"), "org": c.get("org") or c.get("isp"), "asn": c.get("asn")}
    except Exception:
        pass
    try:
        r = get(f"https://internetdb.shodan.io/{ip}", 10)
        v["sh"] = r.json() if r.ok else {"ports": [], "vulns": [], "hostnames": []}
    except Exception:
        pass
    return v


def ssl_info(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=8) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            c = ss.getpeercert()
    exp = datetime.datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z")
    issuer = dict(x[0] for x in c.get("issuer", []))
    return {"expire": exp, "jours": (exp - datetime.datetime.utcnow()).days, "emetteur": issuer.get("organizationName", "?"),
            "san": [v for k, v in c.get("subjectAltName", []) if k == "DNS"]}


def is_ip(s):
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", s)) or (":" in s and bool(re.fullmatch(r"[0-9a-fA-F:]+", s)))


def scan_domain(d, R):
    log("Résolution DNS…", B)
    for ty in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"):
        try:
            R["dns"][ty] = dns(d, ty)
        except Exception:
            R["dns"][ty] = []
    log(f"A: {', '.join(R['dns']['A']) or '—'} · MX: {len(R['dns']['MX'])} · NS: {len(R['dns']['NS'])}", G)

    log("Sécurité e-mail (SPF, DMARC, DKIM)…", B)
    R["spf"] = next((x for x in R["dns"]["TXT"] if x.lower().startswith("v=spf1")), None)
    try:
        R["dmarc"] = next((x for x in dns("_dmarc." + d, "TXT") if x.upper().startswith("V=DMARC1")), None)
    except Exception:
        R["dmarc"] = None

    def dk(sel):
        try:
            return sel if any("p=" in x for x in dns(f"{sel}._domainkey.{d}", "TXT")) else None
        except Exception:
            return None
    with cf.ThreadPoolExecutor(10) as ex:
        R["dkim"] = [x for x in ex.map(dk, ["google", "default", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2", "mx"]) if x]
    log(f"SPF {'✓' if R['spf'] else '✗'} · DMARC {'✓' if R['dmarc'] else '✗'} · DKIM {', '.join(R['dkim']) or 'non trouvé'}", G if R["spf"] and R["dmarc"] else Y)

    log("Sous-domaines (certificats SSL publics)…", B)
    subs = {}

    def add(n, ip=None):
        n = n.lower().strip().lstrip("*.")
        if n.endswith(d) and " " not in n and "@" not in n and n != d:
            subs.setdefault(n, set())
            if ip:
                subs[n].add(ip)

    def src_crt():
        for c in get_json(f"https://crt.sh/?q=%25.{d}&output=json", 40):
            for n in str(c.get("name_value", "")).split("\n"):
                add(n)
        return "crt.sh"

    def src_cs():
        for c in get_json(f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names", 25):
            for n in c.get("dns_names", []):
                add(n)
        return "CertSpotter"

    def src_ht():
        t = get(f"https://api.hackertarget.com/hostsearch/?q={d}", 25).text
        if "error" in t.lower() or "API count" in t:
            raise RuntimeError
        for line in t.splitlines():
            p = line.split(",")
            if p[0]:
                add(p[0], p[1] if len(p) > 1 else None)
        return "HackerTarget"
    with cf.ThreadPoolExecutor(3) as ex:
        for f in [ex.submit(x) for x in (src_crt, src_cs, src_ht)]:
            try:
                log(f"{f.result()} ✓", G)
            except Exception:
                log("une source de sous-domaines n'a pas répondu", Y)
    R["subs"] = sorted(({"n": n, "ips": sorted(s)} for n, s in subs.items()),
                       key=lambda s: (not SENS_SUB.match(s["n"][: -len(d) - 1]), s["n"]))
    log(f"{len(R['subs'])} sous-domaines. Résolution des 80 premiers…", G)

    def res(s):
        if not s["ips"]:
            try:
                s["ips"] = dns(s["n"], "A")
            except Exception:
                pass
    with cf.ThreadPoolExecutor(12) as ex:
        list(ex.map(res, R["subs"][:80]))

    log("WHOIS (RDAP)…", B)
    try:
        j = get_json(f"https://rdap.org/domain/{d}", 15)
        reg = next((e for e in j.get("entities", []) if "registrar" in e.get("roles", [])), {})
        fn = next((x[3] for x in (reg.get("vcardArray") or [None, []])[1] if x[0] == "fn"), reg.get("handle", "?"))
        ev = {e["eventAction"]: e["eventDate"] for e in j.get("events", [])}
        R["rdap"] = {"registrar": fn, "created": ev.get("registration"), "expires": ev.get("expiration"), "changed": ev.get("last changed"), "status": ", ".join(j.get("status", []))}
        log(f"Registrar : {fn}", G)
    except Exception:
        log("RDAP indisponible pour cette extension", Y)

    log("Certificat SSL…", B)
    try:
        R["ssl"] = ssl_info(d)
        log(f"Émis par {R['ssl']['emetteur']} · expire dans {R['ssl']['jours']} jours", G)
    except Exception as e:
        R["ssl_err"] = str(e)
        log(f"Certificat SSL : {e}", Y)

    log("Site web (en-têtes de sécurité, technos)…", B)
    try:
        r = get(f"https://{d}", 15, allow_redirects=True)
        h = {k.lower(): v for k, v in r.headers.items()}
        body = r.text[:600000]
        R["web"] = {"status": r.status_code, "final": r.url, "server": h.get("server"), "powered": h.get("x-powered-by"),
                    "title": (re.search(r"<title[^>]*>([^<]*)", body, re.I) or [None, ""])[1].strip(),
                    "missing": [n for k, n in SEC_HEADERS.items() if k not in h]}
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        R["tech"] = ([gen.group(1)] if gen else []) + [n for n, rx in TECH if re.search(rx, body, re.I)]
        if "cf-ray" in h:
            R["tech"].append("Cloudflare")
        R["emails"] = sorted({e for e in re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", body, re.I) if not re.search(r"\.(png|jpg|svg|webp|gif)$", e, re.I)})[:15]
        log(f"Technos : {', '.join(R['tech']) or 'non détectées'}", G)
        try:
            rr = get(f"http://{d}", 10, allow_redirects=False)
            R["web"]["https_redirect"] = rr.headers.get("location", "").startswith("https")
        except Exception:
            pass
    except Exception as e:
        log(f"Site inaccessible : {e}", Y)
    for path, key in (("/robots.txt", "robots"), ("/.well-known/security.txt", "sectxt")):
        try:
            r = get(f"https://{d}{path}", 10)
            if key == "robots" and r.ok:
                R["robots"] = re.findall(r"(?im)^disallow:\s*(\S+)", r.text)[:30]
            if key == "sectxt":
                R["sectxt"] = r.ok and "contact:" in r.text.lower()
        except Exception:
            pass

    log("Archives Wayback Machine…", B)
    try:
        rows = get_json(f"https://web.archive.org/cdx/search/cdx?url={d}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=5000", 40)[1:]
        ts = sorted(r[0] for r in rows)
        sens = [r[1] for r in rows if re.search(r"\.(env|sql|bak|old|zip|rar|tar|gz|7z|log|conf|cfg|ini|db|sqlite|backup|swp|pem|key)(\?|$)|/(\.git|\.svn|phpmyadmin|backup|wp-config|config\.php|\.htpasswd|debug|phpinfo)", r[1], re.I)]
        R["wb"] = {"count": len(rows), "first": ts[0] if ts else None, "last": ts[-1] if ts else None, "sens": sens[:50]}
        log(f"{len(rows)} URLs archivées · {len(sens)} potentiellement sensibles", Y if sens else G)
    except Exception:
        log("Wayback indisponible", Y)

    ips = list(dict.fromkeys([*R["dns"]["A"], *[i for s in R["subs"] for i in s["ips"]]]))
    ips = [i for i in ips if is_ip(i)][:15]
    log(f"Analyse de {len(ips)} IP (hébergeur, ports, CVE)…", B)
    with cf.ThreadPoolExecutor(5) as ex:
        for ip, v in zip(ips, ex.map(ip_info, ips)):
            R["ips"][ip] = v


def scan_ip(ip, R):
    log("Reverse DNS…", B)
    try:
        if "." in ip:
            R["dns"]["PTR"] = dns(".".join(reversed(ip.split("."))) + ".in-addr.arpa", "PTR")
            log(f"PTR : {', '.join(R['dns']['PTR']) or 'aucun'}", G)
    except Exception:
        pass
    log("Hébergeur, ports exposés, CVE…", B)
    R["ips"][ip] = ip_info(ip)


def analyse(R):
    F = []

    def a(severity, text):
        F.append((severity, text))

    d = R["target"]
    if not R["ip"]:
        spf = R.get("spf")
        if not spf:
            a("high", "Pas de SPF : n'importe qui peut envoyer des e-mails au nom du domaine.")
        elif "+all" in spf:
            a("high", 'SPF en "+all" : autorise tout le monde à envoyer pour le domaine.')
        elif "?all" in spf:
            a("med", 'SPF en "?all" : protection quasi nulle.')
        else:
            a("ok", "SPF présent.")
        dm = R.get("dmarc")
        if not dm:
            a("high", "Pas de DMARC : usurpation d'e-mails (phishing) facilitée.")
        elif re.search(r"p=none", dm, re.I):
            a("med", "DMARC en p=none : surveille mais ne bloque rien.")
        else:
            a("ok", "DMARC actif.")
        if R["dns"].get("MX") and not R.get("dkim"):
            a("low", "DKIM non trouvé sur les sélecteurs courants.")
        if not R["dns"].get("CAA"):
            a("low", "Pas d'enregistrement CAA : toute autorité peut émettre un certificat.")
        sens = [s for s in R["subs"] if SENS_SUB.match(s["n"][: -len(d) - 1])]
        if sens:
            a("med" if any(s["ips"] for s in sens) else "low", f"{len(sens)} sous-domaine(s) sensibles publics : " + ", ".join(s["n"] + (" (actif)" if s["ips"] else "") for s in sens[:8]))
        if R.get("rdap") and R["rdap"].get("expires"):
            try:
                days = (datetime.datetime.fromisoformat(R["rdap"]["expires"].replace("Z", "+00:00")).replace(tzinfo=None) - datetime.datetime.utcnow()).days
                if days < 0:
                    a("high", "Le domaine semble expiré !")
                elif days < 60:
                    a("med", f"Le domaine expire dans {days} jours.")
            except Exception:
                pass
        if R.get("ssl"):
            if R["ssl"]["jours"] < 0:
                a("high", "Certificat SSL expiré.")
            elif R["ssl"]["jours"] < 15:
                a("med", f"Certificat SSL expire dans {R['ssl']['jours']} jours.")
        elif R.get("ssl_err"):
            a("high", "Certificat SSL invalide ou absent : " + R["ssl_err"][:120])
        w = R.get("web")
        if w:
            if w.get("missing"):
                a("med" if "HSTS" in w["missing"] or "CSP" in w["missing"] else "low", "En-têtes de sécurité manquants : " + ", ".join(w["missing"]))
            if w.get("https_redirect") is False:
                a("med", "Le site en http:// ne redirige pas vers https://.")
            leak = [x for x in (w.get("server"), w.get("powered")) if x and re.search(r"\d", x)]
            if leak:
                a("low", "Le serveur affiche sa version : " + ", ".join(leak))
        if R.get("wb", {}).get("sens"):
            a("med", f"{len(R['wb']['sens'])} URL(s) sensibles conservées dans les archives web.")
        if R.get("web") and not R.get("sectxt"):
            a("low", "Pas de security.txt.")
        if R.get("emails"):
            a("low", "E-mails visibles sur la page d'accueil : " + ", ".join(R["emails"]))
    for ip, v in R["ips"].items():
        ports = (v.get("sh") or {}).get("ports") or []
        bad = [p for p in ports if p in RISKY and p not in (22, 25)]
        if bad:
            a("high", f"{ip} expose " + ", ".join(f"{p} ({RISKY[p]})" for p in bad) + " sur Internet.")
        if 22 in ports:
            a("low", f"{ip} expose SSH (22).")
        vulns = (v.get("sh") or {}).get("vulns") or []
        if vulns:
            a("high", f"{ip} : {len(vulns)} CVE connue(s) ({', '.join(vulns[:6])}{'…' if len(vulns) > 6 else ''}).")
    order = {"high": 0, "med": 1, "low": 2, "ok": 3}
    F.sort(key=lambda x: order[x[0]])
    R["find"] = F or [("ok", "Aucun problème évident détecté.")]
    R["score"] = max(0, 100 - sum({"high": 20, "med": 8, "low": 2, "ok": 0}[s] for s, _ in R["find"]))


def show_domain(R):
    SEV = {"high": (R_STYLE, "ÉLEVÉ"), "med": (Y, "MOYEN"), "low": (B, "INFO"), "ok": (G, "OK")}
    sc = R["score"]
    c = G if sc > 70 else Y if sc > 40 else R_STYLE
    con.print(Panel(f"[{c}]{sc}/100[/]  [{c}]{'█' * (sc // 5)}[/][{M}]{'░' * (20 - sc // 5)}[/]", title=f"Score d'exposition : {escape(R['target'])}", border_style="#00e5ff"))
    t = Table(box=box.SIMPLE, show_header=False)
    for s, txt in R["find"]:
        st, lb = SEV[s]
        t.add_row(f"[{st}]{lb}", escape(txt))
    con.print(t)
    if not R["ip"]:
        t = Table(title="DNS", box=box.ROUNDED, border_style="#2b3158", show_header=False)
        for ty in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
            t.add_row(f"[{M}]{ty}", escape("\n".join(R["dns"].get(ty) or ["—"])))
        t.add_row(f"[{M}]DMARC", escape(R.get("dmarc") or "—"))
        t.add_row(f"[{M}]DKIM", escape(", ".join(R.get("dkim") or []) or "—"))
        if R.get("rdap"):
            t.add_row(f"[{M}]Registrar", escape(R["rdap"]["registrar"]))
            t.add_row(f"[{M}]Créé / expire", escape(f"{(R['rdap']['created'] or '—')[:10]} / {(R['rdap']['expires'] or '—')[:10]}"))
        if R.get("ssl"):
            t.add_row(f"[{M}]SSL", escape(f"{R['ssl']['emetteur']} · expire le {R['ssl']['expire']:%d/%m/%Y}"))
        if R.get("web"):
            t.add_row(f"[{M}]Serveur", escape(" / ".join(x for x in (R["web"].get("server"), R["web"].get("powered")) if x) or "—"))
            t.add_row(f"[{M}]Technos", escape(", ".join(R.get("tech") or []) or "—"))
        if R.get("robots"):
            t.add_row(f"[{M}]robots.txt", escape(", ".join(R["robots"])))
        con.print(t)
        if R["subs"]:
            t = Table(title=f"Sous-domaines ({len(R['subs'])}) · 40 premiers", box=box.ROUNDED, border_style="#2b3158")
            t.add_column("Sous-domaine")
            t.add_column("IP")
            for s in R["subs"][:40]:
                sens = SENS_SUB.match(s["n"][: -len(R["target"]) - 1])
                t.add_row(f"[{P}]⚠ {escape(s['n'])}" if sens else escape(s["n"]), escape(", ".join(s["ips"]) or "—"))
            con.print(t)
        if R.get("wb", {}).get("sens"):
            con.print(Panel(escape("\n".join(R["wb"]["sens"][:20])), title=f"URLs sensibles archivées ({len(R['wb']['sens'])})", border_style=Y))
    if R["ips"]:
        t = Table(title="Adresses IP", box=box.ROUNDED, border_style="#2b3158")
        for c in ("IP", "Hébergeur", "Lieu", "Ports", "CVE"):
            t.add_column(c)
        for ip, v in R["ips"].items():
            g, sh = v.get("geo") or {}, v.get("sh") or {}
            ports = ", ".join(f"[{R_STYLE}]{p}[/]" if p in RISKY else str(p) for p in sh.get("ports") or []) or "—"
            t.add_row(ip, escape(str(g.get("org") or "—")), escape(", ".join(x for x in (g.get("city"), g.get("country")) if x) or "—"), ports, escape(", ".join((sh.get("vulns") or [])[:5]) or "—"))
        con.print(t)


R_STYLE = R


def domain_html(R):
    col = {"high": "#ff5c7a", "med": "#ffc861", "low": "#7aa2ff", "ok": "#00e5ff"}
    rows = "".join(f"<tr><td style='color:{col[s]};font-weight:700'>{s.upper()}</td><td>{escape_html(t)}</td></tr>" for s, t in R["find"])
    subs = "".join(f"<tr><td>{escape_html(s['n'])}</td><td>{escape_html(', '.join(s['ips']))}</td></tr>" for s in R["subs"])
    ips = "".join(f"<tr><td>{ip}</td><td>{escape_html((v.get('geo') or {}).get('org'))}</td><td>{escape_html(', '.join(map(str, (v.get('sh') or {}).get('ports') or [])))}</td><td>{escape_html(', '.join((v.get('sh') or {}).get('vulns') or []))}</td></tr>" for ip, v in R["ips"].items())
    # graphe radial
    W, H, cx, cy = 800, 640, 400, 320
    sl = R["subs"][:40]
    ipl = list(dict.fromkeys([i for s in sl for i in s["ips"]] + R["dns"].get("A", [])))[:14]
    pos = {ip: (cx + math.cos(i / max(1, len(ipl)) * 6.283) * 130, cy + math.sin(i / max(1, len(ipl)) * 6.283) * 130) for i, ip in enumerate(ipl)}
    e = n = ""
    for ip, (x, y) in pos.items():
        e += f'<line x1="{cx}" y1="{cy}" x2="{x:.0f}" y2="{y:.0f}" stroke="#22305a"/>'
    for i, s in enumerate(sl):
        ang = i / max(1, len(sl)) * 6.283 + .08
        x, y = cx + math.cos(ang) * 270, cy + math.sin(ang) * 250
        sens = bool(SENS_SUB.match(s["n"][: -len(R["target"]) - 1]))
        for ip in [i for i in s["ips"] if i in pos] or [None]:
            px, py = pos[ip] if ip else (cx, cy)
            e += f'<line x1="{x:.0f}" y1="{y:.0f}" x2="{px:.0f}" y2="{py:.0f}" stroke="{"#3a1f5a" if sens else "#1a1f40"}"/>'
        anc = "start" if math.cos(ang) > .2 else "end" if math.cos(ang) < -.2 else "middle"
        lb = s["n"][: -len(R["target"]) - 1][:22]
        n += f'<circle cx="{x:.0f}" cy="{y:.0f}" r="5" fill="{"#b388ff" if sens else "#7aa2ff" if s["ips"] else "#343a66"}"/><text x="{x + (8 if anc == "start" else -8 if anc == "end" else 0):.0f}" y="{y + 4:.0f}" text-anchor="{anc}" font-size="10" fill="#a3acd1">{escape_html(lb)}</text>'
    for ip, (x, y) in pos.items():
        n += f'<rect x="{x - 5:.0f}" y="{y - 5:.0f}" width="10" height="10" fill="#ffc861"/><text x="{x:.0f}" y="{y - 9:.0f}" text-anchor="middle" font-size="9" fill="#ffc861">{ip}</text>'
    n += f'<circle cx="{cx}" cy="{cy}" r="12" fill="#00e5ff"/><text x="{cx}" y="{cy + 28}" text-anchor="middle" font-size="13" fill="#00e5ff">{escape_html(R["target"])}</text>'
    graph = f'<svg viewBox="0 0 {W} {H}" style="width:100%;background:#03040e;border-radius:10px">{e}{n}</svg>' if sl else ""
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan {escape_html(R['target'])}</title>
<style>body{{font-family:system-ui;background:#07081a;color:#e4e9ff;max-width:1000px;margin:auto;padding:20px}}h1{{font-family:monospace;color:#00e5ff}}h2{{color:#b388ff;font-size:16px;margin-top:28px}}table{{width:100%;border-collapse:collapse;font-family:monospace;font-size:13px}}td,th{{border-bottom:1px solid #2b3158;padding:6px;text-align:left;vertical-align:top;word-break:break-word}}svg text{{font-family:monospace}}@media print{{body{{background:#fff;color:#000}}}}</style></head>
<body><h1>CAT.exe // SCAN {escape_html(R['target'])}</h1><p>Score d'exposition : <b>{R['score']}/100</b> · {datetime.datetime.now():%d/%m/%Y %H:%M}</p>
<h2>Analyse des risques</h2><table>{rows}</table>{f'<h2>Carte des liens</h2>{graph}' if graph else ''}
{f'<h2>Sous-domaines ({len(R["subs"])})</h2><table>{subs}</table>' if subs else ''}<h2>Adresses IP</h2><table><tr><th>IP</th><th>Hébergeur</th><th>Ports</th><th>CVE</th></tr>{ips}</table>
{f"<h2>Rapport IA</h2><pre style='white-space:pre-wrap'>{escape_html(R.get('ai'))}</pre>" if R.get('ai') else ''}</body></html>"""


def mod_domain():
    con.rule(f"[{G}]🔭 SCAN DOMAINE / IP")
    t = Prompt.ask(f"[{G}]Domaine ou IP").strip().lower()
    t = re.sub(r"^https?://", "", t).split("/")[0]
    t = re.sub(r"^www\.", "", t)
    if not t:
        return
    R = {"target": t, "ip": is_ip(t), "dns": {}, "subs": [], "ips": {}}
    try:
        scan_ip(t, R) if R["ip"] else scan_domain(t, R)
    except KeyboardInterrupt:
        log("Scan interrompu.", Y)
    analyse(R)
    show_domain(R)
    add_report("Domaine", t, f"Score {R['score']}/100\n" + "\n".join(f"[{s.upper()}] {x}" for s, x in R["find"]) +
               (f"\nSous-domaines ({len(R['subs'])}) : " + ", ".join(s["n"] for s in R["subs"][:40]) if R["subs"] else ""))
    if ask_yes("Rapport IA détaillé ?"):
        brief = {"cible": t, "constats": [f"{s}: {x}" for s, x in R["find"]], "spf": R.get("spf"), "dmarc": R.get("dmarc"), "mx": R["dns"].get("MX"),
                 "whois": R.get("rdap"), "ssl": {"emetteur": R["ssl"]["emetteur"], "jours": R["ssl"]["jours"]} if R.get("ssl") else R.get("ssl_err"),
                 "web": R.get("web"), "technos": R.get("tech"), "sous_domaines": [s["n"] for s in R["subs"][:50]],
                 "ip": {ip: {"heb": (v.get("geo") or {}).get("org"), "ports": (v.get("sh") or {}).get("ports"), "cve": ((v.get("sh") or {}).get("vulns") or [])[:10]} for ip, v in R["ips"].items()},
                 "archives_sensibles": (R.get("wb") or {}).get("sens", [])[:15], "robots": R.get("robots")}
        R["ai"] = ai_print(f"Tu es analyste en cybersécurité (reconnaissance passive). Données collectées sur {t} :\n{json.dumps(brief, ensure_ascii=False, default=str)[:10000]}\n\n"
                           "Rédige en français un rapport clair pour le propriétaire : 1) résumé en 3 lignes, 2) surface d'attaque, 3) risques classés par priorité expliqués simplement, 4) corrections concrètes (exemples d'enregistrements DNS si utile). Concis, avec des puces.", "Rapport IA", task="cyber")
        if R["ai"]:
            add_report("Domaine", f"Rapport IA {t}", R["ai"])
    f = OUT / f"scan_{t.replace(':', '_')}_{stamp()}.html"
    f.write_text(domain_html(R), encoding="utf-8")
    (OUT / f"scan_{t.replace(':', '_')}_{stamp()}.json").write_text(json.dumps(R, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    log(f"Rapport enregistré : {f}", G)
    if ask_yes("Ouvrir le rapport (avec la carte des liens) dans le navigateur ?"):
        open_file(f)
    pause()


# ============================================================ 4. DORKS
DORKS = [
    ("Fichiers exposés", "d", ["site:{d} ext:pdf OR ext:doc OR ext:docx OR ext:ppt", "site:{d} ext:xls OR ext:xlsx OR ext:csv", "site:{d} ext:sql OR ext:db OR ext:bak OR ext:backup",
                               "site:{d} ext:env OR ext:log OR ext:ini OR ext:conf OR ext:cfg", "site:{d} ext:zip OR ext:rar OR ext:tar OR ext:gz"]),
    ("Pages sensibles", "d", ["site:{d} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:panel", 'site:{d} intitle:"index of"', "site:{d} inurl:wp-admin OR inurl:wp-content/uploads",
                              "site:{d} intitle:phpinfo OR inurl:phpinfo", "site:{d} inurl:test OR inurl:dev OR inurl:staging"]),
    ("Erreurs & fuites", "d", ['site:{d} "sql syntax" OR "mysql_fetch" OR "Warning: include"', 'site:{d} intext:"password" OR intext:"mot de passe" ext:txt OR ext:log', 'site:{d} "api_key" OR "apikey" OR "secret"']),
    ("Sous-domaines", "d", ["site:*.{d} -www", "site:*.*.{d}"]),
    ("Mentions externes", "d", ['"{d}" -site:{d}', 'site:pastebin.com "{d}"', 'site:github.com "{d}"', 'site:trello.com "{d}"', 'site:docs.google.com "{d}"']),
    ("Empreinte pseudo / nom", "k", ['"{k}"', '"{k}" site:pastebin.com', '"{k}" site:github.com OR site:gitlab.com', '"{k}" site:reddit.com', '"{k}" filetype:pdf',
                                     '"{k}" inurl:profile OR inurl:user OR inurl:member', '"{k}" site:instagram.com OR site:tiktok.com OR site:x.com']),
]


def mod_dorks():
    con.rule(f"[{G}]🔍 GOOGLE DORKING")
    d = re.sub(r"^https?://", "", Prompt.ask(f"[{G}]Domaine cible (Entrée = aucun)", default="")).split("/")[0]
    k = Prompt.ask(f"[{G}]Pseudo / nom / mot-clé (Entrée = aucun)", default="")
    allq, items = [], []
    for cat, ty, lst in DORKS:
        if (ty == "d" and not d) or (ty == "k" and not k):
            continue
        items.append({"header": f"── {cat}"})
        for q in lst:
            q = q.replace("{d}", d).replace("{k}", k)
            allq.append(q)
            items.append({"label": q, "value": q})
    if not allq:
        con.print(f"[{Y}]Donne au moins un domaine ou un mot-clé.")
        return pause()
    f = OUT / f"dorks_{stamp()}.txt"
    f.write_text("\n".join(allq), encoding="utf-8")
    log(f"{len(allq)} recherches générées · liste enregistrée : {f}", G)
    items += [{"header": "──"}, {"label": "📝 Requête libre", "value": "__perso"}, {"label": "← Retour au menu", "value": "__back"}]
    eng = {"Google": "https://www.google.com/search?q=", "Bing": "https://www.bing.com/search?q=", "DuckDuckGo": "https://duckduckgo.com/?q=", "Yandex": "https://yandex.com/search/?text="}
    last, last_eng = None, "Google"
    while True:
        q = select("Dorks · Entrée = ouvrir dans le navigateur", items, default=last, echo=False)
        if q in (None, "__back"):
            break
        last = q
        if q == "__perso":
            q = Prompt.ask(f"[{G}]Requête")
            if not q:
                continue
        e = select("Moteur", [{"label": n, "value": n} for n in eng], default=last_eng, echo=False)
        if e:
            last_eng = e
            webbrowser.open(eng[e] + requests.utils.quote(q))
            log(f"Ouvert dans {e} : {q}", G)


# ============================================================ 5. ENTREPRISES
EFF = {"NN": "non renseigné", "00": "0 salarié", "01": "1-2", "02": "3-5", "03": "6-9", "11": "10-19", "12": "20-49", "21": "50-99", "22": "100-199", "31": "200-249",
       "32": "250-499", "41": "500-999", "42": "1000-1999", "51": "2000-4999", "52": "5000-9999", "53": "10 000+"}


def mod_biz():
    con.rule(f"[{G}]🏢 ENTREPRISES")
    q = Prompt.ask(f"[{G}]Nom ou SIREN [{M}](Entrée = retour)", default="", show_default=False).strip()
    if not q:
        return
    cp = Prompt.ask(f"[{G}]Code postal (Entrée = tous)", default="")
    params = {"q": q, "per_page": 10}
    if re.fullmatch(r"\d{5}", cp):
        params["code_postal"] = cp
    try:
        with con.status("Registre officiel des entreprises…"):
            j = get_json("https://recherche-entreprises.api.gouv.fr/search", 15, params=params)
    except Exception as e:
        con.print(f"[{R}]Erreur : {escape(str(e))}")
        return pause()
    res = j.get("results", [])
    log(f"{j.get('total_results', 0)} résultat(s)", G)
    for i, e in enumerate(res, 1):
        s = e.get("siege") or {}
        nom = e.get("nom_complet") or e.get("nom_raison_sociale")
        ville = s.get("libelle_commune") or ""
        dirs = [(d.get("denomination") or " ".join(x for x in (d.get("prenoms"), d.get("nom")) if x)) + (f" — {d['qualite']}" if d.get("qualite") else "") for d in (e.get("dirigeants") or [])[:6]]
        etat = f"[{G}]ACTIVE" if e.get("etat_administratif") == "A" else f"[{R}]FERMÉE"
        body = (f"[{M}]SIREN[/] {e.get('siren')}   {etat}[/]\n[{M}]Adresse[/] {escape(s.get('adresse') or '—')}\n[{M}]Activité[/] {escape(str(e.get('activite_principale') or '—'))}"
                f"   [{M}]Créée le[/] {e.get('date_creation') or '—'}\n[{M}]Effectif[/] {EFF.get(e.get('tranche_effectif_salarie'), e.get('tranche_effectif_salarie') or '—')}"
                f"   [{M}]Catégorie[/] {e.get('categorie_entreprise') or '—'}   [{M}]Établissements[/] {e.get('nombre_etablissements_ouverts', '?')}/{e.get('nombre_etablissements', '?')}")
        if dirs:
            body += f"\n[{M}]Dirigeants[/] " + escape(" · ".join(dirs))
        body += (f"\n[{B}]Pages Jaunes[/] https://www.pagesjaunes.fr/annuaire/chercherlespros?quoiqui={requests.utils.quote(nom)}&ou={requests.utils.quote(ville)}"
                 f"\n[{B}]Pappers[/] https://www.pappers.fr/entreprise/{e.get('siren')}\n[{B}]Maps[/] https://www.google.com/maps/search/?api=1&query={requests.utils.quote(nom + ' ' + (s.get('adresse') or ''))}")
        con.print(Panel(body, title=f"[{G}]{i}. {escape(nom)}", border_style="#2b3158", title_align="left"))
    if res:
        add_report("Entreprise", f'Recherche "{q}"', "\n".join(f"{e.get('nom_complet')} · SIREN {e.get('siren')} · {(e.get('siege') or {}).get('adresse', '')}" for e in res))
        while True:
            i = select("Entreprise", [{"label": f"{(e.get('nom_complet') or '?')[:50]}", "desc": f"{(e.get('siege') or {}).get('libelle_commune', '')} · {e.get('siren')}", "value": n}
                                      for n, e in enumerate(res)] + [{"label": "← Retour au menu", "value": "back"}], echo=False)
            if i in (None, "back"):
                break
            e = res[i]
            nom, ville = e.get("nom_complet", ""), (e.get("siege") or {}).get("libelle_commune", "")
            act = select(nom[:40], [{"label": "🤖 Analyse IA", "value": "ia"}, {"label": "📒 Pages Jaunes", "value": f"https://www.pagesjaunes.fr/annuaire/chercherlespros?quoiqui={requests.utils.quote(nom)}&ou={requests.utils.quote(ville)}"},
                                    {"label": "📑 Pappers (comptes, actes)", "value": f"https://www.pappers.fr/entreprise/{e.get('siren')}"},
                                    {"label": "📍 Google Maps", "value": f"https://www.google.com/maps/search/?api=1&query={requests.utils.quote(nom + ' ' + ((e.get('siege') or {}).get('adresse') or ''))}"},
                                    {"label": "📰 Annonces légales (BODACC)", "value": f"https://www.bodacc.fr/pages/annonces-commerciales/?q.registre=registre:{e.get('siren')}"},
                                    {"label": "← Retour", "value": None}])
            if not act:
                continue
            if act != "ia":
                webbrowser.open(act)
                continue
            data = {k: e.get(k) for k in ("nom_complet", "siren", "etat_administratif", "date_creation", "activite_principale", "categorie_entreprise", "nombre_etablissements_ouverts", "complements")}
            data["effectif"] = EFF.get(e.get("tranche_effectif_salarie"))
            data["siege"] = (e.get("siege") or {}).get("adresse")
            t = ai_print(f"Tu es analyste OSINT entreprise. Données officielles (registre français) :\n{json.dumps(data, ensure_ascii=False)}\n\n"
                         "En français : 1) fiche synthèse (activité en clair d'après le code NAF, ancienneté, taille), 2) signaux de confiance / points de vigilance, 3) vérifications à faire ensuite (avis, site web, Pages Jaunes, BODACC…). Concis.")
            if t:
                add_report("Entreprise", nom, t)
    pause()


# ============================================================ 6. RAPPORT


# ============================================================ 7. PREVNAME (anciens pseudos)
HIST_FILE = BASE / "historique_noms.json"


def hist_load():
    try:
        return json.loads(HIST_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def hist_track(key, name):
    """Mémorise le nom actuel d'un compte (ID stable) et renvoie les anciens noms déjà vus par l'outil."""
    H = hist_load()
    rec = H.setdefault(key, [])
    if name and (not rec or rec[-1]["nom"] != name):
        rec.append({"nom": name, "vu": datetime.datetime.now().strftime("%d/%m/%Y %H:%M")})
        try:
            HIST_FILE.write_text(json.dumps(H, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:
            pass
    return [(r["nom"], "vu le " + r["vu"]) for r in rec if r["nom"] != name]


def pn_steam(q):
    path = f"profiles/{q}" if re.fullmatch(r"7656119\d{10}", q) else f"id/{q}"
    r = get(f"https://steamcommunity.com/{path}/?xml=1", 12)
    if r.status_code != 200 or "<error>" in r.text:
        return None
    name = (re.search(r"<steamID><!\[CDATA\[(.*?)\]\]>", r.text) or [None, "?"])[1]
    sid = (re.search(r"<steamID64>(\d+)</steamID64>", r.text) or [None, "?"])[1]
    created = (re.search(r"<memberSince>(.*?)</memberSince>", r.text) or [None, ""])[1]
    try:
        al = get(f"https://steamcommunity.com/profiles/{sid}/ajaxaliases", 12).json() or []
    except Exception:
        al = []
    old = [(a.get("newname"), a.get("timechanged")) for a in al if a.get("newname") != name]
    return {"p": "Steam", "compte": f"{name} · ID {sid}" + (f" · membre depuis {created}" if created else ""), "old": old,
            "local": hist_track("steam:" + sid, name), "lien": f"https://steamcommunity.com/profiles/{sid}"}


def pn_roblox(q):
    if q.isdigit():
        u = get_json(f"https://users.roblox.com/v1/users/{q}", 12)
        uid, name, disp = u["id"], u["name"], u.get("displayName")
    else:
        d = HTTP.post("https://users.roblox.com/v1/usernames/users", json={"usernames": [q], "excludeBannedUsers": False}, timeout=12).json().get("data") or []
        if not d:
            return None
        uid, name, disp = d[0]["id"], d[0]["name"], d[0].get("displayName")
    created = ""
    try:
        created = get_json(f"https://users.roblox.com/v1/users/{uid}", 10).get("created", "")[:10]
    except Exception:
        pass
    hist = get_json(f"https://users.roblox.com/v1/users/{uid}/username-history?limit=100&sortOrder=Desc", 12).get("data", [])
    return {"p": "Roblox", "compte": f"{name} (affiché : {disp}) · ID {uid}" + (f" · créé le {created}" if created else ""),
            "old": [(h["name"], None) for h in hist if h.get("name") != name], "local": hist_track(f"roblox:{uid}", name),
            "lien": f"https://www.roblox.com/users/{uid}/profile"}


def pn_minecraft(q):
    r = get(f"https://api.mojang.com/users/profiles/minecraft/{q}", 10)
    if r.status_code != 200:
        return None
    j = r.json()
    uuid, name = j["id"], j["name"]
    old = []
    try:
        lj = get_json(f"https://laby.net/api/v3/user/{uuid}/profile", 12)
        hist = lj.get("username_history") or lj.get("name_history") or []
        for h in hist:
            n = h.get("name") or h.get("username")
            if n and n.lower() != name.lower():
                old.append((n, h.get("changed_at") or h.get("changedAt")))
    except Exception:
        pass
    return {"p": "Minecraft", "compte": f"{name} · UUID {uuid}", "old": old, "local": hist_track("mc:" + uuid, name),
            "lien": f"https://laby.net/@{name}  ·  https://namemc.com/profile/{name}"}


def pn_twitter(q):
    j = get_json(f"https://api.memory.lol/v1/tw/{q}", 15)
    out = []
    for acc in j.get("accounts", []):
        names = acc.get("screen_names") or {}
        old = [(n, (d or [None])[0]) for n, d in names.items() if n.lower() != q.lower()]
        out.append({"p": "X / Twitter", "compte": f"@{q} · ID {acc.get('id')}", "old": old, "local": [], "lien": f"https://x.com/i/user/{acc.get('id')}"})
    return out


def pn_github(q):
    j = get_json(f"https://api.github.com/users/{q}", 10)
    return {"p": "GitHub", "compte": f"{j['login']} ({j.get('name') or '—'}) · ID {j['id']} · créé le {j['created_at'][:10]}", "old": [],
            "local": hist_track(f"github:{j['id']}", j["login"]), "lien": j["html_url"]}




WB_TARGETS = {
    "Instagram": "instagram.com/{u}", "TikTok": "tiktok.com/@{u}", "X / Twitter": "twitter.com/{u}", "YouTube": "youtube.com/@{u}",
    "Twitch": "twitch.tv/{u}", "Kick": "kick.com/{u}", "Reddit": "reddit.com/user/{u}", "GitHub": "github.com/{u}", "GitLab": "gitlab.com/{u}",
    "Steam": "steamcommunity.com/id/{u}", "Snapchat": "snapchat.com/add/{u}", "Telegram": "t.me/{u}", "Facebook": "facebook.com/{u}",
    "Pinterest": "pinterest.com/{u}", "Bluesky": "bsky.app/profile/{u}", "Threads": "threads.net/@{u}", "Mastodon": "mastodon.social/@{u}",
    "Chess.com": "chess.com/member/{u}", "Lichess": "lichess.org/@/{u}", "Roblox": "roblox.com/user.aspx?username={u}",
    "Minecraft (NameMC)": "namemc.com/profile/{u}", "Medium": "medium.com/@{u}", "Dev.to": "dev.to/{u}", "Linktree": "linktr.ee/{u}",
    "SoundCloud": "soundcloud.com/{u}", "Scratch": "scratch.mit.edu/users/{u}", "Vimeo": "vimeo.com/{u}", "Last.fm": "last.fm/user/{u}",
    "DeviantArt": "deviantart.com/{u}", "Behance": "behance.net/{u}", "Dribbble": "dribbble.com/{u}", "Flickr": "flickr.com/people/{u}",
    "Patreon": "patreon.com/{u}", "Ko-fi": "ko-fi.com/{u}", "VK": "vk.com/{u}", "Letterboxd": "letterboxd.com/{u}", "Imgur": "imgur.com/user/{u}",
    "Pastebin": "pastebin.com/u/{u}", "Docker Hub": "hub.docker.com/u/{u}", "npm": "npmjs.com/~{u}", "Hacker News": "news.ycombinator.com/user?id={u}",
    "Keybase": "keybase.io/{u}", "Gravatar": "gravatar.com/{u}", "Wattpad": "wattpad.com/user/{u}", "Tumblr": "{u}.tumblr.com",
    "Bandcamp": "{u}.bandcamp.com", "Itch.io": "{u}.itch.io", "Gumroad": "{u}.gumroad.com", "Mixcloud": "mixcloud.com/{u}",
    "Dailymotion": "dailymotion.com/{u}", "Rumble": "rumble.com/user/{u}", "Unsplash": "unsplash.com/@{u}", "Goodreads": "goodreads.com/{u}",
    "Codeforces": "codeforces.com/profile/{u}", "LeetCode": "leetcode.com/u/{u}", "Hackaday": "hackaday.io/{u}", "Thingiverse": "thingiverse.com/{u}",
}

# Plateformes où le site redirige l'ancien pseudo vers le nouveau (301/302/307/308) : détection du renommage.
REDIR_SITES = [
    ("GitHub", "https://github.com/{u}"), ("GitLab", "https://gitlab.com/{u}"), ("Codeberg", "https://codeberg.org/{u}"),
    ("Docker Hub", "https://hub.docker.com/u/{u}"), ("Twitch", "https://www.twitch.tv/{u}"), ("Kick", "https://kick.com/{u}"),
    ("Chess.com", "https://www.chess.com/member/{u}"), ("Lichess", "https://lichess.org/@/{u}"), ("Medium", "https://medium.com/@{u}"),
    ("Dev.to", "https://dev.to/{u}"), ("Pinterest", "https://www.pinterest.com/{u}/"), ("YouTube", "https://www.youtube.com/@{u}"),
    ("Instagram", "https://www.instagram.com/{u}/"), ("SoundCloud", "https://soundcloud.com/{u}"), ("Scratch", "https://scratch.mit.edu/users/{u}/"),
    ("Linktree", "https://linktr.ee/{u}"), ("Telegram", "https://t.me/{u}"), ("Threads", "https://www.threads.net/@{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}"), ("TikTok", "https://www.tiktok.com/@{u}"), ("Snapchat", "https://www.snapchat.com/add/{u}"),
    ("Steam", "https://steamcommunity.com/id/{u}"), ("Mastodon", "https://mastodon.social/@{u}"), ("Vimeo", "https://vimeo.com/{u}"),
    ("Last.fm", "https://www.last.fm/user/{u}"), ("Behance", "https://www.behance.net/{u}"), ("Dribbble", "https://dribbble.com/{u}"),
    ("Patreon", "https://www.patreon.com/{u}"), ("Ko-fi", "https://ko-fi.com/{u}"), ("Letterboxd", "https://letterboxd.com/{u}/"),
    ("Imgur", "https://imgur.com/user/{u}"), ("Hacker News", "https://news.ycombinator.com/user?id={u}"), ("Wattpad", "https://www.wattpad.com/user/{u}"),
    ("Flickr", "https://www.flickr.com/people/{u}"), ("DeviantArt", "https://www.deviantart.com/{u}"), ("Mixcloud", "https://www.mixcloud.com/{u}/"),
]
NON_USER = {"login", "signin", "sign_in", "signup", "accounts", "auth", "404", "error", "home", "explore", "u", "user", "users", "profile",
            "channel", "c", "search", "not-found", "notfound", "unavailable", "suspended", "err", "index.html", "members", "member"}


def wayback_traces(u):
    def one(item):
        n, url = item[0], item[1].replace("{u}", u)
        rows = get_json(f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp&filter=statuscode:200&limit=2000", 25)[1:]
        ts = sorted(r[0] for r in rows)
        return (n, url, len(ts), ts[0] if ts else None, ts[-1] if ts else None)
    out = []
    with cf.ThreadPoolExecutor(10) as ex:
        for f in [ex.submit(one, it) for it in WB_TARGETS.items()]:
            try:
                r = f.result()
                if r[2]:
                    out.append(r)
            except Exception:
                pass
    return sorted(out, key=lambda x: x[3])


def wbd(s):
    return f"{s[6:8]}/{s[4:6]}/{s[:4]}" if s else "—"


def pn_redir_one(p, tpl, n):
    """Si le site redirige « n » vers un autre pseudo, c'est que le compte a été renommé : on renvoie le nouveau pseudo."""
    url = tpl.replace("{u}", n)
    try:
        r = get(url, 10, allow_redirects=False)
    except requests.RequestException:
        return None
    if r.status_code not in (301, 302, 303, 307, 308):
        return None
    full = requests.compat.urljoin(url, r.headers.get("Location", ""))
    pu, pf = requests.utils.urlparse(url), requests.utils.urlparse(full)
    if pf.netloc.lower() != pu.netloc.lower():
        return None
    tsegs = [s for s in requests.utils.urlparse(tpl).path.split("/") if s]
    psegs = [s for s in pf.path.split("/") if s]
    idx = next((i for i, s in enumerate(tsegs) if "{u}" in s), None)
    if idx is None or idx >= len(psegs):
        return None
    if any(a.lstrip("@~").lower() != b.lstrip("@~").lower() for a, b in zip(tsegs[:idx], psegs[:idx]) if "{u}" not in a):
        return None
    new = psegs[idx].lstrip("@~")
    if new.lower() == n.lower() or new.lower() in NON_USER or not re.fullmatch(r"[A-Za-z0-9._-]{2,40}", new):
        return None
    return {"p": p, "compte": f"{new} · renommé depuis « {n} »", "old": [(n, f"redirection {r.status_code}")], "local": [],
            "lien": full}


def pn_bluesky(q):
    """Historique complet des pseudos Bluesky : le journal public PLC garde chaque changement de « handle »."""
    if q.startswith("did:"):
        did = q
    else:
        handle = q if "." in q else q + ".bsky.social"
        did = get_json(f"https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={handle}", 12).get("did")
    if not did:
        return None
    ops = get_json(f"https://plc.directory/{did}/log", 15)
    seen = []
    for op in ops if isinstance(ops, list) else []:
        for aka in op.get("alsoKnownAs") or []:
            h = aka.replace("at://", "")
            if h not in [s[0] for s in seen]:
                seen.append((h, (op.get("createdAt") or "")[:10] or None))
    if not seen:
        return None
    cur = seen[-1][0]
    return {"p": "Bluesky", "compte": f"@{cur} · DID {did}", "old": [(h, d) for h, d in seen[:-1]], "local": [], "lien": f"https://bsky.app/profile/{cur}"}


def prevname_core(q, names=None):
    q = q.strip().lstrip("@")
    names = names or [q]
    tasks = []  # (libellé, fonction sans argument)
    if re.fullmatch(r"7656119\d{10}", q):
        tasks.append(("Steam", lambda: pn_steam(q)))
    elif q.isdigit() and len(q) <= 10:
        tasks.append(("Roblox", lambda: pn_roblox(q)))
    elif q.isdigit():
        con.print(f"[{Y}]Cet identifiant numérique n'est pas pris en charge par les sources actuelles.[/]")
        return
    else:
        for n in names:
            tasks += [("Steam", lambda n=n: pn_steam(n)), ("Roblox", lambda n=n: pn_roblox(n)), ("Minecraft", lambda n=n: pn_minecraft(n)),
                      ("X / Twitter", lambda n=n: pn_twitter(n)), ("GitHub", lambda n=n: pn_github(n)), ("Bluesky", lambda n=n: pn_bluesky(n))]
            tasks += [(p, lambda p=p, t=t, n=n: pn_redir_one(p, t, n)) for p, t in REDIR_SITES]
    found, traces, ok = [], [], 0
    with con.status(f"[{P}]Fouille de {len(tasks)} sources et des archives web…", spinner="dots12"):
        with cf.ThreadPoolExecutor(12) as ex:
            futs = {ex.submit(fn): n for n, fn in tasks}
            wb = ex.submit(wayback_traces, q) if not q.isdigit() else None
            for f in cf.as_completed(futs):
                try:
                    r = f.result()
                    ok += 1
                    r = r if isinstance(r, list) else [r] if r else []
                    for x in r:
                        if x["compte"] not in [y["compte"] for y in found]:
                            found.append(x)
                except Exception:
                    pass
            if wb:
                try:
                    traces = wb.result()
                except Exception:
                    log("Archives web indisponibles", Y)
    log(f"{ok}/{len(tasks)} sources interrogées avec succès · {len(found)} compte(s) trouvé(s) · {len(traces)} plateforme(s) dans les archives web",
        G if found or traces else M)
    lines = []
    for a in found:
        body = f"[{M}]Compte actuel[/] {escape(a['compte'])}\n"
        if a["old"]:
            body += f"[{P}]Anciens pseudos :[/]\n" + "\n".join(
                f"  [{P}]↳[/] {escape(str(n))}" + (f" [{M}]({escape(str(d))})[/]" if d else "") for n, d in a["old"])
        else:
            body += f"[{M}]Aucun ancien pseudo public[/]"
        if a.get("local"):
            body += f"\n[{Y}]Déjà vus par l'outil :[/] " + ", ".join(f"{escape(n)} [{M}]({d})[/]" for n, d in a["local"])
        if a.get("note"):
            body += f"\n[{B}]ℹ {escape(a['note'])}[/]"
        body += f"\n[{B}]{escape(a['lien'])}[/]"
        con.print(Panel(body, title=f"[{G}]{a['p']}", title_align="left", border_style="#b388ff" if a["old"] else "#2b3158"))
        lines.append(f"{a['p']} : {a['compte']}" + (" | anciens : " + ", ".join(str(n) for n, _ in a["old"]) if a["old"] else ""))
    if traces:
        t = Table(title=f"Traces archivées du pseudo « {escape(q)} »", box=box.ROUNDED, border_style="#2b3158")
        for c in ("Plateforme", "Captures", "Première", "Dernière", "Voir"):
            t.add_column(c)
        for n, url, c, a, b in traces:
            t.add_row(n, str(c), wbd(a), wbd(b), f"https://web.archive.org/web/*/{url}")
        con.print(t)
        con.print(f"[{M}]Le pseudo a existé sur ces plateformes à ces dates : compte actuel, ancien compte renommé ou supprimé.")
        lines.append("Archives : " + ", ".join(f"{n} ({wbd(a)} → {wbd(b)})" for n, _, _, a, b in traces))
    if not found and not traces:
        con.print(f"[{M}]Aucun historique trouvé pour « {escape(q)} ».")
    add_report("Prevname", q, "\n".join(lines) or "rien trouvé")


def mod_prevname():
    con.rule(f"[{G}]⏳ PREVNAME · ANCIENS PSEUDOS")
    con.print(f"[{M}]Pseudo → Steam, Roblox, Minecraft, X, GitHub, Bluesky (historique complet), {len(REDIR_SITES)} sites qui redirigent les anciens pseudos,\n"
              f"et {len(WB_TARGETS)} plateformes dans les archives web (Wayback Machine).\n"
              f"ID Steam64 (7656119…) → historique Steam · petit nombre → ID Roblox · DID Bluesky (did:plc:…) accepté.\n")
    q = Prompt.ask(f"[{G}]Pseudo ou ID").strip()
    if not q:
        return pause()
    names = None
    if re.fullmatch(r"[A-Za-z0-9._@-]+", q.lstrip("@")) and not q.isdigit() and ask_yes("Tester aussi les variantes (_ . -) ?"):
        names = variants(q.lstrip("@"))
    prevname_core(q, names)
    pause()


# ============================================================ 8. EMAIL
EMAIL_PROV = [("Google", "google"), ("Microsoft", "outlook|protection.outlook"), ("OVH", "ovh"), ("Proton", "protonmail|proton"), ("iCloud", "icloud"),
              ("Gandi", "gandi"), ("IONOS", "ionos|1and1"), ("Zoho", "zoho"), ("Orange", "orange"), ("Free", "free\\.fr"), ("SFR", "sfr"), ("Yahoo", "yahoo")]


def disposable_list():
    f = OUT / ".jetables.txt"
    if f.exists() and time.time() - f.stat().st_mtime < 7 * 86400:
        return set(f.read_text(encoding="utf-8").split())
    try:
        t = get("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf", 15).text
        f.write_text(t, encoding="utf-8")
        return set(t.split())
    except Exception:
        return set()


def mod_email():
    con.rule(f"[{G}]📧 EMAIL")
    e = Prompt.ask(f"[{G}]Adresse e-mail").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", e):
        con.print(f"[{R}]Adresse invalide.")
        return pause()
    local, dom = e.split("@")
    R_ = {}

    def j_mx():
        R_["mx"] = dns(dom, "MX")

    def j_txt():
        R_["spf"] = next((t for t in dns(dom, "TXT") if "v=spf1" in str(t)), None)

    def j_dmarc():
        R_["dmarc"] = next((t for t in dns("_dmarc." + dom, "TXT") if "DMARC1" in str(t)), None)

    def j_jet():
        R_["jet"] = dom in disposable_list()

    def j_grav():
        r = get(f"https://en.gravatar.com/{hashlib.md5(e.encode()).hexdigest()}.json", 10)
        R_["grav"] = r.json()["entry"][0] if r.ok else False

    def j_leaks():
        try:
            j = get_json(f"https://api.xposedornot.com/v1/breach-analytics?email={_q(e)}", 20)
            det = ((j.get("ExposedBreaches") or {}).get("breaches_details")) or []
            R_["leaks"] = [(d.get("breach"), d.get("xposed_date"), leak_fr(d.get("xposed_data"))) for d in det]
        except Exception:
            j = get_json(f"https://api.xposedornot.com/v1/check-email/{_q(e)}", 15)
            R_["leaks"] = [(b, None, None) for b in (j.get("breaches") or [[]])[0]]

    def j_acc():
        R_["acc"] = email_accounts(e, deep=False)
    with con.status(f"[{P}]Serveurs mail, Gravatar, fuites, comptes…", spinner="dots12"):
        with _TPE(8) as ex:
            fut = {ex.submit(f): f.__name__ for f in (j_mx, j_txt, j_dmarc, j_jet, j_grav, j_leaks, j_acc)}
            for f in fut:
                try:
                    f.result()
                except Exception:
                    R_.setdefault("err", []).append(fut[f][2:])
    mx = R_.get("mx") or []
    prov = next((n for n, rx in EMAIL_PROV if re.search(rx, " ".join(map(str, mx)), re.I)), "autre / perso") if mx else "?"
    g = R_.get("grav")
    rows = [("Adresse", e), ("Hébergeur mail", prov), ("Serveurs (MX)", ", ".join(map(str, mx)) or ("aucun : le domaine ne reçoit pas d'emails" if "mx" in R_ else "pas de réponse")),
            ("Jetable", "OUI (adresse temporaire)" if R_.get("jet") else "non"),
            ("Sécurité du domaine", f"SPF {'oui' if R_.get('spf') else 'non'} · DMARC {'oui' if R_.get('dmarc') else 'non'}" + ("" if R_.get("spf") and R_.get("dmarc") else "  → usurpation plus facile")),
            ("Gravatar", (g.get("displayName") or g.get("preferredUsername") or "profil public") + " · " + g.get("profileUrl", "") if g else ("aucun profil public" if g is False else "pas de réponse"))]
    if g:
        rows += [("Comptes liés (Gravatar)", "\n".join(a.get("url", "") for a in g.get("accounts", []))), ("Lieu (Gravatar)", g.get("currentLocation")), ("Bio", g.get("aboutMe"))]
    leaks = R_.get("leaks")
    found, limited, checked, _ = R_.get("acc") or ([], 0, 0, False)
    rows += [("Fuites de données", f"{len(leaks)} fuite(s)" if leaks else ("aucune connue" if leaks == [] else "pas de réponse")),
             ("Comptes (test rapide)", ", ".join(d for d, _ in found) or f"aucun sur {checked} sites"),
             ("Pseudo probable", local if re.fullmatch(r"[A-Za-z0-9._-]{3,40}", local) else None),
             ("Aller plus loin", f"Email → comptes (120 sites) · https://epieos.com/?q={_q(e)}")]
    if R_.get("err"):
        rows.append(("Sources muettes", ", ".join(R_["err"]) + " (connexion lente ou bloquée : réessaie)"))
    con.print(kv(rows, f"📧 {e}", R_STYLE if leaks else G))
    if leaks:
        lr = [[str(n), str(d or "—"), str(x or "—")] for n, d, x in leaks]
        if len(lr) > 12:
            table_pages(f"⚠ {len(lr)} fuites contenant cette adresse", ["Fuite", "Année", "Données exposées"], lr)
        else:
            lt = Table(title=f"⚠ {len(lr)} fuite(s) contenant cette adresse", box=box.ROUNDED, border_style=R_STYLE)
            for c in ("Fuite", "Année", "Données exposées"):
                lt.add_column(c, overflow="fold")
            for r_ in lr:
                lt.add_row(*map(escape, r_))
            con.print(lt)
        con.print(f"[{Y}]→ Si c'est ton adresse : change les mots de passe de ces services et active la double authentification.")
    root = gnode("email", e)
    for d, _ in found:
        gnode("compte", f"{d} · {e}", None, root, "inscrit", d)
    gsave()
    add_report("Email", e, "\n".join(f"{k} : {v}" for k, v in rows if v) + ("\nFuites : " + ", ".join(str(n) for n, _, _ in leaks[:30]) if leaks else ""))
    nxt = select("Et ensuite ?", [{"label": "Terminé", "value": None}, {"label": "Chercher les comptes sur 120 sites (Holehe)", "value": "h"}]
                 + ([{"label": f"Chercher le pseudo « {local} »", "value": "u"}] if re.fullmatch(r"[A-Za-z0-9._-]{3,40}", local) else []), echo=False)
    if nxt == "h":
        with con.status(f"[{P}]Test de 120 sites (≈ 30-60 s)…", spinner="dots12"):
            f2, l2, c2, hol = email_accounts(e, True)
        con.print(accounts_panel(e, f2, l2, c2))
        if not hol:
            log("Holehe n'est pas installé : passe par le module « Email → comptes » pour l'installer.", Y)
        for d, _ in f2:
            gnode("compte", f"{d} · {e}", None, root, "inscrit", d)
        gsave()
        pause()
    elif nxt == "u":
        mod_user_direct(local)


def mod_user_direct(u):
    """Lance le module pseudo avec un pseudo déjà connu."""
    old = Prompt.ask
    answers = iter([u])
    Prompt.ask = lambda *a, **k: next(answers, None) or old(*a, **k)
    try:
        mod_user()
    finally:
        Prompt.ask = old


# ============================================================ 9. TÉLÉPHONE
PTYPE = {0: "fixe", 1: "mobile", 2: "fixe ou mobile", 3: "numéro gratuit", 4: "numéro surtaxé", 5: "coût partagé", 6: "VoIP", 7: "numéro personnel", 8: "bipeur", 9: "UAN", 10: "messagerie vocale"}


def mod_phone():
    con.rule(f"[{G}]📱 NUMÉRO DE TÉLÉPHONE")
    if phonenumbers is None:
        con.print(f"[{R}]Module manquant : pip install phonenumbers")
        return pause()
    n = Prompt.ask(f"[{G}]Numéro (ex. 06 12 34 56 78 ou +33 6…)")
    try:
        p = phonenumbers.parse(n, "FR")
    except Exception:
        con.print(f"[{R}]Numéro illisible.")
        return pause()
    e164 = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
    nat = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL)
    intl = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    t = Table(box=box.SIMPLE, show_header=False)
    rows = [("Valide", f"[{G}]oui" if phonenumbers.is_valid_number(p) else f"[{R}]non"),
            ("Formats", escape(f"{intl}  ·  {nat}  ·  {e164}")),
            ("Pays / zone", escape(pn_geo.description_for_number(p, "fr") or "—")),
            ("Type", PTYPE.get(phonenumbers.number_type(p), "inconnu")),
            ("Opérateur d'origine", escape(pn_carrier.name_for_number(p, "fr") or "inconnu") + f" [{M}](le numéro a pu être porté ailleurs)"),
            ("Fuseau", escape(", ".join(pn_tz.time_zones_for_number(p))))]
    for k, v in rows:
        t.add_row(f"[{M}]{k}", v)
    con.print(t)
    digits = e164.lstrip("+")
    q = " OR ".join(f'"{x}"' for x in dict.fromkeys([nat, nat.replace(" ", ""), intl, e164]))
    con.print(f"[{B}]Recherche web[/] https://www.google.com/search?q={requests.utils.quote(q)}\n[{B}]WhatsApp[/] https://wa.me/{digits}")
    add_report("Téléphone", intl, "\n".join(f"{k} : {re.sub(r'\[.*?\]', '', v)}" for k, v in rows))
    if ask_yes("Ouvrir la recherche web du numéro ?"):
        webbrowser.open("https://www.google.com/search?q=" + requests.utils.quote(q))
    pause()


# ============================================================ CARTES (commun à toutes les pages HTML)
# Fonds de carte qui marchent même en ouvrant le fichier en local (file://), bascule auto si un fond est bloqué,
# Leaflet chargé depuis 3 CDN, géocodage Nominatim → Photon en secours.
LEAFLET_HEAD = r"""<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" onerror="this.onerror=null;this.href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'">
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<script>window.L||document.write('<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>')</script>
<script>window.L||document.write('<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"><\/script>')</script>
<style>
.cat-toast{position:absolute;z-index:1000;left:50%;top:10px;transform:translateX(-50%);background:#141b20ee;color:#ffc861;border:1px solid #ffb84a55;font:12px monospace;padding:6px 12px;border-radius:8px;pointer-events:none;transition:opacity .4s}
.cat-xy{background:#07090bcc;color:#00e5ff;font:11px monospace;padding:3px 8px;border-radius:6px;border:1px solid #2b3158}
.cat-btn{background:#fff;width:34px;height:34px;line-height:34px;text-align:center;font-size:17px;cursor:pointer;color:#111;display:block;text-decoration:none}
.cat-err{padding:30px;font:14px/1.6 monospace;color:#ffc861;background:#0e1028;height:100%;box-sizing:border-box}
.leaflet-container{background:#0b0d22;font-family:system-ui,-apple-system,sans-serif}
.cat-pop{font:12px/1.6 monospace}.cat-pop a{color:#0a7;margin-right:8px}
</style>
<script>
function catMap(id,o){
 o=o||{};const el=document.getElementById(id);
 if(!window.L){el.innerHTML='<div class="cat-err">⚠ La carte n\'a pas pu se charger.<br>Vérifie la connexion Internet, le pare-feu ou le bloqueur de pub (autorise cdnjs.cloudflare.com / unpkg.com), puis recharge la page (F5).</div>';return null;}
 const map=L.map(id,{preferCanvas:true,worldCopyJump:true});
 const T=(u,a,z,s)=>L.tileLayer(u,{maxZoom:z||19,attribution:a,subdomains:s||'abc'});
 const labels=T('https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}','',19);
 const E=p=>'https://server.arcgisonline.com/ArcGIS/rest/services/'+p+'/MapServer/tile/{z}/{y}/{x}';
 const B={'Plan':T(E('World_Street_Map'),'© Esri, HERE, Garmin, OpenStreetMap',19),
  'Satellite':L.layerGroup([T(E('World_Imagery'),'© Esri, Maxar, Earthstar',19),labels]),
  'Sombre':L.layerGroup([T(E('Canvas/World_Dark_Gray_Base'),'© Esri',16),T(E('Canvas/World_Dark_Gray_Reference'),'',16)]),
  'Relief':T(E('World_Topo_Map'),'© Esri',19),
  'OpenStreetMap':T('https://tile.openstreetmap.org/{z}/{x}/{y}.png','© OpenStreetMap',19),
  'OSM humanitaire':T('https://{s}.tile.openstreetmap.fr/hot/{z}/{x}/{y}.png','© OpenStreetMap, HOT',19),
  'OpenTopoMap':T('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png','© OpenTopoMap',17)};
 const order=['Plan','OpenStreetMap','OSM humanitaire','Satellite','Relief','OpenTopoMap','Sombre'];let cur=o.base&&B[o.base]?o.base:'Plan';
 const toast=t=>{let d=el.querySelector('.cat-toast');if(!d){d=document.createElement('div');d.className='cat-toast';el.appendChild(d);}d.textContent=t;d.style.opacity=1;clearTimeout(d._t);d._t=setTimeout(()=>d.style.opacity=0,4500);};
 Object.entries(B).forEach(([n,l])=>{const tl=l.getLayers?l.getLayers()[0]:l;tl._ok=0;tl._ko=0;
  tl.on('tileload',()=>tl._ok++);
  tl.on('tileerror',()=>{tl._ko++;if(n===cur&&tl._ok===0&&tl._ko>=4){const nx=order[(order.indexOf(n)+1)%order.length];if(nx===o.base)return;toast('Fond « '+n+' » bloqué → bascule sur « '+nx+' »');map.removeLayer(l);cur=nx;B[nx].addTo(map);}});});
 B[cur].addTo(map);map.on('baselayerchange',e=>{cur=Object.keys(B).find(k=>B[k]===e.layer)||cur;});
 L.control.layers(B,null,{position:'topright'}).addTo(map);
 L.control.scale({imperial:false}).addTo(map);
 const XY=L.Control.extend({onAdd(){const d=L.DomUtil.create('div','cat-xy');d.textContent='—';map.on('mousemove',e=>d.textContent=e.latlng.lat.toFixed(5)+', '+e.latlng.lng.toFixed(5));return d;}});
 new XY({position:'bottomleft'}).addTo(map);
 const FS=L.Control.extend({onAdd(){const a=L.DomUtil.create('a','leaflet-bar cat-btn');a.title='Plein écran';a.textContent='⛶';
  L.DomEvent.on(a,'click',ev=>{L.DomEvent.stop(ev);document.fullscreenElement?document.exitFullscreen():el.requestFullscreen&&el.requestFullscreen();});return a;}});
 new FS({position:'topleft'}).addTo(map);document.addEventListener('fullscreenchange',()=>setTimeout(()=>map.invalidateSize(),200));
 if(o.clickCoords!==false)map.on('click',e=>{const la=e.latlng.lat.toFixed(6),lo=e.latlng.lng.toFixed(6);
  L.popup().setLatLng(e.latlng).setContent(`<div class="cat-pop"><b>${la}, ${lo}</b><br><a target="_blank" href="https://www.google.com/maps?q=${la},${lo}">Google Maps</a><a target="_blank" href="https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${la},${lo}">Street View</a><a target="_blank" href="https://earth.google.com/web/@${la},${lo},300a,800d,35y,0h,45t,0r">Earth 3D</a><a target="_blank" href="https://www.openstreetmap.org/?mlat=${la}&mlon=${lo}#map=18/${la}/${lo}">OSM</a></div>`).openOn(map);});
 map.setView(o.center||[20,0],o.zoom||2);return map;}
async function catGeocode(q,vb){
 try{const j=await (await fetch(`https://nominatim.openstreetmap.org/search?format=jsonv2&limit=6&accept-language=fr${vb?'&viewbox='+vb:''}&q=${encodeURIComponent(q)}`)).json();
  if(Array.isArray(j))return j.map(x=>({name:x.display_name,lat:+x.lat,lon:+x.lon}));}catch(e){}
 const j=await (await fetch(`https://photon.komoot.io/api/?limit=6&q=${encodeURIComponent(q)}`)).json();
 return (j.features||[]).map(f=>{const p=f.properties||{};return {name:[p.name,p.street,p.city,p.state,p.country].filter(Boolean).join(', '),lat:f.geometry.coordinates[1],lon:f.geometry.coordinates[0]};});}
async function catReverse(la,lo){
 try{const j=await (await fetch(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${la}&lon=${lo}&zoom=18&accept-language=fr`)).json();if(j&&j.address)return j.address;}catch(e){}
 const j=await (await fetch(`https://photon.komoot.io/reverse?lat=${la}&lon=${lo}`)).json();const p=((j.features||[])[0]||{}).properties||{};
 return {house_number:p.housenumber,road:p.street||p.name,suburb:p.district,city:p.city,country:p.country};}
</script>"""


# ============================================================ OUTILS GÉO COMMUNS
def quick_map(title, markers, extra_html="", circles=None, lines=None, base=None):
    """Page carte autonome : markers [{lat,lon,label(html),c}], circles [{lat,lon,r,c}], lines [[[lat,lon],...]]."""
    data = {"m": markers, "c": circles or [], "l": lines or [], "base": base}
    return QUICK_TPL.replace("__LEAFLET__", LEAFLET_HEAD).replace("__TITLE__", escape_html(title)).replace("__EXTRA__", extra_html).replace("__DATA__", json.dumps(data))


QUICK_TPL = r"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title>
__LEAFLET__
<style>:root{--bg:#07081a;--p:#0e1028;--l:#2b3158;--t:#e4e9ff;--m:#7480a8;--g:#00e5ff;--k:#b388ff}
body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--t)}
header{padding:12px 18px;border-bottom:1px solid var(--l);display:flex;gap:14px;align-items:center;flex-wrap:wrap;background:linear-gradient(110deg,#0b1630,#07081a 55%,#1a0b30)}
header b{font:800 15px monospace;color:var(--g);letter-spacing:.5px}header .n{font:12px monospace;color:var(--m);background:#14173a;border:1px solid var(--l);padding:3px 9px;border-radius:20px}
header a{margin-left:auto;color:#8a8cff;font:13px monospace;text-decoration:none}header a:hover{color:var(--g)}
#map{height:calc(100vh - 52px)}body.ex-on #map{height:70vh}.ex{padding:14px 18px;font-size:14px;line-height:1.6;max-width:1100px}.ex a{color:var(--g)}
.ex table{border-collapse:collapse;font:12px monospace;width:100%;background:var(--p);border:1px solid var(--l);border-radius:10px;overflow:hidden}
.ex td,.ex th{border-bottom:1px solid var(--l);padding:6px 8px;text-align:left}.ex th{color:var(--g)}.leaflet-popup-content{font:13px/1.5 system-ui}.leaflet-popup-content a{color:#0a7}</style></head>
<body><header><b>CAT.exe // __TITLE__</b><span class="n" id="cnt"></span></header><div id="map"></div><div class="ex">__EXTRA__</div>
<script>const D=__DATA__;const map=catMap('map',{base:D.base});const g=L.featureGroup().addTo(map);
D.c.forEach(c=>L.circle([c.lat,c.lon],{radius:c.r,color:c.c||'#b388ff',weight:1,fillOpacity:.15}).addTo(g));
D.l.forEach(l=>L.polyline(l,{color:'#ffc861',weight:2}).addTo(g));
D.m.forEach(m=>(m.icon?L.marker([m.lat,m.lon],{icon:L.divIcon({className:'',iconSize:null,html:`<div style="transform:translate(-50%,-50%) rotate(${m.rot||0}deg);font-size:${m.s||20}px;color:${m.c||'#b388ff'};text-shadow:0 0 3px #000">${m.icon}</div>`})})
 :L.circleMarker([m.lat,m.lon],{radius:m.s||7,color:m.c||'#b388ff',fillOpacity:.85,weight:1})).bindPopup(m.label||'').addTo(g));
if(g.getLayers().length)map.fitBounds(g.getBounds(),{padding:[30,30],maxZoom:16});
document.getElementById('cnt').textContent=D.m.length+' point(s)';if(document.querySelector('.ex').textContent.trim()){document.body.classList.add('ex-on');map.invalidateSize();}</script></body></html>"""


def save_open(prefix, html):
    f = OUT / f"{prefix}_{stamp()}.html"
    f.write_text(html, encoding="utf-8")
    log(f"Page enregistrée : {f}", G)
    open_file(f)
    return f


def dms(v, pos, neg):
    d = abs(v)
    deg = int(d)
    m = int((d - deg) * 60)
    s = (d - deg - m / 60) * 3600
    return f"{deg}°{m:02d}'{s:05.2f}\"{pos if v >= 0 else neg}"


def geohash(lat, lon, prec=9):
    B = "0123456789bcdefghjkmnpqrstuvwxyz"
    la, lo, bits, bit, ch, even, out = [-90.0, 90.0], [-180.0, 180.0], [16, 8, 4, 2, 1], 0, 0, True, ""
    while len(out) < prec:
        rng, v = (lo, lon) if even else (la, lat)
        mid = (rng[0] + rng[1]) / 2
        if v > mid:
            ch |= bits[bit]
            rng[0] = mid
        else:
            rng[1] = mid
        even = not even
        if bit < 4:
            bit += 1
        else:
            out += B[ch]
            bit, ch = 0, 0
    return out


def plus_code(lat, lon):
    A = "23456789CFGHJMPQRVWX"
    lat = min(max(lat, -90), 89.9999999) + 90
    lon = ((lon + 180) % 360)
    code, res = "", 20.0
    for i in range(5):
        dl, dn = int(lat // res), int(lon // res)
        lat -= dl * res
        lon -= dn * res
        code += A[dl] + A[dn]
        res /= 20
        if i == 3:
            code += "+"
    return code


def to_utm(lat, lon):
    zone = int((lon + 180) / 6) + 1
    a, f, k0 = 6378137.0, 1 / 298.257223563, 0.9996
    e2 = f * (2 - f)
    ep2 = e2 / (1 - e2)
    p, l0 = math.radians(lat), math.radians((zone - 1) * 6 - 180 + 3)
    N = a / math.sqrt(1 - e2 * math.sin(p) ** 2)
    T, C, A = math.tan(p) ** 2, ep2 * math.cos(p) ** 2, math.cos(p) * (math.radians(lon) - l0)
    M = a * ((1 - e2 / 4 - 3 * e2 ** 2 / 64 - 5 * e2 ** 3 / 256) * p - (3 * e2 / 8 + 3 * e2 ** 2 / 32 + 45 * e2 ** 3 / 1024) * math.sin(2 * p)
             + (15 * e2 ** 2 / 256 + 45 * e2 ** 3 / 1024) * math.sin(4 * p) - (35 * e2 ** 3 / 3072) * math.sin(6 * p))
    x = k0 * N * (A + (1 - T + C) * A ** 3 / 6 + (5 - 18 * T + T ** 2 + 72 * C - 58 * ep2) * A ** 5 / 120) + 500000
    y = k0 * (M + N * math.tan(p) * (A ** 2 / 2 + (5 - T + 9 * C + 4 * C ** 2) * A ** 4 / 24 + (61 - 58 * T + T ** 2 + 600 * C - 330 * ep2) * A ** 6 / 720))
    if lat < 0:
        y += 10000000
    band = "CDEFGHJKLMNPQRSTUVWXX"[int((lat + 80) / 8)] if -80 <= lat <= 84 else "?"
    return f"{zone}{band} {x:.0f}E {y:.0f}N"


def parse_coords(s):
    """Accepte « 48.858, 2.294 », du DMS (48°51'30"N 2°17'40"E) ou une adresse / un nom de lieu."""
    s = s.strip()
    m = re.fullmatch(r"(-?\d{1,3}\.\d+)\s*[,; ]\s*(-?\d{1,3}\.\d+)", s)
    if m:
        return float(m[1]), float(m[2])
    parts = re.findall(r"(\d+(?:[.,]\d+)?)\s*°\s*(?:(\d+(?:[.,]\d+)?)\s*['’′]\s*)?(?:(\d+(?:[.,]\d+)?)\s*[\"”″]\s*)?([NSEWO])", s, re.I)
    if len(parts) == 2:
        vals = []
        for d, mi, se, h in parts:
            v = float(d.replace(",", ".")) + float((mi or "0").replace(",", ".")) / 60 + float((se or "0").replace(",", ".")) / 3600
            vals.append(-v if h.upper() in "SWO" else v)
        return vals[0], vals[1]
    return geocode(s)


def map_links(lat, lon, h=0):
    return {"Google Maps": f"https://www.google.com/maps?q={lat},{lon}",
            "Street View": f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}&heading={h:.0f}",
            "Google Earth 3D": f"https://earth.google.com/web/@{lat},{lon},80a,800d,35y,0h,60t,0r",
            "Apple Plans": f"https://maps.apple.com/?ll={lat},{lon}&t=k",
            "Bing (aérien)": f"https://www.bing.com/maps?cp={lat}~{lon}&lvl=18&style=a",
            "Yandex": f"https://yandex.com/maps/?ll={lon},{lat}&z=17&l=sat",
            "Mapillary (photos de rue)": f"https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=17",
            "OpenStreetMap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=18/{lat}/{lon}",
            "Sentinel (satellite récent)": f"https://apps.sentinel-hub.com/eo-browser/?zoom=14&lat={lat}&lng={lon}",
            "Esri Wayback (images anciennes)": f"https://livingatlas.arcgis.com/wayback/#mapCenter={lon}%2C{lat}%2C17",
            "SunCalc (soleil)": f"https://www.suncalc.org/#/{lat},{lon},17/null/null/null/null",
            "Wikimapia": f"https://wikimapia.org/#lat={lat}&lon={lon}&z=17"}


def overpass(q, timeout=120):
    last = None
    for ep in ("https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter", "https://overpass.private.coffee/api/interpreter"):
        try:
            r = HTTP.post(ep, data={"data": q}, timeout=(8, timeout))
            if r.ok:
                return r.json()
            last = f"HTTP {r.status_code}"
        except Exception as e:
            last = type(e).__name__
    raise RuntimeError(f"Overpass indisponible ({last}), réessaie dans une minute")


# ============================================================ SOLEIL & OMBRES
def sun_pos(dt, lat, lon):
    """dt en UTC (naïf). Renvoie (azimut ° depuis le nord, élévation °). Algorithme NOAA."""
    doy = dt.timetuple().tm_yday
    hr = dt.hour + dt.minute / 60 + dt.second / 3600
    g = 2 * math.pi / 365 * (doy - 1 + (hr - 12) / 24)
    eq = 229.18 * (0.000075 + 0.001868 * math.cos(g) - 0.032077 * math.sin(g) - 0.014615 * math.cos(2 * g) - 0.040849 * math.sin(2 * g))
    de = (0.006918 - 0.399912 * math.cos(g) + 0.070257 * math.sin(g) - 0.006758 * math.cos(2 * g) + 0.000907 * math.sin(2 * g)
          - 0.002697 * math.cos(3 * g) + 0.00148 * math.sin(3 * g))
    ha = math.radians((hr * 60 + eq + 4 * lon) / 4 - 180)
    p = math.radians(lat)
    cz = math.sin(p) * math.sin(de) + math.cos(p) * math.cos(de) * math.cos(ha)
    el = 90 - math.degrees(math.acos(max(-1, min(1, cz))))
    az = (math.degrees(math.atan2(math.sin(ha), math.cos(ha) * math.sin(p) - math.tan(de) * math.cos(p))) + 180) % 360
    return az, el


def get_tz(name):
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        con.print(f"[{Y}]Fuseau inconnu (pip install tzdata), UTC utilisé.")
        return datetime.timezone.utc


def ask_date(q="Date (JJ/MM/AAAA)", default=None):
    while True:
        v = Prompt.ask(f"[{G}]{q}", default=default or datetime.date.today().strftime("%d/%m/%Y"))
        try:
            return datetime.datetime.strptime(v.strip(), "%d/%m/%Y").date()
        except ValueError:
            con.print(f"[{R}]Format attendu : 21/06/2026")


CARD_DEG = {"N": 0, "NE": 45, "E": 90, "SE": 135, "S": 180, "SO": 225, "SW": 225, "O": 270, "W": 270, "NO": 315, "NW": 315}


def ask_elevation():
    con.print(f"[{M}]Mesure sur la photo un objet vertical et son ombre (en pixels ou en n'importe quelle unité, la même pour les deux).")
    h = ask_num(f"[{G}]Hauteur de l'objet", "1")
    s = ask_num(f"[{G}]Longueur de son ombre", "1")
    el = math.degrees(math.atan2(h, s))
    con.print(f"[{P}]→ Le soleil était à {el:.1f}° au-dessus de l'horizon.")
    return el


def ask_sun_dir():
    v = Prompt.ask(f"[{G}]Direction vers laquelle pointe l'ombre (N, NE, E… ou degrés, Entrée = inconnue)", default="").strip().upper()
    if not v:
        return None
    d = CARD_DEG.get(v)
    if d is None:
        try:
            d = float(v)
        except ValueError:
            return None
    return (d + 180) % 360  # le soleil est à l'opposé de l'ombre


def angdiff(a, b):
    return abs((a - b + 180) % 360 - 180)


def mod_sun():
    con.rule(f"[{G}]🌞 OMBRES & SOLEIL (chronolocalisation)")
    mode = select("Que veux-tu trouver ?", [{"label": "🕐 L'heure de la photo", "value": "1", "desc": "lieu + date + ombre connus"},
                                             {"label": "🌍 Où sur Terre ?", "value": "2", "desc": "date + heure + ombre → zone possible"},
                                             {"label": "🌞 Course du soleil d'un lieu", "value": "3", "desc": "lever, coucher, ombres"},
                                             {"label": "← Retour", "value": None}])
    if not mode:
        return
    if mode in ("1", "3"):
        pl = parse_coords(Prompt.ask(f"[{G}]Lieu (adresse, ville ou coordonnées)"))
        if not pl:
            con.print(f"[{R}]Lieu introuvable.")
            return pause()
        lat, lon = pl
        d = ask_date()
        tz = get_tz(Prompt.ask(f"[{G}]Fuseau horaire", default="Europe/Paris"))
        day = [(datetime.datetime.combine(d, datetime.time()) + datetime.timedelta(minutes=m)).replace(tzinfo=tz) for m in range(0, 1440)]
        pos = [(t, *sun_pos(t.astimezone(datetime.timezone.utc).replace(tzinfo=None), lat, lon)) for t in day]
        up = [p for p in pos if p[2] > 0]
        if mode == "3":
            t = Table(title=f"Soleil le {d:%d/%m/%Y} · {lat:.4f}, {lon:.4f}", box=box.ROUNDED, border_style="#2b3158")
            for c in ("Heure", "Azimut", "Hauteur", "Ombre (× hauteur objet)", "Ombre vers"):
                t.add_column(c)
            for tt, az, el in pos[::60]:
                if el > -1:
                    t.add_row(f"{tt:%H:%M}", f"{az:.0f}° ({cardinal(az)})", f"{el:.1f}°", f"{1 / math.tan(math.radians(el)):.2f}" if el > 0.5 else "—", cardinal((az + 180) % 360) if el > 0 else "—")
            con.print(t)
            if up:
                noon = max(up, key=lambda p: p[2])
                con.print(f"[{G}]Lever {up[0][0]:%H:%M} · midi solaire {noon[0]:%H:%M} ({noon[2]:.1f}°) · coucher {up[-1][0]:%H:%M}")
                add_report("Soleil", f"{lat:.4f},{lon:.4f} {d:%d/%m/%Y}", f"Lever {up[0][0]:%H:%M}, midi {noon[0]:%H:%M}, coucher {up[-1][0]:%H:%M}")
            con.print(f"[{B}]https://www.suncalc.org/#/{lat},{lon},17/{d:%Y.%m.%d}/12:00/1/3")
            return pause()
        el = ask_elevation()
        sd = ask_sun_dir()
        ok = [p for p in up if abs(p[2] - el) <= 1.0 and (sd is None or angdiff(p[1], sd) <= 20)]
        if not ok:
            con.print(f"[{Y}]Aucune heure ne colle ce jour-là à cet endroit (vérifie la mesure, la date ou le lieu).")
            return pause()
        wins, cur = [], [ok[0]]
        for p in ok[1:]:
            if (p[0] - cur[-1][0]).seconds <= 120:
                cur.append(p)
            else:
                wins.append(cur)
                cur = [p]
        wins.append(cur)
        t = Table(title="Heures possibles de la photo", box=box.ROUNDED, border_style="#2b3158")
        for c in ("Créneau (local)", "Soleil (azimut)", "Ombre vers"):
            t.add_column(c)
        lines = []
        for w in wins:
            mid = w[len(w) // 2]
            t.add_row(f"[{G}]{w[0][0]:%H:%M} → {w[-1][0]:%H:%M}", f"{mid[1]:.0f}° ({cardinal(mid[1])})", cardinal((mid[1] + 180) % 360))
            lines.append(f"{w[0][0]:%H:%M}-{w[-1][0]:%H:%M}")
        con.print(t)
        if sd is None and len(wins) > 1:
            con.print(f"[{M}]Deux créneaux (matin / après-midi) : indique la direction de l'ombre pour trancher.")
        add_report("Soleil", f"Heure photo {lat:.4f},{lon:.4f} {d:%d/%m/%Y}", f"Soleil à {el:.1f}° → créneaux : " + ", ".join(lines))
        return pause()
    # mode 2 : où sur Terre
    d = ask_date()
    hh = Prompt.ask(f"[{G}]Heure de la photo en UTC (HH:MM) [{M}](Paris l'hiver = heure locale − 1, l'été − 2)[/]", default="12:00")
    try:
        h, mi = map(int, hh.split(":"))
    except ValueError:
        return pause()
    dt = datetime.datetime.combine(d, datetime.time(h, mi))
    el = ask_elevation()
    sd = ask_sun_dir()
    pts = []
    with con.status(f"[{P}]Calcul sur toute la planète…"):
        for la in range(-60, 71):
            for lo in range(-180, 180):
                az, e = sun_pos(dt, la, lo)
                if abs(e - el) <= 1.0 and (sd is None or angdiff(az, sd) <= 12):
                    pts.append({"lat": la, "lon": lo, "c": "#b388ff", "s": 3, "label": f"{la}, {lo} · soleil {e:.1f}° az {az:.0f}°"})
    con.print(f"[{G}]{len(pts)} zones de 1° compatibles." + ("" if sd is not None else f" [{M}]Ajoute la direction de l'ombre pour réduire la bande."))
    if pts:
        save_open("soleil_monde", quick_map(f"Où le soleil était à {el:.1f}° le {d:%d/%m/%Y} à {hh} UTC", pts,
                                            f"<p>Chaque point rose = zone de 1° où le soleil avait cette hauteur{' et cette direction' if sd is not None else ''}. Croise avec d'autres indices (langue, végétation, conduite à gauche/droite…).</p>"))
        add_report("Soleil", f"Où ? {d:%d/%m/%Y} {hh} UTC", f"Soleil {el:.1f}° → {len(pts)} zones de 1° compatibles")
    pause()


# ============================================================ RECHERCHE PAR INDICES (Overpass)
FEATURES = {
    "église": 'nwr["amenity"="place_of_worship"]["religion"="christian"]', "mosquée": 'nwr["amenity"="place_of_worship"]["religion"="muslim"]',
    "pont": 'way["bridge"="yes"]', "rond-point": 'way["junction"="roundabout"]', "station-service": 'nwr["amenity"="fuel"]',
    "pharmacie": 'nwr["amenity"="pharmacy"]', "école": 'nwr["amenity"="school"]', "hôpital": 'nwr["amenity"="hospital"]',
    "supermarché": 'nwr["shop"="supermarket"]', "boulangerie": 'nwr["shop"="bakery"]', "restaurant": 'nwr["amenity"="restaurant"]',
    "bar": 'nwr["amenity"="bar"]', "fast-food": 'nwr["amenity"="fast_food"]', "hôtel": 'nwr["tourism"="hotel"]', "banque": 'nwr["amenity"="bank"]',
    "gare": 'nwr["railway"="station"]', "voie ferrée": 'way["railway"="rail"]', "passage à niveau": 'node["railway"="level_crossing"]',
    "tramway": 'way["railway"="tram"]', "arrêt de bus": 'node["highway"="bus_stop"]', "feu tricolore": 'node["highway"="traffic_signals"]',
    "autoroute": 'way["highway"="motorway"]', "parking": 'nwr["amenity"="parking"]', "château d'eau": 'nwr["man_made"="water_tower"]',
    "éolienne": 'nwr["generator:source"="wind"]', "pylône électrique": 'node["power"="tower"]', "antenne relais": 'nwr["man_made"~"mast|tower"]',
    "stade": 'nwr["leisure"="stadium"]', "terrain de foot": 'nwr["leisure"="pitch"]["sport"="soccer"]', "piscine": 'nwr["leisure"="swimming_pool"]',
    "parc": 'nwr["leisure"="park"]', "rivière": 'way["waterway"="river"]', "lac / étang": 'nwr["natural"="water"]', "plage": 'nwr["natural"="beach"]',
    "phare": 'nwr["man_made"="lighthouse"]', "château": 'nwr["historic"="castle"]', "monument / statue": 'nwr["historic"~"memorial|monument"]',
    "fontaine": 'nwr["amenity"="fountain"]', "cimetière": 'nwr["landuse"="cemetery"]', "musée": 'nwr["tourism"="museum"]',
    "zone industrielle": 'nwr["landuse"="industrial"]', "aéroport": 'nwr["aeroway"="aerodrome"]', "port de plaisance": 'nwr["leisure"="marina"]',
    "McDonald's": 'nwr["brand"="McDonald\'s"]', "Lidl": 'nwr["brand"="Lidl"]', "Carrefour": 'nwr["brand"~"Carrefour"]', "Total": 'nwr["brand"~"Total"]',
}


def feature_filter(txt):
    txt = txt.strip()
    if txt.lower().startswith("nom:"):
        return f'nwr["name"~"{re.escape(txt[4:].strip())}",i]'
    if txt.lower().startswith("marque:"):
        return f'nwr["brand"~"{re.escape(txt[7:].strip())}",i]'
    m = re.fullmatch(r"([\w:]+)=([\w:;\- ]+)", txt)
    if m:
        return f'nwr["{m[1]}"="{m[2]}"]'
    return FEATURES.get(txt) or next((v for k, v in FEATURES.items() if k.lower() == txt.lower()), None)


def mod_clues():
    con.rule(f"[{G}]📍 RECHERCHE PAR INDICES (où se trouve cet endroit ?)")
    con.print(f"[{M}]Tu vois sur une photo une église, un pont et une station-service proches ? L'outil cherche tous les endroits d'une zone où ces éléments sont réunis.\n")
    keys = list(FEATURES)
    zone = Prompt.ask(f"[{G}]Zone de recherche (ville, département…)")
    try:
        j = get_json("https://nominatim.openstreetmap.org/search", 10, headers=NOMI, params={"format": "jsonv2", "limit": 1, "q": zone})
        s, n, w, e = map(float, j[0]["boundingbox"])
    except Exception:
        con.print(f"[{R}]Zone introuvable.")
        return pause()
    if (n - s) * (e - w) > 1.5:
        con.print(f"[{Y}]Zone très grande : la recherche peut être lente ou échouer. Une ville ou un département marche mieux.")
    filt, names = [], []
    while len(filt) < 4:
        items = [{"label": k, "value": k} for k in keys if k not in names]
        items += [{"header": "──"}, {"label": "📝 Texte libre (nom:…, marque:…, tag=valeur)", "value": "__txt"}]
        if filt:
            items.insert(0, {"label": f"✓ Lancer la recherche ({len(filt)} indice(s) : {', '.join(names)})", "value": "__go"})
        items.append({"label": "← Annuler", "value": "__back"})
        v = select(f"Indice {len(filt) + 1} / 4 · tape pour filtrer", items, echo=False)
        if v in (None, "__back"):
            return
        if v == "__go":
            break
        if v == "__txt":
            v = Prompt.ask(f"[{G}]Indice (ex. nom:Saint-Michel · marque:Intermarché · shop=bicycle)").strip()
            if not v:
                continue
        f = feature_filter(v)
        if not f:
            con.print(f"[{R}]Indice inconnu : {escape(v)}")
            continue
        filt.append(f)
        names.append(v)
        con.print(f"[{G}]+ {escape(v)}")
    if not filt:
        return pause()
    dist = int(ask_num(f"[{G}]Distance max entre les éléments (mètres)", "150"))
    q = f"[out:json][timeout:110];\n{filt[0]}({s},{w},{n},{e})->.a;\n"
    for i, f in enumerate(filt[1:], 1):
        q += f"{f}(around.a:{dist})->.b{i};\nnwr.a(around.b{i}:{dist})->.a;\n"
    q += ".a out center 300;"
    log("Requête Overpass :", B)
    con.print(f"[{M}]{escape(q)}")
    with con.status(f"[{P}]Interrogation d'OpenStreetMap…", spinner="dots12"):
        try:
            res = overpass(q).get("elements", [])
        except Exception as ex:
            con.print(f"[{R}]{escape(str(ex))}")
            return pause()
    pts = []
    for el in res:
        la, lo = el.get("lat") or (el.get("center") or {}).get("lat"), el.get("lon") or (el.get("center") or {}).get("lon")
        if la is None:
            continue
        nm = (el.get("tags") or {}).get("name", names[0])
        L = map_links(la, lo)
        pts.append({"lat": la, "lon": lo, "c": "#b388ff", "label": f"<b>{escape_html(nm)}</b><br>{la:.5f}, {lo:.5f}<br><a target=_blank href='{L['Street View']}'>Street View</a> · <a target=_blank href='{L['Google Maps']}'>Maps</a> · <a target=_blank href='{L['Google Earth 3D']}'>Earth 3D</a>"})
    con.print(f"[{G}]{len(pts)} endroit(s) où « {escape(' + '.join(names))} » sont à moins de {dist} m les uns des autres.")
    tt = Table(box=box.SIMPLE)
    tt.add_column("#")
    tt.add_column("Nom")
    tt.add_column("Coordonnées")
    for i, p in enumerate(pts[:25], 1):
        tt.add_row(str(i), escape(re.sub(r"<.*?>", " ", p["label"]).split("  ")[0][:40]), f"{p['lat']:.5f}, {p['lon']:.5f}")
    if pts:
        con.print(tt)
        save_open("indices", quick_map(f"{' + '.join(names)} · {zone}", pts, f"<p>{len(pts)} candidats. Ouvre Street View sur chacun pour comparer avec la photo.</p>"))
    add_report("Indices", f"{' + '.join(names)} ({zone}, {dist} m)", f"{len(pts)} candidats\n" + "\n".join(f"{p['lat']:.5f}, {p['lon']:.5f}" for p in pts[:30]))
    pause()


# ============================================================ INFOS D'UN LIEU
WMO = {0: "ciel dégagé", 1: "peu nuageux", 2: "partiellement nuageux", 3: "couvert", 45: "brouillard", 48: "brouillard givrant", 51: "bruine légère", 53: "bruine",
       55: "bruine forte", 61: "pluie faible", 63: "pluie", 65: "forte pluie", 71: "neige faible", 73: "neige", 75: "forte neige", 80: "averses", 81: "averses",
       82: "violentes averses", 95: "orage", 96: "orage + grêle", 99: "orage + grêle"}


def mod_place():
    con.rule(f"[{G}]🌍 INFOS D'UN LIEU")
    pl = parse_coords(Prompt.ask(f"[{G}]Coordonnées (48.8584, 2.2945 · 48°51'30\"N 2°17'40\"E) ou adresse"))
    if not pl:
        con.print(f"[{R}]Lieu introuvable.")
        return pause()
    lat, lon = pl
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_row(f"[{M}]Décimal", f"[{G}]{lat:.6f}, {lon:.6f}")
    t.add_row(f"[{M}]DMS", f"{dms(lat, 'N', 'S')} {dms(lon, 'E', 'O')}")
    t.add_row(f"[{M}]UTM", to_utm(lat, lon))
    t.add_row(f"[{M}]Plus Code", plus_code(lat, lon))
    t.add_row(f"[{M}]Geohash", geohash(lat, lon))
    with con.status(f"[{P}]Adresse, altitude, alentours…"):
        adr = place_name(lat, lon, 18)
        try:
            alt = get_json(f"https://api.opentopodata.org/v1/srtm90m?locations={lat},{lon}", 12)["results"][0]["elevation"]
        except Exception:
            alt = None
        poi = []
        try:
            q = f'[out:json][timeout:40];(nwr(around:300,{lat},{lon})["name"]["amenity"];nwr(around:300,{lat},{lon})["name"]["shop"];nwr(around:300,{lat},{lon})["name"]["tourism"];nwr(around:300,{lat},{lon})["name"]["historic"];);out center 60;'
            for el in overpass(q, 25).get("elements", []):
                tg = el.get("tags", {})
                kind = tg.get("amenity") or tg.get("shop") or tg.get("tourism") or tg.get("historic")
                la, lo = el.get("lat") or el.get("center", {}).get("lat"), el.get("lon") or el.get("center", {}).get("lon")
                if la:
                    poi.append((tg["name"], kind, haversine(lat, lon, la, lo) * 1000, la, lo))
        except Exception:
            pass
    t.add_row(f"[{M}]Adresse", escape(adr or "—"))
    t.add_row(f"[{M}]Altitude", f"{alt:.0f} m" if alt is not None else "—")
    con.print(t)
    if poi:
        poi.sort(key=lambda x: x[2])
        pt = Table(title="Lieux nommés à moins de 300 m", box=box.SIMPLE)
        for c in ("Nom", "Type", "Distance"):
            pt.add_column(c)
        for n, k, d, *_ in poi[:15]:
            pt.add_row(escape(n), escape(k), f"{d:.0f} m")
        con.print(pt)
    wx = ""
    dstr = Prompt.ask(f"[{G}]Date d'une photo pour voir la météo ce jour-là (JJ/MM/AAAA, Entrée = passer)", default="")
    if dstr:
        try:
            d = datetime.datetime.strptime(dstr, "%d/%m/%Y").date()
            j = get_json("https://archive-api.open-meteo.com/v1/archive", 20, params={"latitude": lat, "longitude": lon, "start_date": d.isoformat(), "end_date": d.isoformat(),
                                                                                    "hourly": "temperature_2m,precipitation,cloud_cover,weather_code", "timezone": "auto"})
            hr = j["hourly"]
            wt = Table(title=f"Météo le {d:%d/%m/%Y} ({j.get('timezone')})", box=box.SIMPLE)
            for c in ("Heure", "Temps", "Temp.", "Pluie", "Nuages"):
                wt.add_column(c)
            for i in range(0, 24, 2):
                wt.add_row(hr["time"][i][-5:], WMO.get(hr["weather_code"][i], str(hr["weather_code"][i])), f"{hr['temperature_2m'][i]}°C", f"{hr['precipitation'][i]} mm", f"{hr['cloud_cover'][i]} %")
            con.print(wt)
            con.print(f"[{M}]Compare avec la photo : ciel, sol mouillé, ombres… Une photo « ensoleillée » un jour de pluie = date ou lieu faux.")
            wx = f"Météo {d:%d/%m/%Y} : " + ", ".join(f"{hr['time'][i][-5:]} {WMO.get(hr['weather_code'][i], '?')}" for i in (8, 12, 16))
        except Exception as e:
            con.print(f"[{Y}]Météo indisponible ({escape(str(e))}).")
    L = map_links(lat, lon)
    lt = Table(title="Voir ce lieu", box=box.SIMPLE, show_header=False)
    for k, v in L.items():
        lt.add_row(f"[{B}]{k}", v)
    con.print(lt)
    add_report("Lieu", f"{lat:.6f}, {lon:.6f}", f"{adr}\nUTM {to_utm(lat, lon)} · Plus Code {plus_code(lat, lon)} · altitude {alt}\n{wx}")
    if ask_yes("Ouvrir la carte (plan / satellite / relief) ?"):
        mk = [{"lat": lat, "lon": lon, "c": "#00e5ff", "s": 9, "label": f"<b>{escape_html(adr)}</b>"}] + [
            {"lat": a, "lon": b, "c": "#ffc861", "s": 5, "label": f"{escape_html(n)} ({escape_html(k)})"} for n, k, _, a, b in poi[:40]]
        links = " · ".join(f"<a target=_blank href='{v}'>{k}</a>" for k, v in L.items())
        save_open("lieu", quick_map(f"{lat:.5f}, {lon:.5f}", mk, f"<p><b>{escape_html(adr)}</b> · altitude {alt if alt is not None else '?'} m · UTM {to_utm(lat, lon)} · {plus_code(lat, lon)}</p><p>{links}</p>",
                                    circles=[{"lat": lat, "lon": lon, "r": 300, "c": "#00e5ff"}]))
    pause()


# ============================================================ SEARCH LOGO / IMAGE
BRANDS = """Apple,Google,Microsoft,Amazon,Meta,Facebook,Instagram,WhatsApp,TikTok,Snapchat,X (Twitter),YouTube,Netflix,Spotify,Twitch,Reddit,LinkedIn,Pinterest,Telegram,
Signal,Zoom,Slack,Dropbox,Adobe,Samsung,Sony,LG,Huawei,Xiaomi,OnePlus,Oppo,Nokia,Motorola,Intel,AMD,Nvidia,Qualcomm,IBM,HP,Dell,Lenovo,Asus,Acer,MSI,Logitech,
Razer,Corsair,Cisco,Oracle,SAP,Salesforce,PayPal,Visa,Mastercard,American Express,Stripe,Revolut,N26,Bitcoin,Ethereum,Binance,Coinbase,OpenAI,Anthropic,Tesla,
BMW,Mercedes-Benz,Audi,Volkswagen,Porsche,Ferrari,Lamborghini,Toyota,Honda,Nissan,Mazda,Subaru,Hyundai,Kia,Ford,Chevrolet,Jeep,Dodge,Renault,Peugeot,Citroën,
DS Automobiles,Dacia,Fiat,Alfa Romeo,Volvo,Skoda,Seat,Cupra,Opel,Mini,Land Rover,Jaguar,Bentley,Rolls-Royce,Aston Martin,Maserati,Bugatti,McLaren,Yamaha,
Ducati,Harley-Davidson,Kawasaki,Suzuki,Nike,Adidas,Puma,Reebok,New Balance,Under Armour,The North Face,Lacoste,Le Coq Sportif,Kappa,Fila,Converse,Vans,
Gucci,Louis Vuitton,Chanel,Hermès,Dior,Prada,Balenciaga,Versace,Yves Saint Laurent,Burberry,Ralph Lauren,Tommy Hilfiger,Calvin Klein,Levi's,Zara,H&M,Uniqlo,
Shein,Rolex,Omega,Cartier,Swatch,Coca-Cola,Pepsi,Red Bull,Monster Energy,Starbucks,McDonald's,Burger King,KFC,Subway,Domino's,Pizza Hut,Five Guys,Quick,
Heineken,Budweiser,Corona,Nestlé,Danone,Kinder,Nutella,Haribo,Lay's,Pringles,Oreo,Evian,Perrier,Carrefour,Leclerc,Auchan,Intermarché,Lidl,Aldi,Casino,
Monoprix,Fnac,Darty,Boulanger,Decathlon,Leroy Merlin,Castorama,Ikea,Sephora,L'Oréal,Orange,SFR,Bouygues Telecom,Free,Vodafone,T-Mobile,Verizon,AT&T,
BNP Paribas,Société Générale,Crédit Agricole,LCL,La Banque Postale,Caisse d'Épargne,Banque Populaire,Crédit Mutuel,Boursorama,HSBC,ING,Barclays,
La Poste,Colissimo,Chronopost,DHL,UPS,FedEx,SNCF,RATP,Air France,Lufthansa,Ryanair,easyJet,Emirates,Qatar Airways,Airbus,Boeing,TotalEnergies,Shell,BP,
Esso,EDF,Engie,Uber,Lyft,Airbnb,Booking.com,Leboncoin,Vinted,Doctolib,Ameli,Impots.gouv,Steam,PlayStation,Xbox,Nintendo,Ubisoft,Electronic Arts,
Epic Games,Riot Games,Valve,Rockstar Games,Activision,Blizzard,Roblox,Minecraft,Fortnite,Android,Windows,Linux,Ubuntu,Firefox,Chrome,Safari,Opera,
GitHub,GitLab,Docker,Python,JavaScript,WordPress,Shopify,Canva,Figma,Notion,Trello,Asana,Atlassian,Wikipedia,Mozilla,Cloudflare,Kaspersky,Norton,
Avast,ESET,Bitdefender,NordVPN,ExpressVPN,Proton,Tor,Anonymous,Interpol,Europol,FBI,NASA,ESA,SpaceX,Paris Saint-Germain,Olympique de Marseille,
Olympique Lyonnais,Real Madrid,FC Barcelona,Manchester United,Manchester City,Liverpool FC,Chelsea FC,Arsenal,Juventus,AC Milan,Inter Milan,
Bayern Munich,Borussia Dortmund,UEFA Champions League,FIFA,NBA,NFL,Formula 1,Olympic Games,Michelin,Bic,Lego,Disney,Pixar,Marvel,DC Comics,Warner Bros,
Universal,Paramount,Canal+,TF1,France Télévisions,BFM TV,CNN,BBC,Le Monde,Le Figaro""".replace("\n", "").split(",")
_CLIP = {}


def clip_load():
    if "m" not in _CLIP:
        import warnings
        warnings.filterwarnings("ignore")
        from transformers import CLIPModel, CLIPProcessor
        _CLIP["m"] = CLIPModel.from_pretrained("openai/clip-vit-large-patch14").eval()
        _CLIP["p"] = CLIPProcessor.from_pretrained("openai/clip-vit-large-patch14")
    return _CLIP["m"], _CLIP["p"]


def logo_brands():
    extra = BASE / "marques.txt"
    b = [x.strip() for x in BRANDS if x.strip()]
    if extra.exists():
        b += [x.strip() for x in extra.read_text(encoding="utf-8").splitlines() if x.strip()]
    return list(dict.fromkeys(b))


def logo_identify(img, k=5):
    import torch
    m, p = clip_load()
    brands = logo_brands()
    key = hashlib.md5("|".join(brands).encode()).hexdigest()[:10]
    cache = OUT / f".logo_emb_{key}.pt"
    if cache.exists():
        temb = torch.load(cache)
    else:
        prompts = [f"the logo of {b}" for b in brands] + ["a photo with no logo", "a random picture", "a person's face", "a landscape photo", "plain text"]
        embs = []
        with torch.no_grad():
            for i in range(0, len(prompts), 64):
                t = p(text=prompts[i:i + 64], return_tensors="pt", padding=True)
                e = m.get_text_features(**t)
                embs.append(e / e.norm(dim=-1, keepdim=True))
        temb = torch.cat(embs)
        torch.save(temb, cache)
    with torch.no_grad():
        ie = m.get_image_features(**p(images=img.convert("RGB"), return_tensors="pt"))
        ie = ie / ie.norm(dim=-1, keepdim=True)
        probs = (100 * ie @ temb.T).softmax(dim=-1)[0]
    names = brands + ["(aucun logo)", "(image quelconque)", "(visage)", "(paysage)", "(texte)"]
    top = probs.topk(k)
    return [(names[i], float(v)) for v, i in zip(top.values, top.indices)]


def wikidata_brand(name):
    j = get_json("https://www.wikidata.org/w/api.php", 12, params={"action": "wbsearchentities", "search": name, "language": "fr", "format": "json", "limit": 1})
    if not j.get("search"):
        return None
    qid = j["search"][0]["id"]
    e = get_json("https://www.wikidata.org/w/api.php", 12, params={"action": "wbgetentities", "ids": qid, "props": "claims|descriptions|labels", "languages": "fr|en", "format": "json"})["entities"][qid]
    cl = e.get("claims", {})

    def val(p):
        try:
            return cl[p][0]["mainsnak"]["datavalue"]["value"]
        except Exception:
            return None
    refs = {p: val(p) for p in ("P17", "P452", "P159", "P112")}
    ids = [v["id"] for v in refs.values() if isinstance(v, dict) and "id" in v]
    lab = {}
    if ids:
        ents = get_json("https://www.wikidata.org/w/api.php", 12, params={"action": "wbgetentities", "ids": "|".join(ids), "props": "labels", "languages": "fr|en", "format": "json"})["entities"]
        lab = {k: (v.get("labels", {}).get("fr") or v.get("labels", {}).get("en") or {}).get("value") for k, v in ents.items()}
    inc = val("P571")
    return {"Nom": (e.get("labels", {}).get("fr") or e.get("labels", {}).get("en") or {}).get("value"),
            "Description": (e.get("descriptions", {}).get("fr") or e.get("descriptions", {}).get("en") or {}).get("value"),
            "Pays": lab.get((refs["P17"] or {}).get("id")), "Secteur": lab.get((refs["P452"] or {}).get("id")),
            "Siège": lab.get((refs["P159"] or {}).get("id")), "Fondateur": lab.get((refs["P112"] or {}).get("id")),
            "Création": inc["time"][1:5] if isinstance(inc, dict) and inc.get("time") else None,
            "Site officiel": val("P856"), "Wikidata": f"https://www.wikidata.org/wiki/{qid}"}


def mmh3_32(data, seed=0):
    c1, c2, h, n = 0xcc9e2d51, 0x1b873593, seed & 0xffffffff, len(data)
    r = n & ~3
    for i in range(0, r, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xffffffff
        k = ((k << 15) | (k >> 17)) & 0xffffffff
        h ^= (k * c2) & 0xffffffff
        h = ((h << 13) | (h >> 19)) & 0xffffffff
        h = (h * 5 + 0xe6546b64) & 0xffffffff
    k, t = 0, n & 3
    if t >= 3:
        k ^= data[r + 2] << 16
    if t >= 2:
        k ^= data[r + 1] << 8
    if t >= 1:
        k ^= data[r]
        k = (k * c1) & 0xffffffff
        k = ((k << 15) | (k >> 17)) & 0xffffffff
        h ^= (k * c2) & 0xffffffff
    h ^= n
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xffffffff
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xffffffff
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def favicon_hash(content):
    h = mmh3_32(base64.encodebytes(content))
    return h, {"Shodan": f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}",
               "FOFA": "https://fofa.info/result?qbase64=" + base64.b64encode(f'icon_hash="{h}"'.encode()).decode(),
               "ZoomEye": f"https://www.zoomeye.ai/searchResult?q=iconhash%3A%22{h}%22",
               "Censys": f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3A{hashlib.md5(content).hexdigest()}"}


def upload_temp(path):
    with open(path, "rb") as fh:
        r = HTTP.post("https://litterbox.catbox.moe/resources/internals/api.php", data={"reqtype": "fileupload", "time": "1h"}, files={"fileToUpload": fh}, timeout=60)
    u = r.text.strip()
    if not u.startswith("http"):
        raise RuntimeError(u[:120])
    return u


def reverse_links(url):
    q = requests.utils.quote(url, safe="")
    return {"Google Lens": f"https://lens.google.com/uploadbyurl?url={q}", "Bing Visuel": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}",
            "TinEye": f"https://tineye.com/search?url={q}"}


def mod_logo(src=None):
    con.rule(f"[{G}]🔖 SEARCH LOGO / IMAGE")
    con.print(f"[{M}]Photo d'un logo, d'un objet ou d'un lieu (fichier), ou adresse d'un site (→ son favicon).\n"
              f"Identification locale sans clé (CLIP) parmi {len(logo_brands())} marques (ajoute les tiennes dans marques.txt), fiche de la marque, recherche inversée Google Lens / Bing / TinEye, hash favicon Shodan.\n")
    src = src or clean_path(Prompt.ask(f"[{G}]Image ou URL de site"))
    raw, img, tmp = None, None, None
    try:
        if re.match(r"https?://", src):
            r = get(src, 15)
            if "image" in r.headers.get("content-type", ""):
                raw = r.content
            else:
                ic = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)', r.text, re.I) or re.search(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\'][^"\']*icon', r.text, re.I)
                fav = requests.compat.urljoin(r.url, ic.group(1) if ic else "/favicon.ico")
                log(f"Favicon : {fav}", B)
                raw = get(fav, 12).content
            tmp = OUT / f".logo_tmp_{stamp()}"
            tmp.write_bytes(raw)
            path = str(tmp)
        else:
            path = src
            raw = Path(path).read_bytes()
        img = Image.open(io.BytesIO(raw))
        img.load()
    except Exception as e:
        con.print(f"[{R}]Image illisible : {escape(str(e))}")
        return pause()
    lines = []
    if re.match(r"https?://", src) or len(raw) < 60000:
        h, links = favicon_hash(raw)
        t = Table(title=f"Hash favicon (style Shodan) : {h}", box=box.SIMPLE, show_header=False)
        for k, v in links.items():
            t.add_row(f"[{B}]{k}", v)
        con.print(t)
        con.print(f"[{M}]→ Retrouve tous les serveurs qui affichent la même icône (sites miroirs, phishing qui copie un logo, infra cachée).")
        lines.append(f"Hash favicon : {h}")
    res = []
    if geoclip_ready() or ask_yes("Installer l'IA locale (CLIP, gratuite, ~2 Go une fois) pour reconnaître les logos ?"):
        if geoclip_ready() or geoclip_install():
            with con.status(f"[{P}]CLIP compare l'image à {len(logo_brands())} marques… (1er lancement plus long)", spinner="dots12"):
                try:
                    res = logo_identify(img.convert("RGBA").convert("RGB") if img.mode in ("P", "LA", "RGBA") else img)
                except Exception as e:
                    log(f"CLIP : {e}", Y)
    if res:
        t = Table(title="Marques les plus probables", box=box.ROUNDED, border_style="#2b3158")
        for c in ("#", "Marque", "Probabilité"):
            t.add_column(c)
        for i, (n, p) in enumerate(res, 1):
            t.add_row(str(i), f"[{G if i == 1 else 'white'}]{escape(n)}", f"[{G}]{'█' * max(1, round(p * 20))}[/] {p * 100:.0f}%")
        con.print(t)
        lines.append("Logo : " + ", ".join(f"{n} {p * 100:.0f}%" for n, p in res[:3]))
        top = res[0][0]
        if not top.startswith("(") and res[0][1] > .15:
            with con.status("Fiche Wikidata…"):
                try:
                    wd = wikidata_brand(top)
                except Exception:
                    wd = None
            if wd:
                wt = Table(title=f"Fiche : {escape(wd['Nom'] or top)}", box=box.SIMPLE, show_header=False)
                for k, v in wd.items():
                    if v and k != "Nom":
                        wt.add_row(f"[{M}]{k}", escape(str(v)))
                con.print(wt)
                lines.append(f"{wd.get('Nom')} · {wd.get('Pays')} · {wd.get('Site officiel')}")
                site = wd.get("Site officiel")
                if site and ask_yes(f"Scanner le domaine officiel {site} (module Domaine) ?"):
                    dom = re.sub(r"^https?://(www\.)?", "", site).split("/")[0]
                    R_ = {"target": dom, "ip": False, "dns": {}, "subs": [], "ips": {}}
                    scan_domain(dom, R_)
                    analyse(R_)
                    show_domain(R_)
        elif res[0][0].startswith("("):
            con.print(f"[{Y}]Aucun logo connu reconnu avec certitude : utilise la recherche inversée.")
    con.print(f"[{M}]La recherche inversée dépose l'image 1 h sur litterbox.catbox.moe (hébergeur public temporaire) pour que Google Lens / Bing / TinEye la lisent.\n"
              f"Réservé aux logos, objets et lieux : pas pour identifier des personnes.")
    if ask_yes("Lancer la recherche inversée ?"):
        try:
            with con.status("Envoi temporaire…"):
                url = upload_temp(path)
            log(f"Image temporaire : {url}", G)
            for k, v in reverse_links(url).items():
                con.print(f"[{B}]{k}[/] {v}")
                webbrowser.open(v)
        except Exception as e:
            con.print(f"[{R}]Envoi impossible ({escape(str(e))}). Ouvre lens.google.com et dépose l'image à la main.")
    if tmp:
        try:
            tmp.unlink()
        except Exception:
            pass
    add_report("Logo", Path(src).name if not src.startswith("http") else src, "\n".join(lines) or "—")
    pause()


# ============================================================ RETOUCHES (ELA)
STD_LUMA_SUM = 3688  # somme de la table de quantification JPEG standard (luminance)


def jpeg_quality(img):
    try:
        q = img.quantization[0]
        s = sum(q) * 100 / STD_LUMA_SUM
        return round((200 - s) / 2 if s <= 100 else 5000 / s)
    except Exception:
        return None


def ahash(img, size=8):
    g = img.convert("L").resize((size, size))
    px = list(g.getdata())
    avg = sum(px) / len(px)
    return "%016x" % int("".join("1" if p > avg else "0" for p in px), 2)


def dhash(img, size=8):
    g = img.convert("L").resize((size + 1, size))
    px = list(g.getdata())
    bits = "".join("1" if px[r * (size + 1) + c] > px[r * (size + 1) + c + 1] else "0" for r in range(size) for c in range(size))
    return "%016x" % int(bits, 2)


def ela_image(img, q=90):
    from PIL import ImageChops, ImageEnhance
    im = img.convert("RGB")
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=q)
    buf.seek(0)
    diff = ImageChops.difference(im, Image.open(buf))
    ext = max(e[1] for e in diff.getextrema()) or 1
    ela = ImageEnhance.Brightness(diff).enhance(255.0 / ext)
    # zones anormales : blocs 16×16 dont l'erreur dépasse moyenne + 3 écarts-types
    g = diff.convert("L")
    vals = list(g.resize((max(1, g.width // 16), max(1, g.height // 16)), Image.BOX).getdata())
    mu = sum(vals) / max(1, len(vals))
    sd = (sum((v - mu) ** 2 for v in vals) / max(1, len(vals))) ** .5
    hot = sum(1 for v in vals if v > mu + 3 * sd) / max(1, len(vals))
    return ela, hot


def mod_ela():
    con.rule(f"[{G}]🧪 RETOUCHES PHOTO (analyse ELA)")
    con.print(f"[{M}]Cherche les zones modifiées : une partie collée ou retouchée se recompresse différemment du reste de l'image.\n")
    path = clean_path(Prompt.ask(f"[{G}]Photo (JPEG de préférence)"))
    try:
        raw = Path(path).read_bytes()
        img = Image.open(io.BytesIO(raw))
        img.load()
    except Exception as e:
        con.print(f"[{R}]Image illisible : {escape(str(e))}")
        return pause()
    with con.status(f"[{P}]Analyse des niveaux d'erreur…"):
        ela, hot = ela_image(img)
    ex = img.getexif()
    soft = str(ex.get(305) or "").strip("\x00 ")
    dmod = str(ex.get(306) or "")
    try:
        dorig = str(ex.get_ifd(0x8769).get(36867) or "")
    except Exception:
        dorig = ""
    q = jpeg_quality(img)
    F = []
    if re.search(r"photoshop|gimp|lightroom|snapseed|picsart|canva|facetune|affinity|pixelmator|meitu|remini", soft, re.I):
        F.append(("med", f"Passée par un logiciel d'édition : {soft}"))
    if dorig and dmod and dorig != dmod:
        F.append(("med", f"Date de modification ({dmod}) différente de la prise de vue ({dorig})"))
    if not len(ex):
        F.append(("low", "Aucune métadonnée : image ré-enregistrée, capture d'écran ou passée par un réseau social"))
    if hot > .02:
        F.append(("high" if hot > .05 else "med", f"{hot * 100:.1f} % de l'image a un niveau d'erreur anormal : zones claires de l'ELA à examiner"))
    else:
        F.append(("ok", f"Niveau d'erreur homogène ({hot * 100:.1f} % de blocs atypiques)"))
    if img.format != "JPEG":
        F.append(("low", f"Format {img.format} : l'ELA est surtout fiable sur les JPEG"))
    SEVC = {"high": (R_STYLE, "ÉLEVÉ"), "med": (Y, "MOYEN"), "low": (B, "INFO"), "ok": (G, "OK")}
    t = Table(box=box.SIMPLE, show_header=False)
    for s, x in F:
        t.add_row(f"[{SEVC[s][0]}]{SEVC[s][1]}", escape(x))
    con.print(t)
    hs = {"MD5": hashlib.md5(raw).hexdigest(), "SHA-256": hashlib.sha256(raw).hexdigest(), "aHash": ahash(img), "dHash": dhash(img)}
    kt = Table(box=box.SIMPLE, show_header=False)
    kt.add_row(f"[{M}]Format", f"{img.format} {img.width}×{img.height}" + (f" · qualité JPEG ≈ {q}" if q else ""))
    for k, v in hs.items():
        kt.add_row(f"[{M}]{k}", v)
    con.print(kt)
    con.print(f"[{M}]aHash/dHash : empreintes visuelles, identiques pour deux copies de la même photo même recompressée ou redimensionnée.")
    rows = "".join(f"<tr><td style='color:{ {'high': '#ff5c7a', 'med': '#ffc861', 'low': '#7aa2ff', 'ok': '#00e5ff'}[s]};font-weight:700'>{SEVC[s][1]}</td><td>{escape_html(x)}</td></tr>" for s, x in F)
    html = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ELA</title>
<style>body{{margin:0;padding:16px;background:#07081a;color:#e4e9ff;font-family:system-ui}}h1{{font:600 16px monospace;color:#00e5ff}}.g{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}@media(max-width:800px){{.g{{grid-template-columns:1fr}}}}img{{width:100%;border-radius:8px}}td{{padding:6px;border-bottom:1px solid #2b3158;font-size:14px}}code{{font-size:12px}}</style></head><body>
<h1>CAT.exe // ANALYSE DE RETOUCHES · {escape_html(Path(path).name)}</h1><div class="g"><div><p>Original</p><img src="data:image/jpeg;base64,{img_b64(img, 1400)}"></div><div><p>ELA : les zones nettement plus claires que le reste ont pu être modifiées (les bords et textes fins sont toujours clairs, c'est normal).</p><img src="data:image/jpeg;base64,{img_b64(ela, 1400)}"></div></div>
<table>{rows}</table><p><code>{'<br>'.join(f'{k} : {v}' for k, v in hs.items())}</code></p></body></html>"""
    save_open("ela", html)
    add_report("Retouches", Path(path).name, "\n".join(f"[{s.upper()}] {x}" for s, x in F) + f"\nSHA-256 {hs['SHA-256']}")
    pause()


# ============================================================ MÉTADONNÉES FICHIERS
def office_meta(path):
    import zipfile
    out = {}
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        for part in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
            if part in names:
                x = z.read(part).decode("utf-8", "ignore")
                for tag, lab in (("dc:creator", "Auteur"), ("cp:lastModifiedBy", "Modifié par"), ("dcterms:created", "Créé le"), ("dcterms:modified", "Modifié le"),
                                 ("cp:revision", "Révisions"), ("Application", "Logiciel"), ("Company", "Société"), ("TotalTime", "Temps d'édition (min)"),
                                 ("meta:initial-creator", "Auteur"), ("dc:date", "Modifié le"), ("meta:generator", "Logiciel"), ("dc:title", "Titre"), ("Template", "Modèle")):
                    m = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", x)
                    if m and lab not in out:
                        out[lab] = m.group(1)
        media = [n for n in names if "/media/" in n]
        if media:
            out["Images intégrées"] = str(len(media))
    return out


def pdf_meta(path):
    try:
        from pypdf import PdfReader
        r = PdfReader(path)
        md = r.metadata or {}
        out = {k.strip("/"): str(v) for k, v in md.items()}
        out["Pages"] = str(len(r.pages))
        return out
    except ImportError:
        raw = Path(path).read_bytes()[:2_000_000].decode("latin-1", "ignore")
        return {k: m.group(1) for k in ("Author", "Creator", "Producer", "CreationDate", "ModDate", "Title") if (m := re.search(rf"/{k}\s*\(([^)]*)\)", raw))}


def file_meta(path):
    ext = Path(path).suffix.lower()
    if ext in (".jpg", ".jpeg", ".png", ".heic", ".heif", ".tif", ".tiff", ".webp"):
        _, info, gps, _ = read_exif(path)
        if gps:
            info["GPS"] = f"{gps[0]:.6f}, {gps[1]:.6f}"
        return info
    if ext == ".pdf":
        return pdf_meta(path)
    if ext in (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"):
        return office_meta(path)
    return {}


def clean_file(path):
    p = Path(path)
    out = p.with_name(p.stem + "_propre" + p.suffix)
    ext = p.suffix.lower()
    if ext in (".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif"):
        from PIL import ImageOps
        im = ImageOps.exif_transpose(Image.open(p))
        if ext in (".heic", ".heif"):
            out = out.with_suffix(".jpg")
        clean = Image.new(im.mode, im.size)
        clean.putdata(list(im.getdata()))
        clean.save(out, quality=95) if out.suffix.lower() in (".jpg", ".jpeg") else clean.save(out)
        return out
    if ext == ".pdf":
        from pypdf import PdfReader, PdfWriter
        w = PdfWriter()
        for pg in PdfReader(p).pages:
            w.add_page(pg)
        w.add_metadata({"/Producer": "", "/Creator": "", "/Author": ""})
        with open(out, "wb") as fh:
            w.write(fh)
        return out
    return None


def mod_meta():
    con.rule(f"[{G}]🧾 MÉTADONNÉES DE FICHIERS")
    con.print(f"[{M}]Photos (GPS, appareil), PDF, Word/Excel/PowerPoint, LibreOffice : auteur, logiciel, dates, société… Un dossier entier marche aussi.\n")
    src = Path(clean_path(Prompt.ask(f"[{G}]Fichier ou dossier")))
    files = [src] if src.is_file() else [p for p in src.rglob("*") if p.is_file() and p.suffix.lower() in (".jpg", ".jpeg", ".png", ".heic", ".heif", ".tif", ".tiff", ".webp", ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")][:300] if src.is_dir() else []
    if not files:
        con.print(f"[{R}]Rien à analyser.")
        return pause()
    agg, lines = {}, []
    for f in files:
        try:
            md = file_meta(f)
        except Exception as e:
            md = {"Erreur": str(e)}
        if not md:
            continue
        if len(files) <= 5:
            t = Table(title=escape(f.name), box=box.SIMPLE, show_header=False)
            for k, v in md.items():
                t.add_row(f"[{M}]{escape(k)}", f"[{G}]{escape(v)}" if k in ("GPS", "Auteur", "Author", "Modifié par", "Société") else escape(v))
            con.print(t)
        for k in ("Auteur", "Author", "Modifié par", "Société", "Logiciel", "Creator", "Producer", "Modèle", "GPS"):
            if md.get(k):
                agg.setdefault(k, {}).setdefault(md[k], []).append(f.name)
        lines.append(f"{f.name} : " + ", ".join(f"{k}={v}" for k, v in md.items() if k in ("Auteur", "Author", "Modifié par", "Logiciel", "Producer", "GPS", "Société")))
    if len(files) > 5 or len(agg):
        t = Table(title=f"Synthèse sur {len(files)} fichier(s)", box=box.ROUNDED, border_style="#2b3158")
        for c in ("Champ", "Valeur", "Fichiers"):
            t.add_column(c)
        for k, vals in agg.items():
            for v, fs in sorted(vals.items(), key=lambda x: -len(x[1]))[:8]:
                t.add_row(k, escape(v), str(len(fs)))
        con.print(t)
        con.print(f"[{M}]→ Les noms d'auteurs, de société et de logiciels révèlent souvent qui a créé les documents et avec quoi.")
    add_report("Métadonnées", str(src), "\n".join(lines[:60]))
    if src.is_file() and src.suffix.lower() in (".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif", ".pdf") and ask_yes("Créer une copie nettoyée (sans métadonnées) ?"):
        try:
            log(f"Copie propre : {clean_file(src)}", G)
        except Exception as e:
            log(f"Nettoyage impossible : {e}", R)
    pause()


# ============================================================ LIEN SUSPECT
BRAND_DOMAINS = ["paypal", "amazon", "apple", "icloud", "google", "microsoft", "outlook", "office", "netflix", "facebook", "instagram", "whatsapp", "tiktok", "snapchat",
                 "laposte", "colissimo", "chronopost", "dhl", "ups", "fedex", "ameli", "impots", "caf", "antai", "franceconnect", "ants", "creditagricole", "credit-agricole",
                 "labanquepostale", "bnpparibas", "societegenerale", "boursorama", "lcl", "caisse-epargne", "orange", "sfr", "free", "bouyguestelecom", "leboncoin",
                 "vinted", "doctolib", "binance", "coinbase", "steam", "steamcommunity", "epicgames", "roblox", "spotify", "ebay", "cdiscount", "edf", "engie"]
BAD_TLD = {"zip", "mov", "xyz", "top", "icu", "click", "live", "shop", "online", "site", "buzz", "monster", "rest", "cfd", "sbs", "lol", "quest", "gq", "tk", "ml", "cf", "ga", "work", "support", "help"}
PHISH_WORDS = r"login|signin|verify|verification|update|secure|account|compte|confirm|paiement|payment|colis|livraison|amende|remboursement|suspend|bloqu|wallet|unlock|bonus|gift|cadeau"


def lev(a, b):
    p = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        c = [i]
        for j, cb in enumerate(b, 1):
            c.append(min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (ca != cb)))
        p = c
    return p[-1]


def mod_link():
    con.rule(f"[{G}]🔗 ANALYSE DE LIEN SUSPECT")
    con.print(f"[{M}]Déroule les redirections, détecte le typosquatting, les faux domaines et les pages de vol d'identifiants. La page est lue en texte (aucun script exécuté).\n")
    url = Prompt.ask(f"[{G}]Lien").strip()
    if not re.match(r"https?://", url):
        url = "http://" + url
    F = []

    def a(severity, text):
        F.append((severity, text))

    chain = []
    try:
        r = HTTP.get(url, timeout=15, allow_redirects=True)
        chain = [(x.status_code, x.url) for x in r.history] + [(r.status_code, r.url)]
        body = r.text[:400000]
    except Exception as e:
        body = ""
        a("low", f"Page injoignable ({type(e).__name__})")
        r = None
    t = Table(title="Chaîne de redirections", box=box.SIMPLE)
    t.add_column("HTTP")
    t.add_column("URL")
    for s, u in chain or [("—", url)]:
        t.add_row(str(s), escape(u))
    con.print(t)
    final = (chain[-1][1] if chain else url)
    host = requests.utils.urlparse(final).hostname or ""
    host0 = requests.utils.urlparse(url).hostname or ""
    if len(chain) > 2:
        a("med", f"{len(chain) - 1} redirections avant la page finale")
    if host0 != host:
        a("low", f"Le lien mène vers un autre domaine : {host0} → {host}")
    parts = host.split(".")
    tld = parts[-1] if parts else ""
    reg = ".".join(parts[-2:]) if len(parts) >= 2 else host
    if re.fullmatch(r"[\d.]+", host):
        a("high", "Adresse IP brute au lieu d'un nom de domaine")
    if "xn--" in host:
        a("high", f"Domaine en punycode (caractères déguisés) : {host}")
    if tld in BAD_TLD:
        a("med", f"Extension .{tld} très utilisée pour le phishing")
    if host.count(".") >= 4:
        a("med", "Beaucoup de sous-domaines (technique pour cacher le vrai domaine)")
    if "@" in url.split("//", 1)[-1].split("/")[0]:
        a("high", "Caractère @ dans l'adresse : la partie avant est ignorée par le navigateur")
    base = parts[-2] if len(parts) >= 2 else host
    for b in BRAND_DOMAINS:
        if b in host and base not in (b, b.replace("-", "")):
            a("high", f"Contient « {b} » mais le vrai domaine est {reg}")
            break
        if base != b and 0 < lev(base, b) <= (1 if len(b) <= 5 else 2):
            a("high", f"{reg} ressemble à « {b} » (faute volontaire / typosquatting)")
            break
    if re.search(PHISH_WORDS, final, re.I):
        a("med", "Mots typiques du phishing dans l'adresse (login, verify, colis, paiement…)")
    try:
        j = get_json(f"https://rdap.org/domain/{reg}", 12)
        cre = next((e["eventDate"] for e in j.get("events", []) if e.get("eventAction") == "registration"), None)
        if cre:
            age = (datetime.datetime.utcnow() - datetime.datetime.fromisoformat(cre.replace("Z", "+00:00")).replace(tzinfo=None)).days
            a("high" if age < 30 else "med" if age < 180 else "ok", f"Domaine créé il y a {age} jours ({cre[:10]})")
    except Exception:
        pass
    try:
        si = ssl_info(host)
        a("low" if "Let's Encrypt" in si["emetteur"] or "ZeroSSL" in si["emetteur"] else "ok", f"Certificat SSL : {si['emetteur']}")
    except Exception:
        if final.startswith("https"):
            a("high", "Certificat SSL invalide")
        else:
            a("med", "Pas de HTTPS")
    if body:
        title = (re.search(r"<title[^>]*>([^<]*)", body, re.I) or [None, ""])[1].strip()
        if title:
            con.print(f"[{M}]Titre de la page :[/] {escape(title[:120])}")
        if re.search(r'type=["\']?password', body, re.I):
            a("high" if any(s == "high" for s, _ in F) else "med", "La page demande un mot de passe")
        if re.search(r"(carte bancaire|card ?number|cvv|cvc|date d'expiration)", body, re.I):
            a("high", "La page demande des informations de carte bancaire")
        acts = [x for x in re.findall(r'<form[^>]+action=["\']([^"\']+)', body, re.I) if x.startswith("http") and host not in x]
        if acts:
            a("high", f"Le formulaire envoie les données vers un autre site : {acts[0][:80]}")
        for b in BRAND_DOMAINS[:40]:
            if re.search(rf"\b{b}\b", title, re.I) and b not in host:
                a("high", f"La page se présente comme « {b} » mais n'est pas sur son domaine")
                break
    order = {"high": 0, "med": 1, "low": 2, "ok": 3}
    F.sort(key=lambda x: order[x[0]])
    score = min(100, sum({"high": 30, "med": 12, "low": 4, "ok": 0}[s] for s, _ in F))
    verdict = ("DANGEREUX", R_STYLE) if score >= 50 else ("SUSPECT", Y) if score >= 20 else ("Pas de signal évident", G)
    con.print(Panel(f"[{verdict[1]}]{verdict[0]}[/]  risque {score}/100", border_style="#b388ff" if score >= 50 else "#2b3158", title=escape(host)))
    SEVC = {"high": (R_STYLE, "ÉLEVÉ"), "med": (Y, "MOYEN"), "low": (B, "INFO"), "ok": (G, "OK")}
    t = Table(box=box.SIMPLE, show_header=False)
    for s, x in F:
        t.add_row(f"[{SEVC[s][0]}]{SEVC[s][1]}", escape(x))
    con.print(t)
    con.print(f"[{B}]VirusTotal[/] https://www.virustotal.com/gui/search/{requests.utils.quote(final, safe='')}\n[{B}]urlscan[/] https://urlscan.io/search/#domain:{host}")
    add_report("Lien", url, f"{verdict[0]} ({score}/100)\n" + "\n".join(f"[{s.upper()}] {x}" for s, x in F))
    pause()


# ============================================================ CRYPTO
def mod_crypto():
    con.rule(f"[{G}]₿ ADRESSE CRYPTO (Bitcoin / Ethereum)")
    a = Prompt.ask(f"[{G}]Adresse").strip()
    try:
        eur = get_json("https://api.coingecko.com/api/v3/simple/price", 10, params={"ids": "bitcoin,ethereum", "vs_currencies": "eur"})
    except Exception:
        eur = {}
    t = Table(box=box.SIMPLE, show_header=False)
    if re.fullmatch(r"(bc1[a-z0-9]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})", a):
        try:
            j = get_json(f"https://blockstream.info/api/address/{a}", 15)
            cs = j["chain_stats"]
            bal = (cs["funded_txo_sum"] - cs["spent_txo_sum"]) / 1e8
            rec = cs["funded_txo_sum"] / 1e8
            txs = get_json(f"https://blockstream.info/api/address/{a}/txs", 15)
            times = [x["status"].get("block_time") for x in txs if x.get("status", {}).get("block_time")]
            px = (eur.get("bitcoin") or {}).get("eur")
            t.add_row(f"[{M}]Réseau", "Bitcoin")
            t.add_row(f"[{M}]Solde", f"[{G}]{bal:.8f} BTC" + (f" (≈ {bal * px:,.0f} €)" if px else ""))
            t.add_row(f"[{M}]Total reçu", f"{rec:.8f} BTC")
            t.add_row(f"[{M}]Transactions", str(cs["tx_count"]) + (f" (+{j['mempool_stats']['tx_count']} en attente)" if j["mempool_stats"]["tx_count"] else ""))
            if times:
                t.add_row(f"[{M}]Dernière activité", datetime.datetime.utcfromtimestamp(max(times)).strftime("%d/%m/%Y %H:%M UTC"))
            links = {"mempool.space": f"https://mempool.space/address/{a}", "Blockchair": f"https://blockchair.com/bitcoin/address/{a}",
                     "OXT (graphe)": f"https://oxt.me/address/{a}", "Recherche web": f'https://www.google.com/search?q="{a}"'}
        except Exception as e:
            con.print(f"[{R}]Erreur : {escape(str(e))}")
            return pause()
    elif re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        try:
            j = get_json(f"https://eth.blockscout.com/api/v2/addresses/{a}", 15)
            c = get_json(f"https://eth.blockscout.com/api/v2/addresses/{a}/counters", 15)
            bal = int(j.get("coin_balance") or 0) / 1e18
            px = (eur.get("ethereum") or {}).get("eur")
            t.add_row(f"[{M}]Réseau", "Ethereum")
            t.add_row(f"[{M}]Solde", f"[{G}]{bal:.6f} ETH" + (f" (≈ {bal * px:,.0f} €)" if px else ""))
            t.add_row(f"[{M}]Transactions", str(c.get("transactions_count")))
            t.add_row(f"[{M}]Transferts de tokens", str(c.get("token_transfers_count")))
            t.add_row(f"[{M}]Type", "contrat" if j.get("is_contract") else "portefeuille")
            if j.get("ens_domain_name"):
                t.add_row(f"[{M}]Nom ENS", f"[{P}]{j['ens_domain_name']}")
            tags = [x.get("display_name") for x in (j.get("public_tags") or [])] + ([j["name"]] if j.get("name") else [])
            if tags:
                t.add_row(f"[{M}]Étiquettes", escape(", ".join(x for x in tags if x)))
            links = {"Etherscan": f"https://etherscan.io/address/{a}", "Blockscout": f"https://eth.blockscout.com/address/{a}",
                     "Arkham": f"https://intel.arkm.com/explorer/address/{a}", "Recherche web": f'https://www.google.com/search?q="{a}"'}
        except Exception as e:
            con.print(f"[{R}]Erreur : {escape(str(e))}")
            return pause()
    else:
        con.print(f"[{R}]Format non reconnu (Bitcoin 1… / 3… / bc1… ou Ethereum 0x…).")
        return pause()
    con.print(t)
    for k, v in links.items():
        con.print(f"[{B}]{k}[/] {v}")
    add_report("Crypto", a, " · ".join(f"{k}: {v}" for k, v in links.items()))
    pause()


# ============================================================ IA LOCALE (Ollama : texte + vision, sans clé, hors ligne)
import subprocess
OLLAMA = "http://localhost:11434"
OLL = requests.Session()
OLL.trust_env = False
LAST = {"pos": None, "date": None}
OLLAMA_CACHE = {"at": 0.0, "models": None}


def ollama_models(refresh=False):
    if not refresh and time.time() - OLLAMA_CACHE["at"] < 20:
        return OLLAMA_CACHE["models"]
    try:
        models = [m["name"] for m in OLL.get(OLLAMA + "/api/tags", timeout=3).json().get("models", [])]
    except Exception:
        models = None
    OLLAMA_CACHE.update(at=time.time(), models=models)
    return models


def ollama_has(models, m):
    return any(x == m or x == m + ":latest" or x.startswith(m + ":") for x in models or [])


def ollama_setup(interactive=True, m=None):
    """Vérifie Ollama + le modèle demandé (vision par défaut). Renvoie le nom du modèle prêt, sinon None."""
    m = m or CFG.get("ollama_model") or "qwen2.5vl:7b"
    ms = ollama_models()
    if ms is None:
        if not interactive:
            return None
        con.print(Panel("Toute l'IA de Cat.exe tourne sur ton PC avec [bold #00e5ff]Ollama[/] : gratuit, sans clé, sans compte, rien n'est envoyé sur internet.\n"
                        f"Modèle demandé : [bold #00e5ff]{m}[/]", border_style="#00e5ff", title="IA locale"))
        if os.name == "nt" and ask_yes("Installer Ollama maintenant (winget) ?"):
            subprocess.run(["winget", "install", "-e", "--id", "Ollama.Ollama", "--accept-source-agreements", "--accept-package-agreements"])
            with con.status("Démarrage d'Ollama…"):
                for _ in range(40):
                    if ollama_models() is not None:
                        break
                    if _ == 3:
                        try:
                            subprocess.Popen(["ollama", "serve"], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        except Exception:
                            pass
                    time.sleep(2)
        elif ask_yes("Ouvrir la page de téléchargement d'Ollama (ollama.com/download) ?"):
            webbrowser.open("https://ollama.com/download")
            Prompt.ask(f"[{G}]Installe-le, lance-le, puis appuie sur Entrée", default="", show_default=False)
        ms = ollama_models()
        if ms is None:
            log("Ollama introuvable : l'IA locale est indisponible pour l'instant.", Y)
            return None
    if not ollama_has(ms, m):
        if not interactive or not ask_yes(f"Télécharger le modèle d'IA {m} ({MODEL_SIZE.get(m, 'quelques Go')}, une seule fois) ?"):
            return None
        try:
            with OLL.post(OLLAMA + "/api/pull", json={"model": m, "stream": True}, stream=True, timeout=None) as r:
                with Progress(TextColumn(f"[{G}]{m}"), BarColumn(complete_style="#00e5ff"), TaskProgressColumn(), TextColumn("{task.description}"), console=con) as pr:
                    t = pr.add_task("", total=None)
                    for line in r.iter_lines():
                        if not line:
                            continue
                        j = json.loads(line)
                        if j.get("error"):
                            raise RuntimeError(j["error"])
                        pr.update(t, total=j.get("total"), completed=j.get("completed", 0), description=f"[{M}]{j.get('status', '')}")
        except Exception as e:
            log(f"Téléchargement du modèle impossible : {e}", R_STYLE)
            return None
        ollama_models(refresh=True)
    return m


MODEL_SIZE = {"qwen2.5vl:7b": "~6 Go", "qwen2.5vl:3b": "~3 Go", "qwen2.5:3b": "~2 Go", "qwen2.5:7b": "~4,7 Go", "llama3.2:3b": "~2 Go", "qwen2.5:1.5b": "~1 Go"}


def vision_engine():
    """Nom du modèle de vision Ollama prêt, sinon None."""
    return ollama_setup(interactive=False, m=configured_model("vision", CFG, image=True)) or ollama_setup(interactive=True, m=configured_model("vision", CFG, image=True))


def ask_vision(prompt, b64, json_fmt=True, engine=None):
    """Vision : Ollama local. Renvoie (texte, moteur)."""
    prompt = ai_lang(prompt)
    engine = engine or vision_engine()
    if not engine:
        raise RuntimeError("aucune IA de vision disponible")
    body = {"model": engine, "messages": [{"role": "user", "content": prompt, "images": [b64]}], "stream": False,
            "options": {"temperature": 0.1 if json_fmt else 0, "num_ctx": 8192}}
    if json_fmt:
        body["format"] = "json"
    r = OLL.post(OLLAMA + "/api/chat", json=body, timeout=1800)
    r.raise_for_status()
    return r.json()["message"]["content"], f"Ollama · {engine}"


WDQ = """SELECT ?item ?itemLabel ?coord ?sl WHERE {
 SERVICE wikibase:around { ?item wdt:P625 ?coord . bd:serviceParam wikibase:center "Point(%f %f)"^^geo:wktLiteral . bd:serviceParam wikibase:radius "%d" . }
 ?item wikibase:sitelinks ?sl . FILTER(?sl >= 4)
 FILTER(EXISTS{?item wdt:P2048 []} || EXISTS{?item wdt:P1101 []} || EXISTS{?item wdt:P84 []} || EXISTS{?item wdt:P149 []})
 SERVICE wikibase:label { bd:serviceParam wikibase:language "en,fr". }
} ORDER BY DESC(?sl) LIMIT %d"""


def wd_landmarks(lat, lon, radius=6, limit=40):
    """Monuments / bâtiments notables autour d'un point (Wikidata)."""
    r = get("https://query.wikidata.org/sparql", 60, params={"query": WDQ % (lon, lat, radius, limit), "format": "json"}, headers=NOMI)
    out = {}
    for b in r.json()["results"]["bindings"]:
        q = b["item"]["value"].rsplit("/", 1)[1]
        if q not in out:
            lo, la = map(float, b["coord"]["value"][6:-1].split())
            out[q] = {"name": b["itemLabel"]["value"], "lat": la, "lon": lo}
    return list(out.values())


# ============================================================ TRIANGULATION (numpy)
def solve_vantage(P, fov=None, N=120, refine=True):
    """P = [(x 0..1, lat, lon)]. Cherche la position caméra qui voit les repères à ces positions horizontales."""
    import numpy as np
    x = np.array([p[0] for p in P], float)
    la = np.array([p[1] for p in P], float)
    lo = np.array([p[2] for p in P], float)
    lat0, lon0 = la.mean(), lo.mean()
    kx, ky = 111320 * math.cos(math.radians(lat0)), 110540
    X, Y = (lo - lon0) * kx, (la - lat0) * ky
    spread = max(float(np.hypot(X[:, None] - X[None], Y[:, None] - Y[None]).max()), 50)
    Rm = min(40000, max(2500, spread * 14))
    fovs = np.array([fov]) if fov else np.arange(8, 110, 2.0)

    def run(cx, cy, fv):
        dx, dy = X[:, None] - cx[None], Y[:, None] - cy[None]
        be = np.arctan2(dx, dy)
        near = (np.hypot(dx, dy) < 60).any(0)
        bE, bH, bF = np.full(cx.shape, np.inf), np.zeros(cx.shape), np.zeros(cx.shape)
        for f in fv:
            a = np.arctan((x - .5) * 2 * np.tan(np.radians(f) / 2))
            d = be - a[:, None]
            h = np.arctan2(np.sin(d).sum(0), np.cos(d).sum(0))
            r = (d - h + np.pi) % (2 * np.pi) - np.pi
            e = np.sqrt((r ** 2).mean(0))
            m = e < bE
            bE[m], bH[m], bF[m] = e[m], h[m], f
        bE[near] = np.inf
        return bE, bH, bF

    g = np.linspace(-Rm, Rm, N + 1)
    cx, cy = [a.ravel() for a in np.meshgrid(g, g)]
    E, Hh, F = run(cx, cy, fovs)
    i = int(E.argmin())
    best = [E[i], Hh[i], F[i], cx[i], cy[i]]
    step = g[1] - g[0]
    thr = max(best[0] * 2.5, .006 * math.radians(best[2]))
    zone = np.hypot(cx[E <= thr] - best[3], cy[E <= thr] - best[4])
    if refine:
        s = step
        for _ in range(3):
            gg = np.linspace(-s, s, 25)
            ccx, ccy = [a.ravel() for a in np.meshgrid(best[3] + gg, best[4] + gg)]
            fv = fovs if fov else np.arange(max(4, best[2] - 3), best[2] + 3.01, .25)
            E2, H2, F2 = run(ccx, ccy, fv)
            j = int(E2.argmin())
            if E2[j] <= best[0]:
                best = [E2[j], H2[j], F2[j], ccx[j], ccy[j]]
            s = (gg[1] - gg[0]) * 2
    e, h, f, bx, by = best
    return {"lat": lat0 + by / ky, "lon": lon0 + bx / kx, "heading": (math.degrees(h) + 360) % 360, "h": h, "fov": float(f), "err": math.degrees(e),
            "prec": max(float(np.percentile(zone, 90)) if len(zone) else 0.0, step / 2), "dist": [float(v) for v in np.hypot(X - bx, Y - by)]}


def predict_x(sol, lat, lon):
    kx = 111320 * math.cos(math.radians(sol["lat"]))
    be = math.atan2((lon - sol["lon"]) * kx, (lat - sol["lat"]) * 110540)
    a = (be - sol["h"] + math.pi) % (2 * math.pi) - math.pi
    half = math.radians(sol["fov"]) / 2
    return None if abs(a) >= half else .5 + math.tan(a) / (2 * math.tan(half))


def ransac_vantage(C, center=None, max_km=15):
    """C = [{x, lat, lon, name}] (repères proposés par l'IA, parfois faux). Garde le plus grand groupe cohérent."""
    import itertools
    C = C[:8]
    if len(C) < 3:
        return None, []
    groups = {}
    for k in ((4, 3) if len(C) >= 4 else (3,)):
        for sub in itertools.combinations(range(len(C)), k):
            s = solve_vantage([(C[i]["x"], C[i]["lat"], C[i]["lon"]) for i in sub], N=60, refine=False)
            if s["err"] > 2.5 or (center and haversine(center[0], center[1], s["lat"], s["lon"]) > max_km):
                continue
            inl = tuple(i for i, c in enumerate(C) if (lambda xp: xp is not None and abs(xp - c["x"]) < .05)(predict_x(s, c["lat"], c["lon"])))
            if len(inl) >= 3 and (inl not in groups or s["err"] < groups[inl]):
                groups[inl] = s["err"]
    for inl in sorted(groups, key=lambda g: (-len(g), groups[g]))[:12]:
        sol = solve_vantage([(C[i]["x"], C[i]["lat"], C[i]["lon"]) for i in inl], N=150)
        if sol["prec"] <= 3000 and sol["err"] <= 1.0 and not (center and haversine(center[0], center[1], sol["lat"], sol["lon"]) > max_km):
            return sol, [C[i] for i in inl]
    return None, ([C[i] for i in max(groups, key=len)] if groups else [])


# ============================================================ 6. GÉOLOC PHOTO AUTOMATIQUE
RARITY = ["phare", "château d'eau", "éolienne", "château", "stade", "aéroport", "port de plaisance", "piscine", "cimetière", "musée", "gare", "tramway",
          "passage à niveau", "voie ferrée", "pont", "rivière", "lac / étang", "plage", "fontaine", "monument / statue", "mosquée", "église", "rond-point",
          "station-service", "pharmacie", "hôtel", "banque", "supermarché", "boulangerie", "restaurant", "bar", "fast-food", "parking", "arrêt de bus"]


def auto_clues(ai, center, radius):
    """Indices lus par l'IA → recherche automatique (enseignes via Nominatim, objets via Overpass). Renvoie [(nom, lat, lon, source)]."""
    out = []
    la, lo = center
    dl, dn = radius / 110540, radius / (111320 * math.cos(math.radians(la)))
    for tx in [str(t).strip() for t in (ai.get("texts") or []) if len(str(t).strip()) >= 4][:6]:
        try:
            j = get_json("https://nominatim.openstreetmap.org/search", 10, headers=NOMI,
                         params={"format": "jsonv2", "limit": 3, "q": tx, "viewbox": f"{lo - dn},{la + dl},{lo + dn},{la - dl}", "bounded": 1})
            for h in j:
                out.append((f"« {tx} » → {h.get('display_name', '')[:60]}", float(h["lat"]), float(h["lon"]), "texte lu"))
                log(f"  texte « {tx} » trouvé sur la carte : {h.get('display_name', '')[:70]}", G)
        except Exception:
            pass
    objs = [o for o in (ai.get("objects") or []) if feature_filter(str(o))]
    objs = sorted(dict.fromkeys(objs), key=lambda o: RARITY.index(o) if o in RARITY else 99)[:3]
    if len(objs) >= 2:
        fl = [feature_filter(o) for o in objs]
        q = f"[out:json][timeout:60];\n{fl[0]}(around:{int(radius)},{la},{lo})->.a;\n"
        for i, f in enumerate(fl[1:], 1):
            q += f"{f}(around.a:150)->.b{i};\nnwr.a(around.b{i}:150)->.a;\n"
        q += ".a out center 60;"
        try:
            with con.status(f"[{P}]OpenStreetMap : endroits avec {' + '.join(objs)} à moins de 150 m…"):
                res = overpass(q, 70).get("elements", [])
            for el in res[:40]:
                a, b = el.get("lat") or (el.get("center") or {}).get("lat"), el.get("lon") or (el.get("center") or {}).get("lon")
                if a is not None:
                    out.append(((el.get("tags") or {}).get("name") or objs[0], a, b, " + ".join(objs)))
            log(f"  {len(res)} endroit(s) avec {' + '.join(objs)} dans le secteur", G if res else M)
        except Exception as e:
            log(f"  recherche OSM indisponible : {e}", Y)
    return out


SUN_SIDE = {"behind": 180, "front": 0, "left": -90, "right": 90, "front-left": -45, "front-right": 45, "behind-left": -135, "behind-right": 135}


def auto_chrono(ai, pos, when, heading):
    """Heure probable d'après les ombres. Renvoie (texte, meilleure heure) ou None."""
    sun = ai.get("sun") or {}
    try:
        ratio = float(sun.get("shadow_ratio") or 0)
    except Exception:
        ratio = 0
    side = SUN_SIDE.get(str(sun.get("sun_side", "")).lower())
    if not sun.get("shadows_visible") or (ratio <= 0 and (side is None or heading is None)):
        return None
    el_obs = math.degrees(math.atan(1 / ratio)) if ratio > 0 else None
    az_obs = (heading + side) % 360 if side is not None and heading is not None else None
    day = when.date() if when else datetime.date.today()
    off, _ = tz_offset(pos[0], pos[1], day)
    best = []
    for mnt in range(0, 1440, 5):
        loc = datetime.datetime.combine(day, datetime.time()) + datetime.timedelta(minutes=mnt)
        az, el = sun_pos(loc - datetime.timedelta(seconds=off), pos[0], pos[1])
        if el < 2:
            continue
        sc = (abs(el - el_obs) if el_obs is not None else 0) + (angdiff(az, az_obs) / 3 if az_obs is not None else 0)
        best.append((sc, loc, az, el))
    if not best:
        return None
    best.sort()
    sc, loc, az, el = best[0]
    alt = [b for b in best[1:] if abs((b[1] - loc).total_seconds()) > 5400][:1] if az_obs is None else []
    txt = f"soleil à ~{el_obs:.0f}° de hauteur" if el_obs is not None else ""
    txt += (", " if txt else "") + (f"côté {cardinal(az_obs)}" if az_obs is not None else "")
    res = f"{txt} → heure probable [{P}]{loc:%H:%M}[/]" + (f" ou {alt[0][1]:%H:%M}" if alt else "") + f" (le {day:%d/%m/%Y}{'' if when else ', date inconnue : estimation pour aujourd’hui'})"
    if when and when.time() != datetime.time():
        res += f"\n   [{M}]heure enregistrée par l'appareil : {when:%H:%M}[/]"
    return res, loc


GEO_PROMPT = """You are an expert OSINT geolocation analyst. The image is {W}x{H} pixels.
1) Estimate where the photo was taken: country, city, district, and the approximate GPS position of the CAMERA (where the photographer stood).
2) List every identifiable NAMED landmark visible (famous buildings, towers, churches, monuments, bridges, mountains), with its bounding box in pixel coordinates [x1, y1, x2, y2] of this image, and x_pct = horizontal position of its top/spire in percent of the image width (0 = left edge, 100 = right edge).
Reply ONLY with this JSON:
{{"country":"","city":"","district":"","lat":0,"lon":0,"confidence":0,"clues":["indice → conclusion"],"landmarks":[{{"name":"official name as on Wikipedia","bbox_2d":[0,0,0,0],"x_pct":0}}]}}
confidence = 0-100. Write the clues in French. Never try to identify people."""


GEO_PROMPT_A = """You are an expert OSINT geolocation analyst.
Estimate where this photo was taken (country, city, district) and the approximate GPS position of the CAMERA.
List the NAMED landmarks you can identify (famous buildings, towers, churches, monuments, bridges, mountains), from left to right, using official names.{hint}
Reply ONLY with JSON: {{"country":"","city":"","district":"","lat":0,"lon":0,"confidence":0,"clues":["indice en français → conclusion"],"landmarks":["name 1","name 2"]}}
Write the clues in French. Never try to identify people."""
GEO_EXTRA = """

ALSO add these keys to the same JSON:
"objects": things clearly visible, chosen ONLY from this list: [{vocab}],
"texts": readable texts in the photo (shop names, street names, signs), exactly as written,
"sun": {{"shadows_visible": true, "sun_side": "behind|front|left|right|front-left|front-right|behind-left|behind-right|unknown", "shadow_ratio": 0}}
(sun_side = where the sun is relative to the camera; shadow_ratio = shadow length divided by object height, 0 if unknown)."""


def lm_x(lm, W, H):
    b = lm.get("bbox_2d") or lm.get("bbox") or lm.get("box_2d")
    try:
        x1, y1, x2, y2 = [float(v) for v in b]
        if 0 <= x1 < x2 <= W * 1.02:
            return ((x1 + x2) / 2) / W
    except Exception:
        pass
    try:
        return max(0, min(1, float(lm.get("x_pct")) / 100))
    except Exception:
        return None


def mod_geo(path=None):
    con.rule(f"[{G}]📍 GÉOLOC PHOTO AUTOMATIQUE · OÙ SE TENAIT LE PHOTOGRAPHE")
    con.print(f"[{M}]Tout est automatique : GPS caché → IA GeoCLIP → IA de vision (repère et pointe les monuments) → triangulation.\n")
    if Image is None:
        con.print(f"[{R_STYLE}]Pillow manquant : pip install pillow pillow-heif")
        return pause()
    path = path or clean_path(Prompt.ask(f"[{G}]Glisse la photo ici (ou colle son chemin)"))
    if not Path(path).is_file():
        con.print(f"[{R_STYLE}]Fichier introuvable.")
        return pause()
    try:
        img, info, gps, cam = read_exif(path)
    except Exception as e:
        con.print(f"[{R_STYLE}]Image illisible : {escape(str(e))}")
        return pause()
    W0, H0 = img.size
    lines, layers, center, verdict = [f"{k} : {v}" for k, v in info.items()], [], None, None
    if info.get("Prise le"):
        try:
            LAST["date"] = datetime.datetime.strptime(info["Prise le"][:19], "%Y:%m:%d %H:%M:%S")
        except Exception:
            pass

    # ---- étape 1 : EXIF
    log("[1/4] Métadonnées EXIF…", B)
    t = Table(box=box.SIMPLE, show_header=False)
    for k, v in info.items():
        t.add_row(f"[{M}]{k}", escape(v))
    if gps:
        adr = place_name(gps[0], gps[1], 18)
        t.add_row(f"[{G}]GPS", f"[{G}]{gps[0]:.6f}, {gps[1]:.6f}  ({escape(adr)})")
        layers.append({"lat": gps[0], "lon": gps[1], "label": "GPS EXIF : position exacte du téléphone", "c": "#00e5ff", "r": 0})
        center = gps
        verdict = {"lat": gps[0], "lon": gps[1], "how": "GPS caché dans le fichier (exact)", "prec": 10, "heading": cam.get("dir")}
        log("Position GPS exacte trouvée dans le fichier !", G)
    else:
        log("Pas de GPS dans le fichier.", Y)
    con.print(t)

    # ---- étape 2 : GeoCLIP
    log("[2/4] IA GeoCLIP (zone)…", B)
    preds = []
    if geoclip_ready() or (ask_yes("Installer GeoCLIP (IA locale gratuite, ~2 Go une fois) ?") and geoclip_install()):
        with con.status(f"[{P}]GeoCLIP analyse la photo…", spinner="dots12"):
            try:
                preds = geoclip_predict(img, 8)[:5]
            except Exception as e:
                log(f"GeoCLIP : {e}", Y)
        free_geoclip()
    if preds:
        la0, lo0 = preds[0][0], preds[0][1]
        spread = max([haversine(la0, lo0, a, b) for a, b, _ in preds if haversine(la0, lo0, a, b) < 100] or [1])
        for i, (a, b, p) in enumerate(preds, 1):
            layers.append({"lat": a, "lon": b, "label": f"GeoCLIP #{i} ({p * 100:.0f}%)", "c": "#b388ff" if i == 1 else "#ffc861", "r": max(800, spread * 1000) if i == 1 else 0})
        zone = place_name(la0, lo0, 14)
        log(f"GeoCLIP : {zone} (rayon ≈ {max(.8, spread):.1f} km)", G)
        lines.append(f"GeoCLIP : {la0:.5f}, {lo0:.5f} · {zone}")
        center = center or (la0, lo0)
        if not verdict:
            verdict = {"lat": la0, "lon": lo0, "how": "IA GeoCLIP (zone approximative)", "prec": max(800, spread * 1000), "heading": None}

    # ---- étape 3 : IA de vision → nommer puis pointer les monuments sur la photo
    log("[3/4] IA de vision : reconnaissance et pointage des monuments…", B)
    ai, engine, cands, eng = None, None, [], None
    try:
        eng = vision_engine()
    except Exception as e:
        log(f"IA de vision : {e}", Y)
    if eng:
        rgb = img.convert("RGB")
        k = 1092 / max(rgb.size)
        W, H = max(28, round(rgb.width * k / 28) * 28), max(28, round(rgb.height * k / 28) * 28)
        buf = io.BytesIO()
        rgb.resize((W, H)).save(buf, "JPEG", quality=88)
        b64s = base64.b64encode(buf.getvalue()).decode()
        hint = ""
        try:
            with con.status(f"[{P}]L'IA observe la photo… (en local : 10 s à 2 min selon ton PC)", spinner="dots12"):
                prompt = GEO_PROMPT_A.format(hint=hint) + GEO_EXTRA.format(vocab=", ".join(FEATURES))
                txt, engine = ask_vision(prompt, b64s, engine=eng)
            ai = parse_json(txt)
        except Exception as e:
            log(f"IA de vision indisponible ({e}) : résultat basé sur GeoCLIP.", Y)
    if ai:
        where = ", ".join(str(x) for x in [ai.get("district"), ai.get("city"), ai.get("country")] if x)
        try:
            cf_ = float(ai.get("confidence"))
            ai["confidence"] = round(cf_ * 100 if cf_ <= 1 else cf_)
        except Exception:
            pass
        con.print(Panel(f"[{P}]{escape(where)}[/] · confiance {ai.get('confidence', '?')}%\n" + "\n".join(f"[{B}]›[/] {escape(str(c))}" for c in ai.get("clues") or []),
                        title=f"IA de vision ({engine})", border_style="#b388ff"))
        lines.append(f"IA ({engine}) : {where}")
        try:
            if ai.get("lat") and ai.get("lon"):
                layers.append({"lat": float(ai["lat"]), "lon": float(ai["lon"]), "label": f"Estimation {engine}", "c": "#8a8cff", "r": 0})
                center = center or (float(ai["lat"]), float(ai["lon"]))
        except Exception:
            pass
        near, seen, boxes = center, set(), {}
        for lm in (ai.get("landmarks") or [])[:7]:
            nm = str(lm.get("name") if isinstance(lm, dict) else lm or "").strip()
            if not nm or nm.lower() in seen or re.search(r"\b(b[aâ]timents?|buildings|immeubles?|quartier|district|skyline|construction|gratte-ciel|skyscrapers|tours|towers|rue|street|ville|city)\b", nm, re.I) and len(nm.split()) <= 3 \
                    or (ai.get("district") and nm.lower() == str(ai.get("district")).lower()) or (ai.get("city") and nm.lower() == str(ai.get("city")).lower()):
                continue
            seen.add(nm.lower())
            x = lm_x(lm, W, H) if isinstance(lm, dict) else None
            if x is None:
                try:
                    with con.status(f"[{P}]L'IA localise « {escape(nm)} » sur la photo…", spinner="dots12"):
                        c, _ = ask_vision(f"Locate the {nm} in the image and output its bbox coordinates in JSON format.", b64s, json_fmt=False, engine=eng)
                    m = re.search(r"\[\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\]", c)
                    if m:
                        x1, _, x2, _ = map(float, m.groups())
                        if 0 <= x1 < x2 <= W * 1.05 and x2 - x1 < W * .8:
                            dup = next((bn for bn, (a1, a2) in boxes.items() if min(x2, a2) - max(x1, a1) > .6 * max(x2 - x1, a2 - a1)), None)
                            if dup:
                                log(f"  « {nm} » : même zone que « {dup} » → doute, ignoré", Y)
                                continue
                            boxes[nm] = (x1, x2)
                            x = min(1, (x1 + x2) / 2 / W)
                except Exception:
                    pass
            if x is None:
                log(f"  « {nm} » : pas localisé sur la photo", M)
                continue
            g = geocode(f"{nm}, {ai.get('city') or ''}".strip(", "), near) or geocode(nm, near)
            if g and (not near or haversine(near[0], near[1], g[0], g[1]) < 15):
                cands.append({"x": x, "lat": g[0], "lon": g[1], "name": nm})
                log(f"  repère : {nm} · x {x * 100:.0f}% → {g[0]:.5f}, {g[1]:.5f}", G)
            else:
                log(f"  « {nm} » introuvable sur la carte", M)

    # ---- étape 4 : triangulation automatique
    log("[4/4] Triangulation de la position du photographe…", B)
    sol, used = (None, [])
    if len(cands) >= 3:
        sol, used = ransac_vantage(cands, center)
        if not sol and used:
            log("Repères incohérents entre eux (probable erreur de l'IA) : triangulation refusée.", Y)
            used = []
    if sol:
        adr = place_name(sol["lat"], sol["lon"], 18)
        log(f"Triangulation réussie avec {len(used)} repères cohérents.", G)
        if not gps:
            verdict = {"lat": sol["lat"], "lon": sol["lon"], "how": f"triangulation automatique de {len(used)} monuments", "prec": sol["prec"], "heading": sol["heading"], "fov": sol["fov"], "adr": adr}
        lines.append(f"Triangulation ({', '.join(u['name'] for u in used)}) : {sol['lat']:.5f}, {sol['lon']:.5f} · {adr} · regard {sol['heading']:.0f}° · ±{sol['prec']:.0f} m")
        if gps:
            con.print(f"[{G}]Écart triangulation ↔ GPS réel : {haversine(gps[0], gps[1], sol['lat'], sol['lon']) * 1000:.0f} m")
    else:
        log("Pas assez de monuments identifiés pour trianguler (3 minimum) : position = zone de l'IA.", Y)

    # ---- indices automatiques (si pas de GPS ni de triangulation)
    if ai and center and not gps and not sol:
        log("[+] Indices visuels : enseignes, panneaux, objets…", B)
        rad = min(8000, max(1500, (verdict or {}).get("prec", 2000) * 1.5))
        hits = auto_clues(ai, center, rad)
        for nm, a, b, src in hits:
            layers.append({"lat": a, "lon": b, "label": f"Indice ({src}) : {nm}", "c": "#8c9eff", "r": 0})
        txt_hits = [h for h in hits if h[3] == "texte lu"]
        obj_hits = [h for h in hits if h[3] != "texte lu"]
        pick = txt_hits[0] if len(txt_hits) == 1 else (obj_hits[0] if len(obj_hits) == 1 else None)
        if pick:
            verdict = {"lat": pick[1], "lon": pick[2], "how": f"indices visuels ({pick[3]})", "prec": 300, "heading": None}
            log(f"Indice unique trouvé : la photo a été prise près de {pick[0]}", G)
        elif hits:
            log(f"{len(hits)} lieux possibles d'après les indices : ils sont sur la carte, compare avec Street View.", Y)
        lines += [f"Indice : {h[0]} ({h[1]:.5f}, {h[2]:.5f})" for h in hits[:10]]
    # ---- heure par les ombres
    if ai and verdict:
        try:
            ch = auto_chrono(ai, (verdict["lat"], verdict["lon"]), LAST.get("date"), verdict.get("heading") if verdict.get("heading") is not None else cam.get("dir"))
            if ch:
                con.print(f"[{Y}]🌞 Ombres :[/] {ch[0]}")
                lines.append("Ombres : " + re.sub(r"\[.*?\]", "", ch[0]))
        except Exception as e:
            log(f"Ombres : {e}", M)

    # ---- verdict
    if verdict:
        LAST["pos"] = (verdict["lat"], verdict["lon"])
        adr = verdict.get("adr") or place_name(verdict["lat"], verdict["lon"], 18 if verdict["prec"] < 3000 else 14)
        pr = verdict["prec"]
        body = (f"[{P}]📷 {verdict['lat']:.5f}, {verdict['lon']:.5f}[/]\n[{G}]{escape(adr)}[/]\n"
                f"[{M}]Méthode :[/] {verdict['how']}   [{M}]Précision :[/] ± {pr:.0f} m" if pr < 1000 else
                f"[{P}]📷 {verdict['lat']:.5f}, {verdict['lon']:.5f}[/]\n[{G}]{escape(adr)}[/]\n[{M}]Méthode :[/] {verdict['how']}   [{M}]Précision :[/] ± {pr / 1000:.1f} km")
        if verdict.get("heading") is not None:
            body += f"\n[{M}]Regard vers :[/] {verdict['heading']:.0f}° ({cardinal(verdict['heading'])})"
            if verdict.get("fov"):
                body += f"   [{M}]Focale ≈[/] {18 / math.tan(math.radians(verdict['fov']) / 2):.0f} mm éq."
            body += f"\n[{B}]Street View :[/] https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={verdict['lat']},{verdict['lon']}&heading={verdict['heading']:.0f}"
        body += f"\n[{B}]Google Earth 3D :[/] https://earth.google.com/web/@{verdict['lat']},{verdict['lon']},60a,0d,35y,{(verdict.get('heading') or 0):.0f}h,85t,0r"
        con.print(Panel(body, title="POSITION DU PHOTOGRAPHE", border_style="#00e5ff"))
        lines.append(f"VERDICT : {verdict['lat']:.5f}, {verdict['lon']:.5f} · {adr} · {verdict['how']}")
    else:
        con.print(f"[{Y}]Aucune estimation possible (installe GeoCLIP ou une IA de vision).")
    f = OUT / f"photographe_{stamp()}.html"
    f.write_text(vantage_html(img, layers, used if sol else [], gps, cam, center), encoding="utf-8")
    add_report("Géoloc", Path(path).name, "\n".join(lines))
    log(f"Carte interactive : {f}", G)
    if ask_yes("Ouvrir la carte (zone, monuments, position calculée) ?"):
        open_file(f)
    pause()


# ============================================================ OUTILS POSITION / DATE
def parse_pos(s):
    s = s.strip()
    m = re.search(r"@(-?\d+\.\d+),(-?\d+\.\d+)", s) or re.search(r"!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)", s) or re.search(r"[?&](?:q|ll|query)=(-?\d+\.\d+),\s*(-?\d+\.\d+)", s)
    if m:
        return float(m.group(1)), float(m.group(2))
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)\s*", s)
    if m:
        return float(m.group(1)), float(m.group(2))
    d = re.findall(r"(\d+(?:\.\d+)?)\s*°\s*(?:(\d+(?:\.\d+)?)\s*['′]\s*)?(?:(\d+(?:\.\d+)?)\s*[\"″]\s*)?\s*([NSEWO])", s, re.I)
    if len(d) == 2:
        v = []
        for deg, mi, se, h in d:
            x = float(deg) + float(mi or 0) / 60 + float(se or 0) / 3600
            v.append(-x if h.upper() in "SWO" else x)
        return v[0], v[1]
    return geocode(s) if s else None


def ask_pos(label="Lieu"):
    dflt = f"{LAST['pos'][0]:.5f}, {LAST['pos'][1]:.5f}" if LAST["pos"] else None
    s = Prompt.ask(f"[{G}]{label} (coordonnées, lien Google Maps ou nom de lieu)" + (" [Entrée = dernière position]" if dflt else ""), default=dflt or "", show_default=False)
    p = parse_pos(s)
    if not p:
        con.print(f"[{R_STYLE}]Lieu introuvable.")
    else:
        LAST["pos"] = p
    return p


def tz_offset(lat, lon, day):
    """Décalage horaire local (secondes) via Open-Meteo, sinon estimation par la longitude."""
    try:
        api = "https://archive-api.open-meteo.com/v1/archive" if day < datetime.date.today() - datetime.timedelta(days=5) else "https://api.open-meteo.com/v1/forecast"
        j = get_json(api, 12, params={"latitude": lat, "longitude": lon, "start_date": day, "end_date": day, "hourly": "temperature_2m", "timezone": "auto"})
        return j["utc_offset_seconds"], j.get("timezone", "")
    except Exception:
        return round(lon / 15) * 3600, "estimé"


# ============================================================ 11. MÉTÉO HISTORIQUE
WCODE = {0: "🌞 dégagé", 1: "🌤 peu nuageux", 2: "⛅ partiellement nuageux", 3: "☁️ couvert", 45: "🌫 brouillard", 48: "🌫 brouillard givrant", 51: "🌦 bruine légère", 53: "🌦 bruine",
         55: "🌧 bruine forte", 61: "🌧 pluie faible", 63: "🌧 pluie", 65: "🌧 forte pluie", 71: "🌨 neige faible", 73: "🌨 neige", 75: "❄️ forte neige", 77: "🌨 grains de neige",
         80: "🌦 averses", 81: "🌧 averses", 82: "⛈ averses violentes", 85: "🌨 averses de neige", 86: "❄️ fortes averses de neige", 95: "⛈ orage", 96: "⛈ orage + grêle", 99: "⛈ orage violent"}


def mod_weather():
    con.rule(f"[{G}]☔ MÉTÉO HISTORIQUE · VÉRIFIER UNE PHOTO")
    con.print(f"[{M}]Le temps qu'il faisait heure par heure à un endroit et une date (pour vérifier si une photo est cohérente).\n")
    p = ask_pos()
    if not p:
        return pause()
    day = ask_date(default=(LAST["date"] or datetime.datetime.now()).strftime("%d/%m/%Y"))
    api = "https://archive-api.open-meteo.com/v1/archive" if day < datetime.date.today() - datetime.timedelta(days=5) else "https://api.open-meteo.com/v1/forecast"
    try:
        with con.status("Open-Meteo…"):
            apis = [api, "https://historical-forecast-api.open-meteo.com/v1/forecast", api]
            for essai, url in enumerate(apis):
                r = get(url, 25, params={"latitude": p[0], "longitude": p[1], "start_date": day, "end_date": day, "timezone": "auto",
                                         "hourly": "temperature_2m,precipitation,cloud_cover,weather_code,wind_speed_10m,snow_depth"})
                if r.status_code != 429:
                    break
                time.sleep(5 * (essai + 1))
            r.raise_for_status()
            j = r.json()
    except Exception as e:
        con.print(f"[{R_STYLE}]Météo indisponible : {escape(str(e))}")
        return pause()
    h = j["hourly"]
    t = Table(title=f"Météo le {day:%d/%m/%Y} · {escape(place_name(p[0], p[1], 10))}", box=box.ROUNDED, border_style="#2b3158")
    for c in ("Heure", "Ciel", "Temp.", "Nuages", "Pluie", "Vent"):
        t.add_column(c)
    for i in range(0, len(h["time"])):
        t.add_row(h["time"][i][11:16], WCODE.get(h["weather_code"][i], str(h["weather_code"][i])), f"{h['temperature_2m'][i]:.0f}°C", f"{h['cloud_cover'][i]}%",
                  f"{h['precipitation'][i]} mm", f"{h['wind_speed_10m'][i]:.0f} km/h")
    con.print(t)
    tot = sum(x or 0 for x in h["precipitation"])
    con.print(f"[{M}]Total pluie : {tot:.1f} mm · nuages moyens {sum(h['cloud_cover']) / len(h['cloud_cover']):.0f}% · neige au sol max {max((x or 0) for x in h.get('snow_depth', [0])) * 100:.0f} cm")
    add_report("Météo", f"{p[0]:.4f}, {p[1]:.4f} le {day}", f"Pluie {tot:.1f} mm · temp. {min(h['temperature_2m']):.0f} à {max(h['temperature_2m']):.0f}°C")
    pause()


# ============================================================ 13. AVIONS AUTOUR D'UN POINT
def mod_planes():
    con.rule(f"[{G}]🛫 AVIONS AUTOUR D'UN POINT (ADS-B en direct)")
    p = ask_pos()
    if not p:
        return pause()
    km = ask_num(f"[{G}]Rayon en km", "40")
    try:
        with con.status("Réception ADS-B (adsb.lol)…"):
            ac = get_json(f"https://api.adsb.lol/v2/point/{p[0]}/{p[1]}/{max(1, int(km / 1.852))}", 20).get("ac", [])
    except Exception as e:
        con.print(f"[{R_STYLE}]ADS-B indisponible : {escape(str(e))}")
        return pause()
    for a in ac:
        a["_d"] = haversine(p[0], p[1], a.get("lat", p[0]), a.get("lon", p[1]))
    ac.sort(key=lambda a: a["_d"])
    t = Table(title=f"{len(ac)} appareil(s) dans {km:.0f} km", box=box.ROUNDED, border_style="#2b3158")
    for c in ("Vol", "Immat.", "Type", "Altitude", "Vitesse", "Cap", "Distance", ""):
        t.add_column(c)
    for a in ac[:40]:
        alt = a.get("alt_baro")
        alt = "au sol" if alt == "ground" else f"{float(alt) * .3048:,.0f} m".replace(",", " ") if isinstance(alt, (int, float)) else "—"
        mil = f"[{R_STYLE}]MILITAIRE[/]" if (a.get("dbFlags") or 0) & 1 else ""
        t.add_row(escape((a.get("flight") or "").strip() or "—"), escape(a.get("r") or "—"), escape(a.get("t") or "—"), alt,
                  f"{float(a['gs']) * 1.852:.0f} km/h" if a.get("gs") else "—", f"{a.get('track', 0):.0f}°" if a.get("track") is not None else "—", f"{a['_d']:.1f} km", mil)
    con.print(t)
    add_report("Avions", f"{p[0]:.4f}, {p[1]:.4f}", "\n".join(f"{(a.get('flight') or '').strip()} {a.get('r', '')} {a.get('t', '')} à {a['_d']:.1f} km" for a in ac[:20]))
    if ac and ask_yes("Afficher sur une carte ?"):
        pts = [{"lat": a["lat"], "lon": a["lon"], "icon": "✈", "rot": a.get("track") or 0, "s": 22, "c": "#ffc861",
                "label": escape_html(f"{(a.get('flight') or '').strip()} · {a.get('r', '')} · {a.get('t', '')} · {a['_d']:.1f} km")} for a in ac if a.get("lat")]
        save_open("avions", quick_map(f"Avions autour de {p[0]:.3f}, {p[1]:.3f}", pts, circles=[{"lat": p[0], "lon": p[1], "r": km * 1000, "c": "#00e5ff"}]))
    pause()


# ============================================================ CHALLENGES
# ============================================================ RÉGLAGES


# ============================================================ ANIMATIONS
BANNER = r"""
 ██████╗ █████╗ ████████╗   ███████╗██╗  ██╗███████╗
██╔════╝██╔══██╗╚══██╔══╝   ██╔════╝╚██╗██╔╝██╔════╝
██║     ███████║   ██║      █████╗   ╚███╔╝ █████╗
██║     ██╔══██║   ██║      ██╔══╝   ██╔██╗ ██╔══╝
╚██████╗██║  ██║   ██║   ██╗███████╗██╔╝ ██╗███████╗
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝"""
GRAD = ["#00e5ff", "#33ccff", "#66b3ff", "#8c9eff", "#a78bfa", "#c084fc"]
GLYPHS = "01$#@%&*+=<>/\\|{}[]?!~^ｱｶｻﾀﾅﾊﾏ"


def banner_text(revealed=1.0, glitch=0, pad=2):
    t = Text()
    for i, line in enumerate(BANNER.strip("\n").split("\n")):
        off = random.randint(-glitch, glitch) if glitch else 0
        line = " " * (pad + max(0, off)) + line[max(0, -off):]
        for ch in line:
            if ch == " " or random.random() < revealed:
                t.append(ch, style=GRAD[i] if not glitch or random.random() > .15 else "#b388ff")
            else:
                t.append(random.choice(GLYPHS), style=random.choice(["#b388ff", "#4a3fa0", "#00e5ff"]))
        t.append("\n")
    return t


def anim_matrix(sec=1.1):
    w, h = max(20, min(con.width, 120) - 1), 16
    drops = [random.randint(-h, 0) for _ in range(w)]
    end = time.time() + sec
    shades = ["bold #ffffff", "bold #00e5ff", "#00b8d4", "#3f7fd9", "#4a3fa0", "#2a2266"]
    with Live(console=con, refresh_per_second=30, transient=True) as live:
        while time.time() < end:
            t = Text()
            for r in range(h):
                for c in range(w):
                    d = drops[c] - r
                    t.append(random.choice(GLYPHS), style=shades[d]) if 0 <= d < len(shades) else t.append(" ")
                t.append("\n")
            live.update(t)
            for c in range(w):
                drops[c] += 1
                if drops[c] - len(shades) > h:
                    drops[c] = random.randint(-h // 2, 0)
            time.sleep(1 / 30)


def anim_decrypt():
    with Live(console=con, refresh_per_second=40, transient=True) as live:
        n = 30
        for i in range(n + 1):
            live.update(banner_text(i / n))
            time.sleep(.035)
        for g in (3, 1, 2, 0, 1, 0):
            live.update(banner_text(1, g))
            time.sleep(.055)
    con.print(banner_text(1), end="")


def _logo_frame(x, rows, w, pad=2, noise=.07):
    """x = position du « faisceau » de décryptage (colonne)."""
    t = Text()
    for i, line in enumerate(rows):
        t.append(" " * pad)
        for c in range(w):
            ch = line[c] if c < len(line) else " "
            d = x - c
            if d > 7:
                t.append(ch, style=GRAD[i % len(GRAD)])
            elif d > 1:
                t.append(ch, style="bold #ffffff" if d < 4 else "bold #00e5ff")
            elif d > -9:
                if ch != " " or random.random() < .35:
                    t.append(random.choice(GLYPHS), style=random.choice(["bold #b388ff", "#00e5ff", "#4a3fa0"]))
                else:
                    t.append(" ")
            else:
                t.append(random.choice(GLYPHS) if ch != " " and random.random() < noise else " ", style="#2a2266")
        t.append("\n")
    return t


def _logo_glitch(rows, w, k, pad=2):
    t = Text()
    for i, line in enumerate(rows):
        off = random.choice([-2, -1, 0, 0, 1, 2]) if random.random() < k else 0
        line = (" " * max(0, off) + line)[max(0, -off):] if off >= 0 else line[-off:]
        t.append(" " * pad)
        split = random.random() < k
        for ch in line[:w + 2]:
            if ch == " ":
                t.append(" ")
            elif split and random.random() < .5:
                t.append(ch, style=random.choice(["bold #ff5c7a", "bold #00e5ff", "bold #b388ff"]))
            else:
                t.append(ch, style=GRAD[i % len(GRAD)])
        t.append("\n")
    return t


def anim_reveal():
    """Le logo CAT.EXE apparaît petit à petit : bruit → faisceau de décryptage → flash → glitch."""
    rows = BANNER.strip("\n").split("\n")
    w = max(len(r) for r in rows)
    with Live(console=con, refresh_per_second=60, transient=True) as live:
        for _ in range(8):  # bruit qui se densifie
            live.update(_logo_frame(-20, rows, w, noise=.05 + _ * .05))
            time.sleep(.03)
        for x in range(-6, w + 12, 2):
            live.update(_logo_frame(x, rows, w))
            time.sleep(.028)
        for k in (.9, .6, .0, .7, .3, .0, .2, .0):
            live.update(_logo_glitch(rows, w, k))
            time.sleep(.045)
    con.print(banner_text(1), end="")


def type_cursor(txt, style=P, delay=.012):
    """Écriture façon terminal avec curseur clignotant."""
    txt = tr(txt)
    with Live(console=con, refresh_per_second=60, transient=True) as live:
        for i in range(len(txt) + 1):
            live.update(Text.assemble((txt[:i], style), ("█", "bold #00e5ff")))
            if i < len(txt) and txt[i - 1:i] != " ":
                time.sleep(delay)
        for b in range(4):
            live.update(Text.assemble((txt, style), ("█" if b % 2 == 0 else " ", "bold #00e5ff")))
            time.sleep(.12)
    con.print(Text(txt, style=style))


def anim_loadbar(label="chargement des modules", sec=.6):
    with Live(console=con, refresh_per_second=60, transient=True) as live:
        n = 34
        for i in range(n + 1):
            pct = i / n
            live.update(Text.assemble(("  ⟦", M), ("█" * i, "#00e5ff"), ("▒" if i < n else "", "#b388ff"), ("░" * (n - i - 1 if i < n else 0), "#2a2266"),
                                      ("⟧ ", M), (f"{int(pct * 100):>3}% ", "bold #00e5ff"), (tr(label), M)))
            time.sleep(sec / n)


def typewrite(txt, style=G, delay=.014):
    txt = tr(txt)
    for ch in txt:
        con.print(ch, style=style, end="", markup=False, highlight=False)
        if ch != " ":
            time.sleep(delay)
    con.print()


def transition(name):
    if not CFG.get("anim", True):
        return
    with Live(console=con, refresh_per_second=50, transient=True) as live:
        for i in range(26):
            k = i / 25
            gl = "".join(c if random.random() < k else random.choice(GLYPHS) for c in name)
            live.update(Text.assemble(("  » ", P), (f"{gl:<22}", G), ("█" * i + "░" * (25 - i), "#00e5ff"), (f" {int(k * 100):>3}%", M)))
            time.sleep(.014)


# ============================================================ BOOT + MENU
def chk_net():
    return bool(dns("one.one.one.one", "A"))


def chk_ai():
    ms = ollama_models()
    if ms is None:
        return "Ollama non lancé : s'installe au 1er usage (Réglages)"
    return True if ollama_has(ms, CFG.get("ollama_text", "qwen2.5:3b")) else f"modèle {CFG.get('ollama_text')} à télécharger (Réglages)"





def boot():
    anim = CFG.get("anim", True)
    con.clear()
    if anim:
        try:
            anim_matrix(.6)
            con.clear()
            anim_reveal()
            type_cursor(f"  // OSINT · GEOINT TOOL v{VERSION} · recon · géoloc · graphe · IA locale")
            anim_loadbar()
        except KeyboardInterrupt:
            con.clear()
            con.print(banner_text(1))
    else:
        con.print(banner_text(1))
    con.print()
    checks = [("Connexion Internet", chk_net), (f"IA locale : {CFG.get('ollama_text', 'qwen2.5:3b')}", chk_ai),
              ("Photos iPhone (HEIC)", lambda: True if HEIF_OK else "absent : pip install pillow-heif"),
              ("IA géoloc locale GeoCLIP", lambda: True if geoclip_ready() else ("avec LANCER.bat uniquement" if getattr(sys, 'frozen', False) else "s'installe au 1er usage (menu 6)")),
              ("IA de vision locale (Ollama)", lambda: True if ollama_models() is not None else "s'installe au 1er usage (menu 6)"),
              ("Analyse de numéros", lambda: True if phonenumbers else "absent : pip install phonenumbers"),
              (f"Base pseudos : {len(SITES)} sites", lambda: True)]
    for name, fn in checks:
        with con.status(f"[{M}]{name}…", spinner="dots"):
            try:
                res = fn()
            except Exception:
                res = "injoignable"
            if anim:
                time.sleep(.12)
        ok = res is True or (isinstance(res, str) and res.startswith("ok"))
        extra = "" if res is True else (res[5:] if isinstance(res, str) and res.startswith("ok · ") else res)
        con.print(f"  [{G if ok else Y}][{' OK ' if ok else 'WARN'}][/] {name} [{M}]{escape(str(extra or ''))}")
    if anim:
        con.print()
        typewrite("  >>> ACCESS GRANTED", G, .03)
        time.sleep(.45)


def mod_diagnostics():
    """Affiche un état local reproductible sans contacter de service externe."""
    con.rule(f"[{G}]🧪 DIAGNOSTIC SYSTÈME")
    con.print(f"[{M}]Vérification locale : aucune donnée n'est envoyée.[/]")
    checks = collect_checks(BASE)
    table = Table(show_header=True, header_style=f"bold {G}", box=box.SIMPLE)
    table.add_column("Élément")
    table.add_column("Statut", justify="center")
    table.add_column("Détail")
    for check in checks:
        color = G if check.status == "OK" else (R if check.status == "KO" else Y)
        table.add_row(check.name, f"[{color}]{check.status}[/]", check.detail)
    con.print(table)
    con.print()
    for category, label in (("required", "Obligatoire"), ("optional", "Optionnel"), ("ai", "IA locale"), ("ffmpeg", "FFmpeg"), ("browser", "Navigateur")):
        present = ", ".join(c.name for c in checks if c.category == category and c.status == "OK") or "aucun"
        missing = ", ".join(c.name for c in checks if c.category == category and c.status != "OK")
        suffix = f" · absents : {missing}" if missing else ""
        con.print(f"[{P}]{label}[/] : {present}{suffix}")
    pause()


# ============================================================ NOUVEAUX MODULES v4
def fmt_dt(dt):
    """Date UTC → texte « JJ/MM/AAAA HH:MM:SS UTC (heure de Paris …) »."""
    try:
        import zoneinfo
        loc = dt.replace(tzinfo=datetime.timezone.utc).astimezone(zoneinfo.ZoneInfo("Europe/Paris"))
        return f"{dt:%d/%m/%Y %H:%M:%S} UTC", f"{loc:%d/%m/%Y %H:%M:%S}"
    except Exception:
        return f"{dt:%d/%m/%Y %H:%M:%S} UTC", "—"


def human_age(dt):
    s = (datetime.datetime.utcnow() - dt).total_seconds()
    if s < 0:
        return "dans le futur"
    for d, u in ((31557600, "an(s)"), (2629800, "mois"), (86400, "jour(s)"), (3600, "h"), (60, "min")):
        if s >= d:
            return f"il y a {s / d:.0f} {u}" if d != 31557600 else f"il y a {s / d:.1f} an(s)"
    return "à l'instant"


# ------------------------------------------------------------ 🔑 FUITE DE MOT DE PASSE
COMMON_PW = ["123456", "password", "azerty", "qwerty", "motdepasse", "soleil", "doudou", "loulou", "chouchou", "marseille", "football", "iloveyou",
             "admin", "welcome", "bonjour", "princesse", "nicolas", "dragon", "monkey", "letmein", "abc123", "000000", "111111", "123123"]


def pw_strength(pw):
    import math as _m
    pool = sum(n for ok, n in ((re.search(r"[a-z]", pw), 26), (re.search(r"[A-Z]", pw), 26), (re.search(r"\d", pw), 10), (re.search(r"[^A-Za-z0-9]", pw), 33)) if ok)
    bits = len(pw) * _m.log2(max(pool, 2))
    notes = []
    low = pw.lower()
    if any(w in low for w in COMMON_PW):
        bits = min(bits, 20)
        notes.append("contient un mot de passe très courant")
    if re.search(r"(19|20)\d\d|\d\d[/.-]?\d\d[/.-]?\d{2,4}", pw):
        bits -= 10
        notes.append("contient une date (année, anniversaire ?)")
    if re.search(r"(.)\1{2,}", pw):
        bits -= 8
        notes.append("caractères répétés")
    if any(s in low for s in ("azert", "qwert", "12345", "abcde", "wxcvb", "asdf")):
        bits -= 10
        notes.append("suite du clavier")
    if len(pw) < 12:
        notes.append("moins de 12 caractères")
    bits = max(bits, 0)
    secs = 2 ** bits / 1e10  # 10 milliards d'essais / s (carte graphique, empreinte rapide)
    for lim, txt in ((1, "instantané"), (3600, f"{secs / 60:.0f} min"), (86400, f"{secs / 3600:.0f} h"), (31557600, f"{secs / 86400:.0f} jours"),
                     (31557600 * 1000, f"{secs / 31557600:.0f} ans"), (float("inf"), "des millénaires")):
        if secs < lim:
            crack = txt
            break
    lvl = "très faible" if bits < 35 else "faible" if bits < 50 else "moyen" if bits < 65 else "fort" if bits < 85 else "très fort"
    return lvl, bits, crack, notes


def mod_pwned():
    con.rule(f"[{G}]🔑 FUITE DE MOT DE PASSE")
    con.print(f"[{M}]Ton mot de passe ne quitte jamais ton PC : seuls les 5 premiers caractères de son empreinte SHA-1 sont envoyés\n"
              f"(méthode « k-anonymat » de Have I Been Pwned). Rien n'est enregistré.\n")
    while True:
        pw = Prompt.ask(f"[{G}]Mot de passe à tester [{M}](masqué · Entrée = retour)", password=True, default="", show_default=False)
        if not pw:
            break
        h = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        try:
            with con.status(f"[{M}]Vérification dans 900 millions de mots de passe fuités…"):
                r = get(f"https://api.pwnedpasswords.com/range/{h[:5]}", 15, headers={"Add-Padding": "true"})
            n = next((int(c) for line in r.text.splitlines() for s, _, c in [line.strip().partition(":")] if s == h[5:]), 0)
        except Exception as e:
            con.print(f"[{R}]Service injoignable : {escape(str(e))}")
            continue
        lvl, bits, crack, notes = pw_strength(pw)
        col = {"très faible": R, "faible": R, "moyen": Y, "fort": G, "très fort": G}[lvl]
        body = (f"[{R}]⚠ TROUVÉ {n:,} fois dans des fuites de données ![/]\n[{M}]Il est dans les listes des pirates : change-le partout où tu l'utilises.[/]".replace(",", " ")
                if n else f"[{G}]✓ Absent des fuites connues.[/]")
        body += (f"\n\n[{M}]Force[/] [{col}]{lvl}[/] [{M}]({bits:.0f} bits · longueur {len(pw)})[/]\n[{M}]Temps pour le casser (hors ligne) :[/] {crack}")
        if notes:
            body += "\n" + "\n".join(f"[{Y}]• {x}[/]" for x in notes)
        body += f"\n\n[{M}]Conseil : une phrase de passe de 4-5 mots + un gestionnaire (Bitwarden, KeePassXC) + la double authentification.[/]"
        con.print(Panel(body, title=f"[{G}]Résultat", border_style=R if n else "#00e5ff", title_align="left"))
        add_report("Mot de passe", "test (mot de passe masqué)", f"Fuites : {n} · force : {lvl} ({bits:.0f} bits)")
    pause()


# ------------------------------------------------------------ 🆔 DÉCODEUR D'ID & DATES
IG_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
TID_ALPHA = "234567abcdefghijklmnopqrstuvwxyz"


def ig_code_to_id(code):
    n = 0
    for ch in code[:11]:
        n = n * 64 + IG_ALPHA.index(ch)
    return n


def decode_id(s):
    """Renvoie [(source, datetime UTC, détail)] pour un lien ou un identifiant."""
    s = s.strip()
    out = []
    ep = datetime.datetime(1970, 1, 1)

    def ms(v, src, det=""):
        try:
            d = ep + datetime.timedelta(milliseconds=v)
            if datetime.datetime(2004, 1, 1) <= d <= datetime.datetime.utcnow() + datetime.timedelta(days=400):
                out.append((src, d, det))
        except (OverflowError, ValueError):
            pass
    m = re.search(r"tiktok\.com/.*?/(?:video|photo)/(\d{15,20})", s)
    if m:
        ms((int(m.group(1)) >> 32) * 1000, "TikTok (vidéo)", "date de mise en ligne")
    m = re.search(r"(?:twitter|x)\.com/[^/]+/status(?:es)?/(\d{1,20})", s)
    if m:
        if int(m.group(1)) < 30000000000000000:
            out.append(("X / Twitter (post)", None, "post d'avant novembre 2010 : pas de date cachée dans cet ancien ID"))
        else:
            ms((int(m.group(1)) >> 22) + 1288834974657, "X / Twitter (post)", "date de publication")
    m = re.search(r"(instagram\.com|threads\.(?:net|com))/(?:[^/]+/)?(?:p|reel|reels|tv|post)/([A-Za-z0-9_-]{6,})", s)
    if m:
        try:
            mid = ig_code_to_id(m.group(2))
            ms((mid >> 23) + 1314220021721, "Instagram" if "instagram" in m.group(1) else "Threads", f"publication · ID {mid}")
        except ValueError:
            pass
    m = re.search(r"linkedin\.com/.*?(?:activity|ugcPost|share)[:-](\d{18,20})", s)
    if m:
        ms(int(m.group(1)) >> 22, "LinkedIn (post)", "date de publication")
    m = re.search(r"bsky\.app/profile/[^/]+/post/([a-z2-7]{13})", s)
    if m:
        v = 0
        for ch in m.group(1):
            v = v * 32 + TID_ALPHA.index(ch)
        ms((v >> 10) / 1000, "Bluesky (post)", "date de publication")
    m = re.search(r"https?://[^/]+/@[^/]+/(\d{17,19})\b", s)
    if m and "tiktok" not in s:
        ms(int(m.group(1)) >> 16, "Mastodon (post)", "date de publication")
    if out:
        return out
    t = re.sub(r"[\s_]", "", s)
    if re.fullmatch(r"\d{5,20}", t):
        n = int(t)
        for div, lab in ((1, "Timestamp Unix (secondes)"), (1000, "Timestamp Unix (millisecondes)"), (10 ** 6, "Timestamp Unix (microsecondes)"), (10 ** 9, "Timestamp Unix (nanosecondes)")):
            ms(n * 1000 / div, lab)
        if n > 10 ** 14:
            ms((n >> 22) + 1288834974657, "Snowflake X / Twitter", "ID de post")
            ms((n >> 32) * 1000, "ID TikTok", "vidéo")
            ms((n >> 23) + 1314220021721, "ID Instagram", "publication")
            ms(n >> 22, "ID LinkedIn", "post")
            ms(n >> 16, "ID Mastodon", "post")
        if 10 ** 16 < n < 3 * 10 ** 18:
            ms((n - 116444736000000000) / 10000, "Date Windows (FILETIME)", "registre, fichiers NTFS")
        if re.fullmatch(r"7656119\d{10}", t):
            out.append(("Steam64", None, f"compte n°{n - 76561197960265728} · https://steamcommunity.com/profiles/{n}"))
        if 8 <= len(t) <= 10:
            ms((n + 978307200) * 1000, "Date Apple (Cocoa, depuis 2001)", "photos/messages iPhone")
    elif re.fullmatch(r"[0-9a-fA-F]{24}", t):
        ms(int(t[:8], 16) * 1000, "ObjectId MongoDB", "date de création de l'objet")
    elif re.fullmatch(r"[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}", t):
        h = t.replace("-", "").lower()
        ver = int(h[12], 16)
        if ver == 1:
            ts = int(h[13:16] + h[8:12] + h[0:8], 16)
            ms((ts - 0x01B21DD213814000) / 10000, "UUID v1", f"créé par la machine (MAC {':'.join(h[20:][i:i + 2] for i in range(0, 12, 2))})")
        elif ver == 7:
            ms(int(h[:12], 16), "UUID v7", "date de création")
        else:
            out.append((f"UUID v{ver}", None, "aléatoire : pas de date dedans"))
    elif re.fullmatch(r"[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}", t):
        v = 0
        for ch in t[:10].upper():
            v = v * 32 + "0123456789ABCDEFGHJKMNPQRSTVWXYZ".index(ch)
        ms(v, "ULID", "date de création")
    return out


def mod_ids():
    con.rule(f"[{G}]🆔 DÉCODEUR D'ID & DATES CACHÉES")
    con.print(f"[{M}]Colle un lien ou un identifiant : la date est souvent cachée dedans, même si le post est supprimé ou la date masquée.\n"
              "TikTok · X/Twitter · Instagram · Threads · LinkedIn · Bluesky · Mastodon · Steam64 · timestamps Unix/Windows/Apple · UUID · ObjectId · ULID\n")
    while True:
        s = Prompt.ask(f"[{G}]Lien ou ID [{M}](Entrée = retour)", default="", show_default=False).strip()
        if not s:
            break
        res = decode_id(s)
        if not res:
            con.print(f"[{Y}]Aucune date reconnue dans « {escape(s)} ».")
            continue
        t = Table(box=box.ROUNDED, border_style="#2b3158", title=escape(s[:80]))
        for c in ("Source", "Date UTC", "Heure de Paris", "Âge", "Détail"):
            t.add_column(c)
        for src, d, det in res:
            u, loc = fmt_dt(d) if d else ("—", "—")
            t.add_row(f"[{G}]{src}", u, loc, human_age(d) if d else "—", f"[{M}]{escape(det)}")
        con.print(t)
        if len(res) > 1 and re.fullmatch(r"\d+", re.sub(r"\s", "", s)):
            con.print(f"[{M}]Plusieurs lectures possibles pour un nombre seul : garde celle qui correspond à la plateforme d'origine.")
        add_report("Décodeur d'ID", s[:80], "\n".join(f"{a} : {fmt_dt(d)[0] if d else '—'} {c}" for a, d, c in res))
    pause()


# ------------------------------------------------------------ 🎬 VIDÉO → IMAGES + GPS
def ffmpeg_exe():
    import shutil
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        pass
    if shutil.which("ffmpeg"):
        return shutil.which("ffmpeg")
    if getattr(sys, "frozen", False):
        con.print(f"[{Y}]Le module vidéo a besoin de ffmpeg : lance l'outil avec LANCER.bat (version Python) ou installe ffmpeg.")
        return None
    if not ask_yes("Le module vidéo a besoin de ffmpeg (~30 Mo, une seule fois). L'installer maintenant ?", True):
        return None
    with con.status(f"[{M}]pip install imageio-ffmpeg…"):
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--disable-pip-version-check", "imageio-ffmpeg"], capture_output=True)
    try:
        import importlib
        importlib.invalidate_caches()
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception as e:
        con.print(f"[{R}]Installation impossible : {escape(str(e))}")
        return None


def video_meta(ff, path):
    r = subprocess.run([ff, "-hide_banner", "-i", str(path)], capture_output=True, text=True, encoding="utf-8", errors="replace")
    txt = r.stderr
    info = {}
    m = re.search(r"Duration: (\d+):(\d+):([\d.]+)", txt)
    if m:
        info["durée"] = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3))
    for key, lab in (("creation_time", "date de création"), ("com.apple.quicktime.creationdate", "date (iPhone)"), ("com.apple.quicktime.make", "marque"),
                     ("com.apple.quicktime.model", "modèle"), ("com.apple.quicktime.software", "logiciel"), ("com.android.version", "Android"),
                     ("com.android.manufacturer", "marque"), ("com.android.model", "modèle"), ("encoder", "encodeur"), ("handler_name", "piste"),
                     ("major_brand", "format"), ("title", "titre"), ("artist", "auteur"), ("comment", "commentaire"), ("description", "description")):
        m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+)$", txt, re.M)
        if m and lab not in info:
            info[lab] = m.group(1).strip()
    m = re.search(r"(?:location|com\.apple\.quicktime\.location\.ISO6709|location-eng)\s*:\s*([+-]\d+\.?\d*)([+-]\d+\.?\d*)", txt)
    if m:
        info["GPS"] = (float(m.group(1)), float(m.group(2)))
    m = re.search(r"Video: (\w+).*?(\d{2,5})x(\d{2,5})", txt)
    if m:
        info["vidéo"] = f"{m.group(1)} · {m.group(2)}×{m.group(3)}"
    m = re.search(r"([\d.]+) fps", txt)
    if m:
        info["images/s"] = m.group(1)
    return info


def mod_video():
    con.rule(f"[{G}]🎬 VIDÉO → IMAGES + GPS CACHÉ")
    con.print(f"[{M}]Extrait les images d'une vidéo (pour la géoloc, Recherche de logo…) et lit ses métadonnées cachées (date, téléphone, position GPS des vidéos iPhone/Android).\n")
    path = Path(clean_path(Prompt.ask(f"[{G}]Glisse la vidéo ici (mp4, mov, webm, mkv…)")))
    if not path.is_file():
        con.print(f"[{R}]Fichier introuvable.")
        return pause()
    ff = ffmpeg_exe()
    if not ff:
        return pause()
    info = video_meta(ff, path)
    t = Table(box=box.ROUNDED, border_style="#2b3158", title="Métadonnées de la vidéo", show_header=False)
    for k, v in info.items():
        if k == "durée":
            v = f"{int(v // 60)} min {v % 60:.1f} s"
        if k == "GPS":
            v = f"{v[0]:.6f}, {v[1]:.6f}  [{M}]→ {escape(place_name(*v) or '')}[/]"
        t.add_row(f"[{G}]{k}", str(v) if k == "GPS" else escape(str(v)))
    con.print(t)
    if "GPS" in info:
        con.print(Panel(f"[{R}]Position GPS trouvée dans la vidéo ![/]\n" + "\n".join(f"[{B}]{k}[/] {v}" for k, v in list(map_links(*info["GPS"]).items())[:4]), border_style=R))
        LAST["pos"] = info["GPS"]
    dur = info.get("durée") or 0
    if not dur:
        con.print(f"[{Y}]Durée illisible : la vidéo est peut-être abîmée.")
        return pause()
    n = select("Combien d'images extraire ?", [{"label": f"{k} images", "value": k, "desc": f"une toutes les {dur / k:.1f} s"} for k in (6, 12, 24, 48)], default=12)
    if not n:
        return pause()
    d = OUT / f"video_{re.sub(r'[^A-Za-z0-9_-]', '_', path.stem)[:30]}_{stamp()}"
    d.mkdir()
    frames = []
    with Progress(TextColumn(f"[{G}]Extraction"), BarColumn(complete_style="#00e5ff"), TaskProgressColumn(), console=con) as pr:
        tk = pr.add_task("", total=n)
        for i in range(n):
            ts = dur * (i + .5) / n
            f = d / f"image_{i + 1:02d}_{int(ts // 60):02d}m{ts % 60:04.1f}s.jpg"
            subprocess.run([ff, "-hide_banner", "-loglevel", "error", "-ss", f"{ts:.2f}", "-i", str(path), "-frames:v", "1", "-q:v", "2", "-y", str(f)], capture_output=True)
            if f.exists():
                frames.append((f, ts))
            pr.advance(tk)
    if not frames:
        con.print(f"[{R}]Aucune image extraite.")
        return pause()
    if Image:
        ims = [Image.open(f).convert("RGB") for f, _ in frames]
        w = 360
        th = [im.resize((w, int(im.height * w / im.width))) for im in ims]
        h = max(x.height for x in th)
        cols = 4
        rows = (len(th) + cols - 1) // cols
        sheet = Image.new("RGB", (cols * (w + 8) + 8, rows * (h + 30) + 8), (7, 9, 11))
        from PIL import ImageDraw
        dr = ImageDraw.Draw(sheet)
        for i, (im, (f, ts)) in enumerate(zip(th, frames)):
            x, y = 8 + (i % cols) * (w + 8), 8 + (i // cols) * (h + 30)
            sheet.paste(im, (x, y))
            dr.text((x + 4, y + h + 6), f"#{i + 1}  {int(ts // 60):02d}:{ts % 60:04.1f}", fill=(60, 255, 143))
        sheet.save(d / "planche.jpg", quality=88)
        log(f"Planche contact : {d / 'planche.jpg'}", G)
    log(f"{len(frames)} images dans : {d}", G)
    add_report("Vidéo", path.name, "\n".join(f"{k} : {v}" for k, v in info.items()) + f"\n{len(frames)} images extraites dans {d}")
    while True:
        act = select("Et maintenant ?", [{"label": "📷 Ouvrir la planche contact", "value": "sheet"}, {"label": "📂 Ouvrir le dossier des images", "value": "dir"},
                                         {"label": "📍 Géolocaliser une image", "value": "geo"}, {"label": "🔖 Chercher un logo dans une image", "value": "logo"},
                                         {"label": "← Retour au menu", "value": None}])
        if act == "sheet":
            open_file(d / "planche.jpg")
        elif act == "dir":
            open_file(d)
        elif act in ("geo", "logo"):
            k = select("Quelle image ?", [{"label": f"#{i + 1}  à {int(ts // 60):02d}:{ts % 60:04.1f}", "value": str(f)} for i, (f, ts) in enumerate(frames)])
            if k:
                (mod_geo if act == "geo" else mod_logo)(k)
                return
        else:
            return


# ------------------------------------------------------------ 📏 DISTANCE, AZIMUT, HORIZON
def bearing(a, b, c, d):
    y = math.sin(math.radians(d - b)) * math.cos(math.radians(c))
    x = math.cos(math.radians(a)) * math.sin(math.radians(c)) - math.sin(math.radians(a)) * math.cos(math.radians(c)) * math.cos(math.radians(d - b))
    return (math.degrees(math.atan2(y, x)) + 360) % 360


def destination(lat, lon, brg, km):
    R_ = 6371.0088
    d, t = km / R_, math.radians(brg)
    a = math.radians(lat)
    b = math.asin(math.sin(a) * math.cos(d) + math.cos(a) * math.sin(d) * math.cos(t))
    c = math.radians(lon) + math.atan2(math.sin(t) * math.sin(d) * math.cos(a), math.cos(d) - math.sin(a) * math.sin(b))
    return math.degrees(b), (math.degrees(c) + 540) % 360 - 180


def ask_geo_coordinates(label):
    """Saisie de coordonnées littérales uniquement; ne géocode pas de nom de lieu."""
    value = Prompt.ask(f"[{G}]{label} (latitude, longitude en degrés décimaux)").strip()
    match = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)\s*", value)
    if not match:
        con.print(f"[{R_STYLE}]Entre des coordonnées comme 48.8584, 2.2945; aucun nom de lieu ne sera géocodé.")
        return None
    point = float(match.group(1)), float(match.group(2))
    if not (-90 <= point[0] <= 90 and -180 <= point[1] <= 180):
        con.print(f"[{R_STYLE}]Coordonnées hors limites.")
        return None
    LAST["pos"] = point
    return point


def mod_line_of_sight_relief():
    con.rule(f"[{G}]LIGNE DE VUE · PROFIL DE RELIEF")
    con.print(f"[{M}]Relief Copernicus GLO-90 (résolution nominale 90 m). Les bâtiments, arbres et obstacles plus petits ne sont pas représentés. Les coordonnées seront envoyées à Open-Meteo uniquement après confirmation.")
    start = ask_geo_coordinates("Position de l'observateur")
    end = ask_geo_coordinates("Position de la cible") if start else None
    if not (start and end):
        return
    observer_h = ask_num(f"[{G}]Hauteur de l'observateur au-dessus du sol (m)", "1.7")
    target_h = ask_num(f"[{G}]Hauteur de la cible au-dessus du sol (m)", "10")
    try:
        points = great_circle_profile(start, end)
    except ValueError as exc:
        con.print(f"[{R_STYLE}]{escape(str(exc))}")
        return
    calls = math.ceil(len(points) / MAX_POINTS_PER_REQUEST)
    distance_m = haversine(*start, *end) * 1000
    con.print(f"[{M}]Profil : {len(points)} points · pas moyen {distance_m / (len(points) - 1):.0f} m · {calls} requête(s) maximum.")
    if not ask_yes("Envoyer ces coordonnées à Open-Meteo pour obtenir le profil d'altitude ?", default=False):
        con.print(f"[{Y}]Recherche annulée; aucune requête d'altitude envoyée.")
        return
    try:
        with con.status("Récupération des altitudes Copernicus…"):
            elevations = fetch_open_meteo_elevations(points, get_json)
        result = analyze_sightline(start, end, elevations, observer_h, target_h)
    except Exception as exc:
        con.print(Panel(f"Profil indisponible : {escape(str(exc))}", title="Ligne de vue", border_style=R_STYLE))
        return
    if result.visible is None:
        verdict = f"[{Y}]Indéterminé : une ou plusieurs altitudes manquent."
        clearance = "Dégagement non calculé."
    else:
        verdict = f"[{G}]Ligne de vue dégagée selon le modèle." if result.visible else f"[{R_STYLE}]Ligne de vue probablement masquée par le relief."
        loc = f"à {result.obstruction_fraction * 100:.1f} % du trajet" if result.obstruction_fraction is not None else ""
        clearance = f"Dégagement minimal : {result.minimum_clearance_m:.1f} m {loc}."
    body = (f"{verdict}\n{clearance}\nDistance : {result.distance_m / 1000:.2f} km · échantillons : {result.sample_count} · pas moyen : {result.sample_spacing_m:.0f} m\n"
            "Source : Copernicus GLO-90 via Open-Meteo · réfraction standard estimée.\n"
            "Limite : végétation, bâtiments et erreurs du modèle numérique peuvent changer le résultat.")
    con.print(Panel(body, title="Visibilité avec relief", border_style="#00e5ff"))
    add_report("Ligne de vue", f"{start} → {end}", f"{verdict}\n{clearance}\n{result.distance_m / 1000:.2f} km · {result.sample_count} points · Copernicus GLO-90 via Open-Meteo; obstacles bâtis/végétation non modélisés.")


def mod_bearing_triangulation():
    con.rule(f"[{G}]TRIANGULATION PAR RELÈVEMENTS")
    con.print(f"[{M}]Saisis au moins deux positions connues et l'azimut mesuré vers la cible, en degrés depuis le nord vrai, dans le sens horaire. Calcul hors ligne, pour une zone locale (max. 200 km); entre uniquement des lieux que tu es autorisé à analyser.")
    count = ask_num(f"[{G}]Nombre de relèvements (2 à 8)", "2")
    if not count.is_integer() or not 2 <= count <= 8:
        con.print(f"[{R_STYLE}]Choisis un nombre entier de 2 à 8.")
        return
    observations = []
    for index in range(int(count)):
        point = ask_geo_coordinates(f"Position connue {index + 1}")
        if not point:
            return
        azimuth = ask_num(f"[{G}]Azimut vers la cible depuis le nord vrai (degrés)", "0")
        if not 0 <= azimuth <= 360:
            con.print(f"[{R_STYLE}]L'azimut doit être entre 0 et 360 degrés.")
            return
        observations.append(BearingObservation(point[0], point[1], azimuth))
    uncertainty = ask_num(f"[{G}]Erreur angulaire estimée de chaque mesure (degrés)", "1")
    try:
        result = intersect_bearings(observations, uncertainty)
    except ValueError as exc:
        con.print(Panel(escape(str(exc)), title="Triangulation impossible", border_style=R_STYLE))
        return
    body = (f"Position estimée : {result.latitude:.6f}, {result.longitude:.6f}\n"
            f"Incertitude indicative : ± {result.uncertainty_radius_m:.0f} m (erreur angulaire saisie : {uncertainty:g}°)\n"
            f"Écart moyen aux relèvements : {result.residual_rms_m:.1f} m · angle de croisement minimal : {result.minimum_crossing_angle_deg:.1f}°")
    if not result.all_rays_forward:
        body += f"\n[{Y}]Attention : au moins un relèvement pointe à l'opposé de la position calculée; vérifie les mesures."
    if result.residual_rms_m > 500:
        body += f"\n[{Y}]Les lignes ne convergent pas bien; le résultat est peu cohérent."
    body += "\nEstimation plane locale, pas une position vérifiée. L'azimut magnétique doit être corrigé de la déclinaison avant saisie."
    con.print(Panel(body, title="Triangulation · estimation", border_style="#00e5ff"))
    add_report("Triangulation", f"{len(observations)} relèvements", f"{result.latitude:.6f}, {result.longitude:.6f} · incertitude indicative ±{result.uncertainty_radius_m:.0f} m · résidu RMS {result.residual_rms_m:.1f} m · angle minimal {result.minimum_crossing_angle_deg:.1f}° · azimuts vrais, non corrigés automatiquement.")


def mod_bearing():
    con.rule(f"[{G}]📏 DISTANCE · AZIMUT · HORIZON")
    while True:
        c = select("Outil géo", [{"label": "📐 Distance et direction entre 2 points", "value": "dist"},
                                 {"label": "🧭 Point à X km dans une direction", "value": "dest"},
                                 {"label": "🌅 Horizon : jusqu'où voit-on ?", "value": "hor"},
                                 {"label": "🗻 Un sommet / une tour est-il visible d'ici ?", "value": "vis"},
                                 {"label": "🗻 Visibilité avec profil de relief (Open-Meteo)", "value": "terrain"},
                                 {"label": "📐 Trianguler une cible par relèvements", "value": "triangulation"},
                                 {"label": "← Retour", "value": None}])
        if c is None:
            return
        if c == "dist":
            a, b = ask_pos("Point A"), ask_pos("Point B")
            if not (a and b):
                continue
            km = haversine(*a, *b)
            br = bearing(*a, *b)
            con.print(Panel(f"[{M}]Distance[/] [{G}]{km:,.3f} km[/]".replace(",", " ") + f"   [{M}]Direction A→B[/] [{G}]{br:.1f}° ({cardinal(br)})[/]   "
                            f"[{M}]B→A[/] {bearing(*b, *a):.1f}° ({cardinal(bearing(*b, *a))})\n[{M}]Milieu[/] {(a[0] + b[0]) / 2:.5f}, {(a[1] + b[1]) / 2:.5f}", border_style="#00e5ff"))
            add_report("Distance", f"{a} → {b}", f"{km:.3f} km · azimut {br:.1f}°")
            if ask_yes("Voir sur la carte ?"):
                save_open("distance", quick_map(f"Distance {km:.2f} km · {br:.0f}°", [{"lat": a[0], "lon": a[1], "label": "A", "c": "#00e5ff"}, {"lat": b[0], "lon": b[1], "label": "B"}], lines=[[list(a), list(b)]]))
        elif c == "dest":
            a = ask_pos("Point de départ")
            if not a:
                continue
            br = ask_num(f"[{G}]Direction en degrés (0 = nord, 90 = est…)", "0")
            km = ask_num(f"[{G}]Distance en km", "1")
            b = destination(*a, br, km)
            con.print(Panel(f"[{G}]{b[0]:.6f}, {b[1]:.6f}[/]  [{M}]{escape(place_name(*b) or '')}", border_style="#00e5ff"))
            LAST["pos"] = b
            if ask_yes("Voir sur la carte ?"):
                save_open("destination", quick_map("Point calculé", [{"lat": a[0], "lon": a[1], "label": "départ", "c": "#00e5ff"}, {"lat": b[0], "lon": b[1], "label": "arrivée"}], lines=[[list(a), list(b)]]))
        elif c == "hor":
            h = ask_num(f"[{G}]Hauteur des yeux / de la caméra (mètres au-dessus du sol ou de la mer)", "1.7")
            d = 3.57 * math.sqrt(max(h, 0))
            con.print(Panel(f"[{M}]Horizon géométrique[/] [{G}]{d:.1f} km[/]   [{M}]avec la réfraction de l'air[/] [{G}]{d * 1.08:.1f} km[/]\n"
                            f"[{M}]Au-delà, seuls les objets assez hauts dépassent de l'horizon (option suivante du menu).", border_style="#00e5ff"))
        elif c == "vis":
            h = ask_num(f"[{G}]Hauteur de l'observateur (m)", "1.7")
            H = ask_num(f"[{G}]Hauteur de l'objet observé (m, ex. 330 pour la tour Eiffel)", "100")
            km = ask_num(f"[{G}]Distance entre les deux (km)", "20")
            k = 0.13
            hidden = max(0.0, (km - 3.57 * math.sqrt(h) * 1.08)) ** 2 / (2 * 6371 / (1 - k)) * 1000
            vis = H - hidden
            con.print(Panel((f"[{G}]Visible[/] : {vis:.0f} m dépassent de l'horizon (sur {H:.0f} m)" if vis > 0 else f"[{R}]Invisible[/] : caché par la courbure de la Terre")
                            + f"\n[{M}]Partie cachée par la courbure : {hidden:.0f} m · ne tient pas compte du relief (collines, bâtiments).", border_style="#00e5ff"))
        elif c == "terrain":
            mod_line_of_sight_relief()
        elif c == "triangulation":
            mod_bearing_triangulation()


# ------------------------------------------------------------ 📡 IMAGES SATELLITE D'AVANT (Esri Wayback)
SAT_TPL = r"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cat.exe · Satellite d'avant</title>
__LEAFLET__
<style>body{margin:0;background:#07081a;color:#e4e9ff;font-family:system-ui,-apple-system,sans-serif}header{padding:10px 16px;border-bottom:1px solid #2b3158;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
header b{font-family:monospace;color:#00e5ff}header a{margin-left:auto;color:#8a8cff;font:13px monospace}#map{height:calc(100vh - 128px)}
.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid #2b3158;font:13px monospace}
select,button,input{background:#14173a;border:1px solid #2b3158;color:#e4e9ff;padding:6px 9px;border-radius:7px;font:13px monospace}button{cursor:pointer}button:hover{border-color:#00e5ff}
.k{color:#b388ff}.g{color:#00e5ff}.m{color:#7480a8}input[type=range]{width:180px;accent-color:#00e5ff}</style></head><body>
<header><b>CAT.exe // SATELLITE D'AVANT</b><span class="m">__PLACE__</span></header>
<div class="bar"><span class="k">AVANT</span><button id="ap">◀</button><select id="a"></select><button id="an">▶</button>
<span class="g">APRÈS</span><button id="bp">◀</button><select id="b"></select><button id="bn">▶</button>
<span class="m">mélange</span><input type="range" id="op" min="0" max="100" value="100"><span id="ov" class="m">100 % après</span>
<span class="m">· Google Earth (historique) :</span><a target="_blank" style="color:#00e5ff" href="https://earth.google.com/web/@__LAT__,__LON__,200a,1500d,35y,0h,0t,0r">ouvrir</a></div>
<div id="map"></div>
<script>const R=__REL__, C=[__LAT__,__LON__];
const map=catMap('map',{center:C,zoom:17,base:'Satellite'});L.circleMarker(C,{radius:6,color:'#b388ff'}).addTo(map);
const mk=r=>L.tileLayer(r.url,{maxZoom:20,maxNativeZoom:19,attribution:'© Esri World Imagery Wayback · '+r.d});
const A=document.getElementById('a'),B=document.getElementById('b'),O=document.getElementById('op');
R.forEach((r,i)=>{A.add(new Option(r.d,i));B.add(new Option(r.d,i));});A.value=0;B.value=R.length-1;
let la=null,lb=null;function upd(){if(la)map.removeLayer(la);if(lb)map.removeLayer(lb);la=mk(R[+A.value]).addTo(map);lb=mk(R[+B.value]).addTo(map);lb.setOpacity(O.value/100);}
O.oninput=()=>{if(lb)lb.setOpacity(O.value/100);document.getElementById('ov').textContent=O.value+' % après';};
A.onchange=B.onchange=upd;const st=(s,d)=>{s.value=Math.max(0,Math.min(R.length-1,+s.value+d));upd();};
ap.onclick=()=>st(A,-1);an.onclick=()=>st(A,1);bp.onclick=()=>st(B,-1);bn.onclick=()=>st(B,1);upd();</script></body></html>"""


def mod_satellite():
    con.rule(f"[{G}]📡 SATELLITE D'AVANT · HISTORIQUE DES IMAGES")
    con.print(f"[{M}]Compare les vues satellite d'un lieu depuis 2014 (archives Esri, ~200 versions) : constructions, démolitions, travaux, véhicules…\n")
    p = ask_pos("Lieu")
    if not p:
        return pause()
    try:
        with con.status(f"[{M}]Archives satellite Esri…"):
            cfg = get_json("https://s3-us-west-2.amazonaws.com/config.maptiles.arcgis.com/waybackconfig.json", 20)
    except Exception as e:
        con.print(f"[{R}]Archives injoignables : {escape(str(e))}")
        return pause()
    rel = []
    for v in cfg.values():
        m = re.search(r"(\d{4}-\d\d-\d\d)", v.get("itemTitle", ""))
        if m and v.get("itemURL"):
            rel.append({"d": m.group(1), "url": v["itemURL"].replace("{level}", "{z}").replace("{row}", "{y}").replace("{col}", "{x}")})
    rel.sort(key=lambda r: r["d"])
    log(f"{len(rel)} versions de {rel[0]['d']} à {rel[-1]['d']}", G)
    html = (SAT_TPL.replace("__LEAFLET__", LEAFLET_HEAD).replace("__REL__", json.dumps(rel)).replace("__LAT__", f"{p[0]:.6f}").replace("__LON__", f"{p[1]:.6f}")
            .replace("__PLACE__", escape_html(place_name(*p) or f"{p[0]:.5f}, {p[1]:.5f}")))
    save_open("satellite", html)
    con.print(f"[{M}]Dans la page : choisis une date « avant » et « après », puis fais glisser le curseur « mélange » pour voir ce qui a changé.")
    add_report("Satellite d'avant", f"{p[0]:.5f}, {p[1]:.5f}", f"{len(rel)} versions d'images ({rel[0]['d']} → {rel[-1]['d']})")
    pause()


# ------------------------------------------------------------ 📚 ARCHIVES D'UNE PAGE (Wayback Machine)
def mod_archive():
    con.rule(f"[{G}]📚 ARCHIVES D'UNE PAGE WEB")
    con.print(f"[{M}]Retrouve les anciennes versions d'une page ou d'un site : textes effacés, anciens contacts, anciennes équipes, pages supprimées.\n")
    url = re.sub(r"^https?://", "", Prompt.ask(f"[{G}]Adresse (ex. monsite.fr ou monsite.fr/contact)").strip()).rstrip("/")
    if not url:
        return pause()
    whole = ask_yes("Tout le site (toutes les pages) plutôt que cette page seule ?")
    rows = []
    try:
        with con.status(f"[{M}]Wayback Machine (archive.org)…"):
            rows = get_json("https://web.archive.org/cdx/search/cdx", 40, params={"url": url + ("/*" if whole else ""), "output": "json", "fl": "timestamp,original,statuscode,mimetype",
                                                                                  "collapse": "digest" if not whole else "urlkey", "limit": 20000})[1:]
    except Exception as e:
        log(f"Index complet indisponible ({type(e).__name__}) : je tente la capture la plus proche.", Y)
        try:
            s = get_json("https://archive.org/wayback/available", 20, params={"url": url}).get("archived_snapshots", {}).get("closest")
            if s:
                rows = [[s["timestamp"], s["url"], s.get("status", "200"), "text/html"]]
        except Exception:
            pass
    if not rows:
        con.print(f"[{Y}]Aucune archive trouvée.  Essaie aussi : https://archive.ph/{url}")
        return pause()
    years = {}
    for r in rows:
        years[r[0][:4]] = years.get(r[0][:4], 0) + 1
    mx = max(years.values())
    t = Table(box=box.SIMPLE, title=f"{len(rows)} {'pages archivées' if whole else 'versions différentes'} · {wbd(rows[0][0])} → {wbd(rows[-1][0])}")
    t.add_column("Année")
    t.add_column("Nombre", justify="right")
    t.add_column("")
    for y in sorted(years):
        t.add_row(y, str(years[y]), f"[{G}]{'█' * max(1, int(years[y] / mx * 40))}")
    con.print(t)
    if whole:
        pages = sorted({r[1].split("?")[0] for r in rows})
        interesting = [u for u in pages if re.search(r"contact|about|equipe|team|mentions|legal|admin|login|wp-|backup|\.(pdf|docx?|xlsx?|zip|sql|bak|txt|csv)$", u, re.I)]
        con.print(f"[{P}]Pages intéressantes ({len(interesting)}) :")
        for u in interesting[:40]:
            con.print(f"  [{B}]https://web.archive.org/web/*/{escape(u)}")
        f = OUT / f"archives_{re.sub(r'[^A-Za-z0-9]', '_', url)[:40]}_{stamp()}.txt"
        f.write_text("\n".join(pages), encoding="utf-8")
        log(f"Liste complète des {len(pages)} pages : {f}", G)
    else:
        items = [{"label": f"{wbd(r[0])}  {r[0][8:10]}:{r[0][10:12]}", "desc": f"HTTP {r[2]}", "value": f"https://web.archive.org/web/{r[0]}/{r[1]}"} for r in rows]
        con.print(f"[{M}]Choisis une version pour l'ouvrir dans le navigateur.")
        while True:
            v = select("Versions archivées", items + [{"label": "← Retour", "value": None}], echo=False)
            if not v:
                break
            webbrowser.open(v)
    add_report("Archives web", url, f"{len(rows)} entrées · {', '.join(f'{y}: {n}' for y, n in sorted(years.items()))}")
    pause()


# ------------------------------------------------------------ 📨 EN-TÊTES D'EMAIL (phishing)
PRIV_IP = re.compile(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80|fc|fd)")


def mail_domain(v):
    m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", v or "")
    return m.group(1).lower() if m else ""


def mod_headers():
    con.rule(f"[{G}]📨 ANALYSE D'EN-TÊTES D'EMAIL (anti-phishing)")
    con.print(f"[{M}]Gmail : ⋮ → « Afficher l'original » · Outlook : … → Afficher → « Afficher la source du message ». Enregistre en .eml ou copie tout.\n")
    src = select("Source", [{"label": "📂 Fichier .eml / .txt", "value": "f"}, {"label": "📋 Coller les en-têtes", "value": "p"}, {"label": "← Retour", "value": None}])
    if not src:
        return
    if src == "f":
        p = Path(clean_path(Prompt.ask(f"[{G}]Fichier")))
        if not p.is_file():
            con.print(f"[{R}]Fichier introuvable.")
            return pause()
        raw = p.read_bytes().decode("utf-8", "replace")
    else:
        con.print(f"[{M}]Colle les en-têtes puis appuie 2 fois sur Entrée (ligne vide).")
        lines = []
        while True:
            try:
                ln = input()
            except EOFError:
                break
            if not ln.strip() and lines:
                break
            lines.append(ln)
        raw = "\n".join(lines)
    from email.parser import HeaderParser
    from email.utils import parsedate_to_datetime
    msg = HeaderParser().parsestr(raw)
    if not msg.keys():
        con.print(f"[{R}]Aucun en-tête reconnu.")
        return pause()
    g = lambda k: " ".join(str(msg.get(k, "")).split())
    frm, rpath, reply = g("From"), g("Return-Path"), g("Reply-To")
    t = Table(box=box.ROUNDED, border_style="#2b3158", show_header=False, title="Identité du message")
    for k in ("From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID", "X-Mailer", "User-Agent", "X-Originating-IP", "List-Unsubscribe"):
        if msg.get(k):
            t.add_row(f"[{G}]{k}", escape(g(k)[:150]))
    con.print(t)
    hops = []
    for h in reversed(msg.get_all("Received") or []):
        h = " ".join(str(h).split())
        fr = re.search(r"from\s+(\S+)(?:\s+\(([^)]*)\))?", h)
        by = re.search(r"\bby\s+(\S+)", h)
        ips = [x for x in re.findall(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){4,7})\]?", h, re.I) if not PRIV_IP.match(x)]
        dt = None
        try:
            dt = parsedate_to_datetime(h.rsplit(";", 1)[-1].strip())
        except Exception:
            pass
        hops.append({"from": fr.group(1) if fr else "?", "by": by.group(1) if by else "?", "ip": ips[0] if ips else "", "dt": dt})
    if hops:
        t = Table(box=box.ROUNDED, border_style="#2b3158", title="Trajet du message (du premier serveur au dernier)")
        for c in ("#", "De", "Vers", "IP publique", "Heure", "Délai"):
            t.add_column(c)
        prev = None
        for i, hp in enumerate(hops, 1):
            delay = ""
            if hp["dt"] and prev:
                s = (hp["dt"] - prev).total_seconds()
                delay = f"[{Y if s > 300 else M}]{s:+.0f} s"
            prev = hp["dt"] or prev
            t.add_row(str(i), escape(hp["from"][:40]), escape(hp["by"][:40]), hp["ip"], f"{hp['dt']:%d/%m %H:%M:%S}" if hp["dt"] else "—", delay)
        con.print(t)
    auth = " ".join(g(k) for k in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF")).lower()
    res = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{k}=(\w+)", auth) or (re.search(r"^(\w+)", g("Received-SPF").lower()) if k == "spf" and g("Received-SPF") else None)
        res[k] = m.group(1) if m else "absent"
    alerts = []
    fd, rd, yd = mail_domain(frm), mail_domain(rpath), mail_domain(reply)
    for k, v in res.items():
        if v in ("fail", "softfail", "permerror", "none"):
            alerts.append(f"{k.upper()} = {v} : l'expéditeur n'est pas authentifié")
    if rd and fd and not (rd.endswith(fd.split(".", 1)[-1]) or fd.endswith(rd.split(".", 1)[-1])):
        alerts.append(f"Return-Path ({rd}) ≠ From ({fd})")
    if yd and fd and yd != fd:
        alerts.append(f"Les réponses partent vers un autre domaine : {yd}")
    md = re.search(r"@([^>]+)>", g("Message-ID"))
    if md and fd and fd.split(".")[-2] not in md.group(1):
        alerts.append(f"Message-ID créé par {md.group(1)} (≠ {fd})")
    if re.search(r"[^\x00-\x7f]", frm) or re.search(r"xn--", frm):
        alerts.append("Caractères spéciaux / punycode dans l'expéditeur (faux domaine qui ressemble au vrai ?)")
    ages = []
    for dom in dict.fromkeys(x for x in (fd, rd, yd) if x):
        try:
            ev = get_json(f"https://rdap.org/domain/{'.'.join(dom.split('.')[-3 if re.search(r'\.(co|com|gouv|org|ac)\.[a-z]{2}$', dom) else -2:])}", 12).get("events", [])
            reg = next((e["eventDate"][:10] for e in ev if e.get("eventAction") == "registration"), None)
            if reg:
                days = (datetime.date.today() - datetime.date.fromisoformat(reg)).days
                ages.append(f"{dom} : créé le {reg} ({days} j)")
                if days < 180:
                    alerts.append(f"Domaine très récent : {dom} créé il y a {days} jours")
        except Exception:
            pass
    age = " · ".join(ages)
    origin = next((h["ip"] for h in hops if h["ip"]), g("X-Originating-IP").strip("[]"))
    geo = ""
    if origin:
        gi = ip_info(origin).get("geo") or {}
        geo = f"{origin} · {gi.get('city') or '?'}, {gi.get('country') or '?'} · {gi.get('org') or '?'}"
    col = lambda v: G if v == "pass" else R if v in ("fail", "softfail", "permerror") else Y
    body = "   ".join(f"[{M}]{k.upper()}[/] [{col(v)}]{v}[/]" for k, v in res.items())
    if geo:
        body += f"\n[{M}]Serveur d'origine[/] {escape(geo)}"
    if age:
        body += f"\n[{M}]Âge[/] {escape(age)}"
    body += "\n" + ("\n".join(f"[{R}]⚠ {escape(a)}[/]" for a in alerts) if alerts else f"[{G}]✓ Aucun signal d'usurpation détecté.[/]")
    verdict = "SUSPECT" if len(alerts) >= 2 or any("SPF" in a or "DMARC" in a for a in alerts) else "À SURVEILLER" if alerts else "OK"
    con.print(Panel(body, title=f"[{R if verdict == 'SUSPECT' else Y if alerts else G}]Verdict : {verdict}", border_style=R if verdict == "SUSPECT" else "#00e5ff", title_align="left"))
    add_report("En-têtes email", g("Subject")[:80] or "message", f"De : {frm}\nVerdict : {verdict}\n" + "\n".join(alerts) + (f"\nOrigine : {geo}" if geo else ""))
    if ask_yes("Analyse IA du message ?"):
        ai_print(f"Tu es analyste anti-phishing. En-têtes d'un email reçu :\n{raw[:6000]}\n\nRésultats automatiques : {res}, alertes : {alerts}, origine : {geo}.\n"
                 "En français : 1) verdict (légitime / suspect / phishing) justifié, 2) ce que l'attaquant cherche probablement, 3) que faire. Concis, puces.")
    pause()


# ------------------------------------------------------------ 🧲 EXTRACTEUR D'INDICES
EXTRACT = [
    ("Emails", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("Liens", r"https?://[^\s\"'<>()]+"),
    ("IPv4", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    ("Pseudos @", r"(?<![\w.])@[A-Za-z0-9_.]{3,30}\b"),
    ("Profils réseaux", r"(?:instagram\.com|tiktok\.com/@|twitter\.com|x\.com|facebook\.com|youtube\.com/(?:@|c/|channel/)|t\.me|snapchat\.com/add|linkedin\.com/in|github\.com|twitch\.tv|reddit\.com/u(?:ser)?)/[A-Za-z0-9_.@-]{2,60}"),
    ("Bitcoin", r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    ("Ethereum", r"\b0x[a-fA-F0-9]{40}\b"),
    ("Monero", r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b"),
    ("Google Analytics / Ads", r"\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,8}|AW-\d{6,12}|pub-\d{10,20})\b"),
    ("Hashs (MD5/SHA)", r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b"),
    ("Coordonnées GPS", r"-?\b\d{1,2}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}\b"),
    ("Clés / jetons exposés", r"\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,}|[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})\b"),
]


def iban_ok(s):
    s = s.replace(" ", "")
    try:
        return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1
    except ValueError:
        return False


def extract_iocs(text):
    found = {}
    for name, rx in EXTRACT:
        vals = list(dict.fromkeys(m.group(0).rstrip(".,;:") for m in re.finditer(rx, text)))
        if name == "IBAN":
            vals = [v for v in vals if iban_ok(v)]
        if name == "Emails":
            vals = [v for v in vals if not re.search(r"\.(png|jpe?g|gif|webp|svg)$", v, re.I)]
        if vals:
            found[name] = vals
    if phonenumbers:
        tel = list(dict.fromkeys(phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.INTERNATIONAL) for m in phonenumbers.PhoneNumberMatcher(text, "FR")))
        if tel:
            found["Téléphones"] = tel
    return found


def html_text(h):
    h = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", h)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", h)).replace("&nbsp;", " ").replace("&amp;", "&")


def mod_extract():
    con.rule(f"[{G}]🧲 EXTRACTEUR D'INDICES")
    con.print(f"[{M}]Sort automatiquement d'une page web, d'un fichier ou d'un texte : emails, téléphones, liens, réseaux sociaux, IP, cryptos, IBAN,\nidentifiants Google Analytics (pour relier des sites au même propriétaire), clés exposées, coordonnées GPS…\n")
    src = select("Source", [{"label": "🌐 Page web (URL)", "value": "u"}, {"label": "📂 Fichier (txt, html, pdf, docx, json, csv…)", "value": "f"},
                            {"label": "📋 Coller du texte", "value": "p"}, {"label": "← Retour", "value": None}])
    if not src:
        return
    text, extra, label = "", {}, ""
    if src == "u":
        url = Prompt.ask(f"[{G}]Adresse").strip()
        url = url if url.startswith("http") else "https://" + url
        label = url
        try:
            with con.status(f"[{M}]Téléchargement…"):
                r = get(url, 20)
            h = r.text
        except Exception as e:
            con.print(f"[{R}]Erreur : {escape(str(e))}")
            return pause()
        text = html_text(h)
        for k, v in extract_iocs(h).items():
            if k in ("Emails", "Liens", "Profils réseaux", "Google Analytics / Ads", "Clés / jetons exposés", "Bitcoin", "Ethereum", "IBAN"):
                extra[k] = v
        metas = re.findall(r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', h, re.I)
        for k, v in metas:
            if k.lower() in ("author", "generator", "og:site_name", "twitter:site", "twitter:creator", "google-site-verification", "facebook-domain-verification", "msvalidate.01"):
                extra.setdefault("Méta-données", []).append(f"{k} = {v}")
        com = [c.strip()[:150] for c in re.findall(r"<!--(.*?)-->", h, re.S) if len(c.strip()) > 8]
        if com:
            extra["Commentaires HTML"] = com[:30]
        dom = sorted({x for x in re.findall(r"""(?:src|href)=["']https?://([^/"']+)""", h) if requests.utils.urlparse(url).hostname not in x})
        if dom:
            extra["Domaines externes"] = dom
    elif src == "f":
        p = Path(clean_path(Prompt.ask(f"[{G}]Fichier")))
        if not p.is_file():
            con.print(f"[{R}]Fichier introuvable.")
            return pause()
        label = p.name
        if p.suffix.lower() == ".pdf":
            try:
                from pypdf import PdfReader
                text = "\n".join(pg.extract_text() or "" for pg in PdfReader(str(p)).pages)
            except Exception as e:
                con.print(f"[{R}]PDF illisible : {escape(str(e))}")
                return pause()
        elif p.suffix.lower() in (".docx", ".xlsx", ".pptx", ".odt"):
            import zipfile
            with zipfile.ZipFile(p) as z:
                text = " ".join(html_text(z.read(n).decode("utf-8", "replace")) for n in z.namelist() if n.endswith(".xml"))
        else:
            raw = p.read_bytes().decode("utf-8", "replace")
            text = raw + ("\n" + html_text(raw) if p.suffix.lower() in (".html", ".htm") else "")
    else:
        con.print(f"[{M}]Colle le texte puis tape une ligne « FIN ».")
        lines = []
        while True:
            try:
                ln = input()
            except EOFError:
                break
            if ln.strip().upper() == "FIN":
                break
            lines.append(ln)
        text, label = "\n".join(lines), "texte collé"
    found = extract_iocs(text)
    for k, v in extra.items():
        found[k] = list(dict.fromkeys(found.get(k, []) + v))
    if not found:
        con.print(f"[{Y}]Rien trouvé.")
        return pause()
    for k, vals in found.items():
        con.print(Panel("\n".join(escape(v) for v in vals[:40]) + (f"\n[{M}]… +{len(vals) - 40}[/]" if len(vals) > 40 else ""),
                        title=f"[{G}]{k} ({len(vals)})", border_style="#b388ff" if k.startswith("Clés") else "#2b3158", title_align="left"))
    if "Google Analytics / Ads" in found:
        con.print(f"[{Y}]Astuce : cherche ces identifiants sur https://builtwith.com/relationships ou https://dnslytics.com/reverse-analytics pour trouver les autres sites du même propriétaire.")
    f = OUT / f"indices_{stamp()}.txt"
    f.write_text("\n\n".join(f"## {k}\n" + "\n".join(v) for k, v in found.items()), encoding="utf-8")
    log(f"Enregistré : {f}", G)
    add_report("Extracteur", label[:80], "\n".join(f"{k} ({len(v)}) : {', '.join(v[:8])}" for k, v in found.items()))
    pause()


# ------------------------------------------------------------ 🌐 RÉSEAU : IP, ASN, MAC
def mod_net():
    con.rule(f"[{G}]🌐 RÉSEAU · IP · ASN · MAC")
    while True:
        c = select("Outil réseau", [{"label": "🙋 Mon IP publique (ce que les sites voient de moi)", "value": "me"},
                                    {"label": "🔎 IP → propriétaire, plage, ASN, contact abus", "value": "ip"},
                                    {"label": "🏦 ASN → opérateur et plages d'adresses", "value": "asn"},
                                    {"label": "📟 Adresse MAC → fabricant de l'appareil", "value": "mac"},
                                    {"label": "← Retour", "value": None}])
        if c is None:
            return
        try:
            if c in ("me", "ip"):
                ip = "" if c == "me" else Prompt.ask(f"[{G}]Adresse IP").strip()
                with con.status(f"[{M}]Recherche…"):
                    g = get_json(f"https://ipwho.is/{ip}", 12)
                    ip = g.get("ip", ip)
                    pre = get_json("https://stat.ripe.net/data/prefix-overview/data.json", 15, params={"resource": ip}).get("data", {})
                    ab = get_json("https://stat.ripe.net/data/abuse-contact-finder/data.json", 15, params={"resource": ip}).get("data", {})
                    ptr = dns(".".join(reversed(ip.split("."))) + ".in-addr.arpa", "PTR") if "." in ip else []
                cn = g.get("connection") or {}
                asn = (pre.get("asns") or [{}])[0]
                t = Table(box=box.ROUNDED, border_style="#2b3158", show_header=False, title=f"IP {ip}")
                for k, v in (("Lieu", f"{g.get('city')}, {g.get('region')}, {g.get('country')} {(g.get('flag') or {}).get('emoji', '')}"),
                             ("Opérateur", cn.get("isp") or cn.get("org")), ("ASN", f"AS{asn.get('asn', cn.get('asn'))} · {asn.get('holder', '')}"),
                             ("Plage d'adresses", pre.get("resource")), ("Nom inverse (PTR)", ", ".join(ptr) if ptr else "—"),
                             ("Contact abus", ", ".join(ab.get("abuse_contacts") or []) or "—"), ("Fuseau", (g.get("timezone") or {}).get("id")),
                             ("Position approx.", f"{g.get('latitude')}, {g.get('longitude')} (ville, pas l'adresse)")):
                    t.add_row(f"[{G}]{k}", escape(str(v or "—")))
                con.print(t)
                if c == "me":
                    con.print(f"[{M}]C'est ce que n'importe quel site voit quand tu le visites. Avec un VPN, l'opérateur affiché doit être celui du VPN.")
                add_report("Réseau", ip, f"{g.get('city')}, {g.get('country')} · {cn.get('isp')} · AS{asn.get('asn')} · {pre.get('resource')}")
                sh = ip_info(ip).get("sh") or {}
                if sh.get("ports"):
                    con.print(f"[{Y}]Ports ouverts vus par Shodan : {', '.join(map(str, sh['ports']))}" + (f" · failles : {', '.join(sh.get('vulns', [])[:8])}" if sh.get("vulns") else ""))
            elif c == "asn":
                a = Prompt.ask(f"[{G}]Numéro d'AS (ex. 3215 ou AS3215)").strip().upper().lstrip("AS")
                with con.status(f"[{M}]RIPEstat…"):
                    ov = get_json("https://stat.ripe.net/data/as-overview/data.json", 15, params={"resource": f"AS{a}"}).get("data", {})
                    pf = get_json("https://stat.ripe.net/data/announced-prefixes/data.json", 25, params={"resource": f"AS{a}"}).get("data", {}).get("prefixes", [])
                v4 = [p["prefix"] for p in pf if ":" not in p["prefix"]]
                tot = sum(2 ** (32 - int(p.split("/")[1])) for p in v4)
                con.print(Panel(f"[{G}]AS{a}[/] {escape(ov.get('holder') or '?')}\n[{M}]Plages annoncées[/] {len(pf)} ({len(v4)} IPv4 · ≈ {tot:,} adresses)".replace(",", " ")
                                + "\n" + escape(", ".join(v4[:30])) + (" …" if len(v4) > 30 else ""), border_style="#00e5ff"))
                add_report("ASN", f"AS{a}", f"{ov.get('holder')} · {len(pf)} plages")
            elif c == "mac":
                mac = re.sub(r"[^0-9A-Fa-f]", "", Prompt.ask(f"[{G}]Adresse MAC (ex. FC:FB:FB:01:FA:21)"))
                if len(mac) < 6:
                    con.print(f"[{R}]Adresse MAC invalide.")
                    continue
                first = int(mac[:2], 16)
                rnd = bool(first & 2)
                mac_f = ":".join(mac[i:i + 2] for i in range(0, len(mac), 2)).upper()
                ven = "—"
                if not rnd:
                    r = get(f"https://api.macvendors.com/{mac_f}", 12)
                    ven = r.text.strip() if r.ok else "fabricant inconnu"
                con.print(Panel(f"[{G}]{mac_f}[/]\n[{M}]Fabricant[/] {escape(ven)}\n"
                                + (f"[{Y}]Adresse « aléatoire » (bit local) : typique des téléphones récents qui changent de MAC pour ne pas être pistés.[/]" if rnd else f"[{M}]Adresse d'usine (unique à l'appareil).[/]")
                                + ("\n[{0}]Multicast (groupe d'appareils)[/]".format(Y) if first & 1 else ""), border_style="#00e5ff"))
        except Exception as e:
            con.print(f"[{R}]Erreur : {escape(str(e))}")


# ------------------------------------------------------------ 🔐 DÉCODEUR MULTI-FORMAT
MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M",
         "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",
         "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
         ".-.-.-": ".", "--..--": ",", "..--..": "?", "-.-.--": "!", "-..-.": "/", ".--.-.": "@", "---...": ":", "-...-": "="}
WORDS = set("le la les de des un une et est pas pour que qui dans sur avec ce cette mot passe flag cat exe the and you for this that with is are have not was secret password hello bonjour salut code".split())


def txt_score(s):
    if not s:
        return 0
    pr = sum(c.isprintable() or c in "\n\r\t" for c in s) / len(s)
    al = sum(c.isalnum() or c in " .,'-!?:" for c in s) / len(s)
    w = sum(1 for x in re.findall(r"[a-zà-ÿ]{2,}", s.lower()) if x in WORDS)
    let = [c for c in s.lower() if c.isalpha()]
    vow = sum(c in "aeiouyàâéèêëîïôûù" for c in let) / len(let) if len(let) >= 4 else .4
    return (pr * 2 + al + min(w, 6) * .5 + (1 if re.search(r"[A-Za-z]{4,}", s) else 0) + (2 if re.search(r"flag\{|catexe|\bctf\b", s, re.I) else 0)
            + max(-1.5, 1 - abs(vow - .4) * 5))


def b58dec(s):
    al = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in s:
        n = n * 58 + al.index(c)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + b


def decoders(s):
    import binascii, urllib.parse, html as _h, zlib, gzip, codecs
    t = s.strip()
    out = []

    def add(name, fn):
        try:
            v = fn()
            if isinstance(v, bytes):
                for z in (lambda b: gzip.decompress(b), lambda b: zlib.decompress(b)):
                    try:
                        v = z(v)
                        name += " + décompression"
                        break
                    except Exception:
                        pass
                v = v.decode("utf-8")
            if v and v != t:
                out.append((name, v))
        except Exception:
            pass
    c = re.sub(r"\s", "", t)
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{4,}", c):
        add("Base64", lambda: base64.b64decode(c + "=" * (-len(c) % 4), altchars=b"-_" if re.search(r"[-_]", c) else None, validate=False))
    if re.fullmatch(r"[A-Z2-7=]{8,}", c.upper()) and len(c) >= 8:
        add("Base32", lambda: base64.b32decode(c.upper() + "=" * (-len(c) % 8)))
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{6,}", c):
        add("Base58", lambda: b58dec(c))
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", c.replace("\\x", "").replace("0x", "")) and len(c.replace("\\x", "").replace("0x", "")) % 2 == 0:
        add("Hexadécimal", lambda: binascii.unhexlify(c.replace("\\x", "").replace("0x", "")))
    if re.fullmatch(r"[01\s]{8,}", t):
        bits = re.sub(r"\s", "", t)
        add("Binaire", lambda: bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8)))
    if re.fullmatch(r"(\d{2,3}[\s,;]+)+\d{2,3}", t):
        add("Codes ASCII (décimal)", lambda: "".join(chr(int(x)) for x in re.split(r"[\s,;]+", t)))
    if re.fullmatch(r"([0-7]{3}\s+)+[0-7]{3}", t):
        add("Octal", lambda: "".join(chr(int(x, 8)) for x in t.split()))
    if "%" in t:
        add("URL", lambda: urllib.parse.unquote_plus(t))
    if "&" in t and ";" in t:
        add("Entités HTML", lambda: _h.unescape(t))
    if "\\u" in t or "\\x" in t:
        add("Échappements \\u / \\x", lambda: codecs.decode(t, "unicode_escape"))
    if re.fullmatch(r"[.\-/\s|_]+", t) and ("." in t or "-" in t):
        add("Morse", lambda: " ".join("".join(MORSE.get(ch, "?") for ch in w.split()) for w in re.split(r"\s*[/|]\s*|\s{3,}", t.replace("_", "-"))))
    if t.count(".") == 2 and re.fullmatch(r"[\w-]+\.[\w-]+\.[\w-]*", c):
        jw = lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)).decode()
        add("JWT (jeton web)", lambda: f"en-tête : {jw(c.split('.')[0])}\ncontenu : {jw(c.split('.')[1])}")
    if "=" in t and re.search(r"=[0-9A-F]{2}", t):
        import quopri
        add("Quoted-printable", lambda: quopri.decodestring(t.encode()))
    if re.search(r"[A-Za-z]", t):
        rots = sorted(((txt_score("".join(chr((ord(ch) - (65 if ch.isupper() else 97) + k) % 26 + (65 if ch.isupper() else 97)) if ch.isascii() and ch.isalpha() else ch for ch in t)), k) for k in range(1, 26)), reverse=True)
        for sc, k in rots[:2]:
            v = "".join(chr((ord(ch) - (65 if ch.isupper() else 97) + k) % 26 + (65 if ch.isupper() else 97)) if ch.isascii() and ch.isalpha() else ch for ch in t)
            out.append((f"César / ROT{k}" + (" (ROT13)" if k == 13 else ""), v))
        out.append(("Atbash", "".join(chr(155 - ord(ch)) if "A" <= ch <= "Z" else chr(219 - ord(ch)) if "a" <= ch <= "z" else ch for ch in t)))
    out.append(("À l'envers", t[::-1]))
    return out


def magic_decode(s, depth=3):
    res, seen = [], {s}
    front = [([], s)]
    for _ in range(depth):
        nxt = []
        for path, v in front:
            for name, w in decoders(v):
                if w in seen or len(w) > 20000:
                    continue
                seen.add(w)
                p = path + [name]
                res.append((txt_score(w) - .15 * len(p), " → ".join(p), w))
                if not name.startswith(("César", "Atbash", "À l'envers")):
                    nxt.append((p, w))
        front = nxt[:30]
    return sorted(res, reverse=True)


def mod_decode():
    con.rule(f"[{G}]🔐 DÉCODEUR MULTI-FORMAT (mode « magique »)")
    con.print(f"[{M}]Base64, Base32, Base58, hexa, binaire, ASCII, octal, URL, HTML, \\u, Morse, JWT, quoted-printable, César/ROT13, Atbash, à l'envers…\n"
              "Le mode magique essaie tout, même les encodages empilés (base64 dans de l'hexa…), et classe les résultats lisibles en premier.\n")
    while True:
        c = select("Décodeur", [{"label": "🪄 Décoder automatiquement", "value": "d"}, {"label": "🔒 Encoder un texte", "value": "e"}, {"label": "← Retour", "value": None}])
        if c is None:
            return
        s = Prompt.ask(f"[{G}]Texte")
        if not s.strip():
            continue
        if c == "e":
            import urllib.parse
            enc = [("Base64", base64.b64encode(s.encode()).decode()), ("Base32", base64.b32encode(s.encode()).decode()), ("Hexadécimal", s.encode().hex()),
                   ("Binaire", " ".join(f"{b:08b}" for b in s.encode())), ("URL", urllib.parse.quote(s)), ("ROT13", s.translate(str.maketrans(
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))),
                   ("Morse", " / ".join(" ".join({v: k for k, v in MORSE.items()}.get(ch, "?") for ch in w) for w in s.upper().split())), ("À l'envers", s[::-1])]
            t = Table(box=box.ROUNDED, border_style="#2b3158")
            t.add_column("Format")
            t.add_column("Résultat")
            for k, v in enc:
                t.add_row(f"[{G}]{k}", escape(v))
            con.print(t)
            continue
        with con.status(f"[{M}]Décodage…"):
            res = magic_decode(s)
        if not res:
            con.print(f"[{Y}]Rien de décodable trouvé.")
            continue
        t = Table(box=box.ROUNDED, border_style="#2b3158", title="Résultats (les plus lisibles en premier)")
        t.add_column("#", justify="right")
        t.add_column("Chaîne de décodage")
        t.add_column("Résultat")
        for i, (sc, path, v) in enumerate(res[:10], 1):
            t.add_row(str(i), f"[{G if i == 1 else M}]{escape(path)}", escape(v[:300]))
        con.print(t)
        add_report("Décodeur", s[:60], f"{res[0][1]} → {res[0][2][:300]}")


# ------------------------------------------------------------ 🔢 HASH & FICHIER SUSPECT
MAGIC = [(b"%PDF", "PDF", ".pdf"), (b"\x89PNG", "image PNG", ".png"), (b"\xff\xd8\xff", "image JPEG", ".jpg .jpeg"), (b"GIF8", "image GIF", ".gif"),
         (b"PK\x03\x04", "archive ZIP (ou docx/xlsx/apk/jar)", ".zip .docx .xlsx .pptx .apk .jar .odt"), (b"Rar!", "archive RAR", ".rar"),
         (b"7z\xbc\xaf", "archive 7-Zip", ".7z"), (b"MZ", "PROGRAMME Windows (.exe/.dll)", ".exe .dll .scr .sys .com"), (b"\x7fELF", "programme Linux", ""),
         (b"\xca\xfe\xba\xbe", "programme macOS / Java", ".class"), (b"\xd0\xcf\x11\xe0", "ancien Office (doc/xls/msi)", ".doc .xls .ppt .msi .msg"),
         (b"{\\rtf", "document RTF", ".rtf"), (b"RIFF", "média RIFF (wav/avi/webp)", ".wav .avi .webp"), (b"ID3", "audio MP3", ".mp3"),
         (b"\x1f\x8b", "archive GZIP", ".gz .tgz"), (b"OggS", "média OGG", ".ogg .opus"), (b"#!", "script", ".sh .py"), (b"L\x00\x00\x00", "raccourci Windows", ".lnk")]
HASH_TYPES = [(r"\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}", "bcrypt (mot de passe, lent = solide)"), (r"\$argon2(id|i|d)\$.+", "Argon2 (mot de passe, très solide)"),
              (r"\$6\$.+", "SHA-512 crypt (Linux)"), (r"\$5\$.+", "SHA-256 crypt (Linux)"), (r"\$1\$.+", "MD5 crypt (ancien Linux)"), (r"\$y\$.+", "yescrypt (Linux récent)"),
              (r"[a-fA-F0-9]{32}", "MD5 ou NTLM (Windows)"), (r"[a-fA-F0-9]{40}", "SHA-1"), (r"[a-fA-F0-9]{56}", "SHA-224"), (r"[a-fA-F0-9]{64}", "SHA-256"),
              (r"[a-fA-F0-9]{96}", "SHA-384"), (r"[a-fA-F0-9]{128}", "SHA-512"), (r"[a-fA-F0-9]{8}", "CRC32")]


def mod_hash():
    con.rule(f"[{G}]🔢 HASH & FICHIER SUSPECT")
    while True:
        c = select("Hash", [{"label": "📂 Analyser un fichier (empreintes, vrai type, réputation)", "value": "f"},
                            {"label": "🔎 Identifier / rechercher un hash", "value": "h"}, {"label": "← Retour", "value": None}])
        if c is None:
            return
        if c == "f":
            p = Path(clean_path(Prompt.ask(f"[{G}]Fichier")))
            if not p.is_file():
                con.print(f"[{R}]Fichier introuvable.")
                continue
            hs = {k: hashlib.new(k) for k in ("md5", "sha1", "sha256", "sha512")}
            with open(p, "rb") as fh:
                head = fh.read(4096)
                for hh in hs.values():
                    hh.update(head)
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    for hh in hs.values():
                        hh.update(chunk)
            kind = next(((n, ext) for sig, n, ext in MAGIC if head.startswith(sig)), None)
            if not kind and head[4:8] == b"ftyp":
                kind = ("image HEIC/AVIF", ".heic .heif .avif") if head[8:12] in (b"heic", b"heix", b"mif1", b"avif") else ("vidéo/audio MP4-MOV", ".mp4 .mov .m4a .m4v .3gp")
            if not kind and head.startswith(b"\x1aE\xdf\xa3"):
                kind = ("vidéo WebM/MKV", ".webm .mkv")
            if not kind:
                kind = ("texte", "") if all(32 <= b < 127 or b in (9, 10, 13) or b >= 0xC2 for b in head[:512]) else ("inconnu", "")
            ext = p.suffix.lower()
            fake = bool(kind[1]) and ext and ext not in kind[1].split() and not (kind[0].startswith("archive ZIP") and ext in (".zip", ".docx", ".xlsx", ".pptx", ".apk", ".jar", ".odt", ".ods", ".epub"))
            t = Table(box=box.ROUNDED, border_style="#2b3158", show_header=False, title=escape(p.name))
            t.add_row(f"[{G}]Taille", f"{p.stat().st_size:,} octets".replace(",", " "))
            t.add_row(f"[{G}]Vrai type", ("[{0}]".format(R) if fake or "PROGRAMME" in kind[0] else "") + kind[0])
            for k, hh in hs.items():
                t.add_row(f"[{G}]{k.upper()}", hh.hexdigest())
            con.print(t)
            if fake:
                con.print(f"[{R}]⚠ Extension trompeuse : le fichier s'appelle « {ext} » mais c'est en réalité : {kind[0]}. Ne l'ouvre pas.")
            if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|bat|cmd|js|vbs|lnk|hta)$", p.name, re.I):
                con.print(f"[{R}]⚠ Double extension : technique classique pour déguiser un programme.")
            sha = hs["sha256"].hexdigest()
            try:
                with con.status(f"[{M}]Base CIRCL (fichiers connus et sains)…"):
                    r = get(f"https://hashlookup.circl.lu/lookup/sha256/{sha}", 12)
                con.print(f"[{G}]✓ Fichier connu et répertorié : {escape(r.json().get('FileName', '') or r.json().get('ProductName', '') or 'base NSRL')}" if r.status_code == 200
                          else f"[{M}]Fichier absent de la base des logiciels connus (normal pour un document perso).")
            except Exception:
                pass
            con.print(f"[{B}]VirusTotal[/] https://www.virustotal.com/gui/file/{sha}\n[{B}]MalwareBazaar[/] https://bazaar.abuse.ch/browse.php?search=sha256%3A{sha}"
                      f"\n[{B}]Hybrid Analysis[/] https://www.hybrid-analysis.com/search?query={sha}")
            add_report("Fichier", p.name, f"type : {kind[0]}{' (extension trompeuse !)' if fake else ''}\nSHA-256 : {sha}")
            if ask_yes("Ouvrir le résultat VirusTotal ?"):
                webbrowser.open(f"https://www.virustotal.com/gui/file/{sha}")
        else:
            h = Prompt.ask(f"[{G}]Hash").strip()
            typ = [n for rx, n in HASH_TYPES if re.fullmatch(rx, h)]
            con.print(f"[{G}]Type probable :[/] {', '.join(typ) or 'inconnu'}")
            if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", h):
                algo = {32: "md5", 40: "sha1", 64: "sha256"}[len(h)]
                try:
                    r = get(f"https://hashlookup.circl.lu/lookup/{algo}/{h}", 12)
                    if r.status_code == 200:
                        j = r.json()
                        con.print(f"[{G}]Fichier connu :[/] {escape(str(j.get('FileName') or j.get('ProductName') or j))[:200]}")
                    else:
                        con.print(f"[{M}]Inconnu de la base CIRCL.")
                except Exception:
                    pass
                con.print(f"[{B}]VirusTotal[/] https://www.virustotal.com/gui/search/{h}")
            if typ and ("MD5" in typ[0] or "SHA" in typ[0]):
                con.print(f"[{M}]Si c'est l'empreinte d'un mot de passe : un MD5/SHA-1 sans « sel » se casse en quelques secondes avec des tables (crackstation.net).")


def pdf_fonts():
    cands = [("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"), ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
             ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf"), ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf")]
    return next(((a, b) for a, b in cands if Path(a).exists() and Path(b).exists()), None)


def report_pdf(syn, path):
    """Rapport PDF (lisible sur téléphone). Renvoie le chemin ou None si fpdf2 manque."""
    try:
        from fpdf import FPDF
    except ImportError:
        return None
    fonts = pdf_fonts()

    def clean(s):
        s = re.sub(r"\[/?[^\]\[]*\]", "", str(s)) if False else str(s)
        s = "".join(ch for ch in s if ord(ch) <= 0xFFFF and not 0x2600 <= ord(ch) <= 0x27BF and not 0xFE00 <= ord(ch) <= 0xFE0F)
        return s if fonts else s.encode("latin-1", "replace").decode("latin-1")

    class PDF(FPDF):
        def footer(self):
            self.set_y(-12)
            self.set_font(F, "", 8)
            self.set_text_color(125, 143, 155)
            self.cell(0, 6, clean(f"Cat.exe OSINT v{VERSION} · page {self.page_no()}"), align="C")

    pdf = PDF(format="A4")
    if fonts:
        pdf.add_font("A", "", fonts[0])
        pdf.add_font("A", "B", fonts[1])
        F = "A"
    else:
        F = "Helvetica"
    pdf.set_auto_page_break(True, 16)
    pdf.set_margins(14, 14, 14)
    pdf.add_page()
    pdf.set_fill_color(7, 9, 11)
    pdf.rect(0, 0, 210, 34, "F")
    pdf.set_xy(14, 9)
    pdf.set_font(F, "B", 20)
    pdf.set_text_color(60, 255, 143)
    pdf.cell(0, 9, "CAT.EXE // RAPPORT OSINT", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(F, "", 9)
    pdf.set_text_color(160, 175, 185)
    pdf.cell(0, 6, clean(f"{datetime.datetime.now():%d/%m/%Y %H:%M} · {len(REPORT)} élément(s)"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(42)

    def block(tag, title, when, text, col=(255, 61, 139)):
        pdf.set_font(F, "B", 11)
        pdf.set_text_color(*col)
        pdf.multi_cell(0, 6, clean(f"[{tag}] ") + clean(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(60, 255, 143)
        pdf.set_line_width(.5)
        pdf.line(14, pdf.get_y(), 196, pdf.get_y())
        if when:
            pdf.set_font(F, "", 8)
            pdf.set_text_color(125, 143, 155)
            pdf.cell(0, 5, when, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(F, "", 9.5)
        pdf.set_text_color(25, 30, 35)
        pdf.multi_cell(0, 5, clean(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
    if syn:
        block("IA", "Synthèse globale", "", syn, (20, 150, 80))
    for r in REPORT:
        block(r["mod"], r["title"], r["t"], r["text"])
    pdf.output(str(path))
    return path


def mod_report():
    con.rule(f"[{G}]📄 RAPPORT DE SESSION")
    if not REPORT:
        con.print(f"[{M}]Rien pour l'instant : lance une analyse d'abord.")
        return pause()
    for r in REPORT:
        con.print(Panel(escape(r["text"]), title=f"[{G}][{r['mod']}] {escape(r['title'])}", subtitle=r["t"], border_style="#2b3158", title_align="left"))
    syn = None
    if ask_yes("Synthèse IA globale ?"):
        txt = "\n\n".join(f"=== [{r['mod']}] {r['title']} ===\n{r['text']}" for r in REPORT)
        syn = ai_print(f"Tu es analyste OSINT. Voici toutes les trouvailles de mon audit :\n{txt[:12000]}\n\nFais en français une synthèse globale : niveau d'exposition, liens entre les éléments, 5 actions prioritaires. Concis.", "Synthèse")
    fmt = select("Format du rapport", [{"label": "📕 PDF (lisible partout, iPhone compris)", "value": "pdf"}, {"label": "🌐 Page web (HTML)", "value": "html"},
                                       {"label": "📕 + 🌐 Les deux", "value": "both"}, {"label": "← Retour", "value": None}], default="pdf")
    if not fmt:
        return
    if fmt in ("pdf", "both"):
        f = OUT / f"rapport_{stamp()}.pdf"
        try:
            ok = report_pdf(syn, f)
        except Exception as e:
            ok = None
            con.print(f"[{R}]PDF impossible : {escape(str(e))}")
        if ok:
            log(f"Rapport PDF : {f}", G)
            open_file(f)
        elif ok is None and not getattr(sys, "frozen", False):
            con.print(f"[{Y}]Module PDF absent : pip install fpdf2 (LANCER.bat l'installe tout seul).")
    if fmt in ("html", "both"):
        f = OUT / f"rapport_{stamp()}.html"
        body = (f"<section class='ia'><h2>Synthèse IA</h2><pre>{escape_html(syn)}</pre></section>" if syn else "") + "".join(
            f"<section><h2><span>{escape_html(r['mod'])}</span>{escape_html(r['title'])}</h2><div class='m'>{r['t']}</div><pre>{escape_html(r['text'])}</pre></section>" for r in REPORT)
        f.write_text(f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rapport OSINT Cat.exe</title><style>
:root{{--bg:#07081a;--p:#0e1028;--l:#2b3158;--t:#e4e9ff;--m:#7480a8;--g:#00e5ff;--k:#b388ff}}*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--t);font-family:system-ui,-apple-system,sans-serif}}header{{padding:28px 20px;border-bottom:1px solid var(--l);background:linear-gradient(120deg,#0b1630,#07081a 60%)}}
h1{{margin:0;font:800 26px monospace;color:var(--g);letter-spacing:1px}}.m{{color:var(--m);font-size:12px;font-family:monospace}}main{{max-width:920px;margin:auto;padding:16px}}
section{{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:14px 16px;margin:14px 0}}section.ia{{border-color:#4a3fa0}}
h2{{font-size:15px;margin:0 0 4px}}h2 span{{background:var(--k);color:#fff;font:700 11px monospace;padding:2px 7px;border-radius:5px;margin-right:8px}}
pre{{white-space:pre-wrap;font:12.5px/1.55 ui-monospace,monospace;margin:8px 0 0}}a{{color:#8a8cff}}@media print{{body{{background:#fff;color:#111}}section{{background:#fff}}}}</style></head>
<body><header><h1>CAT.EXE // RAPPORT OSINT</h1><div class="m">{datetime.datetime.now():%d/%m/%Y %H:%M} · {len(REPORT)} élément(s)</div></header><main>{body}</main></body></html>""", encoding="utf-8")
        log(f"Rapport HTML : {f}", G)
        open_file(f)
    pause()


# ============================================================ 🎓 APPRENDRE À CODER
# Cours hors ligne (Python) + prof IA illimité pour tous les langages (leçons mises en cache dans « cours/ »),
# exercices corrigés (exécution locale + correction IA), parcours « crée ton propre outil OSINT ».
COURS_DIR = BASE / "cours"
LEARN_PROG = BASE / "progression_cours.json"
LEARN_LANGS = [
    ("python", "Python", "🐍", "le langage de Cat.exe : OSINT, IA, automatisation", ".py"),
    ("javascript", "JavaScript", "🟨", "sites web interactifs, extensions, Node.js", ".js"),
    ("html", "HTML & CSS", "🎨", "créer des pages et des sites web", ".html"),
    ("typescript", "TypeScript", "🔷", "JavaScript avec des types, pour les gros projets", ".ts"),
    ("php", "PHP", "🐘", "sites dynamiques, WordPress", ".php"),
    ("sql", "SQL", "💽", "bases de données : chercher, trier, croiser", ".sql"),
    ("bash", "Bash (Linux)", "🐧", "terminal Linux, scripts, Kali", ".sh"),
    ("powershell", "PowerShell", "💠", "automatiser Windows", ".ps1"),
    ("batch", "Batch (.bat)", "🪟", "petits scripts Windows comme LANCER.bat", ".bat"),
    ("c", "C", "🔧", "bas niveau, mémoire, systèmes", ".c"),
    ("cpp", "C++", "⚡", "jeux, logiciels rapides", ".cpp"),
    ("csharp", "C#", "🎮", "Windows, jeux Unity", ".cs"),
    ("java", "Java", "☕", "applis, Android, Minecraft (mods)", ".java"),
    ("kotlin", "Kotlin", "🤖", "applis Android modernes", ".kt"),
    ("swift", "Swift", "🍎", "applis iPhone et Mac", ".swift"),
    ("go", "Go", "🐹", "outils réseau rapides (comme beaucoup d'outils de sécu)", ".go"),
    ("rust", "Rust", "🦀", "rapide et sûr, outils système", ".rs"),
    ("ruby", "Ruby", "💎", "scripts, web (Rails), Metasploit", ".rb"),
    ("lua", "Lua", "🌙", "scripts de jeux (Roblox, Garry's Mod)", ".lua"),
    ("dart", "Dart / Flutter", "🎯", "une appli pour iPhone + Android d'un coup", ".dart"),
    ("r", "R", "📊", "statistiques et graphiques", ".r"),
    ("regex", "Regex", "🔣", "trouver des motifs dans du texte (emails, IP…)", ".txt"),
    ("git", "Git & GitHub", "🌱", "sauvegarder et partager son code", ".txt"),
]
CHAPTERS = [
    ("bases", "Installer et premier programme", "installer les outils, écrire et lancer un premier programme"),
    ("variables", "Variables et types", "nombres, textes, booléens, conversions, affichage"),
    ("conditions", "Conditions", "if / else, comparaisons, et / ou"),
    ("boucles", "Boucles", "for, while, parcourir, compter, arrêter une boucle"),
    ("fonctions", "Fonctions", "créer des fonctions, paramètres, valeurs de retour"),
    ("listes", "Listes et dictionnaires", "stocker plusieurs valeurs, clés/valeurs, parcourir"),
    ("fichiers", "Fichiers", "lire et écrire des fichiers texte, JSON, CSV"),
    ("erreurs", "Gérer les erreurs", "exceptions, try/except, messages clairs"),
    ("modules", "Modules et paquets", "importer, installer des bibliothèques, organiser son code"),
    ("web", "Le web : requêtes et API", "télécharger une page, appeler une API JSON"),
    ("regex", "Expressions régulières", "trouver emails, numéros, IP dans du texte"),
    ("objets", "Classes et objets", "programmation orientée objet"),
    ("projet", "Mini-projet OSINT", "un vérificateur de pseudo sur plusieurs sites"),
]

PY_LESSONS = {
"bases": """# Installer et premier programme
**Python** est le langage de Cat.exe : simple à lire, et parfait pour l'OSINT, l'automatisation et l'IA.

## Installer
- Windows : `winget install Python.Python.3.11` (ou python.org, coche **Add to PATH**).
- Vérifie dans un terminal : `python --version`
- Éditeur conseillé : **VS Code** + l'extension Python.

## Premier programme
Crée un fichier `salut.py` :
```python
print("Salut, je suis Cat.exe !")
nom = input("Ton pseudo : ")
print("Bienvenue", nom)
```
Lance-le : `python salut.py`

## À retenir
- `print()` affiche, `input()` demande quelque chose à l'utilisateur.
- Python lit le fichier **de haut en bas**, ligne par ligne.
- Les commentaires commencent par `#` : Python les ignore.
""",
"variables": """# Variables et types
Une **variable** est une boîte avec un nom, dans laquelle on range une valeur.
```python
pseudo = "cat.3xe"      # texte (str)
abonnes = 1500          # nombre entier (int)
note = 4.5              # nombre à virgule (float)
verifie = True          # booléen (True / False)
```
## Opérations
```python
total = abonnes + 200
print(total * 2, total / 3, total // 3, total % 3)   # multiplier, diviser, division entière, reste
```
## Textes
```python
print(pseudo.upper())            # CAT.3XE
print(len(pseudo))               # 7 caractères
print(f"{pseudo} a {abonnes} abonnés")   # f-string : la façon moderne d'assembler du texte
```
## Convertir
`input()` renvoie toujours du **texte** :
```python
age = int(input("Âge : "))   # texte → nombre
print(str(age) + " ans")     # nombre → texte
```
**Piège classique** : `"5" + 3` plante. Il faut convertir d'abord.
""",
"conditions": """# Conditions
Faire des choix avec `if`, `elif`, `else`. **L'indentation (4 espaces) est obligatoire.**
```python
score = int(input("Score : "))
if score >= 2900:
    print("Maître Cat.exe 👑")
elif score >= 1000:
    print("Chat de garde")
else:
    print("Chaton")
```
## Comparaisons
`==` égal · `!=` différent · `<` `>` `<=` `>=` · `in` (contient)
```python
mail = "test@gmail.com"
if "@" in mail and mail.endswith(".com"):
    print("ça ressemble à un email")
if not mail:
    print("vide")
```
- `and` : les deux doivent être vrais · `or` : au moins un · `not` : l'inverse.
""",
"boucles": """# Boucles
## for : répéter pour chaque élément
```python
sites = ["github.com", "reddit.com", "twitch.tv"]
for site in sites:
    print("Je teste", site)

for i in range(5):        # 0, 1, 2, 3, 4
    print(i)
```
## while : répéter tant qu'une condition est vraie
```python
essais = 0
while essais < 3:
    mdp = input("Mot de passe : ")
    if mdp == "chat":
        print("Accès autorisé")
        break             # sortir de la boucle
    essais += 1
else:
    print("Bloqué !")    # exécuté si la boucle n'a pas fait break
```
- `continue` passe directement au tour suivant.
- `enumerate(liste)` donne la position **et** l'élément : `for i, s in enumerate(sites):`
""",
"fonctions": """# Fonctions
Une fonction = un morceau de code réutilisable, avec un nom.
```python
def saluer(pseudo, emoji="🐱"):
    return f"Salut {pseudo} {emoji}"

print(saluer("cat.3xe"))
print(saluer("neo", "🕶"))
```
- `def` crée la fonction, les **paramètres** sont entre parenthèses.
- `return` renvoie un résultat (sinon la fonction renvoie `None`).
- Un paramètre peut avoir une **valeur par défaut** (`emoji="🐱"`).

## Exemple OSINT
```python
def est_email(texte):
    return "@" in texte and "." in texte.split("@")[-1]

for t in ["a@b.fr", "pas un mail", "x@y"]:
    print(t, "→", est_email(t))
```
**Règle d'or** : une fonction = une seule tâche, avec un nom clair.
""",
"listes": """# Listes et dictionnaires
## Listes : plusieurs valeurs dans l'ordre
```python
pseudos = ["cat", "neo", "trinity"]
pseudos.append("morpheus")     # ajouter
print(pseudos[0], pseudos[-1]) # premier, dernier
print(len(pseudos))
pseudos.remove("neo")
print(sorted(pseudos))
courts = [p for p in pseudos if len(p) <= 4]   # liste en compréhension
```
## Dictionnaires : des clés → des valeurs
```python
compte = {"pseudo": "cat.3xe", "site": "Instagram", "abonnes": 1500}
print(compte["pseudo"])
compte["verifie"] = True
for cle, valeur in compte.items():
    print(cle, "=", valeur)
print(compte.get("bio", "pas de bio"))   # valeur par défaut si la clé manque
```
C'est exactement le format **JSON** que renvoient les API du web.
""",
"fichiers": """# Fichiers
Toujours avec `with` : le fichier se ferme tout seul.
```python
# écrire
with open("resultats.txt", "w", encoding="utf-8") as f:
    f.write("github : trouvé\\n")

# lire ligne par ligne
with open("resultats.txt", encoding="utf-8") as f:
    for ligne in f:
        print(ligne.strip())
```
## JSON (sauvegarder des données)
```python
import json
data = {"pseudo": "cat", "comptes": ["github", "twitch"]}
with open("data.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
data2 = json.load(open("data.json", encoding="utf-8"))
```
## CSV (tableur)
```python
import csv
with open("comptes.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["site", "statut"])
    w.writerow(["github", "trouvé"])
```
""",
"erreurs": """# Gérer les erreurs
Sans protection, une erreur arrête tout le programme. `try / except` l'attrape :
```python
try:
    age = int(input("Âge : "))
except ValueError:
    print("Ce n'est pas un nombre !")
else:
    print("OK", age)
finally:
    print("fini")   # toujours exécuté
```
## Erreurs réseau (très courant en OSINT)
```python
import requests
try:
    r = requests.get("https://site-qui-existe-pas.xyz", timeout=5)
except requests.RequestException as e:
    print("Site injoignable :", type(e).__name__)
```
- Attrape des erreurs **précises** (`ValueError`, `KeyError`…), pas tout en vrac.
- Lis toujours le message d'erreur : la **dernière ligne** dit le type et la cause.
""",
"modules": """# Modules et paquets
Un **module** = un fichier Python qu'on importe. Python en a des centaines inclus :
```python
import random, datetime, os
print(random.choice(["pile", "face"]))
print(datetime.datetime.now().strftime("%d/%m/%Y %H:%M"))
print(os.listdir("."))
```
## Installer des bibliothèques (pip)
```
pip install requests rich pillow
```
- `requests` : le web · `rich` : de belles couleurs dans le terminal · `pillow` : les images.
## Ton propre module
`outils.py` :
```python
def crier(t):
    return t.upper() + " !"
```
`main.py` :
```python
from outils import crier
print(crier("salut"))
```
## Le point d'entrée
```python
if __name__ == "__main__":
    main()   # ne s'exécute que si on lance CE fichier
```
""",
"web": """# Le web : requêtes et API
C'est le cœur de l'OSINT : interroger des sites et des **API** (des adresses qui renvoient du JSON).
```python
import requests
r = requests.get("https://ipwho.is/8.8.8.8", timeout=10)
print(r.status_code)        # 200 = OK, 404 = introuvable
info = r.json()             # JSON → dictionnaire Python
print(info["country"], info["city"], info["connection"]["isp"])
```
## Paramètres et en-têtes
```python
r = requests.get("https://api.github.com/users/torvalds",
                 headers={"User-Agent": "MonOutil/1.0"}, timeout=10)
u = r.json()
print(u["name"], u["public_repos"], u["created_at"])
```
## Les codes HTTP
`200` OK · `301/302` redirection · `403` interdit · `404` introuvable · `429` trop de requêtes (ralentis !) · `500` erreur du serveur.

**Éthique** : respecte les sites (pas de spam de requêtes) et n'enquête que sur toi ou avec accord.
""",
"regex": """# Expressions régulières (regex)
Une **regex** décrit un motif de texte. Indispensable pour extraire des infos.
```python
import re
texte = "Contact : jean@exemple.fr ou admin@site.com, IP 192.168.1.10"
emails = re.findall(r"[\\w.+-]+@[\\w-]+\\.[\\w.]+", texte)
ips = re.findall(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", texte)
print(emails, ips)
```
## Les briques
| Motif | Signifie |
|---|---|
| `\\d` | un chiffre |
| `\\w` | lettre, chiffre ou _ |
| `\\s` | espace |
| `.` | n'importe quel caractère |
| `+` `*` `?` | 1 ou plus · 0 ou plus · 0 ou 1 |
| `{2,4}` | entre 2 et 4 fois |
| `[abc]` | a, b ou c |
| `^` `$` | début · fin |
| `( )` | groupe à récupérer |

```python
m = re.search(r"(\\d{2})/(\\d{2})/(\\d{4})", "né le 14/07/2001")
print(m.group(3))   # 2001
```
Teste tes regex sur **regex101.com**.
""",
"objets": """# Classes et objets
Une **classe** est un plan ; un **objet** est une chose construite avec ce plan.
```python
class Compte:
    def __init__(self, site, pseudo):
        self.site = site
        self.pseudo = pseudo
        self.trouve = False

    def url(self):
        return f"https://{self.site}/{self.pseudo}"

    def __str__(self):
        return f"{self.site}: {'✓' if self.trouve else '✗'}"

c = Compte("github.com", "torvalds")
c.trouve = True
print(c.url())
print(c)
```
- `__init__` s'exécute à la création, `self` = l'objet lui-même.
- **Héritage** : `class CompteGitHub(Compte):` reprend tout et peut modifier des méthodes.
""",
"projet": """# Mini-projet OSINT : vérificateur de pseudo
On combine tout : fonctions, boucles, dictionnaires, web, erreurs et threads.
```python
import requests, concurrent.futures as cf

SITES = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}/about.json",
    "Chess.com": "https://api.chess.com/pub/player/{}",
    "Lichess": "https://lichess.org/api/user/{}",
}

def tester(site, url, pseudo):
    try:
        r = requests.get(url.format(pseudo), timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        return site, "trouvé" if r.status_code == 200 else "absent" if r.status_code == 404 else f"? ({r.status_code})"
    except requests.RequestException:
        return site, "erreur"

pseudo = input("Pseudo : ").strip()
with cf.ThreadPoolExecutor(8) as ex:          # 8 tests en même temps
    for site, statut in ex.map(lambda kv: tester(kv[0], kv[1], pseudo), SITES.items()):
        print(f"{site:<10} {statut}")
```
## Améliore-le
1. Ajoute 5 sites.
2. Enregistre les résultats dans un fichier JSON.
3. Affiche un tableau en couleurs avec `rich`.
4. Ajoute les variantes du pseudo (`_` ↔ `.`).
""",
}

PROJECT = [
    ("menu", "Un menu stylé avec rich", "menu.py", """Le terminal peut être beau : la bibliothèque **rich** gère couleurs, tableaux et panneaux (c'est elle qu'utilise Cat.exe).
`pip install rich`""", '''from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

con = Console()
con.print(Panel("[bold #00e5ff]MON OUTIL OSINT[/]\\n[#7480a8]v1.0 · fait maison", border_style="#b388ff"))
t = Table(title="Menu")
t.add_column("N°", style="bold #00e5ff")
t.add_column("Module")
for i, m in enumerate(["Pseudo", "Mon IP", "GPS d'une photo", "Carte"], 1):
    t.add_row(str(i), m)
con.print(t)
choix = Prompt.ask("Ton choix", choices=["1", "2", "3", "4"])
con.print(f"[bold]Tu as choisi le module {choix}[/] 🐱")
'''),
    ("api", "Interroger une API : où est cette IP ?", "ip.py", """Une **API** répond en JSON. Ici on localise une adresse IP (ou la tienne si tu laisses vide) avec ipwho.is, gratuit et sans clé.""", '''import requests

ip = input("Adresse IP (Entrée = la mienne) : ").strip()
r = requests.get(f"https://ipwho.is/{ip}", timeout=10)
d = r.json()
if not d.get("success", True):
    print("Erreur :", d.get("message"))
else:
    print(f"IP        : {d['ip']}")
    print(f"Lieu      : {d['city']}, {d['region']}, {d['country']} {d['flag']['emoji']}")
    print(f"Opérateur : {d['connection']['isp']}")
    print(f"Carte     : https://www.google.com/maps?q={d['latitude']},{d['longitude']}")
'''),
    ("pseudo", "Chercher un pseudo sur plusieurs sites", "pseudo.py", """Le principe des outils comme Sherlock : on teste l'adresse du profil sur chaque site. Code **200** = le compte existe, **404** = non.
Avec des *threads*, tous les sites sont testés en même temps.""", '''import requests, concurrent.futures as cf

SITES = {
    "GitHub": "https://api.github.com/users/{}",
    "GitLab": "https://gitlab.com/api/v4/users?username={}",
    "Chess.com": "https://api.chess.com/pub/player/{}",
    "Lichess": "https://lichess.org/api/user/{}",
    "Scratch": "https://api.scratch.mit.edu/users/{}",
    "Keybase": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}",
}

def test(item, pseudo):
    site, url = item
    try:
        r = requests.get(url.format(pseudo), timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        ok = r.status_code == 200 and r.text not in ("[]", "") and '"them":[null]' not in r.text
        return site, ok
    except requests.RequestException:
        return site, None

pseudo = input("Pseudo : ").strip()
with cf.ThreadPoolExecutor(10) as ex:
    for site, ok in ex.map(lambda it: test(it, pseudo), SITES.items()):
        print(f"{'✅' if ok else '❌' if ok is False else '⚠'}  {site}")
'''),
    ("exif", "Lire le GPS caché d'une photo", "gps_photo.py", """Les photos de téléphone contiennent souvent leur **position GPS** dans les métadonnées EXIF. On les lit avec Pillow (`pip install pillow`).""", '''from PIL import Image

def dms(v, ref):
    d, m, s = (float(x) for x in v)
    r = d + m / 60 + s / 3600
    return -r if ref in ("S", "W") else r

chemin = input("Photo (glisse-la ici) : ").strip().strip('"')
exif = Image.open(chemin).getexif()
print("Appareil :", exif.get(271), exif.get(272))
print("Date     :", exif.get(306))
gps = exif.get_ifd(0x8825)
if gps and 2 in gps:
    lat, lon = dms(gps[2], gps[1]), dms(gps[4], gps[3])
    print(f"GPS      : {lat:.6f}, {lon:.6f}")
    print(f"Carte    : https://www.google.com/maps?q={lat},{lon}")
else:
    print("Pas de GPS dans cette photo (ou supprimé par le réseau social).")
'''),
    ("carte", "Afficher des points sur une carte", "carte.py", """On génère une page HTML avec **Leaflet** (bibliothèque de cartes) et on l'ouvre dans le navigateur. Fond Esri : marche même en ouvrant le fichier en local (sans clé, sans « Referer »).""", '''import json, webbrowser, pathlib

points = [
    {"nom": "Tour Eiffel", "lat": 48.8584, "lon": 2.2945},
    {"nom": "Notre-Dame", "lat": 48.8530, "lon": 2.3499},
    {"nom": "Sacré-Cœur", "lat": 48.8867, "lon": 2.3431},
]
html = """<!doctype html><html><head><meta charset="utf-8"><title>Ma carte</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<style>html,body,#m{height:100%;margin:0}</style></head><body><div id="m"></div><script>
const P = __POINTS__;
const map = L.map('m');
L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}', {attribution: '© Esri, OpenStreetMap'}).addTo(map);
const g = L.featureGroup(P.map(p => L.marker([p.lat, p.lon]).bindPopup(p.nom))).addTo(map);
map.fitBounds(g.getBounds(), {padding: [40, 40]});
</script></body></html>""".replace("__POINTS__", json.dumps(points))
f = pathlib.Path("ma_carte.html")
f.write_text(html, encoding="utf-8")
webbrowser.open(f.resolve().as_uri())
print("Carte ouverte :", f.resolve())
'''),
    ("fleches", "Un menu aux flèches (comme Cat.exe)", "menu_fleches.py", """Lire les touches du clavier une par une : `msvcrt` sur Windows, `termios` sur Mac/Linux. Le menu se redessine à chaque appui.""", '''import os, sys

def touche():
    if os.name == "nt":
        import msvcrt
        c = msvcrt.getwch()
        if c in ("\\x00", "\\xe0"):
            return {"H": "haut", "P": "bas"}.get(msvcrt.getwch(), "")
        return "entree" if c == "\\r" else c
    import termios, tty
    fd = sys.stdin.fileno(); old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        c = sys.stdin.read(1)
        if c == "\\x1b":
            return {"[A": "haut", "[B": "bas"}.get(sys.stdin.read(2), "")
        return "entree" if c in ("\\r", "\\n") else c
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

options = ["Chercher un pseudo", "Mon IP", "GPS d'une photo", "Quitter"]
pos = 0
while True:
    os.system("cls" if os.name == "nt" else "clear")
    print("=== MON OUTIL ===  (↑ ↓ puis Entrée)\\n")
    for i, o in enumerate(options):
        print(("\\033[30;42m ❯ " if i == pos else "   ") + o + "\\033[0m")
    k = touche()
    if k == "haut": pos = (pos - 1) % len(options)
    elif k == "bas": pos = (pos + 1) % len(options)
    elif k == "entree":
        print("\\nTu as choisi :", options[pos])
        break
'''),
    ("exe", "Transformer ton outil en .exe", "creer_exe.bat", """**PyInstaller** emballe ton script + Python dans un seul `.exe`, lançable sur n'importe quel PC Windows sans rien installer.
Lance ce .bat dans le dossier de ton script (remplace `menu.py` par ton fichier).""", '''@echo off
cd /d "%~dp0"
python -m pip install -q pyinstaller rich requests pillow
python -m PyInstaller --noconfirm --onefile --console --name MonOutil menu.py
echo.
echo Ton .exe est dans le dossier dist\\MonOutil.exe
pause
'''),
]


def learn_prog():
    try:
        return json.loads(LEARN_PROG.read_text(encoding="utf-8"))
    except Exception:
        return {}


def learn_save(p):
    try:
        LEARN_PROG.write_text(json.dumps(p, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception:
        pass


def show_md(title, md, sub=""):
    from rich.markdown import Markdown
    con.clear()
    con.print(Panel(Text.assemble((tr(title), "bold #00e5ff"), ("\n" + tr(sub) if sub else "", M)), border_style="#b388ff", box=box.HEAVY))
    con.print(Markdown(md, code_theme="monokai", hyperlinks=False))
    con.print()


def ai_lesson(key, prompt, force=False):
    """Leçon générée par l'IA puis gardée dans cours/ (relire = gratuit et hors ligne)."""
    f = COURS_DIR / (re.sub(r"[^A-Za-z0-9_-]+", "_", key)[:90] + f"_{LANG['code']}.md")
    if f.exists() and not force:
        return f.read_text(encoding="utf-8")
    with con.status(f"[{P}]Le prof IA prépare ta leçon…", spinner="dots12"):
        try:
            t = ask_ai(prompt)
        except Exception as e:
            con.print(f"[{R}]IA indisponible : {escape(str(e))}\n[{M}]Change de moteur dans Réglages, ou réessaie dans un moment.")
            return None
    COURS_DIR.mkdir(exist_ok=True)
    f.write_text(t, encoding="utf-8")
    return t


TEACH = ("Tu es un excellent prof de programmation pour un ado/jeune adulte qui débute et adore la cybersécurité / l'OSINT (chaîne Cat.exe). "
         "Écris en Markdown, ton direct et motivant, phrases courtes. Structure : titre, explication simple, exemples de code COMPLETS et CORRECTS "
         "dans des blocs ```, pièges fréquents, puis un mini-exercice (sans la solution). Les exemples doivent tourner tels quels. "
         "Reste éthique : OSINT uniquement sur soi ou avec accord. ")


def lang_info(code):
    return next(x for x in LEARN_LANGS if x[0] == code)


def lesson_text(code, ch, again=False):
    if code == "python" and ch[0] in PY_LESSONS and not again and LANG["code"] == "fr":
        return PY_LESSONS[ch[0]]
    name = lang_info(code)[1]
    extra = " Explique-le AUTREMENT que d'habitude, avec d'autres exemples." if again else ""
    return ai_lesson(f"{code}_{ch[0]}" + ("_bis" if again else ""), TEACH + f"Langage : {name}. Chapitre : « {ch[1]} » ({ch[2]}). "
                     f"Si le chapitre ne s'applique pas tel quel à {name}, adapte-le à ce qui existe vraiment dans {name}.{extra}", force=again)


def ask_multiline(label):
    con.print(f"[{M}]{label} — tape une ligne « FIN » pour terminer.")
    out = []
    while True:
        try:
            ln = input()
        except EOFError:
            break
        if ln.strip().upper() == "FIN":
            break
        out.append(ln)
    return "\n".join(out)


def open_editor(path):
    try:
        if os.name == "nt":
            subprocess.Popen(["notepad.exe", str(path)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-t", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def runner(code, path):
    import shutil
    py = sys.executable if not getattr(sys, "frozen", False) else (shutil.which("python") or shutil.which("py"))
    R_ = {"python": [py, "-X", "utf8", str(path)] if py else None, "javascript": ["node", str(path)], "typescript": ["npx", "-y", "tsx", str(path)],
          "bash": ["bash", str(path)], "powershell": ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(path)], "batch": ["cmd", "/c", str(path)],
          "php": ["php", str(path)], "ruby": ["ruby", str(path)], "lua": ["lua", str(path)], "go": ["go", "run", str(path)], "r": ["Rscript", str(path)],
          "dart": ["dart", "run", str(path)], "kotlin": None, "swift": ["swift", str(path)]}.get(code)
    if R_ and R_[0] and (shutil.which(R_[0]) or Path(R_[0]).exists()):
        return R_
    return None


def run_code(code, path, stdin_text=""):
    cmd = runner(code, path)
    if not cmd:
        return None
    try:
        r = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, cwd=str(path.parent))
        return (r.stdout + ("\n" + r.stderr if r.stderr else ""))[-4000:]
    except subprocess.TimeoutExpired:
        return "⏱ Temps dépassé (20 s) : boucle infinie ou programme qui attend une saisie ?"


def write_code(code_lang, name, template=""):
    """Fait écrire du code à l'utilisateur : Bloc-notes (fichier) ou collé dans le terminal."""
    ext = lang_info(code_lang)[4]
    d = BASE / "projets"
    d.mkdir(exist_ok=True)
    f = d / f"{name}{ext}"
    how = select("Où écrire ton code ?", [{"label": "📝 Dans le Bloc-notes (conseillé)", "value": "ed", "desc": str(f)}, {"label": "📋 Le coller ici", "value": "paste"},
                                          {"label": "← Annuler", "value": None}])
    if not how:
        return None, None
    if how == "ed":
        if not f.exists() or not f.read_text(encoding="utf-8").strip():
            f.write_text(template, encoding="utf-8")
        open_editor(f)
        Prompt.ask(f"[{G}]Écris ton code, ENREGISTRE (Ctrl+S), puis appuie sur Entrée ici", default="", show_default=False)
        src = f.read_text(encoding="utf-8", errors="replace")
    else:
        src = ask_multiline("Colle ton code")
        f.write_text(src, encoding="utf-8")
    return src, f


def learn_exercise(code, topic, level):
    name = lang_info(code)[1]
    ex = ai_lesson(f"exo_{code}_{level}_{topic}_{random.randint(0, 99999)}", f"Tu es prof de {name}. Donne UN exercice de programmation en {name}, niveau {level}, sur : {topic}. "
                   "Thème OSINT/cyber/geek si possible. Format Markdown : titre, consigne claire, exemple d'entrée/sortie attendue, 1 indice caché sous un titre « Indice ». "
                   "PAS de solution.")
    if not ex:
        return
    while True:
        show_md(f"🧪 Exercice · {name} · {level}", ex)
        a = select("Exercice", [{"label": "📝 Écrire ma solution", "value": "w"}, {"label": "💡 Voir la solution commentée", "value": "sol"},
                                {"label": "← Retour", "value": None}], echo=False)
        if not a:
            return
        if a == "sol":
            sol = ai_lesson(f"sol_{hashlib.md5(ex.encode()).hexdigest()}", f"Donne la solution commentée en {name} de cet exercice, puis explique-la ligne par ligne :\n{ex}")
            if sol:
                show_md("💡 Solution", sol)
                pause()
            continue
        src, f = write_code(code, f"exo_{code}")
        if not src or not src.strip():
            continue
        out = run_code(code, f)
        if out is not None:
            con.print(Panel(escape(out or "(rien affiché)"), title=f"[{G}]▶ Exécution de ton programme", border_style="#4a3fa0", title_align="left"))
        elif code not in ("html", "sql", "regex", "git"):
            con.print(f"[{M}]Je ne peux pas lancer du {name} ici (compilateur/interpréteur absent) : l'IA corrige en lisant ton code.")
        if code == "html":
            open_file(f)
        cor = None
        with con.status(f"[{P}]Le prof IA corrige…"):
            try:
                cor = ask_ai(f"Tu es prof de {name}, bienveillant mais exigeant. Exercice :\n{ex}\n\nCode de l'élève :\n```\n{src[:6000]}\n```\n"
                             + (f"Sortie réelle à l'exécution :\n```\n{out[:2000]}\n```\n" if out else "")
                             + "Corrige en Markdown : 1) verdict (✅ réussi / ⚠ presque / ❌ à revoir), 2) ce qui est bien, 3) les erreurs avec la ligne et pourquoi, "
                               "4) une version améliorée si utile, 5) une note sur 10. Concis.", task="code")
            except Exception as e:
                con.print(f"[{R}]IA indisponible : {escape(str(e))}")
        if cor:
            from rich.markdown import Markdown
            con.print(Panel(Markdown(cor, code_theme="monokai"), title="[bold #b388ff]Correction", border_style="#b388ff", title_align="left"))
        pause()


def learn_chat(code):
    name = lang_info(code)[1]
    from rich.markdown import Markdown
    con.clear()
    con.rule(f"[{G}]💬 PROF IA · {name}")
    con.print(f"[{M}]Pose n'importe quelle question (colle aussi une erreur ou du code). Entrée vide = retour.\n")
    hist = []
    while True:
        q = Prompt.ask(f"[{P}]toi").strip()
        if not q:
            return
        ctx = "\n".join(f"Élève : {a}\nProf : {b[:800]}" for a, b in hist[-4:])
        with con.status(f"[{P}]Le prof réfléchit…"):
            try:
                t = ask_ai(TEACH + f"Langage étudié : {name}. Réponds à la question de l'élève, avec du code si utile.\n{ctx}\nÉlève : {q}", task="code")
            except Exception as e:
                con.print(f"[{R}]IA indisponible : {escape(str(e))}")
                continue
        hist.append((q, t))
        con.print(Panel(Markdown(t, code_theme="monokai"), title=f"[{G}]prof", border_style="#4a3fa0", title_align="left"))


def md_pdf(title, md, path):
    """Exporte une leçon en PDF (lisible sur téléphone)."""
    from fpdf import FPDF
    fonts = pdf_fonts()
    mono = next((p for p in ("C:/Windows/Fonts/consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/System/Library/Fonts/Menlo.ttc") if Path(p).exists()), None)
    clean = lambda s: "".join(ch for ch in s if ord(ch) <= 0xFFFF and not 0x2600 <= ord(ch) <= 0x27BF and not 0xFE00 <= ord(ch) <= 0xFE0F) if fonts else s.encode("latin-1", "replace").decode("latin-1")
    pdf = FPDF(format="A4")
    if fonts:
        pdf.add_font("A", "", fonts[0])
        pdf.add_font("A", "B", fonts[1])
    F = "A" if fonts else "Helvetica"
    FM = F
    if mono and fonts and not mono.endswith(".ttc"):
        pdf.add_font("M", "", mono)
        FM = "M"
    elif not fonts:
        FM = "Courier"
    pdf.set_margins(14, 14, 14)
    pdf.set_auto_page_break(True, 14)
    pdf.add_page()
    pdf.set_fill_color(7, 9, 11)
    pdf.rect(0, 0, 210, 26, "F")
    pdf.set_xy(14, 8)
    pdf.set_font(F, "B", 15)
    pdf.set_text_color(60, 255, 143)
    pdf.cell(0, 10, clean(title))
    pdf.set_y(32)
    incode = False
    for ln in md.split("\n"):
        if ln.strip().startswith("```"):
            incode = not incode
            pdf.ln(1)
            continue
        if incode:
            pdf.set_font(FM, "", 8.5)
            pdf.set_fill_color(238, 241, 243)
            pdf.set_text_color(20, 20, 20)
            pdf.multi_cell(0, 4.6, clean(ln) or " ", fill=True, new_x="LMARGIN", new_y="NEXT")
            continue
        t = ln.strip()
        h = re.match(r"(#+)\s*(.*)", t)
        if h:
            pdf.ln(2)
            pdf.set_font(F, "B", {1: 15, 2: 12.5}.get(len(h.group(1)), 11))
            pdf.set_text_color(200, 30, 100)
            pdf.multi_cell(0, 7, clean(h.group(2)), new_x="LMARGIN", new_y="NEXT")
            continue
        t = re.sub(r"\*\*(.+?)\*\*|`([^`]+)`", lambda m: m.group(1) or m.group(2), t)
        t = re.sub(r"^[-*]\s+", "• ", t)
        if t.startswith("|"):
            if set(t) <= set("|-: "):
                continue
            t = "   ".join(c.strip() for c in t.strip("|").split("|"))
        pdf.set_font(F, "", 10)
        pdf.set_text_color(25, 30, 35)
        pdf.multi_cell(0, 5.2, clean(t) or " ", new_x="LMARGIN", new_y="NEXT")
    pdf.output(str(path))
    return path


def lesson_actions(code, title, md, extra=None):
    """Menu sous une leçon. Renvoie l'action choisie."""
    items = (extra or []) + [{"label": "📕 Exporter la leçon en PDF", "value": "pdf"}, {"label": "← Retour", "value": None}]
    while True:
        a = select("Et ensuite ?", items, echo=False)
        if a == "pdf":
            try:
                f = md_pdf(title, md, OUT / f"cours_{re.sub(r'[^A-Za-z0-9]+', '_', title)[:40]}_{stamp()}.pdf")
                log(f"PDF : {f}", G)
                open_file(f)
            except Exception as e:
                con.print(f"[{R}]PDF impossible : {escape(str(e))} (pip install fpdf2)")
            continue
        return a


def learn_course(code):
    name = lang_info(code)[1]
    prog = learn_prog()
    last = None
    while True:
        done = prog.get(code, {})
        con.clear()
        con.rule(f"[{G}]📘 COURS · {name}")
        n = sum(1 for c in CHAPTERS if done.get(c[0]))
        con.print(f"  [{G}]{'█' * int(n / len(CHAPTERS) * 40)}[/][{M}]{'░' * (40 - int(n / len(CHAPTERS) * 40))}[/]  {n}/{len(CHAPTERS)} chapitres\n")
        items = [{"label": f"{'✅' if done.get(c[0]) else '⬜'} {i}. {c[1]}", "desc": c[2], "value": c[0]} for i, c in enumerate(CHAPTERS, 1)]
        items.append({"label": "← Retour", "value": "back"})
        default = last or next((c[0] for c in CHAPTERS if not done.get(c[0])), CHAPTERS[0][0])
        k = select(f"Chapitres · {name}", items, default=default, echo=False, height=con.size.height - 4)
        if k in (None, "back"):
            return
        last = k
        idx = [c[0] for c in CHAPTERS].index(k)
        ch = CHAPTERS[idx]
        again = False
        while True:
            md = lesson_text(code, ch, again)
            if not md:
                pause()
                break
            show_md(f"{lang_info(code)[2]} {name} · {idx + 1}. {ch[1]}", md, f"chapitre {idx + 1}/{len(CHAPTERS)}")
            a = lesson_actions(code, f"{name} · {ch[1]}", md, [
                {"label": "✅ Compris ! Chapitre suivant", "value": "next"}, {"label": "🧪 Un exercice sur ce chapitre", "value": "exo"},
                {"label": "🔁 Réexplique autrement (IA)", "value": "again"}, {"label": "💬 Poser une question au prof", "value": "chat"}])
            if a == "next":
                prog.setdefault(code, {})[ch[0]] = True
                learn_save(prog)
                if idx + 1 < len(CHAPTERS):
                    idx += 1
                    ch = CHAPTERS[idx]
                    last = ch[0]
                    again = False
                    continue
                con.print(f"[{G}]🏆 Cours {name} terminé ! Passe aux sujets libres et aux exercices avancés.")
                pause()
                break
            if a == "exo":
                learn_exercise(code, ch[1] + " (" + ch[2] + ")", "débutant")
                continue
            if a == "again":
                again = True
                continue
            if a == "chat":
                learn_chat(code)
                continue
            break


def learn_lang(code):
    lid, name, ic, desc, ext = lang_info(code)
    last = None
    while True:
        con.clear()
        con.rule(f"[{G}]{ic} {name.upper()}")
        con.print(f"[{M}]{desc}\n")
        c = select(name, [{"label": "📘 Cours pas à pas", "value": "course", "desc": f"{len(CHAPTERS)} chapitres" + (" · hors ligne" if code == "python" else " · générés par l'IA")},
                          {"label": "🧭 Sujet libre (sans limite)", "value": "free", "desc": "n'importe quel thème → une leçon"},
                          {"label": "🧪 Exercice corrigé", "value": "exo", "desc": "débutant · intermédiaire · avancé"},
                          {"label": "💬 Prof IA", "value": "chat", "desc": "questions, erreurs, explications"},
                          {"label": "📖 Aide-mémoire", "value": "cheat", "desc": "l'essentiel sur une page"},
                          {"label": "← Changer de langage", "value": None}], default=last, echo=False)
        if not c:
            return
        last = c
        if c == "course":
            learn_course(code)
        elif c == "free":
            sug = {"python": "scraper une page avec BeautifulSoup", "javascript": "faire une extension Chrome", "bash": "scanner son réseau avec nmap",
                   "html": "un site perso avec un mode sombre", "sql": "les jointures"}.get(code, "les bases")
            t = Prompt.ask(f"[{G}]Sujet [{M}](ex. {sug})", default="", show_default=False).strip()
            if not t:
                continue
            md = ai_lesson(f"{code}_libre_{t}", TEACH + f"Langage : {name}. Sujet demandé : « {t} ». Fais une vraie leçon complète sur ce sujet.")
            if md:
                show_md(f"{ic} {name} · {t}", md)
                a = lesson_actions(code, f"{name} · {t}", md, [{"label": "🧪 Un exercice sur ce sujet", "value": "exo"}, {"label": "💬 Question au prof", "value": "chat"}])
                if a == "exo":
                    learn_exercise(code, t, "débutant")
                elif a == "chat":
                    learn_chat(code)
        elif c == "exo":
            lv = select("Niveau", [{"label": "🟢 Débutant", "value": "débutant"}, {"label": "🟡 Intermédiaire", "value": "intermédiaire"},
                                   {"label": "🔴 Avancé", "value": "avancé"}, {"label": "← Retour", "value": None}])
            if lv:
                t = Prompt.ask(f"[{G}]Thème [{M}](Entrée = au hasard)", default="", show_default=False).strip() or random.choice(
                    ["chaînes de caractères", "listes", "boucles", "fonctions", "fichiers", "un mini-outil OSINT", "dictionnaires", "un petit jeu", "un générateur de mots de passe", "un décodeur"])
                learn_exercise(code, t, lv)
        elif c == "chat":
            learn_chat(code)
        elif c == "cheat":
            md = ai_lesson(f"{code}_aide_memoire", f"Fais un aide-mémoire (cheat sheet) de {name} en Markdown, très dense : syntaxe essentielle en blocs de code courts, "
                           "commandes utiles, pièges. Tient sur 2 pages.")
            if md:
                show_md(f"📖 Aide-mémoire {name}", md)
                lesson_actions(code, f"Aide-mémoire {name}", md)


def learn_project():
    last = None
    prog = learn_prog()
    while True:
        done = prog.get("projet", {})
        con.clear()
        con.rule(f"[{G}]🧰 CRÉE TON PROPRE OUTIL OSINT (Python)")
        con.print(f"[{M}]7 étapes, du menu au .exe. Chaque étape crée un vrai fichier dans le dossier « projets » que tu peux lancer et modifier.\n")
        items = [{"label": f"{'✅' if done.get(s) else '⬜'} {i}. {t}", "value": s, "desc": f} for i, (s, t, f, _, _) in enumerate(PROJECT, 1)]
        items.append({"label": "← Retour", "value": "back"})
        k = select("Étapes", items, default=last or next((p[0] for p in PROJECT if not done.get(p[0])), PROJECT[0][0]), echo=False)
        if k in (None, "back"):
            return
        last = k
        i = [p[0] for p in PROJECT].index(k)
        s, t, fname, expl, codetxt = PROJECT[i]
        lang = "batch" if fname.endswith(".bat") else "python"
        md = f"{expl}\n\n```{'bat' if lang == 'batch' else 'python'}\n{codetxt}```\n"
        d = BASE / "projets"
        while True:
            show_md(f"🧰 Étape {i + 1}/{len(PROJECT)} · {t}", md, f"fichier : projets/{fname}")
            a = lesson_actions("python", t, md, [{"label": "🚀 Créer le fichier et le lancer", "value": "run"}, {"label": "📝 L'ouvrir dans le Bloc-notes pour le modifier", "value": "edit"},
                                                 {"label": "💬 Poser une question sur ce code", "value": "chat"}, {"label": "✅ Étape suivante", "value": "next"}])
            d.mkdir(exist_ok=True)
            f = d / fname
            if a in ("run", "edit") and not f.exists():
                f.write_text(codetxt, encoding="utf-8" if lang == "python" else "cp1252", errors="replace")
            if a == "run":
                if lang == "batch":
                    if os.name == "nt":
                        subprocess.Popen(["cmd", "/c", "start", "", str(f)], cwd=str(d))
                    else:
                        con.print(f"[{Y}]Ce fichier .bat se lance sur Windows.")
                    pause()
                    continue
                import shutil
                py = sys.executable if not getattr(sys, "frozen", False) else (shutil.which("python") or shutil.which("py"))
                if not py:
                    con.print(f"[{Y}]Python n'est pas installé : lance Cat.exe avec LANCER.bat, ou installe Python 3.14.")
                    pause()
                    continue
                con.rule(f"[{G}]▶ python {fname}")
                try:
                    subprocess.run([py, "-X", "utf8", str(f)], cwd=str(d))
                except KeyboardInterrupt:
                    pass
                con.rule(f"[{M}]fin du programme")
                pause()
            elif a == "edit":
                open_editor(f)
                log(f"Fichier : {f}", G)
                pause()
            elif a == "chat":
                learn_chat("python")
            elif a == "next":
                prog.setdefault("projet", {})[s] = True
                learn_save(prog)
                if i + 1 < len(PROJECT):
                    last = PROJECT[i + 1][0]
                break
            else:
                break


def mod_learn():
    last = None
    while True:
        con.clear()
        con.rule(f"[{G}]🎓 APPRENDRE À CODER")
        con.print(f"[{M}]Cours, exercices corrigés et prof IA illimité, dans {len(LEARN_LANGS)} langages. Les leçons générées sont gardées dans le dossier « cours » (relecture hors ligne).\n")
        prog = learn_prog()
        items = [{"label": "🧰 Parcours : crée ton propre outil OSINT", "value": "__proj", "desc": f"Python · {sum(prog.get('projet', {}).values())}/{len(PROJECT)} étapes"},
                 {"header": "── LANGAGES"}]
        for lid, name, ic, desc, ext in LEARN_LANGS:
            n = sum(prog.get(lid, {}).values())
            items.append({"label": f"{ic} {name}", "value": lid, "desc": (f"{n}/{len(CHAPTERS)} ✅ · " if n else "") + desc})
        items.append({"label": "← Retour au menu", "value": "back"})
        k = select("Que veux-tu apprendre ?", items, default=last, echo=False, height=con.size.height - 4)
        if k in (None, "back"):
            return
        last = k
        if k == "__proj":
            learn_project()
        else:
            learn_lang(k)


# ============================================================ MENU PRINCIPAL
# ============================================================ v5 : PAGES + NOUVEAUX MODULES OSINT
import ipaddress, secrets, string, hashlib as _hl
from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _asc

CACHE = BASE / "cache"


def view_pages(title, pages, sub=""):
    """Affiche une liste de « pages » (objets Rich) : n / → suivante, p / ← précédente, Échap / Entrée pour quitter."""
    from rich.console import Group
    pages = [p for p in pages if p is not None]
    if not pages:
        return
    if not ARROWS:
        for p in pages:
            con.print(p)
        return
    i = 0

    def render():
        dots = Text.assemble(*[("●" if k == i else "○", P if k == i else M) for k in range(min(len(pages), 40))], (" …" if len(pages) > 40 else "", M))
        head = Text.assemble((" " + tr(title) + " ", f"bold #050816 on {P.split()[-1]}"), "  ", (f"page {i + 1}/{len(pages)}", "bold #00e5ff"), "  ", dots,
                             ("   " + tr(sub) if sub else "", M))
        foot = Text(" " + tr("n / → page suivante · p / ← page précédente · Échap retour"), style=M)
        return Group(head, pages[i], foot)
    with Live(render(), console=con, auto_refresh=False, transient=True, redirect_stdout=False, redirect_stderr=False) as live:
        while True:
            k = read_key()
            if k == "ctrlc":
                raise KeyboardInterrupt
            if k in ("n", "N", "right", "down", "pgdn", " ", "tab"):
                i = (i + 1) % len(pages)
            elif k in ("p", "P", "left", "up", "pgup"):
                i = (i - 1) % len(pages)
            elif k == "home":
                i = 0
            elif k == "end":
                i = len(pages) - 1
            elif k in ("esc", "enter", "q", "Q"):
                break
            live.update(render(), refresh=True)
    con.print(pages[i])


def table_pages(title, cols, rows, per=None, sub=""):
    """Tableau découpé en pages (n / p pour tourner)."""
    per = per or max(6, con.size.height - 10)
    pages = []
    for k in range(0, max(1, len(rows)), per):
        t = Table(box=box.ROUNDED, border_style="#2b3158", header_style="bold #00e5ff", expand=True)
        for c in cols:
            t.add_column(c, overflow="fold")
        for r in rows[k:k + per]:
            t.add_row(*[x if isinstance(x, Text) else escape(str(x)) for x in r])
        pages.append(t)
    view_pages(title, pages, sub or f"{len(rows)} " + tr("ligne(s)"))


def kv(rows, title=None, color=None):
    t = Table.grid(padding=(0, 2))
    t.add_column(style=M, no_wrap=True)
    t.add_column(style="#e4e9ff", overflow="fold")
    for k, v in rows:
        if v not in (None, "", [], {}):
            t.add_row(tr(k), v if isinstance(v, Text) else escape(str(v)))
    return Panel(t, title=f"[{G}]{escape(title)}" if title else None, title_align="left", border_style=color or "#4a3fa0", box=box.ROUNDED, padding=(1, 2))


def ask_path(q="Glisse le fichier ici (ou colle son chemin / une URL)"):
    p = clean_path(ask_text(q))
    if not p:
        return None
    if p.startswith(("http://", "https://")):
        r = get(p, 30)
        r.raise_for_status()
        if not r.headers.get("content-type", "").startswith(("image/", "video/", "application/pdf", "application/octet-stream")):
            log("Ce lien ouvre une page web, pas directement un fichier : clic droit sur l'image → « Copier l'adresse de l'image ».", Y)
            return None
        ext = {"image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}.get(r.headers.get("content-type", "").split(";")[0], ".jpg")
        f = OUT / f"telecharge_{stamp()}{ext}"
        f.write_bytes(r.content)
        return f
    f = Path(p).expanduser()
    if not f.exists():
        log("Fichier introuvable.", R)
        return None
    return f


def coords_panel(lat, lon, title="Coordonnées"):
    rows = [("Décimal", f"{lat:.6f}, {lon:.6f}"), ("DMS", f"{dms(lat, 'N', 'S')} {dms(lon, 'E', 'O')}")]
    for k, fn in (("UTM", lambda: to_utm(lat, lon)), ("Plus Code", lambda: plus_code(lat, lon)), ("Geohash", lambda: geohash(lat, lon))):
        try:
            rows.append((k, fn()))
        except Exception:
            pass
    try:
        rows.append(("Adresse", place_name(lat, lon, 16)))
    except Exception:
        pass
    rows += [("Google Maps", f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"), ("Street View", f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat:.6f},{lon:.6f}")]
    return kv(rows, title, "#00e5ff")


# ------------------------------------------------------------ IMAGE → COORDONNÉES
IMG_GPS_PROMPT = """Tu es un expert GEOINT (comme les meilleurs joueurs de GeoGuessr). Regarde la photo et estime où elle a été prise.
Indices : panneaux, langue, plaques, marquage au sol, végétation, architecture, poteaux, relief, soleil.
Réponds UNIQUEMENT en JSON : {"lat": nombre, "lon": nombre, "pays": "...", "ville": "...", "confiance": 0-100, "indices": ["...", "..."]}"""


def mod_img2gps():
    con.rule(f"[{G}]📌 IMAGE → COORDONNÉES")
    con.print(f"[{M}]Donne une image : l'outil sort ses coordonnées GPS. 1) GPS caché dans le fichier  2) IA GeoCLIP (locale)  3) IA de vision (locale).")
    f = ask_path()
    if not f:
        return
    try:
        img, info, gps, cam = read_exif(f)
    except Exception:
        log("Ce fichier n'est pas une image lisible (JPG, PNG, HEIC, WebP…).", R)
        return pause()
    found = []
    hypotheses = []
    if gps:
        lat, lon = gps[0], gps[1]
        con.print(Panel("[bold #00e5ff]GPS trouvé dans le fichier[/] : position exacte de l'appareil", border_style=G))
        con.print(coords_panel(lat, lon, "📌 Position exacte (EXIF)"))
        hypotheses.append(GeoHypothesis(lat, lon, "GPS EXIF", source="exif"))
        found.append({"lat": lat, "lon": lon, "label": "<b>GPS EXIF</b><br>position exacte", "c": "#00e5ff", "s": 9})
        add_report("Image → coordonnées", f.name, f"GPS EXIF : {lat:.6f}, {lon:.6f}")
    else:
        con.print(Panel("Pas de GPS dans le fichier (normal pour une image de réseau social) → estimation par IA locale.", border_style=Y))
        if not geoclip_ready() and not getattr(sys, "frozen", False) and ask_yes("Installer l'IA GeoCLIP (locale, ~1 Go, une seule fois) ?"):
            geoclip_install()
        if geoclip_ready():
            with con.status(f"[{P}]GeoCLIP analyse l'image…", spinner="dots12"):
                preds = geoclip_predict(img, 5)
            rows = []
            for n, (a, b, p) in enumerate(preds, 1):
                try:
                    nm = place_name(a, b, 10)
                except Exception:
                    nm = "?"
                rows.append((str(n), f"{a:.5f}, {b:.5f}", nm, f"{p * 100:.0f} %"))
                hypotheses.append(GeoHypothesis(a, b, nm, probability=float(p), source="geoclip", radius_km=150))
                found.append({"lat": a, "lon": b, "label": f"<b>GeoCLIP #{n}</b><br>{escape_html(nm)}<br>{p * 100:.0f} %", "c": "#b388ff"})
            t = Table(title="Positions les plus probables (GeoCLIP)", box=box.ROUNDED, border_style="#2b3158", header_style="bold #00e5ff")
            for c in ("#", "Coordonnées", "Lieu", "Proba"):
                t.add_column(c)
            for r in rows:
                t.add_row(*map(escape, r))
            con.print(t)
            free_geoclip()
            con.print(coords_panel(preds[0][0], preds[0][1], "📌 Meilleure estimation"))
            add_report("Image → coordonnées", f.name, "GeoCLIP : " + " | ".join(f"{r[1]} ({r[2]}, {r[3]})" for r in rows))
        if ollama_models() is not None and ask_yes("Demander aussi à l'IA de vision locale (Ollama) ?", True):
            try:
                with con.status(f"[{P}]L'IA de vision observe l'image… (10 s à 2 min)", spinner="dots12"):
                    txt, eng = ask_vision(IMG_GPS_PROMPT, img_b64(img))
                j = parse_json(txt) or {}
                a, b = float(j["lat"]), float(j["lon"])
                con.print(kv([("Lieu", f"{j.get('ville', '?')}, {j.get('pays', '?')}"), ("Confiance", f"{j.get('confiance', '?')} %"),
                              ("Indices", " · ".join(j.get("indices") or []))], f"🤖 IA de vision ({eng})", P))
                con.print(coords_panel(a, b, "📌 Estimation de l'IA de vision"))
                hypotheses.append(GeoHypothesis(a, b, str(j.get("ville") or j.get("pays") or "IA vision"), probability=float(j.get("confiance", 0)) / 100, source="vision", evidence=tuple(j.get("indices") or []), radius_km=150))
                found.append({"lat": a, "lon": b, "label": f"<b>IA vision</b><br>{escape_html(str(j.get('ville', '')))}", "c": "#ffc861", "icon": "★", "s": 22})
                add_report("Image → coordonnées", f.name, f"IA vision : {a:.5f}, {b:.5f} ({j.get('ville')}, {j.get('pays')})")
            except Exception as e:
                log(f"IA de vision : {e}", Y)
    if hypotheses:
        best = rank_hypotheses(hypotheses)[0]
        con.print(Panel(f"Source principale : {best.source}\nConfiance : {confidence_text(best)}\n{limitation_text(best)}", title="Interprétation prudente", border_style=Y if best.confidence != "high" else G))
    if found:
        if ask_yes("Ouvrir la carte ?", True):
            save_open("image_coords", quick_map(f"Image → coordonnées · {f.name}", found))
        if ask_yes("Lancer la géoloc complète (triangulation, ombres…) sur cette image ?"):
            return mod_geo(str(f))
    else:
        log("Aucune position : installe GeoCLIP (avec LANCER.bat) ou Ollama pour l'estimation par IA.", Y)
    pause()


# ------------------------------------------------------------ IP LOOKUP
_TOR = {}


def tor_exits():
    if "l" not in _TOR:
        try:
            _TOR["l"] = set(get("https://check.torproject.org/torbulkexitlist", 10).text.split())
        except Exception:
            _TOR["l"] = None
    return _TOR["l"]


def mod_iplookup():
    con.rule(f"[{G}]🧭 IP LOOKUP")
    q = ask_text("IP ou domaine (Entrée = ta propre IP)").strip()
    if not q:
        q = get("https://api.ipify.org", 8).text.strip()
        log(f"Ton IP publique : {q}", G)
    ip = q
    if not is_ip(q):
        try:
            ip = socket.gethostbyname(q.split("/")[2] if "://" in q else q)
            log(f"{q} → {ip}", B)
        except Exception:
            log("Domaine introuvable.", R)
            return pause()
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback:
            log("IP privée / locale : elle n'existe que dans un réseau interne, pas de lookup possible.", Y)
            return pause()
    except ValueError:
        log("IP invalide.", R)
        return pause()
    res = {}

    def job(k, fn):
        try:
            res[k] = fn()
        except Exception:
            res[k] = None
    jobs = {"who": lambda: get_json(f"https://ipwho.is/{ip}", 10),
            "api": lambda: get_json(f"http://ip-api.com/json/{ip}?fields=66846719", 10),
            "sdb": lambda: get_json(f"https://internetdb.shodan.io/{ip}", 10),
            "rdns": lambda: socket.gethostbyaddr(ip)[0],
            "tor": lambda: ip in (tor_exits() or set()),
            "abuse": lambda: ", ".join(get_json(f"https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={ip}", 10)["data"].get("abuse_contacts") or []),
            "rev": lambda: [d for d in get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", 12).text.split() if "." in d and "error" not in d.lower()][:200]}
    with con.status(f"[{P}]Interrogation de 7 sources…", spinner="dots12"):
        with _TPE(8) as ex:
            list(ex.map(lambda kv_: job(*kv_), jobs.items()))
    w, a, s = res.get("who") or {}, res.get("api") or {}, res.get("sdb") or {}
    conn = w.get("connection") or {}
    ip_summary = summarize_ip_sources(w, a)
    lat, lon = w.get("latitude") or a.get("lat"), w.get("longitude") or a.get("lon")
    flags = []
    if res.get("tor"):
        flags.append("[bold #ff5c7a]TOR[/]")
    if a.get("proxy"):
        flags.append("[#ffc861]VPN / proxy[/]")
    if a.get("hosting"):
        flags.append("[#ffc861]hébergeur / datacenter[/]")
    if a.get("mobile"):
        flags.append("[#7aa2ff]réseau mobile[/]")
    p1 = kv([("IP", f"{ip}  ({'IPv6' if ':' in ip else 'IPv4'})"), ("Reverse DNS", res.get("rdns") or a.get("reverse")),
             ("Pays estimé", f"{ip_summary.country or ''} ({w.get('country_code') or a.get('countryCode', '')})"), ("Région", w.get("region") or a.get("regionName")),
             ("Ville estimée", f"{ip_summary.city or ''} {w.get('postal') or a.get('zip') or ''}"), ("Précision", f"{ip_summary.precision} · accord {ip_summary.agreement}/{ip_summary.compared_sources} éléments"),
             ("Coordonnées (approx.)", f"{lat}, {lon}" if lat else None),
             ("Fuseau", (w.get("timezone") or {}).get("id") or a.get("timezone")), ("Opérateur (ISP)", conn.get("isp") or a.get("isp")),
             ("Organisation", conn.get("org") or a.get("org")), ("ASN", f"AS{conn.get('asn')}" if conn.get("asn") else a.get("as")),
             ("Domaine opérateur", conn.get("domain")), ("Type", Text.from_markup(" · ".join(flags)) if flags else "connexion classique (box, entreprise…)"),
             ("Contact abus", res.get("abuse"))], f"🧭 {ip}", G)
    pages = [p1]
    if s:
        pages.append(kv([("Ports ouverts", ", ".join(map(str, s.get("ports") or [])) or "aucun vu"), ("Noms d'hôtes", ", ".join(s.get("hostnames") or [])),
                         ("Logiciels (CPE)", "\n".join(s.get("cpes") or [])), ("Failles connues (CVE)", ", ".join((s.get("vulns") or [])[:40])),
                         ("Étiquettes", ", ".join(s.get("tags") or []))], "🔓 Exposition (Shodan InternetDB)", R if s.get("vulns") else "#4a3fa0"))
    if res.get("rev"):
        pages.append(kv([("Sites sur la même IP", "\n".join(res["rev"][:60]) + (f"\n… +{len(res['rev']) - 60}" if len(res["rev"]) > 60 else ""))], f"🌐 Reverse IP · {len(res['rev'])} domaine(s)"))
    pages.append(kv([("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}"), ("Shodan", f"https://www.shodan.io/host/{ip}"), ("Censys", f"https://search.censys.io/hosts/{ip}"),
                     ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip}"), ("GreyNoise", f"https://viz.greynoise.io/ip/{ip}"),
                     ("BGP.tools", f"https://bgp.tools/prefix/{ip}"), ("IPinfo", f"https://ipinfo.io/{ip}")], "🔗 Aller plus loin"))
    view_pages(f"IP LOOKUP · {ip}", pages)
    add_report("IP lookup", ip, f"{w.get('country')} {w.get('city')} · {conn.get('isp') or a.get('isp')} · AS{conn.get('asn')} · ports {s.get('ports') if s else '?'}"
               + (" · TOR" if res.get("tor") else "") + (" · VPN/proxy" if a.get("proxy") else ""))
    con.print(f"[{M}]⚠ {ip_summary.warning}")
    if lat and ask_yes("Ouvrir la carte ?"):
        save_open("ip", quick_map(f"IP {ip}", [{"lat": lat, "lon": lon, "label": f"<b>{ip}</b><br>{escape_html(str(conn.get('isp') or ''))}"}],
                                  circles=[{"lat": lat, "lon": lon, "r": 25000}]))
    pause()


# ------------------------------------------------------------ LOOKUP RÉSEAUX SOCIAUX
def _dt(v, ms=False):
    try:
        if isinstance(v, (int, float)):
            return datetime.datetime.fromtimestamp(v / (1000 if ms else 1), datetime.timezone.utc).strftime("%d/%m/%Y")
        return datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00")).strftime("%d/%m/%Y")
    except Exception:
        return str(v)


def _meta(html, prop):
    m = re.search(r'<meta[^>]+(?:property|name)="%s"[^>]+content="([^"]*)"' % re.escape(prop), html) or \
        re.search(r'<meta[^>]+content="([^"]*)"[^>]+(?:property|name)="%s"' % re.escape(prop), html)
    import html as _h
    return _h.unescape(m.group(1)) if m else None


def sl_github(u):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", u):
        return None
    r = get(f"https://api.github.com/users/{u}", 10)
    if r.status_code == 404:
        return None
    j = r.json()
    if "login" not in j:
        raise RuntimeError("limite GitHub atteinte (60 requêtes / heure) : réessaie plus tard" if r.status_code == 403 else j.get("message", "erreur GitHub"))
    emails, repos = set(), []
    try:
        for e in get_json(f"https://api.github.com/users/{u}/events/public?per_page=100", 10):
            for c in (e.get("payload") or {}).get("commits") or []:
                em = (c.get("author") or {}).get("email", "")
                if em and "noreply" not in em:
                    emails.add(f"{em} ({(c.get('author') or {}).get('name', '')})")
    except Exception:
        pass
    try:
        rs = get_json(f"https://api.github.com/users/{u}/repos?per_page=100&sort=updated", 10)
        repos = [f"{x['name']} ★{x['stargazers_count']}" + (f" ({x['language']})" if x.get("language") else "") for x in sorted(rs, key=lambda x: -x["stargazers_count"])[:8]]
    except Exception:
        pass
    try:
        keys = len([k for k in get(f"https://github.com/{u}.keys", 8).text.splitlines() if k.strip() and k.startswith(("ssh-", "ecdsa-", "sk-"))])
    except Exception:
        keys = "?"
    return {"Nom": j.get("name"), "Bio": j.get("bio"), "Lieu": j.get("location"), "Entreprise": j.get("company"), "Site": j.get("blog"),
            "Email public": j.get("email"), "X / Twitter": j.get("twitter_username"), "Créé le": _dt(j.get("created_at")), "Dernière activité": _dt(j.get("updated_at")),
            "Abonnés / abonnements": f"{j.get('followers')} / {j.get('following')}", "Dépôts publics": j.get("public_repos"),
            "Emails trouvés dans les commits": "\n".join(sorted(emails)) or "aucun", "Meilleurs dépôts": "\n".join(repos), "Clés SSH publiques": keys,
            "_url": j.get("html_url"), "_img": j.get("avatar_url")}


def sl_reddit(u):
    h = {"User-Agent": "catexe-osint/5.0"}
    r = get(f"https://www.reddit.com/user/{u}/about.json", 10, headers=h)
    if r.status_code == 404:
        return None
    if r.status_code in (403, 429) or not r.headers.get("content-type", "").startswith("application/json"):
        raise RuntimeError("Reddit bloque ta connexion pour l'instant (VPN ?) : réessaie plus tard")
    d = r.json().get("data") or {}
    if not d.get("name"):
        return None
    subs, hours = {}, [0] * 24
    try:
        for kind in ("comments", "submitted"):
            for c in get_json(f"https://www.reddit.com/user/{u}/{kind}.json?limit=100", 10, headers=h)["data"]["children"]:
                c = c["data"]
                subs[c.get("subreddit")] = subs.get(c.get("subreddit"), 0) + 1
                hours[datetime.datetime.fromtimestamp(c["created_utc"], datetime.timezone.utc).hour] += 1
    except Exception:
        pass
    act = ""
    if sum(hours):
        quiet = min(range(24), key=lambda h0: sum(hours[(h0 + k) % 24] for k in range(6)))
        mid = (quiet + 3) % 24
        off = (3 - mid + 12) % 24 - 12
        act = "".join(" ▁▂▃▄▅▆▇█"[min(8, round(8 * x / max(hours)))] for x in hours) + f"\n0h UTC → 23h · creux vers {quiet}h-{(quiet + 6) % 24}h UTC → fuseau probable UTC{off:+d} (si sommeil vers 3 h)"
    return {"Nom": d.get("subreddit", {}).get("title"), "Créé le": _dt(d.get("created_utc")), "Karma": f"{d.get('link_karma', 0)} posts · {d.get('comment_karma', 0)} commentaires",
            "Email vérifié": d.get("has_verified_email"), "Modérateur": d.get("is_mod"), "Subreddits favoris": ", ".join(f"r/{k} ({v})" for k, v in sorted(subs.items(), key=lambda x: -x[1])[:12]),
            "Heures d'activité (UTC)": act, "_url": f"https://www.reddit.com/user/{u}"}


def sl_bluesky(u):
    h = u if "." in u else u + ".bsky.social"
    r = get(f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={h}", 10)
    if not r.ok:
        return None
    j = r.json()
    return {"Nom": j.get("displayName"), "Handle": j.get("handle"), "DID": j.get("did"), "Bio": j.get("description"), "Créé le": _dt(j.get("createdAt")),
            "Abonnés / abonnements": f"{j.get('followersCount')} / {j.get('followsCount')}", "Posts": j.get("postsCount"),
            "_url": f"https://bsky.app/profile/{j.get('handle')}", "_img": j.get("avatar")}


def sl_mastodon(u):
    acct = u.lstrip("@")
    hosts = [acct.split("@")[1]] if "@" in acct else ["mastodon.social", "piaille.fr", "mamot.fr", "framapiaf.org", "mastodon.online", "infosec.exchange"]
    name = acct.split("@")[0]
    for hst in hosts:
        try:
            r = get(f"https://{hst}/api/v1/accounts/lookup?acct={name}", 8)
            if r.ok:
                j = r.json()
                return {"Nom": j.get("display_name"), "Compte": f"@{j.get('acct')}@{hst}", "Bio": re.sub("<[^>]+>", " ", j.get("note") or "").strip(),
                        "Créé le": _dt(j.get("created_at")), "Abonnés / abonnements": f"{j.get('followers_count')} / {j.get('following_count')}", "Posts": j.get("statuses_count"),
                        "Dernier post": j.get("last_status_at"), "Liens vérifiés": "\n".join(re.sub("<[^>]+>", "", f["value"]) for f in j.get("fields", []) if f.get("verified_at")),
                        "_url": j.get("url"), "_img": j.get("avatar")}
        except Exception:
            pass
    return None


def sl_steam(u):
    path = f"profiles/{u}" if re.fullmatch(r"7656\d{13}", u) else f"id/{u}"
    x = get(f"https://steamcommunity.com/{path}/?xml=1", 10).text
    if "<steamID64>" not in x:
        return None
    g = lambda t: (re.search(rf"<{t}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{t}>", x, re.S) or [None, None])[1]
    sid = g("steamID64")
    return {"Pseudo actuel": g("steamID"), "SteamID64": sid, "Nom réel": g("realname"), "Lieu": g("location"), "Membre depuis": g("memberSince"),
            "Statut": g("onlineState"), "Profil": g("privacyState"), "Résumé": re.sub("<[^>]+>", " ", g("summary") or "").strip()[:300],
            "Anciens pseudos": f"https://steamhistory.net/id/{sid}", "_url": f"https://steamcommunity.com/profiles/{sid}", "_img": g("avatarFull")}


def sl_youtube(u):
    r = get(f"https://www.youtube.com/@{u.lstrip('@')}", 12, cookies={"CONSENT": "YES+1", "SOCS": "CAI"})
    if r.status_code == 404:
        return None
    h = r.text
    cid = (re.search(r'"(?:channelId|externalId)":"(UC[\w-]{22})"', h) or [None, None])[1]
    if not cid:
        return None
    subs = (re.search(r'"subscriberCountText":\{[^}]*?"simpleText":"([^"]+)"', h) or re.search(r'"content":"([\d,.\s  ]+[kKMm]?\s*(?:abonnés|subscribers))"', h) or [None, None])[1]
    vids = []
    try:
        feed = get(f"https://www.youtube.com/feeds/videos.xml?channel_id={cid}", 10).text
        vids = [f"{d[:10]} · {t}" for t, d in re.findall(r"<entry>.*?<title>(.*?)</title>.*?<published>(.*?)</published>", feed, re.S)[:6]]
    except Exception:
        pass
    return {"Nom": _meta(h, "og:title"), "ID de chaîne": cid, "Abonnés": subs, "Description": (_meta(h, "og:description") or "")[:300],
            "Dernières vidéos": "\n".join(vids), "_url": f"https://www.youtube.com/channel/{cid}", "_img": _meta(h, "og:image")}


def sl_telegram(u):
    h = get(f"https://t.me/{u.lstrip('@')}", 10).text
    if "tgme_page_title" not in h:
        return None
    extra = re.search(r'tgme_page_extra">([^<]+)', h)
    return {"Nom": _meta(h, "og:title"), "Bio": _meta(h, "og:description"), "Type / membres": extra.group(1).strip() if extra else "compte personnel",
            "_url": f"https://t.me/{u.lstrip('@')}", "_img": _meta(h, "og:image")}


def sl_tiktok(u):
    h = get(f"https://www.tiktok.com/@{u.lstrip('@')}", 12).text
    m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', h, re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(1))["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"]
    except Exception:
        return None
    us, st = d.get("user", {}), d.get("stats", {})
    if not us.get("id"):
        return None
    created = us.get("createTime") or (int(us["id"]) >> 32 if str(us.get("id", "")).isdigit() else None)
    return {"Nom": us.get("nickname"), "ID": us.get("id"), "Bio": us.get("signature"), "Créé le (d'après l'ID)": _dt(created) if created else None,
            "Région / langue": f"{us.get('region', '')} {us.get('language', '')}".strip(), "Abonnés / abonnements": f"{st.get('followerCount')} / {st.get('followingCount')}",
            "J'aime": st.get("heartCount"), "Vidéos": st.get("videoCount"), "Compte privé": us.get("privateAccount"), "Vérifié": us.get("verified"),
            "Pseudo modifié le": _dt(us.get("uniqueIdModifyTime")) if us.get("uniqueIdModifyTime") else None,
            "_url": f"https://www.tiktok.com/@{u.lstrip('@')}", "_img": us.get("avatarLarger")}


def sl_instagram(u):
    u = u.lstrip("@")
    try:
        r = get(f"https://www.instagram.com/api/v1/users/web_profile_info/?username={u}", 10, headers={"x-ig-app-id": "936619743392459"})
        us = r.json()["data"]["user"] if r.ok else None
        if us:
            return {"Nom": us.get("full_name"), "ID": us.get("id"), "Bio": us.get("biography"), "Lien": us.get("external_url"),
                    "Abonnés / abonnements": f"{us['edge_followed_by']['count']} / {us['edge_follow']['count']}", "Posts": us["edge_owner_to_timeline_media"]["count"],
                    "Privé": us.get("is_private"), "Vérifié": us.get("is_verified"), "Compte pro": us.get("is_business_account"), "Catégorie": us.get("category_name"),
                    "Email / tél. pro": " ".join(x for x in (us.get("business_email"), us.get("business_phone_number")) if x),
                    "_url": f"https://www.instagram.com/{u}", "_img": us.get("profile_pic_url_hd")}
    except Exception:
        pass
    # plan B : la fiche de partage (celle que voient Google / Twitter)
    h = HTTP.get(f"https://www.instagram.com/{u}/", timeout=10, headers={"User-Agent": "Twitterbot/1.0"}).text
    d = _meta(h, "og:description")
    if d and "Followers" in d:
        m = re.match(r"([\d.,KMk]+) Followers, ([\d.,KMk]+) Following, ([\d.,KMk]+) Posts", d)
        name = (_meta(h, "og:title") or "").split("(@")[0].strip()
        return {"Nom": name or None, "Abonnés / abonnements": f"{m.group(1)} / {m.group(2)}" if m else None, "Posts": m.group(3) if m else None,
                "Bio": (re.search(r'"description":"(.*?)"', h) or [None, None])[1], "_url": f"https://www.instagram.com/{u}", "_img": _meta(h, "og:image")}
    if "Page Not Found" in h or "Page introuvable" in h:
        return None
    raise RuntimeError("Instagram bloque les requêtes sans compte : vérifie à la main")


def sl_chess(u):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", u):
        return None
    r = get(f"https://api.chess.com/pub/player/{u.lower()}", 10)
    if not r.ok:
        return None
    j = r.json()
    st = {}
    try:
        st = get_json(f"https://api.chess.com/pub/player/{u.lower()}/stats", 10)
    except Exception:
        pass
    el = " · ".join(f"{k[6:]} {v['last']['rating']}" for k, v in st.items() if k.startswith("chess_") and "last" in v)
    return {"Nom": j.get("name"), "Pays": (j.get("country") or "").rsplit("/", 1)[-1], "Lieu": j.get("location"), "Créé le": _dt(j.get("joined")),
            "Dernière connexion": _dt(j.get("last_online")), "Elo": el, "Titre": j.get("title"), "_url": j.get("url"), "_img": j.get("avatar")}


def sl_lichess(u):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", u):
        return None
    r = get(f"https://lichess.org/api/user/{u}", 10)
    if not r.ok:
        return None
    j = r.json()
    if j.get("disabled") is None and not j.get("id"):
        return None
    pr = j.get("profile") or {}
    return {"Nom": " ".join(x for x in (pr.get("firstName"), pr.get("lastName")) if x) or pr.get("realName"), "Pays / drapeau": pr.get("flag") or pr.get("country"),
            "Bio": pr.get("bio"), "Liens": pr.get("links"), "Créé le": _dt(j.get("createdAt"), True), "Vu le": _dt(j.get("seenAt"), True),
            "Parties": (j.get("count") or {}).get("all"), "_url": j.get("url")}


def sl_roblox(u):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", u):
        return None
    r = HTTP.post("https://users.roblox.com/v1/usernames/users", json={"usernames": [u], "excludeBannedUsers": False}, timeout=10).json()
    if not r.get("data"):
        return None
    uid = r["data"][0]["id"]
    j = get_json(f"https://users.roblox.com/v1/users/{uid}", 10)
    fr = {}
    try:
        fr = get_json(f"https://friends.roblox.com/v1/users/{uid}/friends/count", 8)
    except Exception:
        pass
    return {"Nom affiché": j.get("displayName"), "ID": uid, "Créé le": _dt(j.get("created")), "Bio": j.get("description"), "Banni": j.get("isBanned"),
            "Amis": fr.get("count"), "Anciens pseudos": f"https://users.roblox.com/v1/users/{uid}/username-history?limit=100",
            "_url": f"https://www.roblox.com/users/{uid}/profile"}


def sl_gitlab(u):
    j = get_json(f"https://gitlab.com/api/v4/users?username={u}", 10)
    if not j:
        return None
    j = j[0]
    return {"Nom": j.get("name"), "ID": j.get("id"), "État": j.get("state"), "_url": j.get("web_url"), "_img": j.get("avatar_url")}


def sl_hn(u):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", u):
        return None
    j = get_json(f"https://hacker-news.firebaseio.com/v0/user/{u}.json", 10)
    if not j:
        return None
    return {"Créé le": _dt(j.get("created")), "Karma": j.get("karma"), "À propos": re.sub("<[^>]+>", " ", j.get("about") or "")[:300],
            "Contributions": len(j.get("submitted") or []), "_url": f"https://news.ycombinator.com/user?id={u}"}


def sl_keybase(u):
    j = get_json(f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", 10)
    them = (j.get("them") or [None])[0]
    if not them:
        return None
    pr = them.get("profile") or {}
    proofs = [f"{p['proof_type']} : {p['nametag']}" for p in (them.get("proofs_summary") or {}).get("all", [])]
    return {"Nom": pr.get("full_name"), "Lieu": pr.get("location"), "Bio": pr.get("bio"), "Comptes prouvés": "\n".join(proofs), "_url": f"https://keybase.io/{u}"}


def sl_linktree(u):
    r = get(f"https://linktr.ee/{u}", 10)
    if r.status_code == 404:
        return None
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text, re.S)
    if not m:
        return None
    try:
        p = json.loads(m.group(1))["props"]["pageProps"]
        acc = p["account"]
    except Exception:
        return None
    links = [f"{l.get('title', '')} → {l.get('url', '')}" for l in p.get("links") or [] if l.get("url")]
    soc = [s.get("url") for s in acc.get("socialLinks") or [] if s.get("url")]
    return {"Nom": acc.get("pageTitle"), "Bio": acc.get("description"), "Liens": "\n".join(links[:25]), "Réseaux liés": "\n".join(soc), "_url": f"https://linktr.ee/{u}"}


def sl_docker(u):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", u):
        return None
    r = get(f"https://hub.docker.com/v2/users/{u}/", 10)
    if not r.ok:
        return None
    j = r.json()
    return {"Nom": j.get("full_name"), "Lieu": j.get("location"), "Entreprise": j.get("company"), "Créé le": _dt(j.get("date_joined")), "_url": f"https://hub.docker.com/u/{u}"}


SOCIAL = [("GitHub", "🐙", sl_github), ("Reddit", "👽", sl_reddit), ("TikTok", "🎵", sl_tiktok), ("Instagram", "📸", sl_instagram), ("YouTube", "📺", sl_youtube),
          ("Bluesky", "🦋", sl_bluesky), ("Mastodon", "🐘", sl_mastodon), ("Telegram", "📮", sl_telegram), ("Steam", "🎮", sl_steam), ("Roblox", "🧱", sl_roblox),
          ("Chess.com", "🏁", sl_chess), ("Lichess", "♞", sl_lichess), ("GitLab", "🦊", sl_gitlab), ("Hacker News", "📰", sl_hn), ("Keybase", "🔑", sl_keybase),
          ("Linktree", "🌳", sl_linktree), ("Docker Hub", "🐳", sl_docker)]


def social_page(name, ico, d):
    rows = [(k, v) for k, v in d.items() if not k.startswith("_")] + [("Profil", d.get("_url")), ("Photo", d.get("_img"))]
    return kv(rows, f"{ico} {name}", G)


def sl_err(e):
    t = str(e)
    if isinstance(e, requests.Timeout):
        return "le site met trop de temps à répondre : réessaie"
    if isinstance(e, requests.ConnectionError):
        return "site injoignable (connexion, VPN ou pare-feu)"
    if "429" in t or "Too Many" in t:
        return "trop de requêtes : attends quelques minutes"
    if isinstance(e, (ValueError, KeyError, TypeError)) and not isinstance(e, RuntimeError):
        return "le site a changé ou bloque les robots : vérifie à la main"
    return t[:90]


def social_scan(u, todo=None):
    todo = todo or SOCIAL
    found, rows = [], []
    with con.status(f"[{P}]Recherche de « {escape(u)} » sur {len(todo)} plateforme(s)…", spinner="dots12"):
        with _TPE(10) as ex:
            fut = {ex.submit(fn, u): (n, ico) for n, ico, fn in todo}
            for f in _asc(fut):
                n, ico = fut[f]
                try:
                    d = f.result()
                    rows.append((f"{ico} {n}", Text("✔ trouvé", style=G) if d else Text("— absent", style=M), (d or {}).get("_url", "") or ""))
                    if d:
                        found.append((n, ico, d))
                except Exception as e:
                    rows.append((f"{ico} {n}", Text("⚠ non vérifié", style=Y), sl_err(e)))
    order = [x[0] for x in SOCIAL]
    found.sort(key=lambda x: order.index(x[0]))
    rows.sort(key=lambda r: order.index(r[0].split(" ", 1)[1]))
    return found, rows


def mod_social():
    con.rule(f"[{G}]👥 LOOKUP RÉSEAUX SOCIAUX")
    items = [{"label": "⚡ Toutes les plateformes", "value": "all", "desc": f"{len(SOCIAL)} en parallèle"}] + \
            [{"label": f"{ico} {n}", "value": n, "desc": "fiche détaillée"} for n, ico, _ in SOCIAL]
    c = select("Plateforme", items)
    if c is None:
        return
    u = ask_text("Pseudo (ou @handle, ou user@instance pour Mastodon)").strip().lstrip("@")
    if not u:
        return
    found, rows = social_scan(u, SOCIAL if c == "all" else [x for x in SOCIAL if x[0] == c])
    t = Table(box=box.ROUNDED, border_style="#2b3158", header_style="bold #00e5ff", expand=True)
    for col in ("Plateforme", "Résultat", "Lien / info"):
        t.add_column(col, overflow="fold")
    for r in rows:
        t.add_row(r[0], r[1], escape(r[2]))
    view_pages(f"LOOKUP · {u}", [t] + [social_page(*x) for x in found], f"{len(found)} profil(s) trouvé(s) · une fiche par page")
    for n, ico, d in found:
        add_report("Réseaux sociaux", f"{n} · {u}", " · ".join(f"{k}: {v}" for k, v in d.items() if not k.startswith("_") and v not in (None, "", "aucun"))[:900])
    if found and ask_yes("Lancer aussi la recherche du pseudo sur 600+ sites (WhatsMyName) ?"):
        return mod_wmn(u)
    pause()


# ------------------------------------------------------------ WHATSMYNAME (600+ sites)
WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"


def wmn_data():
    CACHE.mkdir(exist_ok=True)
    f = CACHE / "wmn-data.json"
    if not f.exists() or time.time() - f.stat().st_mtime > 7 * 86400:
        try:
            with con.status(f"[{P}]Téléchargement de la base WhatsMyName…"):
                r = get(WMN_URL, 30)
                r.raise_for_status()
                f.write_bytes(r.content)
        except Exception as e:
            if not f.exists():
                raise RuntimeError(f"base WhatsMyName injoignable : {e}")
    return json.loads(f.read_text(encoding="utf-8"))["sites"]


def wmn_check(s, u):
    normalized = normalize_username(u)
    encoded = requests.utils.quote(normalized, safe="")
    url = s["uri_check"].replace("{account}", encoded)
    try:
        if s.get("post_body"):
            r = HTTP.post(url, data=s["post_body"].replace("{account}", normalized), headers=s.get("headers") or {}, timeout=8, allow_redirects=True)
        else:
            r = HTTP.get(url, headers=s.get("headers") or {}, timeout=8, allow_redirects=True)
    except Exception:
        return None
    if s.get("name", "").casefold() == "stackoverflow" and "api.stackexchange.com" in url:
        try:
            items = r.json().get("items", [])
            ok = any(str(item.get("display_name", "")).casefold() == normalized.casefold() for item in items)
        except Exception:
            ok = False
        return (s.get("uri_pretty") or url).replace("{account}", normalized) if ok else None
    ok = r.status_code == s.get("e_code") and s.get("e_string", "") in r.text
    if ok and s.get("m_string") and s["m_string"] in r.text:
        ok = False
    return (s.get("uri_pretty") or url).replace("{account}", normalized) if ok else None


def mod_wmn(u=None):
    con.rule(f"[{G}]🌐 PSEUDO SUR 600+ SITES (WhatsMyName)")
    raw_u = u or ask_text("Pseudo")
    u = normalize_username(raw_u)
    if u != raw_u.strip().lstrip("@"):
        con.print(f"[{M}]Pseudo Unicode normalisé :[/] {escape(u)}")
    if not u:
        return
    try:
        sites = [s for s in wmn_data() if s.get("valid") is not False and "nsfw" not in s.get("cat", "").lower()]
    except Exception as e:
        log(str(e), R)
        return pause()
    hits = []
    with Progress(TextColumn(f"[{G}]{escape(u)}"), BarColumn(complete_style="#00e5ff", finished_style="#b388ff"), TaskProgressColumn(),
                  TextColumn("{task.description}"), console=con, transient=True) as pr:
        t = pr.add_task("", total=len(sites))
        with _TPE(48) as ex:
            fut = {ex.submit(wmn_check, s, u): s for s in sites}
            for f in _asc(fut):
                s = fut[f]
                res = f.result()
                if res:
                    hits.append((s["name"], s.get("cat", ""), res))
                pr.update(t, advance=1, description=f"[{P}]{len(hits)} trouvé(s)")
    hits.sort(key=lambda h: (h[1], h[0].lower()))
    log(f"{len(hits)} compte(s) trouvé(s) sur {len(sites)} sites.", G)
    if hits:
        table_pages(f"WHATSMYNAME · {u}", ["Site", "Catégorie", "Lien"], hits)
        add_report("WhatsMyName", u, "\n".join(f"{a} ({b}) : {c}" for a, b, c in hits))
        if ask_yes("Créer une page HTML cliquable ?"):
            rows = "".join(f"<tr><td>{escape_html(a)}</td><td>{escape_html(b)}</td><td><a href='{escape_html(c)}' target=_blank>{escape_html(c)}</a></td></tr>" for a, b, c in hits)
            f = OUT / f"wmn_{u}_{stamp()}.html"
            f.write_text(f"<!doctype html><meta charset=utf-8><title>{escape_html(u)}</title><style>body{{background:#07081a;color:#e4e9ff;font:14px system-ui;padding:20px}}"
                         f"a{{color:#00e5ff}}td{{padding:6px;border-bottom:1px solid #2b3158}}h1{{color:#b388ff;font-family:monospace}}</style>"
                         f"<h1>CAT.exe // {escape_html(u)} · {len(hits)} comptes</h1><table>{rows}</table>", encoding="utf-8")
            open_file(f)
    con.print(f"[{M}]⚠ Un compte au même pseudo n'est pas forcément la même personne : recoupe (photo, bio, liens).")
    pause()




# ------------------------------------------------------------ RECHERCHE DE PERSONNE
def _strip_acc(s):
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn").lower()


def email_perms(first, last, domain):
    f, l = re.sub(r"[^a-z]", "", _strip_acc(first)), re.sub(r"[^a-z\-]", "", _strip_acc(last))
    pats = [f"{f}.{l}", f"{f}{l}", f"{f[:1]}{l}", f"{f[:1]}.{l}", f"{f}_{l}", f"{f}-{l}", f"{l}.{f}", f"{l}{f}", f"{l}{f[:1]}", f"{f}", f"{l}", f"{f}.{l[:1]}", f"{f}{l[:1]}"]
    return list(dict.fromkeys(p + "@" + domain for p in pats if p.strip(".-_")))


def gravatar_hit(e):
    try:
        return get(f"https://gravatar.com/avatar/{_hl.md5(e.encode()).hexdigest()}?d=404", 6).status_code == 200
    except Exception:
        return False


def mod_person():
    con.rule(f"[{G}]🧍 RECHERCHE DE PERSONNE")
    con.print(f"[{M}]À utiliser pour toi-même ou dans un cadre légal (recherche de contact pro, vérification). Pas de harcèlement.")
    first, last = ask_text("Prénom").strip(), ask_text("Nom").strip()
    if not (first and last):
        return
    city = ask_text("Ville (optionnel)").strip()
    dom = ask_text("Domaine d'entreprise pour les emails (optionnel, ex : societe.fr)").strip().lower()
    full = f"{first} {last}"
    doms = [dom] if dom else ["gmail.com", "outlook.fr", "hotmail.fr", "yahoo.fr", "orange.fr", "free.fr", "icloud.com"]
    perms = [e for d in doms for e in email_perms(first, last, d)]
    with con.status(f"[{P}]Test de {len(perms)} adresses possibles (Gravatar)…", spinner="dots12"):
        with _TPE(16) as ex:
            grav = [e for e, ok in zip(perms, ex.map(gravatar_hit, perms)) if ok]
    mx = None
    if dom:
        mx = ", ".join(dns(dom, "MX")[:3]) or "aucun (le domaine ne reçoit pas d'emails)"
    q = f'"{full}"' + (f" {city}" if city else "")
    from urllib.parse import quote_plus as qp
    links = [("Google", f"https://www.google.com/search?q={qp(q)}"), ("LinkedIn", f"https://www.google.com/search?q={qp(q + ' site:linkedin.com/in')}"),
             ("Facebook", f"https://www.facebook.com/search/people/?q={qp(full)}"), ("Instagram", f"https://www.google.com/search?q={qp(q + ' site:instagram.com')}"),
             ("X / Twitter", f"https://x.com/search?q={qp(q)}&f=user"), ("TikTok", f"https://www.tiktok.com/search/user?q={qp(full)}"),
             ("Pages Blanches", f"https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui={qp(full)}&ou={qp(city)}"),
             ("Copains d'avant", f"https://www.google.com/search?q={qp(q + ' site:copainsdavant.linternaute.com')}"),
             ("Dirigeant d'entreprise", f"https://recherche-entreprises.api.gouv.fr/search?q={qp(full)}"),
             ("Documents PDF", f"https://www.google.com/search?q={qp(q + ' filetype:pdf')}"), ("Images", f"https://www.google.com/search?tbm=isch&q={qp(q)}"),
             ("Décès (INSEE)", f"https://deces.matchid.io/search?q={qp(full)}")]
    users = list(dict.fromkeys([_strip_acc(first + last), _strip_acc(first + "." + last), _strip_acc(first + "_" + last), _strip_acc(first[:1] + last), _strip_acc(last + first)]))
    pages = [kv([("Personne", full + (f" · {city}" if city else "")), ("Emails avec Gravatar (existent)", "\n".join(grav) or "aucun"),
                 ("Serveur mail du domaine", mx), ("Pseudos probables", ", ".join(users)), ("Emails possibles", f"{len(perms)} combinaisons (page suivante)")], f"🧍 {full}", G),
             kv([(d, "\n".join(e for e in perms if e.endswith("@" + d))) for d in doms], "📧 Emails possibles"),
             kv(links, "🔎 Recherches prêtes")]
    view_pages(f"PERSONNE · {full}", pages)
    add_report("Recherche de personne", full, f"Gravatar : {', '.join(grav) or 'aucun'} · pseudos : {', '.join(users)}")
    while True:
        c = select("Ouvrir une recherche", [{"label": n, "value": l} for n, l in links] + [{"label": "👥 Tester les pseudos probables sur les réseaux", "value": "soc"}], echo=False)
        if c is None:
            break
        if c == "soc":
            u = select("Pseudo à tester", users)
            if u is not None:
                found, _ = social_scan(users[u])
                view_pages(f"LOOKUP · {users[u]}", [social_page(*x) for x in found] or [kv([("Résultat", "aucun profil trouvé")])])
        else:
            webbrowser.open(c)


# ------------------------------------------------------------ BOÎTE À OUTILS HORS LIGNE
def stego_scan(f):
    data = f.read_bytes()
    out = []
    end = None
    if data[:3] == b"\xff\xd8\xff":
        end = data.rfind(b"\xff\xd9") + 2
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        k = data.find(b"IEND")
        end = k + 8 if k > 0 else None
    if end and end < len(data) - 2:
        extra = data[end:]
        kind = next((n for sig, n in ((b"PK\x03\x04", "archive ZIP"), (b"Rar!", "archive RAR"), (b"%PDF", "PDF"), (b"\x89PNG", "image PNG"), (b"\xff\xd8\xff", "image JPEG"), (b"7z\xbc\xaf", "archive 7z")) if sig in extra[:64]), "données")
        out.append(("Données cachées après l'image", f"{len(extra)} octets ({kind}) → extraites"))
        (OUT / f"cache_{f.stem}_{stamp()}.bin").write_bytes(extra)
    for k in (b"tEXt", b"zTXt", b"iTXt"):
        for m in re.finditer(re.escape(k) + rb"([\x20-\x7e]{1,80})\x00([\x20-\x7e]{1,300})", data):
            out.append((f"Texte PNG ({k.decode()})", f"{m.group(1).decode()} = {m.group(2).decode()}"))
    if Image:
        import numpy as np
        img = Image.open(f).convert("RGB")
        a = np.array(img)
        for name, bits in (("LSB R+G+B", a[..., :3] & 1), ("LSB rouge", a[..., 0:1] & 1)):
            flat = bits.reshape(-1)[:200000]
            by = np.packbits(flat).tobytes()
            txt = re.match(rb"[\x20-\x7e\n\r\t]{6,}", by)
            if txt:
                out.append((f"Message caché ({name})", txt.group(0)[:300].decode("ascii", "ignore")))
        plane = Image.fromarray(((a[..., 0] & 1) * 255).astype("uint8"))
        pf = OUT / f"plan_bits_{f.stem}_{stamp()}.png"
        plane.save(pf)
        out.append(("Plan de bits (à regarder)", str(pf)))
    return out


def mod_toolbox():
    while True:
        con.rule(f"[{G}]🧰 BOÎTE À OUTILS (hors ligne)")
        c = select("Outil", [{"label": "🎨 Stéganographie", "value": "steg", "desc": "message caché dans une image"},
                             {"label": "🔤 Strings", "value": "str", "desc": "texte lisible d'un fichier ou d'un .exe"},
                             {"label": "🧮 Calculateur IP / CIDR", "value": "cidr", "desc": "plage, masque, nombre d'adresses"},
                             {"label": "⌛ Convertisseur de timestamp", "value": "ts", "desc": "Unix, ms, Windows, date → nombre"},
                             {"label": "🔐 Générateur de mot de passe", "value": "pw", "desc": "aléatoire ou phrase de passe"},
                             {"label": "🌐 Coordonnées", "value": "co", "desc": "décimal · DMS · UTM · Plus Code"}])
        if c is None:
            return
        try:
            if c == "steg":
                f = ask_path("Image à analyser")
                if f:
                    r = stego_scan(f)
                    con.print(kv(r or [("Résultat", "rien de suspect trouvé")], f"🎨 {f.name}", P if r else G))
            elif c == "str":
                f = ask_path()
                if f:
                    data = f.read_bytes()[:30_000_000]
                    ss = [m.group(0).decode() for m in re.finditer(rb"[\x20-\x7e]{6,}", data)]
                    ss += [m.group(0).decode("utf-16le") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data)]
                    flt = ask_text("Filtre (Entrée = tout, ex : http)").strip().lower()
                    ss = [s for s in dict.fromkeys(ss) if flt in s.lower()]
                    iocs = extract_iocs("\n".join(ss))
                    if iocs:
                        con.print(kv([(k, "\n".join(sorted(v)[:15])) for k, v in iocs.items() if v], "🧲 Indices trouvés", P))
                    table_pages(f"STRINGS · {f.name}", ["Texte"], [[s[:200]] for s in ss])
            elif c == "cidr":
                n = ipaddress.ip_network(ask_text("Réseau (ex : 192.168.1.0/24 ou 10.0.0.5/255.255.0.0)").strip(), strict=False)
                h = list(n.hosts()) if n.num_addresses <= 65536 else []
                con.print(kv([("Réseau", n.with_prefixlen), ("Masque", n.netmask), ("Joker (wildcard)", n.hostmask), ("Broadcast", n.broadcast_address),
                              ("Première / dernière", f"{h[0]} → {h[-1]}" if h else f"{n[1]} → {n[-2]}"), ("Adresses", f"{n.num_addresses:,}".replace(",", " ")),
                              ("Type", "privé" if n.is_private else "public")], "🧮 CIDR", G))
            elif c == "ts":
                v = ask_text("Nombre ou date (JJ/MM/AAAA HH:MM)").strip()
                if re.fullmatch(r"\d+(\.\d+)?", v):
                    x = float(v)
                    rows = []
                    for nm, div in (("Unix (secondes)", 1), ("Unix (millisecondes)", 1e3), ("Unix (microsecondes)", 1e6)):
                        try:
                            rows.append((nm, fdt(datetime.datetime.fromtimestamp(x / div, datetime.timezone.utc))))
                        except Exception:
                            pass
                    try:
                        rows.append(("Windows FILETIME", fdt(datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=x / 10))))
                    except Exception:
                        pass
                    con.print(kv(rows, f"⌛ {v}", G))
                else:
                    d = datetime.datetime.strptime(v, "%d/%m/%Y %H:%M" if ":" in v else "%d/%m/%Y").replace(tzinfo=datetime.timezone.utc)
                    con.print(kv([("Unix", int(d.timestamp())), ("Unix ms", int(d.timestamp() * 1000))], f"⌛ {v} UTC", G))
            elif c == "pw":
                al = string.ascii_letters + string.digits + "!#$%&*+-=?@_"
                mots = ["chat", "pixel", "nuage", "radar", "tigre", "lune", "orage", "cactus", "piano", "fusee", "glace", "noyau", "dragon", "ombre", "volcan", "marbre", "laser", "rivage", "comete", "zebre"]
                rows = [(f"Aléatoire {n}", "".join(secrets.choice(al) for _ in range(n))) for n in (16, 24, 32)]
                rows.append(("Phrase de passe", "-".join(secrets.choice(mots) for _ in range(5)) + str(secrets.randbelow(100))))
                con.print(kv(rows, "🔐 Mots de passe (générés sur ton PC)", G))
            elif c == "co":
                p = parse_coords(ask_text("Coordonnées (n'importe quel format)"))
                if p:
                    con.print(coords_panel(p[0], p[1]))
                else:
                    log("Format non reconnu.", Y)
        except Exception as e:
            log(f"Erreur : {e}", R)
        pause()


# ============================================================ v6 : OUTILS OSINT / GEOINT SUPPLÉMENTAIRES
from urllib.parse import unquote


# ------------------------------------------------------------ LIEN DE CARTE → COORDONNÉES
def coords_from_link(u):
    """Google Maps, Apple Plans, Waze, OpenStreetMap, Bing, Yandex, Here, liens courts… → (lat, lon, nom du lieu)."""
    u = u.strip()
    if re.match(r"^https?://(maps\.app\.goo\.gl|goo\.gl/maps|g\.co/kgs|maps\.apple|bit\.ly|tinyurl\.com|waze\.com/ul/|yandex\.\w+/maps/-/)", u):
        try:
            r = HTTP.get(u, timeout=12, allow_redirects=True)
            u = r.url
            m = re.search(r'https://www\.google\.[a-z.]+/maps[^"\'\s<>]+', r.text) if "consent." in u else None
            if m:
                u = unquote(m.group(0))
        except Exception:
            pass
    d = unquote(u)
    name = None
    m = re.search(r"/maps/place/([^/@]+)", d)
    if m:
        name = m.group(1).replace("+", " ")
    if "yandex." in d:
        m = re.search(r"[?&]ll=(-?\d+\.\d+),(-?\d+\.\d+)", d)
        if m:
            return float(m.group(2)), float(m.group(1)), name, u
    pats = [(r"!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)", False), (r"@(-?\d+\.\d+),(-?\d+\.\d+)", False), (r"[?&](?:q|query|ll|sll|daddr|destination|center|cp|coordinate)=(-?\d+\.\d+)[,~ ](-?\d+\.\d+)", False),
            (r"[?&]mlat=(-?\d+\.\d+)&mlon=(-?\d+\.\d+)", False), (r"#map=\d+/(-?\d+\.\d+)/(-?\d+\.\d+)", False), (r"[?&]ll=(-?\d+\.\d+),(-?\d+\.\d+).*yandex", True),
            (r"yandex.*[?&]ll=(-?\d+\.\d+)%?2?C?,?(-?\d+\.\d+)", True), (r"here\.com/.*?(-?\d+\.\d+),(-?\d+\.\d+)", False), (r"(-?\d{1,2}\.\d{3,}),\s*(-?\d{1,3}\.\d{3,})", False)]
    for p, swap in pats:
        m = re.search(p, d)
        if m:
            a, b = float(m.group(1)), float(m.group(2))
            if swap:
                a, b = b, a
            if -90 <= a <= 90 and -180 <= b <= 180:
                return a, b, name, u
    if name:
        g = geocode(name)
        if g:
            return g[0], g[1], name, u
    return None


def mod_maplink():
    con.rule(f"[{G}]📎 LIEN DE CARTE → COORDONNÉES")
    con.print(f"[{M}]Colle un lien Google Maps (même court : maps.app.goo.gl/…), Apple Plans, Waze, OpenStreetMap, Bing, Yandex, Here…")
    u = ask_text("Lien").strip()
    if not u:
        return
    with con.status(f"[{P}]Lecture du lien…", spinner="dots12"):
        r = coords_from_link(u)
    if not r:
        log("Pas de coordonnées dans ce lien. Astuce : dans Google Maps, clic droit sur le point → les chiffres en haut sont copiés.", Y)
        return pause()
    lat, lon, name, full = r
    if full != u:
        con.print(f"[{M}]Lien complet : {escape(full[:200])}")
    con.print(coords_panel(lat, lon, f"📌 {name or 'Position du lien'}"))
    con.print(kv([("Google Earth", f"https://earth.google.com/web/@{lat},{lon},300a,800d,35y,0h,0t,0r"), ("OpenStreetMap", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=18/{lat}/{lon}"),
                  ("Bing (vue aérienne)", f"https://www.bing.com/maps?cp={lat}~{lon}&lvl=19&style=a"), ("Yandex (panoramas)", f"https://yandex.com/maps/?ll={lon},{lat}&z=18&l=sat"),
                  ("Apple Plans", f"https://maps.apple.com/?ll={lat},{lon}&z=18"), ("Mapillary (photos de rue)", f"https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=17"),
                  ("Géoportail (IGN)", f"https://www.geoportail.gouv.fr/carte?c={lon},{lat}&z=18&l0=ORTHOIMAGERY.ORTHOPHOTOS::GEOPORTAIL:OGC:WMTS(1)"),
                  ("Peakvisor (montagnes)", f"https://peakvisor.com/panorama.html?lat={lat}&lng={lon}")], "🔗 Ouvrir ailleurs"))
    add_report("Lien de carte", u[:80], f"{lat:.6f}, {lon:.6f} {name or ''}")
    if ask_yes("Ouvrir la carte ?"):
        save_open("lien_carte", quick_map(name or "Lien de carte", [{"lat": lat, "lon": lon, "label": escape_html(name or f"{lat:.5f}, {lon:.5f}")}]))
    pause()


# ------------------------------------------------------------ LOT DE PHOTOS → CARTE + CHRONOLOGIE
IMG_EXT = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".tif", ".tiff", ".webp", ".dng"}


def photo_date(img):
    ex = img.getexif()
    try:
        sub = ex.get_ifd(0x8769)
    except Exception:
        sub = {}
    v = sub.get(36867) or sub.get(36868) or ex.get(306)
    try:
        return datetime.datetime.strptime(str(v)[:19], "%Y:%m:%d %H:%M:%S") if v else None
    except Exception:
        return None


def mod_photobatch():
    con.rule(f"[{G}]👣 LOT DE PHOTOS → CARTE & CHRONOLOGIE")
    con.print(f"[{M}]Donne un dossier : l'outil lit toutes les photos, les range par date et trace le trajet sur une carte.")
    d = Path(clean_path(ask_text("Dossier de photos (glisse-le ici)"))).expanduser()
    if not d.is_dir():
        log("Dossier introuvable.", R)
        return pause()
    files = [f for f in sorted(d.rglob("*")) if f.suffix.lower() in IMG_EXT][:2000]
    if not files:
        log("Aucune photo dans ce dossier.", Y)
        return pause()
    rows = []
    with Progress(TextColumn(f"[{G}]Lecture"), BarColumn(complete_style="#00e5ff"), TaskProgressColumn(), console=con, transient=True) as pr:
        t = pr.add_task("", total=len(files))
        for f in files:
            try:
                img, info, gps, cam = read_exif(f)
                rows.append({"f": f, "dt": photo_date(Image.open(f)), "gps": gps, "cam": " ".join(x for x in (info.get("Appareil (marque)"), info.get("Modèle")) if x)})
            except Exception:
                rows.append({"f": f, "dt": None, "gps": None, "cam": ""})
            pr.advance(t)
    rows.sort(key=lambda r: (r["dt"] is None, r["dt"] or datetime.datetime.min, r["f"].name))
    geo = [r for r in rows if r["gps"]]
    dated = [r for r in rows if r["dt"]]
    cams = sorted({r["cam"] for r in rows if r["cam"]})
    con.print(kv([("Photos", len(rows)), ("Avec GPS", len(geo)), ("Avec date", len(dated)),
                  ("Période", f"{dated[0]['dt']:%d/%m/%Y %H:%M} → {dated[-1]['dt']:%d/%m/%Y %H:%M}" if dated else None),
                  ("Appareils", "\n".join(cams) or "—"), ("Distance parcourue", f"{sum(haversine(*a['gps'][:2], *b['gps'][:2]) for a, b in zip(geo, geo[1:])):.1f} km" if len(geo) > 1 else None)],
                 f"👣 {d.name}", G))
    table_pages("CHRONOLOGIE", ["#", "Date", "Fichier", "GPS", "Appareil"],
                [(str(i), f"{r['dt']:%d/%m/%Y %H:%M:%S}" if r["dt"] else "—", r["f"].name, f"{r['gps'][0]:.5f}, {r['gps'][1]:.5f}" if r["gps"] else "—", r["cam"] or "—")
                 for i, r in enumerate(rows, 1)])
    csvf = OUT / f"chronologie_{d.name}_{stamp()}.csv"
    csvf.write_text("ordre;date;fichier;lat;lon;appareil\n" + "\n".join(
        f"{i};{r['dt'] or ''};{r['f'].name};{r['gps'][0] if r['gps'] else ''};{r['gps'][1] if r['gps'] else ''};{r['cam']}" for i, r in enumerate(rows, 1)), encoding="utf-8-sig")
    log(f"Chronologie enregistrée (ouvrable dans Excel) : {csvf}", G)
    add_report("Lot de photos", d.name, f"{len(rows)} photos, {len(geo)} avec GPS, appareils : {', '.join(cams)}")
    if geo and ask_yes("Ouvrir la carte du trajet ?", True):
        mk = [{"lat": r["gps"][0], "lon": r["gps"][1], "label": f"<b>#{i}</b> {escape_html(r['f'].name)}<br>{r['dt'] or ''}", "c": "#00e5ff" if i == 1 else "#b388ff"}
              for i, r in enumerate(geo, 1)]
        save_open("trajet_photos", quick_map(f"Trajet · {d.name}", mk, lines=[[[r["gps"][0], r["gps"][1]] for r in geo]]))
    pause()


# ------------------------------------------------------------ COMPARER DEUX IMAGES
def _hashes(img):
    import numpy as np
    g = img.convert("L")
    a = np.asarray(g.resize((8, 8)), dtype=float)
    ah = (a > a.mean()).flatten()
    d = np.asarray(g.resize((9, 8)), dtype=float)
    dh = (d[:, 1:] > d[:, :-1]).flatten()
    p = np.asarray(g.resize((32, 32)), dtype=float)
    n = 32
    k = np.arange(n)
    C = np.cos(np.pi * (2 * k[None, :] + 1) * k[:, None] / (2 * n))
    dct = C @ p @ C.T
    low = dct[:8, :8].flatten()[1:]
    ph = low > np.median(low)
    return ah, dh, ph


def mod_imgcompare():
    con.rule(f"[{G}]🪞 COMPARER DEUX IMAGES")
    con.print(f"[{M}]Savoir si deux images sont la même (recadrée, recompressée, retouchée) et voir les différences.")
    a = ask_path("Image 1")
    b = a and ask_path("Image 2")
    if not (a and b):
        return
    try:
        A, B = Image.open(a), Image.open(b)
        A.load(), B.load()
    except Exception:
        log("Un des fichiers n'est pas une image lisible.", R)
        return pause()
    import numpy as np
    ha, hb = _hashes(A), _hashes(B)
    dist = [int((x != y).sum()) for x, y in zip(ha, hb)]
    sim = 100 - (dist[0] / 64 + dist[1] / 64 + dist[2] / 63) / 3 * 100
    verdict = ("🟢 même image (ou quasi identique)" if max(dist) <= 4 else "🟡 très probablement la même image retouchée, recadrée ou recompressée" if sim >= 80
               else "🟠 images ressemblantes (même scène ? même série ?)" if sim >= 65 else "🔴 images différentes")
    A2 = A.convert("RGB")
    B2 = B.convert("RGB").resize(A2.size)
    diff = np.abs(np.asarray(A2, dtype=int) - np.asarray(B2, dtype=int)).sum(axis=2)
    pct = float((diff > 60).mean() * 100)
    heat = np.clip(diff * 3, 0, 255).astype("uint8")
    out = Image.fromarray(np.stack([heat, (heat * .2).astype("uint8"), (255 - heat) // 4], axis=2))
    f = OUT / f"differences_{stamp()}.png"
    out.save(f)
    da, db = photo_date(A), photo_date(B)
    con.print(kv([("Verdict", verdict), ("Ressemblance", f"{sim:.0f} %"), ("Écarts (aHash / dHash / pHash)", f"{dist[0]} / {dist[1]} / {dist[2]}  (0 = identique)"),
                  ("Pixels différents", f"{pct:.1f} %"), ("Tailles", f"{A.size[0]}×{A.size[1]}  vs  {B.size[0]}×{B.size[1]}"),
                  ("Poids", f"{a.stat().st_size // 1024} Ko  vs  {b.stat().st_size // 1024} Ko"),
                  ("Dates EXIF", f"{da or '—'}  vs  {db or '—'}"), ("Carte des différences", str(f))], "🪞 Comparaison", G))
    con.print(f"[{M}]La plus grande, la plus lourde ou la plus ancienne est souvent l'ORIGINALE. Les zones claires de la carte des différences = parties modifiées.")
    add_report("Comparer deux images", f"{a.name} / {b.name}", f"{verdict} · ressemblance {sim:.0f} %")
    if ask_yes("Ouvrir la carte des différences ?"):
        webbrowser.open(f.resolve().as_uri())
    pause()


# ------------------------------------------------------------ VIDÉO EN LIGNE : DATE EXACTE & MINIATURES (façon InVID / YouTube DataViewer)
def yt_id(u):
    m = re.search(r"(?:v=|youtu\.be/|shorts/|embed/|live/)([\w-]{11})", u)
    return m.group(1) if m else (u if re.fullmatch(r"[\w-]{11}", u) else None)


def mod_vidinfo():
    con.rule(f"[{G}]📼 VIDÉO EN LIGNE : DATE EXACTE & MINIATURES")
    con.print(f"[{M}]YouTube, Shorts, TikTok : date de mise en ligne exacte, chaîne, vues, et miniatures prêtes pour la recherche inversée (trouver la vidéo d'origine).")
    u = ask_text("Lien de la vidéo").strip()
    if not u:
        return
    from urllib.parse import quote
    thumbs, rows, title = [], [], ""
    try:
        if "tiktok.com" in u or "vm.tiktok" in u:
            if "vm.tiktok" in u or "/t/" in u:
                u = HTTP.get(u, timeout=10, allow_redirects=True).url
            m = re.search(r"/video/(\d+)", u)
            try:
                j = get_json(f"https://www.tiktok.com/oembed?url={quote(u, safe='')}", 10)
            except Exception:
                j = {}
            title = j.get("title", "") or "Vidéo TikTok"
            dt = datetime.datetime.fromtimestamp(int(m.group(1)) >> 32, datetime.timezone.utc).replace(tzinfo=None) if m else None
            rows = [("Plateforme", "TikTok"), ("Titre / légende", title), ("Compte", f"{j.get('author_name')} · {j.get('author_url')}" if j.get("author_name") else (re.search(r"tiktok\.com/(@[\w.]+)", u) or [None, None])[1]),
                    ("Publiée le (d'après l'ID)", fdt(dt) if dt else None), ("Il y a", human_age(dt) if dt else None)]
            thumbs = [j.get("thumbnail_url")]
        else:
            vid = yt_id(u)
            if not vid:
                log("Lien YouTube ou TikTok non reconnu.", R)
                return pause()
            h = get(f"https://www.youtube.com/watch?v={vid}&hl=fr", 15, cookies={"CONSENT": "YES+1", "SOCS": "CAI"}).text
            g = lambda k: (re.search(r'"%s":"(.*?)(?<!\\)"' % k, h) or [None, None])[1]
            title = json.loads(f'"{g("title")}"') if g("title") else _meta(h, "og:title")
            vd = re.search(r'"lengthSeconds":"(\d+)"', h)
            views = re.search(r'"viewCount":"(\d+)"', h)
            kw = re.search(r'"keywords":\[(.*?)\]', h)
            desc = g("shortDescription")
            rows = [("Plateforme", "YouTube"), ("Titre", title), ("Chaîne", f"{g('ownerChannelName') or g('author')} · https://www.youtube.com/channel/{g('channelId')}"),
                    ("Mise en ligne", g("uploadDate")), ("Publiée", g("publishDate")), ("Durée", f"{int(vd.group(1)) // 60} min {int(vd.group(1)) % 60} s" if vd else None),
                    ("Vues", f"{int(views.group(1)):,}".replace(",", " ") if views else None), ("Mots-clés cachés", kw.group(1).replace('"', "")[:300] if kw else None),
                    ("Description", json.loads(f'"{desc}"')[:500] if desc else None), ("Pays / langue", g("defaultAudioLanguage"))]
            thumbs = [f"https://i.ytimg.com/vi/{vid}/{n}.jpg" for n in ("maxresdefault", "hqdefault", "1", "2", "3")]
    except Exception as e:
        log(f"Impossible de lire la vidéo : {sl_err(e)}", R)
        return pause()
    con.print(kv(rows, f"📼 {title[:70]}", G))
    thumbs = [t for t in thumbs if t]
    if thumbs:
        q = quote(thumbs[0], safe="")
        con.print(kv([("Miniatures", "\n".join(thumbs)), ("Google Lens", f"https://lens.google.com/uploadbyurl?url={q}"),
                      ("Yandex", f"https://yandex.com/images/search?rpt=imageview&url={q}"), ("Bing", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}"),
                      ("TinEye", f"https://tineye.com/search?url={q}")], "🔍 Recherche inversée de la miniature (fais-la aussi sur 1.jpg, 2.jpg, 3.jpg)"))
    con.print(f"[{M}]Une vidéo « d'aujourd'hui » dont la miniature existe déjà en 2019 = vieille vidéo republiée (classique des fausses infos).")
    add_report("Vidéo en ligne", u[:80], " · ".join(f"{k}: {v}" for k, v in rows if v and k != "Description")[:600])
    pause()


# ------------------------------------------------------------ FUITES D'UN SITE / SERVICE
def mod_breaches():
    con.rule(f"[{G}]💧 FUITES D'UN SITE / SERVICE")
    con.print(f"[{M}]Est-ce qu'un site (ou un service) a déjà été piraté ? Quelles données ont fuité ? Base publique Have I Been Pwned, sans clé.")
    q = ask_text("Site ou nom du service (ex : canva.com, Deezer, Twitter)").strip()
    if not q:
        return
    try:
        with con.status(f"[{P}]Recherche dans 900+ fuites connues…", spinner="dots12"):
            allb = get_json("https://haveibeenpwned.com/api/v3/breaches", 20, headers={"User-Agent": "CatExe-OSINT"})
    except Exception as e:
        log(f"Base injoignable : {sl_err(e)}", R)
        return pause()
    ql = q.lower().replace("https://", "").replace("www.", "").strip("/")
    hits = [b for b in allb if ql in (b.get("Domain") or "").lower() or ql in b["Name"].lower() or ql in b["Title"].lower()]
    if not hits:
        log(f"Aucune fuite connue pour « {q} » dans Have I Been Pwned.", G)
        return pause()
    pages = []
    for b in sorted(hits, key=lambda x: x["BreachDate"], reverse=True):
        pages.append(kv([("Service", f"{b['Title']} ({b.get('Domain') or '—'})"), ("Date de la fuite", b["BreachDate"]), ("Ajoutée à la base", b["AddedDate"][:10]),
                         ("Comptes touchés", f"{b['PwnCount']:,}".replace(",", " ")), ("Données exposées", ", ".join(b.get("DataClasses") or [])),
                         ("Vérifiée", "oui" if b.get("IsVerified") else "non"), ("Sensible", "oui" if b.get("IsSensitive") else "non"),
                         ("Résumé", re.sub("<[^>]+>", "", b.get("Description") or "")[:700])], f"💧 {b['Title']}", R))
    view_pages(f"FUITES · {q}", pages, f"{len(hits)} fuite(s)")
    add_report("Fuites d'un service", q, " | ".join(f"{b['Title']} {b['BreachDate']} ({b['PwnCount']} comptes)" for b in hits))
    con.print(f"[{M}]Tu avais un compte dessus ? Change ce mot de passe partout où tu l'utilisais (module Fuite de mot de passe pour le tester).")
    pause()


# ============================================================ 🧬 GRAPHE D'ENQUÊTE (façon Obsidian / Maltego)
GTYPES = {"enquete": ("#d4a35a", "Enquête", "🧬"), "pseudo": ("#5aa9e6", "Pseudo", "👤"), "compte": ("#8fa3b8", "Compte", "🪪"), "personne": ("#e8b04a", "Personne", "🧍"),
          "email": ("#e57c9a", "Email", "📧"), "telephone": ("#6cc28f", "Téléphone", "📱"), "ip": ("#e0605e", "IP", "🧭"), "domaine": ("#9b8ce0", "Domaine", "🌐"),
          "url": ("#7f8c99", "Lien", "🔗"), "lieu": ("#59b86a", "Lieu", "📍"), "image": ("#d47fbf", "Image", "🖼"), "crypto": ("#d9b54a", "Crypto", "₿"),
"fuite": ("#d94b4b", "Fuite", "💧"), "organisation": ("#d98c3a", "Organisation", "🏢"),
          "note": ("#c9c9c9", "Note", "📝"), "autre": ("#8a8f96", "Autre", "◆")}

TRANSFORMS = {
    "pseudo": [("social", "Chercher sur 17 réseaux sociaux"), ("wmn", "Chercher sur 600+ sites (≈ 20 s)")],
    "compte": [("pseudo_of", "Extraire le pseudo"), ("iocs", "Indices de la page du profil")],
    "email": [("gravatar", "Profil Gravatar"), ("email_user", "Pseudo depuis l'email"), ("email_dom", "Domaine + serveur mail"), ("breach_dom", "Fuites du domaine")],
    "ip": [("ip", "IP lookup (géo, opérateur, ports)"), ("revip", "Sites sur la même IP")],
    "domaine": [("dns", "DNS : IP, MX, NS"), ("subs", "Sous-domaines (certificats)"), ("breach_dom", "Fuites du domaine"), ("iocs", "Indices du site")],
    "url": [("url_dom", "Domaine du lien"), ("iocs", "Indices de la page")],
    "personne": [("perms", "Emails probables (vérifiés Gravatar)")],
    "lieu": [("rev", "Adresse du lieu")],
}


def _dom(v):
    v = v.lower().strip()
    v = re.sub(r"^https?://", "", v).split("/")[0].split("?")[0]
    return v[4:] if v.startswith("www.") else v


def graph_transform(e, nid, t):
    """Lance une « transformation » (façon Maltego) depuis la fenêtre du graphe. Renvoie le nombre d'éléments ajoutés."""
    if e and e != gname():
        CFG["enquete"] = e
    _G.clear()
    g = gload()
    n = g["nodes"].get(nid)
    if not n:
        return 0, "élément introuvable"
    before = len(g["nodes"])
    lab, data = n["label"], n.get("data") or {}
    url = data.get("url") or (lab if lab.startswith("http") else None)
    msg = ""
    if t == "social":
        found, _ = _quiet_social(lab)
        for name, ico, d in found:
            gnode("compte", f"{name} · {lab}", {k: v for k, v in d.items() if not k.startswith("_")} | {"url": d.get("_url")}, nid, "", name)
            for em in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", str(d.get("Emails trouvés dans les commits", "")) + " " + str(d.get("Email public") or "")):
                gnode("email", em, None, f"compte:{name.lower()} · {lab.lower()}", "commit")
        msg = f"{len(found)} profil(s)"
    elif t == "wmn":
        sites = [s for s in wmn_data() if s.get("valid") is not False and "nsfw" not in s.get("cat", "").lower()]
        with _TPE(48) as ex:
            for s, res in zip(sites, ex.map(lambda s: wmn_check(s, lab), sites)):
                if res:
                    gnode("compte", f"{s['name']} · {lab}", {"url": res, "catégorie": s.get("cat")}, nid, "", s["name"])
    elif t == "pseudo_of":
        u = lab.split(" · ", 1)[-1] if " · " in lab else (re.search(r"[/@]([\w.-]{2,40})/?$", url or "") or [None, None])[1]
        if u:
            gnode("pseudo", u, None, nid, "pseudo")
    elif t == "gravatar":
        h = hashlib.md5(lab.lower().strip().encode()).hexdigest()
        try:
            j = get_json(f"https://en.gravatar.com/{h}.json", 10)["entry"][0]
            gnode("personne", j.get("displayName") or j.get("preferredUsername"), {"photo": j.get("thumbnailUrl"), "lieu": j.get("currentLocation"), "bio": j.get("aboutMe")}, nid, "gravatar")
            if j.get("preferredUsername"):
                gnode("pseudo", j["preferredUsername"], None, nid, "gravatar")
            for a in j.get("accounts", []):
                gnode("compte", f"{a.get('shortname')} · {a.get('username') or a.get('display')}", {"url": a.get("url")}, nid, "", a.get("shortname"))
            for u in j.get("urls", []):
                gnode("url", u.get("value"), {"url": u.get("value")}, nid, "", re.sub(r"^https?://(www\.)?", "", u.get("value", "")))
        except Exception:
            msg = "pas de profil Gravatar public"
    elif t == "email_user":
        gnode("pseudo", lab.split("@")[0], None, nid, "début de l'email")
    elif t == "email_dom":
        d = lab.split("@")[-1]
        dn = gnode("domaine", d, {"MX": ", ".join(dns(d, "MX")[:4])}, nid, "domaine")
        for mx in dns(d, "MX")[:4]:
            mxh = _dom(mx.split()[-1].rstrip("."))
            if "." in mxh:
                gnode("domaine", mxh, None, dn, "MX")
    elif t == "breach_dom":
        d = _dom(lab.split("@")[-1])
        for b in get_json(f"https://haveibeenpwned.com/api/v3/breaches?domain={d}", 15, headers={"User-Agent": "CatExe-OSINT"}) or []:
            gnode("fuite", f"{b['Title']} ({b['BreachDate'][:4]})", {"date": b["BreachDate"], "comptes": b["PwnCount"], "données": ", ".join(b.get("DataClasses") or [])}, nid, "fuite")
        if len(gload()["nodes"]) == before:
            msg = "aucune fuite connue pour ce domaine"
    elif t == "ip":
        w = get_json(f"https://ipwho.is/{lab}", 10)
        s = {}
        try:
            s = get_json(f"https://internetdb.shodan.io/{lab}", 10)
        except Exception:
            pass
        n["data"].update({"pays": w.get("country"), "ville": w.get("city"), "opérateur": (w.get("connection") or {}).get("isp"), "ASN": (w.get("connection") or {}).get("asn"),
                          "ports": ", ".join(map(str, s.get("ports") or [])), "failles": ", ".join((s.get("vulns") or [])[:15])})
        if w.get("connection", {}).get("org"):
            gnode("organisation", w["connection"]["org"], {"ASN": w["connection"].get("asn")}, nid, "opérateur")
        if w.get("latitude"):
            gnode("lieu", f"{w.get('city')}, {w.get('country')}", {"coordonnées": f"{w['latitude']}, {w['longitude']}", "url": f"https://www.google.com/maps?q={w['latitude']},{w['longitude']}"}, nid, "≈ position")
        for hn in s.get("hostnames") or []:
            gnode("domaine", hn, None, nid, "nom d'hôte")
    elif t == "revip":
        for d in [x for x in get(f"https://api.hackertarget.com/reverseiplookup/?q={lab}", 15).text.split() if "." in x and "error" not in x.lower()][:80]:
            gnode("domaine", d, None, nid, "même IP")
    elif t == "dns":
        d = _dom(lab)
        for ip in dns(d, "A")[:6]:
            gnode("ip", ip, None, nid, "A")
        for mx in dns(d, "MX")[:4]:
            mxh = _dom(mx.split()[-1].rstrip("."))
            if "." in mxh:
                gnode("domaine", mxh, None, nid, "MX")
        for ns in dns(d, "NS")[:4]:
            gnode("domaine", _dom(ns.rstrip(".")), None, nid, "NS")
    elif t == "subs":
        d = _dom(lab)
        subs = sorted({x.strip().lower().lstrip("*.") for c in get_json(f"https://crt.sh/?q=%25.{d}&output=json", 30) for x in c.get("name_value", "").split("\n")} - {d})
        for sd in subs[:80]:
            gnode("domaine", sd, None, nid, "sous-domaine")
        msg = f"{len(subs)} sous-domaine(s)" + (" (80 affichés)" if len(subs) > 80 else "")
    elif t == "url_dom":
        gnode("domaine", _dom(url or lab), None, nid, "domaine")
    elif t == "iocs":
        page = url or ("https://" + _dom(lab))
        txt = get(page, 15).text
        io_ = extract_iocs(html_text(txt) + " " + " ".join(re.findall(r'href="([^"]+)"', txt)))
        for cat, ty in (("Emails", "email"), ("IPv4", "ip"), ("Profils réseaux", "url"), ("Bitcoin", "crypto"), ("Ethereum", "crypto")):
            for v in sorted(io_.get(cat) or [])[:30]:
                gnode(ty, v, {"url": "https://" + v} if ty == "url" and not v.startswith("http") else None, nid, cat.lower(), re.sub(r"^https?://(www\.)?", "", v) if ty == "url" else None)
    elif t == "perms":
        parts = lab.split()
        if len(parts) >= 2:
            perms = [x for d in ("gmail.com", "outlook.fr", "hotmail.fr", "yahoo.fr", "orange.fr", "free.fr", "icloud.com") for x in email_perms(parts[0], parts[-1], d)]
            with _TPE(16) as ex:
                for em, ok in zip(perms, ex.map(gravatar_hit, perms)):
                    if ok:
                        gnode("email", em, None, nid, "existe (Gravatar)")
    elif t == "rev":
        c = parse_coords(data.get("coordonnées") or lab)
        if c:
            n["data"]["adresse"] = place_name(c[0], c[1], 18)
    n.setdefault("data", {})["_faits"] = sorted(set(n["data"].get("_faits") or []) | {t})
    gsave()
    added = len(gload()["nodes"]) - before
    return added, msg


def _quiet_social(u):
    """social_scan sans affichage (appelé depuis la fenêtre du graphe)."""
    found = []
    with _TPE(10) as ex:
        for (n, ico, fn), d in zip(SOCIAL, ex.map(lambda x: _safe(x[2], u), SOCIAL)):
            if d:
                found.append((n, ico, d))
    return found, []


def _safe(fn, *a):
    try:
        return fn(*a)
    except Exception:
        return None



MOD_TYPE = {"Réseaux sociaux": "compte", "WhatsMyName": "pseudo", "IP lookup": "ip", "Recherche de personne": "personne",
            "Image → coordonnées": "image", "Pseudos": "pseudo", "Prevname": "pseudo", "Email": "email", "Téléphone": "telephone", "Domaine": "domaine",
            "Crypto": "crypto", "Géoloc": "image", "Métadonnées": "image", "Fuite de mot de passe": None}
_G = {}


def gdir():
    d = OUT / "enquetes"
    d.mkdir(parents=True, exist_ok=True)
    return d


def gname():
    return re.sub(r"[^\w-]", "_", CFG.get("enquete") or "mon_enquete")[:40]


def gload():
    n = gname()
    if _G.get("name") != n:
        f = gdir() / f"{n}.json"
        try:
            g = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            g = {"nodes": {}, "edges": [], "rev": 0}
        g["name"] = n
        _G.clear()
        _G.update(g)
        if "enquete:" + n not in _G["nodes"]:
            _G["nodes"]["enquete:" + n] = {"type": "enquete", "label": n.replace("_", " "), "data": {}, "t": datetime.datetime.now().strftime("%d/%m/%Y %H:%M")}
    return _G


def gsave():
    g = gload()
    g["rev"] = g.get("rev", 0) + 1
    (gdir() / f"{g['name']}.json").write_text(json.dumps(g, ensure_ascii=False), encoding="utf-8")


def gnode(typ, label, data=None, parent=None, rel="", short=None):
    g = gload()
    label = str(label).strip()[:120]
    if not label:
        return None
    nid = f"{typ}:{label.lower()}"
    n = g["nodes"].setdefault(nid, {"type": typ, "label": label, "data": {}, "t": datetime.datetime.now().strftime("%d/%m/%Y %H:%M")})
    if short:
        n["short"] = short
    if data:
        n["data"].update({k: (v if isinstance(v, (str, int, float, bool)) else str(v))[:600] if isinstance(v, str) else v for k, v in data.items() if v not in (None, "", [], {})})
    if parent and parent != nid and not any(e["from"] == parent and e["to"] == nid for e in g["edges"]):
        g["edges"].append({"from": parent, "to": nid, "label": rel})
    return nid


def graph_feed(mod, title, text):
    """Appelé à chaque résultat (add_report) : ajoute la cible et les indices trouvés au graphe."""
    try:
        root = "enquete:" + gload()["name"]
        typ = next((v for k, v in MOD_TYPE.items() if mod.startswith(k)), "autre")
        if typ is None:
            return
        title = str(title)
        if mod == "Réseaux sociaux" and " · " in title:
            plat, u = title.split(" · ", 1)
            p = gnode("pseudo", u, None, root)
            d = dict(x.split(": ", 1) for x in str(text).split(" · ") if ": " in x)
            c = gnode("compte", f"{plat} · {u}", d, p, "", plat)
        else:
            c = gnode(typ, title, {"résumé": str(text)[:600]}, root, mod)
        n = 0
        for line in str(text).splitlines():
            m = re.match(r"^(.+?) \((.*?)\) : (https?://\S+)$", line.strip())
            if m and n < 150:
                gnode("compte", f"{m.group(1)} · {title}", {"url": m.group(3), "catégorie": m.group(2)}, c, "", m.group(1))
                n += 1
        if n == 0:
            iocs = extract_iocs(str(text))
            for cat, typ2 in (("Emails", "email"), ("IPv4", "ip"), ("Liens", "url"), ("Bitcoin", "crypto"), ("Ethereum", "crypto"), ("Coordonnées GPS", "lieu")):
                for v in sorted(iocs.get(cat) or [])[:25]:
                    gnode(typ2, v, {"url": v} if typ2 == "url" else None, c, "", re.sub(r"^https?://(www\.)?", "", v) if typ2 == "url" else None)
        gsave()
    except Exception:
        pass


def app_window(url, w=1400, h=900):
    """Ouvre l'URL dans une fenêtre seule (Edge / Chrome en mode application), sinon dans le navigateur."""
    import shutil, subprocess
    env = os.environ
    cands = [shutil.which(x) for x in ("msedge", "chrome", "google-chrome", "chromium", "chromium-browser", "brave")]
    cands += [os.path.join(env.get(v, ""), *p) for v in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA")
              for p in (("Microsoft", "Edge", "Application", "msedge.exe"), ("Google", "Chrome", "Application", "chrome.exe"),
                        ("BraveSoftware", "Brave-Browser", "Application", "brave.exe")) if env.get(v)]
    cands += ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    for c in cands:
        if c and os.path.isfile(c):
            try:
                subprocess.Popen([c, f"--app={url}", f"--window-size={w},{h}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except Exception:
                pass
    webbrowser.open(url)
    return False


GRAPH_TPL = r"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CAT.exe · Dossier d'enquête</title>
<style>
:root{--bg:#07081a;--p1:#0e1028;--p2:#14173a;--p3:#1a1f40;--bd:#2b3158;--tx:#e4e9ff;--mu:#7480a8;--c:#00e5ff;--v:#b388ff;--r:#ff5c7a;--ok:#4caf7a;--ck:#e0a83a;--no:#6b7079}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--tx);font:13.5px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif;overflow:hidden}
.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace}
svg.i{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px;flex:none}
/* ---------- barre du haut */
header{position:absolute;top:0;left:0;right:0;height:58px;display:flex;align-items:center;gap:10px;padding:0 14px;background:linear-gradient(180deg,var(--p2),var(--p1));border-bottom:1px solid var(--bd);z-index:10}
.case{display:flex;align-items:center;gap:10px;min-width:0;padding-right:12px;border-right:1px solid var(--bd)}
.case .ic{width:34px;height:34px;border-radius:8px;display:grid;place-items:center;background:var(--p3);border:1px solid var(--bd);color:var(--c)}
.case .ic svg{width:20px;height:20px}
.case b{display:block;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:190px}.case small{color:var(--mu);font-size:11px;letter-spacing:.04em}
#addf{display:flex;gap:6px;flex:1;max-width:780px}
.inp{display:flex;align-items:center;gap:8px;flex:1;background:var(--bg);border:1px solid var(--bd);border-radius:7px;padding:0 10px}
.inp:focus-within{border-color:var(--c)}.inp svg{color:var(--mu)}
input,select,button,textarea{font:inherit;color:var(--tx)}
.inp input{flex:1;border:0;background:transparent;padding:8px 0;outline:0;min-width:80px}
select{background:var(--bg);border:1px solid var(--bd);border-radius:7px;padding:7px 8px}
button{display:inline-flex;align-items:center;gap:6px;justify-content:center;padding:7px 12px;cursor:pointer;background:var(--p3);border:1px solid var(--bd);border-radius:7px;white-space:nowrap}
button:hover{border-color:var(--mu)}button.pri{background:var(--c);color:var(--bg);border-color:var(--c);font-weight:600}button.pri:hover{filter:brightness(1.08)}
button.ghost{background:transparent}button.danger:hover{border-color:var(--r);color:var(--r)}button.sm{padding:4px 9px;font-size:12px}
.tools{display:flex;gap:4px;margin-left:auto}.tools button{padding:7px 9px}
.dd{position:relative}.menu{position:absolute;right:0;top:42px;width:260px;background:var(--p1);border:1px solid var(--bd);border-radius:9px;padding:6px;display:none;box-shadow:0 12px 32px rgba(0,0,0,.5);z-index:30}
.menu .h{color:var(--mu);font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;padding:8px 9px 4px}
.menu div.i{display:flex;gap:9px;align-items:center;padding:7px 9px;border-radius:6px;cursor:pointer}.menu div.i:hover{background:var(--p3)}
/* ---------- zone graphe */
#stage{position:absolute;top:58px;left:0;right:360px;bottom:36px;background:radial-gradient(ellipse at center,var(--p1) 0%,var(--bg) 75%)}
#stage:after{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(600px 420px at 18% 12%,rgba(0,229,255,.07),transparent 70%),radial-gradient(700px 500px at 88% 92%,rgba(179,136,255,.08),transparent 70%)}
#stage:before{content:"";position:absolute;inset:0;background-image:linear-gradient(rgba(116,128,168,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(116,128,168,.06) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
#net{position:absolute;inset:0}
#filters{position:absolute;top:12px;left:12px;display:flex;flex-direction:column;gap:4px;z-index:4;max-height:calc(100% - 24px);overflow:auto}
.chip{display:flex;gap:8px;align-items:center;padding:5px 10px 5px 6px;backdrop-filter:blur(6px);transition:transform .12s,border-color .12s;background:rgba(14,16,40,.82);border:1px solid var(--bd);border-radius:7px;cursor:pointer;user-select:none;font-size:12px}
.chip .dot{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;border:1.5px solid}.chip .dot svg{width:12px;height:12px}
.chip b{margin-left:auto;padding-left:8px;color:var(--mu);font-weight:500}.chip:hover{transform:translateX(3px);border-color:var(--mu)}.chip.off{opacity:.35}
#zoom{position:absolute;right:12px;bottom:12px;display:flex;flex-direction:column;gap:4px;z-index:4}#zoom button{width:34px;height:34px;padding:0}
#empty{position:absolute;inset:0;display:none;align-items:center;justify-content:center;text-align:center;color:var(--mu);pointer-events:none;padding:30px}
#empty .box{max-width:470px}#empty .big{width:64px;height:64px;margin:0 auto 14px;border-radius:16px;display:grid;place-items:center;background:var(--p2);border:1px solid var(--bd);color:var(--c)}#empty .big svg{width:32px;height:32px}
#empty b{color:var(--tx);font-size:18px;display:block;margin-bottom:6px}
.ex{display:flex;gap:6px;justify-content:center;flex-wrap:wrap;margin-top:12px}.ex span{border:1px solid var(--bd);border-radius:6px;padding:3px 8px;font-size:12px}
/* ---------- panneau droit */
aside{position:absolute;top:58px;right:0;width:360px;bottom:0;background:var(--p1);border-left:1px solid var(--bd);display:flex;flex-direction:column}
.tabs{display:flex;border-bottom:1px solid var(--bd);padding:0 8px;flex:none}
.tabs div{padding:11px 10px;cursor:pointer;color:var(--mu);border-bottom:2px solid transparent;font-size:12.5px;display:flex;gap:6px;align-items:center}.tabs div.on{color:var(--tx);border-color:var(--c)}
.tabs div em{font-style:normal;background:var(--p3);border-radius:8px;padding:0 6px;font-size:11px}
#body{flex:1;overflow:auto;padding:16px 16px 24px}
.ent{display:flex;gap:12px;align-items:flex-start}.ent .av{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;border:2px solid;flex:none;background:var(--p2)}.ent .av svg{width:22px;height:22px}
.ent h2{margin:0;font-size:16px;word-break:break-all;line-height:1.3}.ent .meta{color:var(--mu);font-size:12px;margin-top:3px}
h3{margin:20px 0 8px;font-size:10.5px;letter-spacing:.09em;color:var(--mu);text-transform:uppercase;font-weight:600;display:flex;align-items:center;gap:8px}h3:after{content:"";flex:1;height:1px;background:var(--bd)}
.seg{display:grid;grid-template-columns:repeat(3,1fr);gap:4px}.seg button{font-size:12px;padding:6px 4px}
.seg button.on[data-s=ok]{border-color:var(--ok);color:var(--ok);background:rgba(76,175,122,.1)}.seg button.on[data-s=check]{border-color:var(--ck);color:var(--ck);background:rgba(224,168,58,.1)}.seg button.on[data-s=faux]{border-color:var(--no);color:var(--tx);background:rgba(107,112,121,.15)}
.row2{display:flex;gap:6px;margin-top:6px}.row2 button{flex:1}
button.star.on{border-color:var(--ck);color:var(--ck)}
table{width:100%;border-collapse:collapse;font-size:12.5px}td{border-top:1px solid var(--bd);padding:6px 4px;vertical-align:top;word-break:break-word}td:first-child{color:var(--mu);width:36%}
a{color:var(--c);text-decoration:none}a:hover{text-decoration:underline}
.tf{display:flex;align-items:center;gap:10px;width:100%;text-align:left;margin:5px 0;background:var(--bg);padding:9px 11px;justify-content:flex-start}
.tf span{flex:1}.tf small{color:var(--mu);font-size:11px}.tf.done small{color:var(--ok)}
textarea{width:100%;min-height:84px;padding:9px;resize:vertical;background:var(--bg);border:1px solid var(--bd);border-radius:7px}
.kpi{display:grid;grid-template-columns:1fr 1fr;gap:8px}.kpi div{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;color:var(--mu);font-size:11.5px}.kpi b{display:block;font-size:22px;color:var(--tx);font-weight:600}
.bar{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:12px}.bar .lab{width:96px;color:var(--mu);display:flex;gap:6px;align-items:center}.bar .tr{flex:1;height:6px;background:var(--p3);border-radius:3px;overflow:hidden}.bar .tr i{display:block;height:100%}.bar b{width:28px;text-align:right;font-weight:500}
.lk{display:flex;align-items:center;gap:9px;padding:7px 4px;border-top:1px solid var(--bd);cursor:pointer}.lk:hover{background:var(--p2)}.lk .d{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;border:1.5px solid;flex:none}.lk .d svg{width:12px;height:12px}
.lk .n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.lk .st{flex:none}.lk small{color:var(--mu);font-size:11px}
.st{font-size:10.5px;padding:1px 6px;border-radius:5px;border:1px solid}.st.ok{color:var(--ok);border-color:var(--ok)}.st.check{color:var(--ck);border-color:var(--ck)}.st.faux{color:var(--no);border-color:var(--no)}
.log{border-left:2px solid var(--bd);margin-left:6px;padding-left:12px}.log div{position:relative;padding:5px 0;font-size:12.5px}.log div:before{content:"";position:absolute;left:-17px;top:11px;width:8px;height:8px;border-radius:50%;background:var(--bd)}
.log div.k:before{background:var(--c)}.log time{color:var(--mu);font-size:11px;display:block}
.hint{color:var(--mu);font-size:12px}ol.steps{padding-left:18px;margin:0;color:var(--mu)}ol.steps li{margin:5px 0}ol.steps b{color:var(--tx)}
kbd{border:1px solid var(--bd);border-bottom-width:2px;border-radius:4px;padding:0 5px;font-size:11px;background:var(--p2)}
/* ---------- bas, toast, menu contextuel */
footer{position:absolute;left:0;right:360px;bottom:0;height:36px;display:flex;align-items:center;gap:14px;padding:0 14px;border-top:1px solid var(--bd);background:var(--p1);font-size:12px;color:var(--mu)}
footer .live{display:flex;align-items:center;gap:6px}footer .live i{width:7px;height:7px;border-radius:50%;background:var(--ok)}footer .live.off i{background:var(--r)}
footer .sp{margin-left:auto}
#toast{position:absolute;left:calc(50% - 180px);top:72px;transform:translateX(-50%);background:var(--p1);border:1px solid var(--bd);border-left:3px solid var(--c);padding:9px 16px;border-radius:7px;z-index:40;display:none;box-shadow:0 8px 24px rgba(0,0,0,.45);max-width:560px}
#ctx{position:absolute;display:none;z-index:50;width:250px;background:var(--p1);border:1px solid var(--bd);border-radius:9px;padding:5px;box-shadow:0 12px 32px rgba(0,0,0,.55)}
#ctx .h{padding:7px 9px;color:var(--mu);font-size:11px;border-bottom:1px solid var(--bd);margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#ctx div.i{display:flex;gap:9px;align-items:center;padding:6px 9px;border-radius:6px;cursor:pointer}#ctx div.i:hover{background:var(--p3)}#ctx hr{border:0;border-top:1px solid var(--bd);margin:4px 0}
#err{position:absolute;inset:0;display:none;align-items:center;justify-content:center;color:var(--mu);text-align:center;padding:40px;z-index:60;background:var(--bg)}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--mu);border-top-color:var(--c);border-radius:50%;animation:sp .8s linear infinite;vertical-align:-2px;margin-right:6px}@keyframes sp{to{transform:rotate(360deg)}}
@media(max-width:860px){#stage,footer{right:0}aside{display:none}aside.show{display:flex;width:100%;top:auto;height:58%;border-left:0;border-top:1px solid var(--bd)}.case b{max-width:110px}.tools .hide-s{display:none}}
</style></head><body>
<header>
 <div class="case"><div class="ic" id="caseic"></div><div><b id="casename"></b><small id="caseno"></small></div></div>
 <form id="addf" autocomplete="off"><div class="inp"><span id="addic"></span><input id="addv" placeholder="Nouvelle cible : pseudo, email, IP, domaine, lien, Prénom Nom…"></div>
  <select id="addt" title="Type (détecté tout seul)"></select><button type="submit" title="Ajouter au dossier">Ajouter</button><button type="button" id="addall" class="pri" title="Ajouter puis lancer toutes les recherches"></button></form>
 <div class="tools">
  <div class="inp hide-s" style="width:170px;flex:none"><span id="qic"></span><input id="q" placeholder="Filtrer  /"></div><button type="button" id="qmode" class="ghost" title="Correspondance littérale">Exact</button>
  <div class="dd"><button id="more" class="ghost" title="Options"></button><div class="menu" id="menu">
   <div class="h">Disposition</div><div class="i" data-m="force">Libre (physique)</div><div class="i" data-m="hier">Arbre hiérarchique</div><div class="i" data-m="circle">Cercle</div><div class="i" data-m="type">Colonnes par type</div>
   <div class="h">Analyse</div><div class="i" data-m="path">Chemin entre 2 éléments (Ctrl + clic)</div><div class="i" data-m="clu">Regrouper / dégrouper par type</div><div class="i" data-m="keys">Ne montrer que les pistes clés</div><div class="i" data-m="nofaux">Masquer les fausses pistes</div><div class="i" data-m="phys">Figer / animer</div>
   <div class="h">Dossier</div><div class="i" data-m="report">Rapport d'enquête (imprimable / PDF)</div><div class="i" data-m="png">Exporter l'image (PNG)</div><div class="i" data-m="json">Exporter les données (JSON)</div><div class="i" data-m="csv">Exporter pour Excel (CSV)</div><div class="i" data-m="imp">Importer un JSON</div>
  </div></div></div>
 <input type="file" id="imp" accept=".json" style="display:none">
</header>
<div id="stage"><div id="net"></div><div id="filters"></div>
 <div id="zoom"><button id="zin" title="Zoom +">+</button><button id="zout" title="Zoom −">−</button><button id="zfit" title="Tout voir (F)"></button></div>
 <div id="empty"><div class="box"><div class="big" id="emptyic"></div><b>Dossier vide</b>Tape une première cible dans la barre du haut, puis <b style="display:inline;font-size:13.5px">Ajouter + chercher</b>.<br>Les modules lancés dans le terminal alimentent aussi ce dossier en direct.
  <div class="ex"><span>pseudo</span><span>prenom.nom@gmail.com</span><span>8.8.8.8</span><span>exemple.fr</span><span>Jean Dupont</span></div></div></div>
</div>
<aside id="side"><div class="tabs" id="tabs"></div><div id="body"></div></aside>
<footer><span class="live" id="live"><i></i>synchro avec Cat.exe</span><span id="fstat"></span><span id="fsel"></span><span class="sp"><kbd>clic droit</kbd> actions · <kbd>/</kbd> filtrer · <kbd>F</kbd> tout voir · <kbd>Suppr</kbd> supprimer</span></footer>
<div id="toast"></div><div id="ctx"></div><div id="err"></div>
<script>
const NAME=new URLSearchParams(location.search).get('e')||'mon_enquete',TYPES=__TYPES__,TRANS=__TRANS__,ROOT='enquete:'+NAME;
const SRC=['https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js','https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js','https://cdn.jsdelivr.net/npm/vis-network@9.1.9/standalone/umd/vis-network.min.js'];
function load(i){if(i>=SRC.length){err('Impossible de charger le moteur du graphe (pas de connexion internet ?).');return}const s=document.createElement('script');s.src=SRC[i];s.onload=start;s.onerror=()=>load(i+1);document.head.appendChild(s)}
const $=id=>document.getElementById(id),esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function err(t){$('err').style.display='flex';$('err').textContent=t}
/* ---------- icônes (traits, 24×24) */
const P={pseudo:'<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
compte:'<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M5.8 16.5c.6-1.6 1.8-2.4 3.2-2.4s2.6.8 3.2 2.4M14 10h4M14 13.5h4"/>',
personne:'<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.8 2.9-6 6.5-6s6.5 2.2 6.5 6"/><circle cx="17" cy="9" r="2.6"/><path d="M16 14.2c3 .2 5.5 2 5.5 5.3"/>',
email:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3.5 6.5l8.5 6.5 8.5-6.5"/>',telephone:'<rect x="7" y="2.5" width="10" height="19" rx="2.2"/><path d="M10.5 18.5h3"/>',
ip:'<rect x="3.5" y="4" width="17" height="7" rx="1.5"/><rect x="3.5" y="13" width="17" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6"/>',
domaine:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
url:'<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1.2 1.2"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1.2-1.2"/>',
lieu:'<path d="M12 21.5s-7-7.2-7-12.2a7 7 0 0 1 14 0c0 5-7 12.2-7 12.2z"/><circle cx="12" cy="9.3" r="2.6"/>',
image:'<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="9.5" r="1.8"/><path d="M3.5 18l5.5-5.5 4 4 3-3 4.5 4.5"/>',
crypto:'<circle cx="12" cy="12" r="9"/><path d="M9.5 7.5h4a2.2 2.2 0 0 1 0 4.4h-4zM9.5 11.9h4.6a2.3 2.3 0 0 1 0 4.6H9.5zM9.5 7.5v9M11 6v1.5M11 16.5V18"/>',
fuite:'<path d="M12 2.8s-6.5 7.4-6.5 12a6.5 6.5 0 0 0 13 0c0-4.6-6.5-12-6.5-12z"/><path d="M9 15.5a3 3 0 0 0 3 3"/>',
organisation:'<rect x="4" y="3" width="11" height="18" rx="1"/><path d="M15 9h4a1 1 0 0 1 1 1v11M7.5 7h4M7.5 11h4M7.5 15h4M9.5 21v-2.5"/>',
note:'<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 12h7M9 16h7"/>',
enquete:'<path d="M3 7a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M3 11h18"/>',autre:'<path d="M12 3l9 9-9 9-9-9z"/>',
search:'<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',plus:'<path d="M12 5v14M5 12h14"/>',bolt:'<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',dots:'<path d="M5 12h.01M12 12h.01M19 12h.01"/>',
fit:'<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',star:'<path d="M12 3l2.8 5.8 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.3l1-6.2L3 9.7l6.2-.9z"/>',
open:'<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',link2:'<path d="M9 17H7a5 5 0 0 1 0-10h2M15 7h2a5 5 0 0 1 0 10h-2M8 12h8"/>',
trash:'<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',check:'<path d="M5 12.5l4.5 4.5L19 7.5"/>',google:'<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4M8.5 11h5"/>',
doc:'<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 13h6M9 17h4"/>'};
const ico=(k,c)=>`<svg class="i" viewBox="0 0 24 24"${c?` style="color:${c}"`:''}>${P[k]||P.autre}</svg>`;
const ST={ok:['Confirmé','#4caf7a'],check:['À vérifier','#e0a83a'],faux:['Fausse piste','#6b7079']};
let G={nodes:{},edges:[],rev:-1},net,N,E,hidden=new Set(),sel=null,linkFrom=null,saving=false,busy=0,clustered=false,pathSet=null,manualType=false,REAL=0,childOf=null,tab='dossier',onlyKeys=false,noFaux=false,PH='',qmode='exact';
const T=t=>TYPES[t]||TYPES.autre,col=t=>T(t)[0],tn=t=>T(t)[1];
function toast(h,ms){const t=$('toast');t.innerHTML=h;t.style.display='block';clearTimeout(t._t);if(ms)t._t=setTimeout(()=>t.style.display='none',ms)}
function now(){return new Date().toLocaleString('fr-FR',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'})}
function logp(txt,id){G.log=G.log||[];G.log.push({t:now(),txt,id:id||null});if(G.log.length>400)G.log=G.log.slice(-400)}
function deg(id){let d=0;for(const e of G.edges)if(e.from==id||e.to==id)d++;return d}
function caseNo(){let h=0;for(const c of NAME)h=(h*31+c.charCodeAt(0))>>>0;return 'DOSSIER CAT-'+new Date().getFullYear()+'-'+String(h%10000).padStart(4,'0')}
function svgNode(t,stc,key){const c=col(t);return 'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96"><circle cx="48" cy="48" r="48" fill="#0e1028"/><circle cx="48" cy="48" r="48" fill="${c}" fill-opacity=".16"/><g transform="translate(24 24) scale(2)" fill="none" stroke="${c}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${P[t]||P.autre}</g></svg>`)}
/* ---------- ajout */
function ttype(v){v=v.trim();if(/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(v))return'email';if(/^\d{1,3}(\.\d{1,3}){3}$/.test(v)||/^[0-9a-f:]{6,}$/i.test(v)&&v.includes(':'))return'ip';
 if(/^https?:\/\//i.test(v))return'url';if(/^-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+$/.test(v))return'lieu';if(/^\+?[\d\s.()-]{9,}$/.test(v))return'telephone';
 if(/^(0x[0-9a-f]{40}|(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62})$/i.test(v))return'crypto';if(/^([\w-]+\.)+[a-z]{2,}$/i.test(v))return'domaine';if(/\s/.test(v))return'personne';return'pseudo'}
function setAddIcon(){$('addic').innerHTML=ico($('addt').value,col($('addt').value))}
function addNode(v,t,parent){const id=t+':'+v.toLowerCase();if(!G.nodes[ROOT])G.nodes[ROOT]={type:'enquete',label:NAME.replace(/_/g,' '),data:{}};
 if(!G.nodes[id]){G.nodes[id]={type:t,label:v,data:{},t:now()};logp('Ajout : '+tn(t)+' « '+v+' »',id)}
 const p=parent&&parent!=id?parent:ROOT;if(!G.edges.some(e=>e.from==p&&e.to==id))G.edges.push({from:p,to:id,label:''});return id}
async function submitAdd(all){const v=$('addv').value.trim();if(!v)return $('addv').focus();const id=addNode(v,$('addt').value,childOf);
 childOf=null;$('addv').placeholder=PH;$('addv').value='';manualType=false;render();await save();focusN(id);if(all)runAll(id)}
/* ---------- rendu */
function vnode(id,n){const d=deg(id),root=n.type=='enquete',lb=n.short||n.label,inP=pathSet&&pathSet.has(id),dt=n.data||{},st=dt._statut,key=dt._cle;
 const bc=inP?'#e4e9ff':st?ST[st][1]:key?'#e0a83a':col(n.type),sz=root?24:Math.min(16+d*1.4,34)+(key?6:0);
 const hide=hidden.has(n.type)||(root&&!REAL)||(onlyKeys&&!key&&!root)||(noFaux&&st=='faux');
 return {id,label:(lb.length>26?lb.slice(0,24)+'…':lb)+(st&&st!='faux'?'\n'+ST[st][0]:''),shape:'circularImage',image:svgNode(n.type),size:sz,group:n.type,
  color:{border:bc,background:'#0e1028',highlight:{border:'#00e5ff',background:'#0e1028'},hover:{border:'#e4e9ff',background:'#0e1028'}},
  borderWidth:st=='ok'||key||inP?3:1.5,borderWidthSelected:4,shapeProperties:{borderDashes:st=='faux'?[5,4]:false,interpolation:false},
  font:{color:st=='faux'?'#7480a8':'#e4e9ff',size:root?15:13,face:'Segoe UI,system-ui,sans-serif',strokeWidth:0,background:'rgba(7,8,26,.78)',vadjust:4,multi:false},shadow:{enabled:st!='faux',color:(key?'#e0a83a':st=='ok'?'#4caf7a':col(n.type))+(key||st=='ok'?'cc':'77'),size:key?36:st=='ok'?26:16,x:0,y:0},
  hidden:hide,opacity:pathSet&&!inP?.15:(st=='faux'?.5:1)}}
function render(){const ids=new Set(Object.keys(G.nodes));REAL=[...ids].filter(i=>!i.startsWith('enquete:')).length;
 N.update(Object.entries(G.nodes).map(([id,n])=>vnode(id,n)));N.getIds().forEach(i=>{if(!ids.has(i))N.remove(i)});
 const ek=new Set();E.update(G.edges.filter(e=>G.nodes[e.from]&&G.nodes[e.to]).map(e=>{const id=e.from+'→'+e.to;ek.add(id);const inP=pathSet&&pathSet.has(e.from)&&pathSet.has(e.to);
  return {id,from:e.from,to:e.to,label:e.label||'',font:{color:'#7480a8',size:10,strokeWidth:3,strokeColor:'#07081a',align:'middle'},color:{color:inP?'#00e5ff':col((G.nodes[e.to]||{}).type),highlight:'#00e5ff',hover:'#e4e9ff',opacity:pathSet&&!inP?.12:(inP?1:.42)},
   width:inP?3.5:1.4,hoverWidth:1.6,selectionWidth:2.2,arrows:{to:{enabled:true,scaleFactor:.4}},smooth:{type:'continuous',roundness:.35}}}));
 E.getIds().forEach(i=>{if(!ek.has(i))E.remove(i)});
 $('empty').style.display=REAL?'none':'flex';filters();head();panel()}
function head(){$('casename').textContent=NAME.replace(/_/g,' ');$('caseno').textContent=caseNo();
 const c={};Object.values(G.nodes).forEach(n=>{const s=(n.data||{})._statut;if(s)c[s]=(c[s]||0)+1});
 $('fstat').textContent=`${REAL} entités · ${G.edges.length} liens · ${c.ok||0} confirmées · ${c.check||0} à vérifier`}
function filters(){const F=$('filters'),cnt={};Object.values(G.nodes).forEach(n=>{if(n.type!='enquete')cnt[n.type]=(cnt[n.type]||0)+1});
 F.innerHTML=Object.keys(cnt).sort((a,b)=>cnt[b]-cnt[a]).map(t=>`<div class="chip ${hidden.has(t)?'off':''}" data-t="${t}" title="Clic : masquer / afficher"><span class="dot" style="border-color:${col(t)};color:${col(t)}">${ico(t)}</span>${esc(tn(t))}<b>${cnt[t]}</b></div>`).join('');
 F.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{const t=c.dataset.t;hidden.has(t)?hidden.delete(t):hidden.add(t);render()})}
/* ---------- panneau */
function tabsFor(){return sel&&G.nodes[sel]?[['fiche','Fiche'],['rech','Recherches',(TRANS[G.nodes[sel].type]||[]).length],['liens','Liens',G.edges.filter(e=>e.from==sel||e.to==sel).length]]:[['dossier','Dossier'],['journal','Journal',(G.log||[]).length],['pistes','Pistes']]}
function panel(){const TB=tabsFor();if(!TB.some(t=>t[0]==tab))tab=TB[0][0];
 $('tabs').innerHTML=TB.map(([k,l,n])=>`<div data-k="${k}" class="${k==tab?'on':''}">${l}${n!=null?` <em>${n}</em>`:''}</div>`).join('');
 $('tabs').querySelectorAll('div').forEach(d=>d.onclick=()=>{tab=d.dataset.k;panel()});
 const B=$('body');$('side').classList.toggle('show',!!sel);
 if(!sel||!G.nodes[sel]){sel=null;B.innerHTML=tab=='journal'?journal():tab=='pistes'?pistes():dossier()}
 else{const n=G.nodes[sel];B.innerHTML=entHead(sel,n)+(tab=='rech'?rech(sel,n):tab=='liens'?liens(sel):fiche(sel,n))}
 bind(B);$('fsel').textContent=sel?'· sélection : '+(G.nodes[sel].short||G.nodes[sel].label).slice(0,40):''}
function entHead(id,n){const st=(n.data||{})._statut,nb=deg(id);return `<div class="ent"><div class="av" style="border-color:${col(n.type)};color:${col(n.type)}">${ico(n.type)}</div><div style="min-width:0">
 <h2 class="mono">${esc(n.label)}</h2><div class="meta">${esc(tn(n.type))} · ${nb} lien(s)${n.t?' · '+esc(n.t):''} ${st?`<span class="st ${st}">${ST[st][0]}</span>`:''}</div></div></div>`}
function fiche(id,n){const dt=n.data||{},u=urlOf(n),st=dt._statut;
 const link=v=>/^https?:\/\//.test(v)?`<a href="${esc(v)}" target="_blank">${esc(v)}</a>`:esc(v).replace(/\n/g,'<br>');
 const det=Object.entries(dt).filter(([k,v])=>!['note'].includes(k)&&!k.startsWith('_')&&v!==''&&v!=null);
 return `<h3>Évaluation</h3><div class="seg">${Object.entries(ST).map(([k,[l]])=>`<button data-s="${k}" class="${st==k?'on':''}">${l}</button>`).join('')}</div>
 <div class="row2"><button data-a="star" class="star ${dt._cle?'on':''}">${ico('star')} ${dt._cle?'Piste clé':'Marquer piste clé'}</button></div>
 ${(TRANS[n.type]||[]).length?`<h3>Recherches</h3><button class="pri" data-a="all" style="width:100%">${ico('bolt')} Tout chercher (${TRANS[n.type].length})</button>`:''}
 <h3>Actions</h3><div class="row2">${u?`<button data-a="open">${ico('open')} Ouvrir</button>`:''}<button data-a="google">${ico('google')} Google</button></div>
 <div class="row2"><button data-a="link">${ico('link2')} Relier à…</button><button data-a="child">${ico('plus')} Élément lié</button></div>
 ${id.startsWith('enquete:')?'':`<div class="row2"><button data-a="del" class="danger">${ico('trash')} Supprimer</button></div>`}
 <h3>Informations</h3><table>${det.map(([k,v])=>`<tr><td>${esc(k)}</td><td>${link(String(v))}</td></tr>`).join('')||'<tr><td colspan=2 class="hint">aucune information pour l\'instant : lance une recherche</td></tr>'}</table>
 <h3>Note de l'enquêteur</h3><textarea id="note" placeholder="Ce que tu as remarqué, ce qu'il reste à vérifier…">${esc(dt.note||'')}</textarea>`}
function rech(id,n){const tr=TRANS[n.type]||[],done=new Set((n.data||{})._faits||[]);if(!tr.length)return '<h3>Recherches</h3><div class="hint">Pas de recherche automatique pour ce type. Utilise Google ou ajoute des éléments liés.</div>';
 return `<h3>Recherches automatiques</h3><button class="pri" data-a="all" style="width:100%">${ico('bolt')} Tout chercher (${tr.length})</button>
 ${tr.map(([k,l])=>`<button class="tf ${done.has(k)?'done':''}" data-t="${k}">${ico('search')}<span>${esc(l)}</span><small>${done.has(k)?'✓ fait':'lancer'}</small></button>`).join('')}
 <h3>Recherches manuelles</h3><button class="tf" data-a="google">${ico('google')}<span>Google : « ${esc((n.short||n.label).slice(0,30))} »</span></button>`}
function lkRow(x,l){const m=G.nodes[x]||{},st=(m.data||{})._statut;return `<div class="lk" data-id="${esc(x)}"><span class="d" style="border-color:${col(m.type)};color:${col(m.type)}">${ico(m.type)}</span><span class="n">${esc(m.short||m.label||x)}</span>${st?`<span class="st ${st}">${ST[st][0]}</span>`:''}<small>${esc(l||tn(m.type))}</small></div>`}
function liens(id){const nb=G.edges.filter(e=>e.from==id||e.to==id).map(e=>[e.from==id?e.to:e.from,e.label]);return `<h3>Relié à (${nb.length})</h3>${nb.map(([x,l])=>lkRow(x,l)).join('')||'<div class="hint">aucun lien</div>'}`}
function dossier(){const ns=Object.entries(G.nodes).filter(([,n])=>n.type!='enquete'),cnt={},stc={};ns.forEach(([,n])=>{cnt[n.type]=(cnt[n.type]||0)+1;const s=(n.data||{})._statut;if(s)stc[s]=(stc[s]||0)+1});
 const mx=Math.max(1,...Object.values(cnt)),keys=ns.filter(([,n])=>(n.data||{})._cle);
 return `<div class="ent"><div class="av" style="border-color:var(--c);color:var(--c)">${ico('enquete')}</div><div><h2>${esc(NAME.replace(/_/g,' '))}</h2><div class="meta">${caseNo()}${G.created?' · ouvert le '+esc(G.created):''}</div></div></div>
 <h3>Vue d'ensemble</h3><div class="kpi"><div><b>${ns.length}</b>entités</div><div><b>${G.edges.length}</b>liens</div><div><b style="color:var(--ok)">${stc.ok||0}</b>confirmées</div><div><b style="color:var(--ck)">${stc.check||0}</b>à vérifier</div></div>
 <h3>Répartition</h3>${Object.keys(cnt).sort((a,b)=>cnt[b]-cnt[a]).map(t=>`<div class="bar"><span class="lab">${ico(t,col(t))}${esc(tn(t))}</span><span class="tr"><i style="width:${cnt[t]/mx*100}%;background:${col(t)}"></i></span><b>${cnt[t]}</b></div>`).join('')||'<div class="hint">aucune entité</div>'}
 <h3>Pistes clés (${keys.length})</h3>${keys.map(([id])=>lkRow(id,'')).join('')||'<div class="hint">Marque les éléments importants comme « piste clé » depuis leur fiche.</div>'}
 <h3>Méthode</h3><ol class="steps"><li>Ajoute une cible en haut, puis <b>Ajouter + chercher</b>.</li><li>Clique une entité : <b>Fiche</b>, <b>Recherches</b>, <b>Liens</b>.</li><li>Évalue chaque piste : <b>Confirmé</b>, <b>À vérifier</b> ou <b>Fausse piste</b>.</li><li><b>Options → Rapport d'enquête</b> pour sortir le dossier en PDF.</li></ol>`}
function pistes(){const ns=Object.entries(G.nodes).filter(([,n])=>n.type!='enquete').map(([id,n])=>[id,n,deg(id)]).sort((a,b)=>b[2]-a[2]).slice(0,25);
 return `<h3>Entités les plus reliées</h3>${ns.map(([id,,d])=>lkRow(id,d+' liens')).join('')||'<div class="hint">rien pour l\'instant</div>'}`}
function journal(){const ev=(G.log||[]).slice().reverse();const added=Object.entries(G.nodes).filter(([id,n])=>n.t&&n.type!='enquete'&&!(G.log||[]).some(l=>l.id==id)).length;
 return `<h3>Journal de l'enquête</h3><div class="log">${ev.slice(0,150).map(l=>`<div class="${/Recherche|Évaluation/.test(l.txt)?'k':''}"><time>${esc(l.t)}</time>${l.id&&G.nodes[l.id]?`<a href="#" data-id="${esc(l.id)}">${esc(l.txt)}</a>`:esc(l.txt)}</div>`).join('')||'<div>Rien pour l\'instant.</div>'}</div>
 ${added?`<div class="hint" style="margin-top:10px">+ ${added} entité(s) ajoutée(s) par les modules du terminal.</div>`:''}`}
function bind(B){B.querySelectorAll('[data-id]').forEach(a=>a.onclick=ev=>{ev.preventDefault();focusN(a.dataset.id)});
 B.querySelectorAll('button[data-t]').forEach(b=>b.onclick=()=>transform(sel,b.dataset.t,b.querySelector('span').textContent));
 B.querySelectorAll('button[data-a]').forEach(b=>b.onclick=()=>action(sel,b.dataset.a));
 B.querySelectorAll('.seg button').forEach(b=>b.onclick=()=>setStatus(sel,b.dataset.s));
 const no=$('note');if(no)no.onchange=ev=>{const n=G.nodes[sel];n.data=n.data||{};n.data.note=ev.target.value;logp('Note modifiée : '+(n.short||n.label),sel);save()}}
function setStatus(id,s){const n=G.nodes[id];n.data=n.data||{};n.data._statut=n.data._statut==s?undefined:s;if(!n.data._statut)delete n.data._statut;
 logp('Évaluation : '+(n.short||n.label)+' → '+(n.data._statut?ST[s][0]:'aucune'),id);render();save()}
function urlOf(n){return (n.data||{}).url||(/^https?:/.test(n.label)?n.label:null)||(n.type=='domaine'?'https://'+n.label:null)}
function action(id,a){const n=G.nodes[id];if(!n)return;
 if(a=='open')window.open(urlOf(n),'_blank');else if(a=='google')window.open('https://www.google.com/search?q='+encodeURIComponent('"'+(n.short||n.label)+'"'),'_blank');
 else if(a=='all')runAll(id);else if(a=='star'){n.data=n.data||{};n.data._cle=!n.data._cle;if(!n.data._cle)delete n.data._cle;logp((n.data._cle?'Piste clé : ':'Plus piste clé : ')+(n.short||n.label),id);render();save()}
 else if(a=='link'){linkFrom=id;toast(ico('link2')+' Clique maintenant l\'entité à relier… (Échap pour annuler)')}
 else if(a=='child'){childOf=id;$('addv').placeholder='Nouvelle entité liée à « '+(n.short||n.label).slice(0,30)+' »…';$('addv').focus()}
 else if(a=='del'&&confirm('Supprimer « '+(n.short||n.label)+' » du dossier ?')){delete G.nodes[id];G.edges=G.edges.filter(e=>e.from!=id&&e.to!=id);logp('Supprimé : '+(n.short||n.label));sel=null;render();save()}
 else if(a.startsWith('s:'))setStatus(id,a.slice(2))}
/* ---------- recherches (serveur Cat.exe) */
const SCAN=new Set();
async function transform(id,t,label,quiet){busy++;SCAN.add(id);if(!quiet)toast('<span class="spin"></span>'+esc(label)+' …');let added=0;
 try{const r=await fetch('/api/transform',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({e:NAME,id,t})});const j=await r.json();
  await poll(true);added=j.ok?j.added:0;const n=G.nodes[id];if(n)logp('Recherche « '+label+' » sur '+(n.short||n.label)+' : '+(j.ok?added+' résultat(s)':'échec'),id);
  if(!quiet){save();toast(j.ok?`${ico('check','#4caf7a')} ${added} élément(s) ajouté(s)${j.msg?' · '+esc(j.msg):''}`:`Échec : ${esc(j.error||'?')}`,4000)}}
 catch(e){toast('L\'outil Cat.exe doit rester ouvert pour lancer les recherches.',5000);$('live').classList.add('off')}busy--;SCAN.delete(id);if(sel==id)panel();return added}
async function runAll(id){const n=G.nodes[id];if(!n)return;const tr=TRANS[n.type]||[];if(!tr.length){toast('Pas de recherche automatique pour ce type.',3000);return}let tot=0;
 for(let k=0;k<tr.length;k++){toast(`<span class="spin"></span>Recherche ${k+1}/${tr.length} : ${esc(tr[k][1])} …`);tot+=await transform(id,tr[k][0],tr[k][1],true)}
 await save();toast(`${ico('check','#4caf7a')} Terminé : ${tot} élément(s) ajouté(s)`,5000);if(tot)setTimeout(()=>net.fit({animation:true}),300)}
async function save(){G.rev=(G.rev||0)+1;if(!G.created)G.created=now();saving=true;try{await fetch('/api/enquete/'+NAME,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(G)});$('live').classList.remove('off')}catch(e){$('live').classList.add('off')}saving=false}
async function poll(force){if(saving&&!force)return;try{const r=await fetch('enquetes/'+NAME+'.json?'+Date.now());$('live').classList.remove('off');if(!r.ok){if(G.rev==-1){G.rev=0;render()}return}const g=await r.json();
 if(g.rev!==G.rev){const first=G.rev==-1;G=g;render();if(first)setTimeout(()=>net.fit({animation:true}),600)}}catch(e){$('live').classList.add('off');if(G.rev==-1){G.rev=0;render()}}}
/* ---------- graphe */
function focusN(id){if(!N.get(id))return;net.selectNodes([id]);net.focus(id,{scale:1.05,animation:true});sel=id;if(!['fiche','rech','liens'].includes(tab))tab='fiche';panel();dim(id)}
function dim(id){if(pathSet)return;if(!id){N.update(N.get().map(n=>({id:n.id,opacity:(G.nodes[n.id]?.data||{})._statut=='faux'?.5:1})));return}const keep=new Set([id,...net.getConnectedNodes(id)]);N.update(N.get().map(n=>({id:n.id,opacity:keep.has(n.id)?1:.18})))}
function bfs(a,b){const adj={};G.edges.forEach(e=>{(adj[e.from]=adj[e.from]||[]).push(e.to);(adj[e.to]=adj[e.to]||[]).push(e.from)});const prev={[a]:null},q=[a];
 while(q.length){const x=q.shift();if(x==b)break;for(const y of adj[x]||[])if(!(y in prev)){prev[y]=x;q.push(y)}}if(!(b in prev))return null;const p=[];for(let x=b;x!=null;x=prev[x])p.push(x);return p.reverse()}
function layout(m){const ids=Object.keys(G.nodes);net.setOptions({layout:{hierarchical:m=='hier'?{enabled:true,direction:'UD',sortMethod:'hubsize',nodeSpacing:150,levelSeparation:140}:{enabled:false}},physics:{enabled:m=='force'||m=='hier'}});
 if(m=='circle'){const R=Math.max(260,ids.length*14);N.update(ids.map((id,i)=>({id,x:R*Math.cos(2*Math.PI*i/ids.length),y:R*Math.sin(2*Math.PI*i/ids.length)})))}
 if(m=='type'){const ty=[...new Set(ids.map(i=>G.nodes[i].type))],pos={};ids.forEach(id=>{const t=ty.indexOf(G.nodes[id].type);pos[t]=(pos[t]||0)+1;N.update({id,x:t*250,y:pos[t]*70})})}
 setTimeout(()=>net.fit({animation:true}),300)}
function report(){const ns=Object.entries(G.nodes).filter(([,n])=>n.type!='enquete'),by={};ns.forEach(([id,n])=>(by[n.type]=by[n.type]||[]).push([id,n]));
 const rel=id=>G.edges.filter(e=>e.to==id||e.from==id).map(e=>{const o=G.nodes[e.from==id?e.to:e.from];return o&&o.type!='enquete'?(o.short||o.label):null}).filter(Boolean).slice(0,6).join(', ');
 const stc={};ns.forEach(([,n])=>{const s=(n.data||{})._statut;if(s)stc[s]=(stc[s]||0)+1});
 const keys=ns.filter(([,n])=>(n.data||{})._cle);
 const h=`<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Rapport · ${esc(NAME)}</title><style>body{font:13px/1.5 "Segoe UI",system-ui,sans-serif;color:#1b1d21;margin:32px auto;max-width:960px;padding:0 20px}
h1{font-size:22px;margin:0}h2{font-size:15px;border-bottom:2px solid #1b1d21;padding-bottom:4px;margin-top:28px}.m{color:#666}table{width:100%;border-collapse:collapse;margin-top:8px}th,td{border:1px solid #ccc;padding:5px 7px;text-align:left;vertical-align:top}th{background:#f1f2f4}
.k{display:inline-block;border:1px solid #ccc;border-radius:6px;padding:8px 14px;margin:4px 6px 0 0}.k b{display:block;font-size:18px}.ok{color:#23874f}.check{color:#a86e00}.faux{color:#777}button{margin-top:14px;padding:8px 14px}@media print{button{display:none}}</style></head><body>
<div class="m">${caseNo()} · généré le ${now()} · CAT.exe</div><h1>Rapport d'enquête : ${esc(NAME.replace(/_/g,' '))}</h1>
<div><span class="k"><b>${ns.length}</b>entités</span><span class="k"><b>${G.edges.length}</b>liens</span><span class="k ok"><b>${stc.ok||0}</b>confirmées</span><span class="k check"><b>${stc.check||0}</b>à vérifier</span><span class="k faux"><b>${stc.faux||0}</b>fausses pistes</span></div>
<button onclick="print()">Imprimer / Enregistrer en PDF</button>
${keys.length?`<h2>Pistes clés</h2><ul>${keys.map(([,n])=>`<li><b>${esc(n.label)}</b> (${esc(tn(n.type))})${(n.data||{}).note?' : '+esc(n.data.note):''}</li>`).join('')}</ul>`:''}
${Object.keys(by).map(t=>`<h2>${esc(tn(t))} (${by[t].length})</h2><table><tr><th>Valeur</th><th>Évaluation</th><th>Relié à</th><th>Informations / note</th></tr>${by[t].map(([id,n])=>{const d=n.data||{};
 return `<tr><td>${esc(n.label)}</td><td class="${d._statut||''}">${d._statut?ST[d._statut][0]:'—'}</td><td>${esc(rel(id))}</td><td>${Object.entries(d).filter(([k,v])=>!k.startsWith('_')&&k!='note'&&v).slice(0,6).map(([k,v])=>esc(k)+' : '+esc(String(v).slice(0,140))).join('<br>')}${d.note?'<br><i>Note : '+esc(d.note)+'</i>':''}</td></tr>`}).join('')}</table>`).join('')}
${(G.log||[]).length?`<h2>Journal</h2><table><tr><th>Date</th><th>Événement</th></tr>${G.log.slice(-120).map(l=>`<tr><td>${esc(l.t)}</td><td>${esc(l.txt)}</td></tr>`).join('')}</table>`:''}</body></html>`;
 const w=window.open('','_blank');if(w){w.document.write(h);w.document.close()}else dl('rapport_'+NAME+'.html',h,'text/html')}
function menu(m){$('menu').style.display='none';
 if(['force','hier','circle','type'].includes(m))layout(m);else if(m=='report')report();
 else if(m=='phys'){const on=!net.physics.options.enabled;net.setOptions({physics:{enabled:on}});toast(on?'Animation activée':'Positions figées',2000)}
 else if(m=='keys'){onlyKeys=!onlyKeys;render();toast(onlyKeys?'Seules les pistes clés sont affichées':'Tout est affiché',2500)}
 else if(m=='nofaux'){noFaux=!noFaux;render();toast(noFaux?'Fausses pistes masquées':'Fausses pistes affichées',2500)}
 else if(m=='clu'){clustered=!clustered;if(!clustered){net.setData({nodes:N,edges:E});render();return}
  Object.keys(TYPES).forEach(t=>{const c=Object.values(G.nodes).filter(n=>n.type==t).length;if(c>2&&t!='enquete')net.cluster({joinCondition:o=>o.group==t,clusterNodeProperties:{id:'cl:'+t,label:tn(t)+' ×'+c,shape:'circularImage',image:svgNode(t),size:22+Math.min(c,30),color:{border:col(t),background:'#0e1028'},borderWidth:2,font:{color:'#e4e9ff',size:13,strokeWidth:4,strokeColor:'#07081a'}}})})}
 else if(m=='path'){const s=net.getSelectedNodes();if(s.length!=2){toast('Ctrl + clic sur 2 entités, puis relance « Chemin ».',4000);return}const p=bfs(s[0],s[1]);if(!p){toast('Aucun lien entre ces deux entités.',4000);return}
  pathSet=new Set(p);render();toast(p.map(i=>esc((G.nodes[i].short||G.nodes[i].label).slice(0,20))).join(' → '),9000)}
 else if(m=='png'){const c=document.querySelector('#net canvas'),o=document.createElement('canvas');o.width=c.width;o.height=c.height;const x=o.getContext('2d');x.fillStyle='#07081a';x.fillRect(0,0,o.width,o.height);x.drawImage(c,0,0);
  x.fillStyle='#7480a8';x.font='14px sans-serif';x.fillText(caseNo()+' · '+NAME+' · '+now(),16,o.height-16);dl('graphe_'+NAME+'.png',null,null,o.toDataURL())}
 else if(m=='json')dl('enquete_'+NAME+'.json',JSON.stringify(G,null,1),'application/json');
 else if(m=='csv')dl('enquete_'+NAME+'.csv','﻿type;valeur;évaluation;relié à;note;détails\n'+Object.entries(G.nodes).map(([id,n])=>[tn(n.type),n.label,((n.data||{})._statut&&ST[n.data._statut][0])||'',G.edges.filter(e=>e.to==id).map(e=>(G.nodes[e.from]||{}).label).join(' | '),(n.data||{}).note||'',JSON.stringify(n.data||{})].map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(';')).join('\n'),'text/csv');
 else if(m=='imp')$('imp').click()}
function dl(name,txt,type,href){const a=document.createElement('a');a.download=name;a.href=href||URL.createObjectURL(new Blob([txt],{type}));a.click()}
function ctx(x,y,id){const n=G.nodes[id],C=$('ctx');if(!n)return;const tr=TRANS[n.type]||[],u=urlOf(n),st=(n.data||{})._statut;
 C.innerHTML=`<div class="h">${esc(tn(n.type))} · ${esc((n.short||n.label).slice(0,36))}</div>`+(tr.length?`<div class="i" data-a="all">${ico('bolt')} Tout chercher</div>`+tr.map(([k,l])=>`<div class="i" data-t="${k}">${ico('search')} ${esc(l)}</div>`).join('')+'<hr>':'')+
  Object.entries(ST).map(([k,[l,c]])=>`<div class="i" data-a="s:${k}">${st==k?ico('check',c):`<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" style="color:${c}" stroke="${c}"/></svg>`} ${l}</div>`).join('')+
  `<div class="i" data-a="star">${ico('star')} ${(n.data||{})._cle?'Retirer des pistes clés':'Piste clé'}</div><hr>`+
  (u?`<div class="i" data-a="open">${ico('open')} Ouvrir le lien</div>`:'')+`<div class="i" data-a="google">${ico('google')} Rechercher sur Google</div><div class="i" data-a="link">${ico('link2')} Relier à…</div><div class="i" data-a="child">${ico('plus')} Ajouter un élément lié</div>`+
  (id.startsWith('enquete:')?'':`<hr><div class="i" data-a="del">${ico('trash')} Supprimer</div>`);
 C.style.display='block';C.style.left=Math.min(x,innerWidth-260)+'px';C.style.top=Math.max(8,Math.min(y,innerHeight-C.offsetHeight-8))+'px';
 C.querySelectorAll('.i').forEach(it=>it.onclick=()=>{C.style.display='none';if(it.dataset.t)transform(id,it.dataset.t,it.textContent.trim());else action(id,it.dataset.a)})}
function start(){N=new vis.DataSet();E=new vis.DataSet();
 net=new vis.Network($('net'),{nodes:N,edges:E},{interaction:{hover:true,multiselect:true,keyboard:false,tooltipDelay:300},
  physics:{solver:'forceAtlas2Based',forceAtlas2Based:{gravitationalConstant:-70,springLength:130,springConstant:.05,damping:.6,avoidOverlap:.4},stabilization:{iterations:180}}});
 net.on('click',p=>{$('ctx').style.display='none';const id=p.nodes[0];
  if(linkFrom&&id&&id!=linkFrom){const l=prompt('Nature du lien (facultatif, ex : même photo, même email…)','')||'';G.edges.push({from:linkFrom,to:id,label:l});logp('Lien : '+(G.nodes[linkFrom].short||G.nodes[linkFrom].label)+' ↔ '+(G.nodes[id].short||G.nodes[id].label)+(l?' ('+l+')':''),id);linkFrom=null;$('toast').style.display='none';render();save();focusN(id);return}
  if(pathSet){pathSet=null;render()}if(id&&net.isCluster&&net.isCluster(id)){net.openCluster(id);return}
  if(id){focusN(id)}else{sel=null;tab='dossier';panel();dim(null)}});
 net.on('afterDrawing',c=>{const t=Date.now()/1000;for(const id of Object.keys(G.nodes)){const n=G.nodes[id],d=n.data||{},scan=SCAN.has(id);if(!(d._cle||scan||id==sel))continue;const bb=net.getBoundingBox(id);if(!bb||!N.get(id)||N.get(id).hidden)continue;
   const cx=(bb.left+bb.right)/2,r0=Math.min(bb.right-bb.left,90)/2,cy=bb.top+r0;c.save();
   if(scan){for(let k=0;k<2;k++){const ph=(t*1.1+k*.5)%1;c.beginPath();c.arc(cx,cy,r0+6+ph*46,0,7);c.strokeStyle='#00e5ff';c.globalAlpha=(1-ph)*.75;c.lineWidth=3;c.stroke()}}
   else if(d._cle){const ph=(Math.sin(t*2.4)+1)/2;c.beginPath();c.arc(cx,cy,r0+9+ph*5,0,7);c.strokeStyle='#e0a83a';c.globalAlpha=.35+ph*.4;c.lineWidth=2.5;c.setLineDash([7,6]);c.lineDashOffset=-t*18;c.stroke()}
   if(id==sel&&!scan){c.beginPath();c.arc(cx,cy,r0+7,0,7);c.strokeStyle='#00e5ff';c.globalAlpha=.9;c.lineWidth=2;c.setLineDash([3,5]);c.lineDashOffset=t*14;c.stroke()}c.restore()}});
 setInterval(()=>{if(SCAN.size||sel||Object.values(G.nodes).some(n=>(n.data||{})._cle))net.redraw()},70);
 net.on('doubleClick',p=>{const n=G.nodes[p.nodes[0]];if(n&&urlOf(n))window.open(urlOf(n),'_blank')});
 net.on('oncontext',p=>{p.event.preventDefault();const id=net.getNodeAt(p.pointer.DOM);if(id&&G.nodes[id]){net.selectNodes([id]);ctx(p.event.clientX,p.event.clientY,id)}});
 poll();setInterval(()=>{if(!busy)poll()},2000)}
/* ---------- interface */
PH=$('addv').placeholder;$('addt').innerHTML=Object.keys(TYPES).filter(k=>k!='enquete').map(k=>`<option value="${k}">${esc(tn(k))}</option>`).join('');
 $('caseic').innerHTML=ico('enquete');$('emptyic').innerHTML=ico('enquete');$('qic').innerHTML=ico('search');$('addall').innerHTML=ico('bolt')+' Ajouter + chercher';$('more').innerHTML=ico('dots')+' Options';$('zfit').innerHTML=ico('fit');setAddIcon();
$('addv').oninput=ev=>{if(!manualType)$('addt').value=ttype(ev.target.value)||'pseudo';setAddIcon()};$('addt').onchange=()=>{manualType=true;setAddIcon()};
$('addf').onsubmit=ev=>{ev.preventDefault();submitAdd(false)};$('addall').onclick=()=>submitAdd(true);
$('more').onclick=ev=>{ev.stopPropagation();const M=$('menu');M.style.display=M.style.display=='block'?'none':'block'};
$('menu').querySelectorAll('.i').forEach(i=>i.onclick=()=>menu(i.dataset.m));
$('zin').onclick=()=>net.moveTo({scale:net.getScale()*1.25,animation:true});$('zout').onclick=()=>net.moveTo({scale:net.getScale()/1.25,animation:true});$('zfit').onclick=()=>net.fit({animation:true});
$('imp').onchange=async ev=>{const f=ev.target.files[0];if(!f)return;try{const g=JSON.parse(await f.text());Object.assign(G.nodes,g.nodes||{});(g.edges||[]).forEach(e=>G.edges.push(e));logp('Import : '+f.name);render();save();toast('Importé',3000)}catch(e){toast('Fichier invalide',3000)}};
function normQ(s){return String(s).normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase()}
function edit1(a,b){if(a===b)return true;if(Math.abs(a.length-b.length)>1)return false;if(a.length===b.length){let n=0;for(let i=0;i<a.length;i++)if(a[i]!==b[i]&&++n>1)return false;return true}let x=0,y=0,n=0;while(x<a.length&&y<b.length){if(a[x]===b[y]){x++;y++}else{if(++n>1)return false;if(a.length<b.length)y++;else x++}}return true}
function approxQ(q,text){const a=normQ(q),b=normQ(text);if(b.includes(a))return true;const words=b.split(/[^\p{L}\p{N}._-]+/u).filter(Boolean);return a.split(/\s+/).every(w=>words.includes(w)||(w.length>=4&&words.some(x=>x.length>=4&&edit1(w,x))))}
function applyQ(){const raw=$('q').value;if(!raw){dim(null);return}const hit=Object.keys(G.nodes).filter(id=>{const text=G.nodes[id].label+JSON.stringify(G.nodes[id].data||{});return qmode==='exact'?text.includes(raw):approxQ(raw,text)});
 N.update(N.get().map(n=>({id:n.id,opacity:hit.includes(n.id)?1:.1})));if(hit.length==1)focusN(hit[0])}
$('q').oninput=applyQ;$('qmode').onclick=()=>{qmode=qmode==='exact'?'approx':'exact';$('qmode').textContent=qmode==='exact'?'Exact':'Approx';$('qmode').title=qmode==='exact'?'Correspondance littérale':'Casse/accents ignorés, une modification tolérée';applyQ()};
document.addEventListener('keydown',ev=>{if(['INPUT','TEXTAREA','SELECT'].includes(ev.target.tagName)){if(ev.key=='Escape')ev.target.blur();return}
 if(ev.key=='/'){ev.preventDefault();$('q').focus()}else if(ev.key=='f'||ev.key=='F')net.fit({animation:true});
 else if(ev.key=='Escape'){linkFrom=null;childOf=null;$('addv').placeholder=PH;pathSet=null;$('toast').style.display='none';$('ctx').style.display='none';net.unselectAll();sel=null;tab='dossier';render();dim(null)}
 else if(ev.key=='Delete'){const ids=net.getSelectedNodes().filter(i=>!i.startsWith('enquete:'));if(ids.length&&confirm('Supprimer '+ids.length+' entité(s) ?')){ids.forEach(i=>delete G.nodes[i]);G.edges=G.edges.filter(e=>G.nodes[e.from]&&G.nodes[e.to]);logp('Supprimé : '+ids.length+' entité(s)');sel=null;render();save()}}});
document.addEventListener('click',ev=>{if(!ev.target.closest('.dd'))$('menu').style.display='none';if(!ev.target.closest('#ctx'))$('ctx').style.display='none'});
load(0);
</script></body></html>"""


def graph_url():
    f = OUT / "graphe.html"
    f.write_text(theme_html(GRAPH_TPL.replace("__TYPES__", json.dumps({k: list(v) for k, v in GTYPES.items()}, ensure_ascii=False)).replace("__TRANS__", json.dumps(TRANSFORMS, ensure_ascii=False))), encoding="utf-8")
    gsave()
    return f"http://127.0.0.1:{local_server()}/graphe.html?e={gname()}"


def mod_graph():
    while True:
        g = gload()
        con.rule(f"[{G}]🧬 GRAPHE D'ENQUÊTE")
        con.print(f"[{M}]Enquête : [bold #00e5ff]{g['name'].replace('_', ' ')}[/] · {len(g['nodes'])} éléments · {len(g['edges'])} liens. "
                  "Chaque module que tu lances ajoute ses résultats ici tout seul, et la fenêtre se met à jour en direct.")
        others = sorted(f.stem for f in gdir().glob("*.json"))
        c = select("Graphe", [{"label": "🪟 Ouvrir le graphe (fenêtre)", "value": "open", "desc": "tout se fait dans la fenêtre : ajouter, chercher, relier"},
                              {"label": "⚡ Scan auto d'une cible", "value": "auto", "desc": "toutes les recherches d'un coup"},
                              {"label": "➕ Ajouter un élément", "value": "add", "desc": "pseudo, email, IP, personne, note…"},
                              {"label": "🔗 Relier deux éléments", "value": "link"},
                              {"label": "📁 Changer d'enquête / en créer une", "value": "sw", "desc": f"{len(others)} enquête(s)"},
                              {"label": "🧹 Vider cette enquête", "value": "clr"}])
        if c is None:
            return
        if c == "open":
            url = graph_url()
            alone = app_window(url)
            log("Graphe ouvert dans une fenêtre à part." if alone else f"Graphe ouvert dans le navigateur : {url}", G)
            con.print(f"[{M}]Laisse la fenêtre ouverte : elle se met à jour pendant que tu utilises les autres modules (l'outil doit rester lancé).")
            pause()
        elif c == "auto":
            mod_autoscan()
        elif c == "add":
            v = ask_text("Valeur (pseudo, email, IP, domaine, lien, Prénom Nom…)").strip()
            t = v and select("Type (détecté tout seul, Entrée pour valider)", [{"label": tv[1], "value": k} for k, tv in GTYPES.items() if k != "enquete"], default=target_type(v), echo=False)
            if t:
                if v:
                    note = ask_text("Note (optionnel)").strip()
                    nodes = [k for k in gload()["nodes"]]
                    par = select("Relier à", [{"label": f"{GTYPES[gload()['nodes'][k]['type']][1]} · {gload()['nodes'][k]['label']}", "value": k} for k in nodes],
                                 default="enquete:" + g["name"])
                    gnode(t, v, {"note": note} if note else None, par or "enquete:" + g["name"])
                    gsave()
                    log("Ajouté au graphe.", G)
        elif c == "link":
            items = [{"label": f"{GTYPES.get(n['type'], GTYPES['autre'])[1]} · {n['label']}", "value": k} for k, n in g["nodes"].items()]
            a = select("Premier élément", items)
            b = a and select("Second élément", items)
            if a and b and a != b:
                g["edges"].append({"from": a, "to": b, "label": ask_text("Nom du lien (optionnel, ex : même photo)").strip()})
                gsave()
                log("Relié.", G)
        elif c == "sw":
            v = select("Enquête", [{"label": "➕ Nouvelle enquête", "value": "+"}] + [{"label": o.replace("_", " "), "value": o} for o in others], default=g["name"])
            if v == "+":
                v = ask_text("Nom de la nouvelle enquête").strip()
            if v:
                CFG["enquete"] = v
                save_cfg()
                gload()
                gsave()
        elif c == "clr" and ask_yes("Tout effacer dans cette enquête ?"):
            (gdir() / f"{g['name']}.json").unlink(missing_ok=True)
            _G.clear()
            gload()
            gsave()


# ============================================================ 📘 TUTOS (un par module : touche ? dans le menu)
_ORIG_PHOTO = """
### 📸 Récupérer la photo ORIGINALE (avec GPS)
C'est le point le plus important :
- **Captures d'écran = GPS perdu.** Il faut le fichier d'origine.
- **iPhone** : Photos → la photo → Partager → *Options* → active **Toutes les données de la photo** → *Enregistrer dans Fichiers* (ou AirDrop vers le PC).
- **Android** : Galerie → Partager → envoie **en fichier** (Gmail, Drive, câble USB). Sur Google Photos : *⋮ → Télécharger*.
- **WhatsApp** : demande l'envoi **en Document** (trombone → Document), pas en photo : en photo, WhatsApp efface le GPS.
- **Telegram (en fichier)** : clic droit → *Enregistrer l'image* garde souvent les données.
- **Instagram, TikTok, X, Facebook, Snapchat** effacent toujours le GPS → l'outil passe alors à l'**IA** (GeoCLIP + vision) et aux indices visuels.
- **Sur PC** : glisse le fichier directement dans la fenêtre noire, le chemin se colle tout seul."""

# ============================================================ 🧅 ANONYMAT (Tor)
TOR_SOCKS = (9050, 9150)  # SOCKS : service Tor (9050) ou Tor Browser (9150)
TOR_CTRL = (9051, 9151)   # port de contrôle : nouveau circuit
ANON_DIR = Path.home() / ".catexe_anon"
ANON_USERJS = """
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", __PORT__);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("media.peerconnection.enabled", false);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("network.prefetch-next", false);
user_pref("geo.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
"""


def _port_open(port, t=.6):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=t):
            return True
    except OSError:
        return False


def tor_port(ports):
    return next((p for p in ports if _port_open(p)), None)


def my_ip_direct():
    """Ton IP réelle, sans Tor."""
    try:
        d = get_json("https://ipwho.is/", 10)
        lieu = ", ".join(x for x in (d.get("city"), d.get("country")) if x)
        return d.get("ip"), lieu, (d.get("connection") or {}).get("isp", "")
    except Exception:
        return None, "", ""


def tor_status():
    """(ok, ip, message) : demande au service officiel du Tor Project si le trafic passe par Tor."""
    port = tor_port(TOR_SOCKS)
    if not port:
        return False, None, "Tor n'est pas lancé"
    p = f"socks5h://127.0.0.1:{port}"
    try:
        d = HTTP.get("https://check.torproject.org/api/ip", timeout=25, proxies={"http": p, "https": p}).json()
        return bool(d.get("IsTor")), d.get("IP"), ""
    except Exception as e:
        return False, None, "module PySocks manquant (pip install pysocks)" if "SOCKS" in str(e) else "pas de réponse via Tor"


def find_tor_browser():
    """Cherche Tor Browser à ses emplacements habituels."""
    h = Path.home()
    exe = "firefox.exe" if os.name == "nt" else "firefox"
    for base in (h / "Desktop", h / "Bureau", h / "Downloads", h / "Téléchargements", h, Path("/opt")):
        for nom in ("Tor Browser", "tor-browser"):
            p = base / nom / "Browser" / exe
            if p.exists():
                return p
    return None


def find_firefox():
    if os.name == "nt":
        for p in (r"C:\Program Files\Mozilla Firefox\firefox.exe", r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"):
            if Path(p).exists():
                return Path(p)
        return None
    import shutil
    w = shutil.which("firefox")
    return Path(w) if w else None


def _cookie_paths():
    """Fichiers de cookie d'authentification du port de contrôle (Tor Browser ou service Tor)."""
    h = Path.home()
    c = []
    tb = find_tor_browser()
    if tb:
        c.append(tb.parent / "TorBrowser" / "Data" / "Tor" / "control_auth_cookie")
    if os.name == "nt":
        c.append(h / "AppData" / "Roaming" / "tor" / "control_auth_cookie")
    else:
        c += [h / ".tor" / "control_auth_cookie", Path("/var/lib/tor/control_auth_cookie")]
    return c


def tor_newnym():
    """Demande une nouvelle sortie Tor (nouvelle IP) via le port de contrôle."""
    port = tor_port(TOR_CTRL)
    if not port:
        return False, "port de contrôle fermé : ouvre Tor Browser (il l'active tout seul)"
    s = socket.create_connection(("127.0.0.1", port), timeout=6)
    try:
        f = s.makefile("rwb")

        def cmd(c):
            f.write(c.encode() + b"\r\n")
            f.flush()
            return f.readline().decode(errors="replace").strip()
        r = cmd("AUTHENTICATE")
        if not r.startswith("250"):
            for cp in _cookie_paths():
                if cp.exists():
                    r = cmd("AUTHENTICATE " + cp.read_bytes().hex())
                    break
        if not r.startswith("250"):
            return False, "accès refusé au port de contrôle"
        r = cmd("SIGNAL NEWNYM")
        if r.startswith("250"):
            return True, "nouveau circuit demandé"
        return False, "Tor a refusé : attends une dizaine de secondes entre deux changements"
    finally:
        s.close()


def mod_anon_launch():
    port = tor_port(TOR_SOCKS)
    if not port:
        log("Tor n'est pas lancé. Ouvre Tor Browser (il lance Tor tout seul), ou installe-le sur torproject.org.", Y)
        return
    tb = find_tor_browser()
    if tb:
        log("Tor Browser trouvé : lancement.", G)
        subprocess.Popen([str(tb)])
        return
    ff = find_firefox()
    if not ff:
        log("Ni Tor Browser ni Firefox trouvés. Installe Tor Browser depuis torproject.org (le plus sûr).", Y)
        return
    prof = ANON_DIR / "profil-firefox"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "user.js").write_text(ANON_USERJS.replace("__PORT__", str(port)), encoding="utf-8")
    log("Firefox trouvé : lancement sur Tor avec un profil séparé. Moins protégé que Tor Browser.", Y)
    subprocess.Popen([str(ff), "-no-remote", "-profile", str(prof), "https://check.torproject.org"])


def mod_anon():
    while True:
        con.rule(f"[{G}]🧅 ANONYMAT")
        port = tor_port(TOR_SOCKS)
        con.print(f"  [{M}]{'Tor actif (port ' + str(port) + ')' if port else 'Tor non lancé'}")
        c = select("Action", [
            {"label": "🔍 Test d'exposition", "value": "test", "desc": "ton IP réelle vs IP via Tor"},
            {"label": "🔄 Changer d'IP", "value": "nym", "desc": "nouveau circuit Tor"},
            {"label": "🧅 Ouvrir un navigateur protégé", "value": "open", "desc": "Tor Browser ou Firefox sur Tor"},
            {"label": "🧪 Tests de fuites", "value": "leak", "desc": "WebRTC, DNS, empreinte"},
        ])
        if c is None:
            return
        if c == "test":
            ip, lieu, fai = my_ip_direct()
            ok, tip, msg = tor_status()
            rows = [("IP réelle (sans Tor)", f"{ip or '?'}  {lieu}".strip()), ("Fournisseur", fai),
                    ("IP via Tor", tip or msg or "?")]
            if ok and ip and tip == ip:
                rows.append(("Statut", "⚠ même IP : ton trafic ne passe pas par Tor"))
            elif ok:
                rows.append(("Statut", "✔ trafic passé par Tor"))
            else:
                rows.append(("Statut", f"✘ pas par Tor ({msg})" if msg else "✘ pas par Tor"))
            con.print(kv(rows, "🧅 Test d'exposition", G if ok else Y))
            add_report("mod_anon", "Test d'exposition", f"IP réelle : {ip} · via Tor : {tip} · Tor actif : {ok}")
            pause()
        elif c == "nym":
            ok, msg = tor_newnym()
            log(msg, G if ok else Y)
            if ok:
                time.sleep(3)
                log(f"Nouvelle IP via Tor : {tor_status()[1] or '?'}", G)
            pause()
        elif c == "open":
            mod_anon_launch()
            pause()
        elif c == "leak":
            con.print(kv([("WebRTC", "https://browserleaks.com/webrtc"), ("DNS", "https://dnsleaktest.com"),
                          ("Empreinte", "https://coveryourtracks.eff.org"), ("Tor", "https://check.torproject.org")],
                         "🧪 À ouvrir dans ton navigateur protégé", M))
            pause()


# ============================================================ v6.1 : OUTILS OSINT CONNUS
from urllib.parse import quote as _q


def api_key(name, where):
    """Clé API optionnelle, demandée une fois puis gardée dans les réglages (Entrée = sans clé)."""
    key_name = "api_" + name
    key = secret_get(key_name)
    if not SECRETS.has(key_name):
        con.print(f"[{M}]Clé {name} (gratuite, facultative) : {where}  ·  Entrée = continuer sans clé")
        key = ask_text(f"Clé {name}").strip()
        SECRETS.set(key_name, key)
    return key


def open_links(links, ask=True):
    if not ask or select("Ouvrir ces liens ?", [{"label": "🌐 Tout ouvrir dans le navigateur", "value": "y"}, {"label": "Non", "value": "n"}], echo=False) == "y":
        for u in links:
            webbrowser.open(u)
            time.sleep(.25)


# ---------- 🔎 Recherche inversée d'image (Google Lens, TinEye, Bing, Yandex…)
def mod_revimg():
    con.rule(f"[{G}]🔎 RECHERCHE INVERSÉE D'IMAGE")
    c = select("L'image est…", [{"label": "🔗 Sur internet (lien de l'image)", "value": "url", "desc": "recherche automatique sur 6 moteurs"},
                                 {"label": "💾 Sur mon PC", "value": "file", "desc": "ouvre les moteurs, tu glisses la photo"}])
    if c is None:
        return
    if c == "url":
        u = ask_text("Lien direct de l'image (clic droit → Copier l'adresse de l'image)").strip()
        if not u.startswith("http"):
            log("Il faut un lien qui commence par http.", Y)
            return pause()
        q = _q(u, safe="")
        links = {"Google Lens": f"https://lens.google.com/uploadbyurl?url={q}", "Bing Visual Search": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}",
                 "Yandex Images": f"https://yandex.com/images/search?rpt=imageview&url={q}", "TinEye (date la plus ancienne)": f"https://tineye.com/search?url={q}&sort=crawl_date&order=asc",
                 "SauceNAO (dessins, anime)": f"https://saucenao.com/search.php?url={q}", "Baidu": f"https://graph.baidu.com/details?isfromtusoupc=1&tn=pc&image={q}"}
        con.print(kv(list(links.items()), "🔎 Recherches prêtes", G))
        add_report("mod_revimg", "Recherche inversée", u)
        open_links(list(links.values()))
    else:
        f = clean_path(ask_text("Glisse la photo ici (pour vérifier le chemin)"))
        if f and not Path(f).exists():
            log("Fichier introuvable.", Y)
            return pause()
        links = {"Google Lens": "https://lens.google.com/", "Bing Visual Search": "https://www.bing.com/visualsearch", "Yandex Images": "https://yandex.com/images/",
                 "TinEye": "https://tineye.com/"}
        con.print(kv(list(links.items()) + [("Ta photo", f or "—")], "🔎 Glisse ta photo dans chaque page", G))
        con.print(f"[{M}]Astuce : recadre sur l'élément intéressant (bâtiment, logo, objet) pour de meilleurs résultats. Yandex est souvent le meilleur pour les lieux.")
        open_links(list(links.values()))
    pause()


# ---------- 📹 Webcams publiques autour d'un lieu (vérification météo / lieu)
def mod_webcams():
    con.rule(f"[{G}]📹 WEBCAMS PUBLIQUES D'UN LIEU")
    con.print(f"[{M}]Webcams officielles (météo, tourisme, stations, ports) pour vérifier un lieu : météo, lumière, décor.")
    s = ask_text("Lieu (ville, adresse ou coordonnées)").strip()
    if not s:
        return
    c = parse_coords(s)
    if not c:
        log("Lieu introuvable.", Y)
        return pause()
    lat, lon = c
    r = int(ask_num("Rayon en km (max 250)", "30") or 30)
    key = api_key("windy", "https://api.windy.com/keys (Webcams API)")
    links = {"Carte Windy des webcams": f"https://www.windy.com/-Webcams/webcams?{lat:.4f},{lon:.4f},10",
             "Google Maps « webcam »": f"https://www.google.com/maps/search/webcam/@{lat},{lon},12z",
             "SkylineWebcams": "https://www.skylinewebcams.com/", "EarthCam": "https://www.earthcam.com/", "Webcamtaxi": "https://www.webcamtaxi.com/"}
    if not key:
        con.print(kv(list(links.items()), "📹 Webcams (sans clé : liens)", G))
        open_links([list(links.values())[0]])
        return pause()
    with con.status(f"[{P}]Recherche des webcams…", spinner="dots12"):
        j = get_json(f"https://api.windy.com/webcams/api/v3/webcams?nearby={lat},{lon},{min(r, 250)}&limit=50&include=location,images,player,urls",
                     20, headers={"x-windy-api-key": key})
    cams = j.get("webcams", [])
    if not cams:
        log("Aucune webcam dans ce rayon. Agrandis-le.", Y)
        return pause()
    rows, marks = [], []
    for w in cams:
        loc = w.get("location", {})
        url = (w.get("urls") or {}).get("detail") or f"https://www.windy.com/webcams/{w.get('webcamId')}"
        live = (w.get("player") or {}).get("live") or (w.get("player") or {}).get("day") or url
        img = ((w.get("images") or {}).get("current") or {}).get("preview", "")
        rows.append([w.get("title", "?"), loc.get("city", ""), url])
        marks.append({"lat": loc.get("latitude"), "lon": loc.get("longitude"), "c": "#00e5ff",
                      "label": f"<b>{escape_html(w.get('title', ''))}</b><br>{'<img src=' + chr(34) + img + chr(34) + ' width=240><br>' if img else ''}<a href='{live}' target=_blank>▶ direct / journée</a> · <a href='{url}' target=_blank>fiche</a>"})
    marks.append({"lat": lat, "lon": lon, "icon": "✚", "c": "#ff5c7a", "label": "Lieu recherché"})
    table_pages(f"📹 {len(cams)} webcams", ["Webcam", "Ville", "Lien"], rows)
    save_open("webcams", theme_html(quick_map(f"Webcams · {s}", marks)))
    add_report("mod_webcams", f"Webcams autour de {s}", "\n".join(f"{a} ({b}) {u}" for a, b, u in rows))
    pause()


# ---------- comptes liés à un email : vérifs maison (rapides) + Holehe (complet)
_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"}
NSFW_DOM = ("xvideos", "pornhub", "xnxx", "xhamster", "redtube", "youporn", "onlyfans")


def _acc_duo(e):
    u = get_json("https://www.duolingo.com/2017-06-30/users", 12, params={"email": e, "fields": "users{username}"}, headers=_UA).get("users") or []
    return (True, u[0].get("username") or "") if u else (False, "")


def _acc_chess(e):
    return get_json("https://www.chess.com/callback/email/available", 12, params={"email": e}, headers=_UA).get("isEmailAvailable") is False, ""


def _acc_spotify(e):
    return get_json("https://spclient.wg.spotify.com/signup/public/v1/account", 12, params={"validate": 1, "email": e}, headers=_UA).get("status") == 20, ""


def _acc_wp(e):
    t = get(f"https://public-api.wordpress.com/rest/v1.1/users/{_q(e)}/auth-options", 12, headers=_UA).text
    if "unknown_user" in t:
        return False, ""
    return ("email_login_not_allowed" in t or "passwordless" in t), ""


def _acc_x(e):
    return get_json("https://api.twitter.com/i/users/email_available.json", 12, params={"email": e}, headers=_UA).get("taken") is True, ""


def _acc_adobe(e):
    r = HTTP.post("https://auth.services.adobe.com/signin/v2/users/accounts", json={"username": e}, timeout=12,
                  headers=_UA | {"X-IMS-ClientId": "adobedotcom2", "Content-Type": "application/json"})
    return bool(r.ok and r.json()), ""


def _acc_gravatar(e):
    return get(f"https://gravatar.com/avatar/{hashlib.md5(e.lower().encode()).hexdigest()}?d=404", 10).status_code == 200, ""


ACC_CHECKS = [("Gravatar", "gravatar.com", _acc_gravatar), ("Duolingo", "duolingo.com", _acc_duo), ("Chess.com", "chess.com", _acc_chess),
              ("Spotify", "spotify.com", _acc_spotify), ("WordPress", "wordpress.com", _acc_wp), ("X / Twitter", "x.com", _acc_x), ("Adobe", "adobe.com", _acc_adobe)]


def holehe_run(e):
    """Holehe lancé directement dans l'outil (pas de sous-programme). None si Holehe n'est pas installé."""
    try:
        import trio
        import httpx
        from holehe.core import import_submodules, get_functions, launch_module
    except Exception:
        return None
    import contextlib
    webs = get_functions(import_submodules("holehe.modules"))

    async def go():
        out = []
        c = httpx.AsyncClient(timeout=12)
        async with trio.open_nursery() as n:
            for w in webs:
                n.start_soon(launch_module, w, e, c, out)
        await c.aclose()
        return out
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return trio.run(go)


def email_accounts(e, deep=True):
    """Renvoie (trouvés [(site, détail)], sites bloqués, sites testés, holehe_ok)."""
    found, seen, limited, checked = [], set(), 0, 0
    with _TPE(8) as ex:
        for (name, dom, fn), res in zip(ACC_CHECKS, ex.map(lambda x: _safe(x[2], e), ACC_CHECKS)):
            checked += 1
            if res is None:
                limited += 1
            elif res[0]:
                found.append((dom, res[1] and f"pseudo : {res[1]}"))
                seen.add(dom.split(".")[0])
    hol = holehe_run(e) if deep else None
    for o in hol or []:
        dom = o.get("domain", "")
        key = "x" if dom.startswith("twitter") else dom.split(".")[0]
        if key in seen or any(n in dom for n in NSFW_DOM):
            continue
        checked += 1
        if o.get("rateLimit"):
            limited += 1
        elif o.get("exists"):
            seen.add(key)
            extra = " · ".join(x for x in (o.get("emailrecovery") and f"email de secours : {o['emailrecovery']}",
                                            o.get("phoneNumber") and f"téléphone : {o['phoneNumber']}") if x)
            found.append((dom, extra))
    return found, limited, checked, hol is not None


def accounts_panel(e, found, limited, checked):
    t = Table(box=box.ROUNDED, border_style="#2b3158", header_style="bold #00e5ff", title=f"Comptes liés à {e}", title_justify="left", expand=True)
    t.add_column("Site")
    t.add_column("Détail", overflow="fold")
    for d, x in sorted(found):
        t.add_row(d, x or "")
    if not found:
        t.add_row("aucun compte trouvé", "")
    t.caption = f"{checked} sites testés · {len(found)} trouvé(s) · {limited} n'ont pas répondu ou ont bloqué"
    return t


def mod_holehe():
    con.rule(f"[{G}]📬 EMAIL → COMPTES")
    con.print(f"[{M}]Cherche sur quels sites un compte existe avec cet email (pages d'inscription / mot de passe oublié), sans prévenir la personne. "
              "À n'utiliser que sur ton email ou dans un cadre autorisé.")
    em = ask_text("Email").strip().lower()
    if not re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.-]+", em):
        log("Email invalide.", Y)
        return pause()
    if not _holehe_ok():
        if getattr(sys, "frozen", False):
            log("Holehe (120 sites) n'est pas dans le .exe : seuls les 7 tests rapides vont tourner. Pour tout avoir, lance avec LANCER.bat.", Y)
        elif select("Holehe (120 sites de plus) n'est pas installé. L'installer ? (≈ 20 s)", [{"label": "Installer", "value": "y"}, {"label": "Non, tests rapides seulement", "value": "n"}], echo=False) == "y":
            import subprocess as sp
            with con.status(f"[{P}]Installation de Holehe…", spinner="dots12"):
                r = sp.run([sys.executable, "-m", "pip", "install", "-q", "holehe"], capture_output=True, text=True)
            import importlib
            importlib.invalidate_caches()
            log("Holehe installé." if r.returncode == 0 else "Installation impossible. Dans un terminal : py -3.14 -m pip install holehe", G if r.returncode == 0 else Y)
    with con.status(f"[{P}]Test des sites (≈ 20-60 s)…", spinner="dots12"):
        found, limited, checked, hol = email_accounts(em, True)
    con.print(accounts_panel(em, found, limited, checked))
    if not hol:
        con.print(f"[{M}]Holehe absent : seuls {len(ACC_CHECKS)} sites ont été testés.")
    con.print(f"[{M}]Pour aller plus loin : https://epieos.com/?q={_q(em)}")
    root = gnode("email", em)
    for d, _ in found:
        gnode("compte", f"{d} · {em}", None, root, "inscrit", d)
    gsave()
    add_report("mod_holehe", f"Comptes de {em}", "\n".join(f"{d} {x}" for d, x in found) or "aucun")
    pause()


def _holehe_ok():
    try:
        import importlib.util
        return importlib.util.find_spec("holehe") is not None
    except Exception:
        return False


LEAK_FR = {"Email addresses": "emails", "Passwords": "mots de passe", "Usernames": "pseudos", "Names": "noms", "IP addresses": "adresses IP",
           "Phone numbers": "téléphones", "Dates of birth": "dates de naissance", "Physical addresses": "adresses postales", "Geographic locations": "localisations",
           "Genders": "genres", "Credit card details": "cartes bancaires", "Social media profiles": "réseaux sociaux", "Job titles": "postes", "Employers": "employeurs"}


def leak_fr(s):
    return ", ".join(LEAK_FR.get(x.strip(), x.strip()) for x in str(s or "").split(";") if x.strip())



# ---------- 🌾 Récolte d'un domaine (façon theHarvester)
def mod_harvest():
    con.rule(f"[{G}]🌾 RÉCOLTE D'UN DOMAINE (façon theHarvester)")
    d = _dom(ask_text("Domaine (ex : exemple.fr)"))
    if "." not in d:
        return
    subs, emails, people = set(), set(), []

    def crt():
        for c in get_json(f"https://crt.sh/?q=%25.{d}&output=json", 40):
            subs.update(x.strip().lower().lstrip("*.") for x in c.get("name_value", "").split("\n"))

    def ht():
        t = get(f"https://api.hackertarget.com/hostsearch/?q={d}", 25).text
        if "API count" not in t:
            subs.update(l.split(",")[0].lower() for l in t.splitlines() if l)

    def cs():
        for c in get_json(f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names", 25):
            subs.update(n.lower().lstrip("*.") for n in c.get("dns_names", []))

    def pages():
        for p in ("", "contact", "contact-us", "nous-contacter", "mentions-legales", "legal", "a-propos", "about", "impressum", "equipe", "team"):
            try:
                h = get(f"https://{d}/{p}", 10).text
                emails.update(e.lower() for e in extract_iocs(html_text(h) + " " + h).get("Emails", []))
            except Exception:
                pass

    def hunter():
        k = CFG.get("keys", {}).get("hunter")
        if k:
            for e in get_json(f"https://api.hunter.io/v2/domain-search?domain={d}&limit=50&api_key={k}", 20).get("data", {}).get("emails", []):
                emails.add(e["value"].lower())
                people.append([e["value"], f"{e.get('first_name') or ''} {e.get('last_name') or ''}".strip(), e.get("position") or "", f"{e.get('confidence', '')} %"])
    api_key("hunter", "https://hunter.io/api-keys (50 recherches / mois)")
    with con.status(f"[{P}]Récolte : certificats, HackerTarget, CertSpotter, pages du site, Hunter…", spinner="dots12"):
        with cf.ThreadPoolExecutor(5) as ex:
            for f in [ex.submit(x) for x in (crt, ht, cs, pages, hunter)]:
                try:
                    f.result()
                except Exception:
                    pass
    subs = sorted(s for s in subs if s.endswith(d) and s != d and " " not in s and "@" not in s)
    try:
        mx = dns(d, "MX")
    except Exception:
        mx = []
    con.print(kv([("Sous-domaines", len(subs)), ("Emails", ", ".join(sorted(emails)) or "aucun"), ("Serveurs mail (MX)", ", ".join(map(str, mx)) or "?")], f"🌾 {d}", G))
    if people:
        table_pages("👤 Personnes (Hunter)", ["Email", "Nom", "Poste", "Confiance"], people)
    if subs:
        table_pages(f"🌐 {len(subs)} sous-domaines", ["Sous-domaine"], [[s] for s in subs])
    root = gnode("domaine", d)
    for s in subs[:60]:
        gnode("domaine", s, None, root, "sous-domaine")
    for e in emails:
        gnode("email", e, None, root, "email")
    gsave()
    add_report("mod_harvest", f"Récolte {d}", f"Emails : {', '.join(sorted(emails))}\nSous-domaines ({len(subs)}) : {', '.join(subs[:200])}")
    pause()


# ---------- 📸 URLScan.io
def mod_urlscan():
    con.rule(f"[{G}]📸 URLSCAN.IO")
    t = ask_text("Domaine ou lien").strip()
    if not t:
        return
    host = _dom(t)
    c = select("Action", [{"label": "📚 Scans existants", "value": "s", "desc": "historique public, captures d'écran"},
                          {"label": "🚀 Nouveau scan", "value": "n", "desc": "clé gratuite urlscan.io"}])
    if c is None:
        return
    if c == "n":
        k = api_key("urlscan", "https://urlscan.io/user/profile/ (onglet API)")
        if not k:
            return pause()
        r = HTTP.post("https://urlscan.io/api/v1/scan/", headers={"API-Key": k}, json={"url": t if t.startswith("http") else "https://" + t, "visibility": "unlisted"}, timeout=20)
        if r.status_code >= 400:
            log(f"urlscan a refusé : {r.json().get('message', r.status_code)}", Y)
            return pause()
        uid = r.json()["uuid"]
        res = None
        with con.status(f"[{P}]Scan en cours (≈ 20 s)…", spinner="dots12"):
            for _ in range(20):
                time.sleep(4)
                rr = get(f"https://urlscan.io/api/v1/result/{uid}/", 15)
                if rr.status_code == 200:
                    res = rr.json()
                    break
        if not res:
            log(f"Pas encore fini : https://urlscan.io/result/{uid}/", Y)
            return pause()
        p, v = res.get("page", {}), res.get("verdicts", {}).get("overall", {})
        con.print(kv([("URL finale", p.get("url")), ("IP", p.get("ip")), ("Pays", p.get("country")), ("Serveur", p.get("server")), ("Titre", p.get("title")),
                      ("Verdict", "⚠ malveillant" if v.get("malicious") else "rien de signalé"), ("Requêtes", len(res.get("data", {}).get("requests", []))),
                      ("Domaines contactés", ", ".join(res.get("lists", {}).get("domains", [])[:25])), ("Capture", f"https://urlscan.io/screenshots/{uid}.png"),
                      ("Rapport", f"https://urlscan.io/result/{uid}/")], f"📸 {host}", R_STYLE if v.get("malicious") else G))
        add_report("mod_urlscan", f"urlscan {host}", f"https://urlscan.io/result/{uid}/")
        return pause()
    j = get_json(f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=100", 20)
    rs = j.get("results", [])
    if not rs:
        log("Aucun scan public pour ce domaine.", Y)
        return pause()
    rows = [[x.get("task", {}).get("time", "")[:16].replace("T", " "), x.get("page", {}).get("url", "")[:70], x.get("page", {}).get("ip", ""),
             x.get("page", {}).get("country", ""), f"https://urlscan.io/result/{x.get('_id')}/"] for x in rs]
    table_pages(f"📚 {len(rs)} scans de {host}", ["Date", "URL", "IP", "Pays", "Rapport"], rows)
    ips = sorted({r_[2] for r_ in rows if r_[2]})
    root = gnode("domaine", host)
    for ip in ips[:30]:
        gnode("ip", ip, None, root, "urlscan")
    gsave()
    add_report("mod_urlscan", f"urlscan {host}", "\n".join(" · ".join(r_) for r_ in rows[:50]))
    if rs[0].get("screenshot") and select("Ouvrir la capture la plus récente ?", [{"label": "Oui", "value": "y"}, {"label": "Non", "value": "n"}], echo=False) == "y":
        webbrowser.open(rs[0]["screenshot"])
    pause()


# ---------- ⚡ Scan auto (façon SpiderFoot) : toutes les transformations du graphe d'un coup
def target_type(v):
    v = v.strip()
    if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.-]+", v):
        return "email"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v) or (":" in v and re.fullmatch(r"[0-9a-fA-F:]+", v)):
        return "ip"
    if v.startswith("http"):
        return "url"
    if re.fullmatch(r"-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+", v):
        return "lieu"
    if re.fullmatch(r"([\w-]+\.)+[a-zA-Z]{2,}", v):
        return "domaine"
    if " " in v:
        return "personne"
    return "pseudo"


def mod_autoscan():
    con.rule(f"[{G}]⚡ SCAN AUTO (façon SpiderFoot)")
    con.print(f"[{M}]Donne une cible (pseudo, email, domaine, IP, lien, « Prénom Nom », coordonnées) : l'outil lance toutes les recherches possibles, "
              "puis recommence sur ce qu'il trouve, et remplit le graphe.")
    v = ask_text("Cible").strip()
    if not v:
        return
    typ = target_type(v)
    deep = select(f"Type détecté : {typ}. Profondeur ?", [{"label": "1 · rapide", "value": 1, "desc": "la cible seulement"},
                                                          {"label": "2 · complet", "value": 2, "desc": "+ ce qui est trouvé (plus long)"}], echo=False)
    if deep is None:
        return
    g = gload()
    root = gnode(typ, v, None, "enquete:" + g["name"])
    gsave()
    todo, done, total = [(root, 1)], set(), 0
    while todo:
        nid, lvl = todo.pop(0)
        if nid in done:
            continue
        done.add(nid)
        n = gload()["nodes"].get(nid)
        if not n:
            continue
        before = set(gload()["nodes"])
        for t, lab in TRANSFORMS.get(n["type"], []):
            if t == "wmn" and lvl > 1:
                continue
            with con.status(f"[{P}]{n['label'][:40]} → {lab}…", spinner="dots12"):
                try:
                    added, _ = graph_transform(gname(), nid, t)
                except Exception:
                    added = 0
            total += added
            log(f"{n['label'][:40]} → {lab} : +{added}", G if added else M)
        if lvl < deep:
            new = [k for k in gload()["nodes"] if k not in before]
            todo += [(k, lvl + 1) for k in new if gload()["nodes"][k]["type"] in ("email", "domaine", "pseudo", "ip")][:15]
    con.print(kv([("Cible", f"{v} ({typ})"), ("Éléments ajoutés", total), ("Recherches lancées", len(done))], "⚡ Scan terminé", G))
    add_report("mod_autoscan", f"Scan auto {v}", f"{total} éléments ajoutés au graphe")
    if select("Ouvrir le graphe ?", [{"label": "🧬 Oui", "value": "y"}, {"label": "Non", "value": "n"}], echo=False) == "y":
        app_window(graph_url())
    pause()


# ---------- 🗂 Sources pro (Censys, Hunter, IntelX, DeHashed, Epieos, OSINT Framework…)
def mod_prosrc():
    con.rule(f"[{G}]🗂 SOURCES PRO")
    v = ask_text("Cible (email, domaine, IP, pseudo, téléphone…)").strip()
    if not v:
        return
    t, q = target_type(v), _q(v, safe="")
    L = []
    if t == "email":
        L += [("Epieos (compte Google, Skype…)", f"https://epieos.com/?q={q}"), ("Hunter (vérifier l'email)", f"https://hunter.io/email-verifier/{q}"),
              ("Have I Been Pwned", f"https://haveibeenpwned.com/account/{q}")]
    if t in ("domaine", "url", "email"):
        d = _dom(v.split("@")[-1])
        L += [("Hunter (emails du domaine)", f"https://hunter.io/search/{d}"), ("Censys (certificats)", f"https://search.censys.io/certificates?q={d}"),
              ("SecurityTrails (DNS historique)", f"https://securitytrails.com/domain/{d}/history/a"), ("VirusTotal", f"https://www.virustotal.com/gui/domain/{d}"),
              ("BuiltWith (technos)", f"https://builtwith.com/{d}"), ("DNSDumpster", "https://dnsdumpster.com/")]
    if t == "ip":
        L += [("Censys", f"https://search.censys.io/hosts/{v}"), ("Shodan", f"https://www.shodan.io/host/{v}"), ("GreyNoise", f"https://viz.greynoise.io/ip/{v}"),
              ("AbuseIPDB", f"https://www.abuseipdb.com/check/{v}")]
    if t == "pseudo":
        L += [("Google (pseudo exact)", f"https://www.google.com/search?q=%22{q}%22"), ("IDCrawl", f"https://www.idcrawl.com/u/{q}")]
    L += [("Intelligence X", f"https://intelx.io/?s={q}"), ("DeHashed (payant)", f"https://dehashed.com/search?query={q}"),
          ("OSINT Framework (annuaire)", "https://osintframework.com/"), ("Bellingcat Toolkit", "https://bellingcat.gitbook.io/toolkit")]
    con.print(kv(L, f"🗂 {v} ({t})", G))
    open_links([u for _, u in L])
    pause()


# ============================================================ v6.3 : BODACC, IBAN, VIN, MAC, URLs archivées
def mod_bodacc():
    con.rule(f"[{G}]📰 ANNONCES LÉGALES (BODACC)")
    q = ask_text("Nom d'entreprise, de dirigeant, ou SIREN").strip()
    if not q:
        return
    with con.status(f"[{P}]Recherche au BODACC…", spinner="dots12"):
        j = get_json("https://bodacc-datadila.opendatasoft.com/api/explore/v2.1/catalog/datasets/annonces-commerciales/records", 25,
                     params={"where": f'search("{q.replace(chr(34), "")}")', "limit": 50, "order_by": "dateparution desc"})
    rs = j.get("results", [])
    if not rs:
        log("Aucune annonce trouvée.", Y)
        return pause()
    rows = []
    for r in rs:
        reg = r.get("registre")
        rows.append([str(r.get("dateparution", "")), str(r.get("familleavis_lib") or r.get("typeavis_lib") or ""), str(r.get("commercant") or "")[:44],
                     f"{r.get('cp') or ''} {r.get('ville') or ''}".strip(), (reg[0] if isinstance(reg, list) and reg else str(reg or ""))[:11], str(r.get("tribunal") or "")[:34]])
    table_pages(f"📰 {j.get('total_count', len(rs))} annonce(s) · {q}", ["Date", "Type", "Entreprise", "Ville", "SIREN", "Tribunal"], rows)
    con.print(f"[{M}]Détail de chaque annonce : https://www.bodacc.fr/pages/annonces-commerciales/?q={_q(q)}")
    root = gnode("organisation" if not q.isdigit() else "organisation", q)
    for r in rows[:15]:
        if r[2]:
            gnode("organisation", r[2], {"ville": r[3], "SIREN": r[4], "dernière annonce": f"{r[0]} · {r[1]}"}, root, "BODACC")
    gsave()
    add_report("mod_bodacc", f"BODACC {q}", "\n".join(" · ".join(r) for r in rows[:40]))
    pause()


IBAN_LEN = {"FR": 27, "DE": 22, "ES": 24, "IT": 27, "BE": 16, "NL": 18, "LU": 20, "CH": 21, "GB": 22, "PT": 25, "IE": 22, "AT": 20, "MC": 27, "PL": 28, "LT": 20, "EE": 20, "MT": 31, "CY": 28, "BG": 22, "RO": 24}
FR_BANKS = {"30004": "BNP Paribas", "30003": "Société Générale", "30002": "LCL", "30006": "Crédit Agricole (siège)", "20041": "La Banque Postale", "10278": "Crédit Mutuel",
            "30066": "CIC", "10907": "Banque Populaire", "12548": "Axa Banque", "16958": "Qonto", "28233": "Revolut", "16598": "Nickel", "40618": "Boursorama",
            "17515": "Caisse d'Épargne", "30056": "HSBC France", "14518": "Fortuneo", "16798": "Shine", "27190": "Lydia / Sumeria", "23605": "Treezor"}


def mod_iban():
    con.rule(f"[{G}]🏦 IBAN")
    s = re.sub(r"\s+", "", ask_text("IBAN")).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        log("Ce n'est pas un IBAN (2 lettres, 2 chiffres, puis le compte).", Y)
        return pause()
    result = validate_iban(s, IBAN_LEN, FR_BANKS)
    rows = [("IBAN", " ".join(result.value[i:i + 4] for i in range(0, len(result.value), 4))),
            ("Clé de contrôle", "valide" if result.checksum_valid else "FAUSSE : IBAN mal recopié ou inventé"),
            ("Pays", result.country), ("Longueur", f"{result.length}" + (f" (attendu {result.expected_length})" if result.expected_length and not result.length_valid else " (correcte)" if result.expected_length else " (pays non référencé)"))]
    if result.bank_code:
        rows += [("Code banque", result.bank_code + (f" · {result.bank_name}" if result.bank_name else "")), ("Code guichet", s[9:14]), ("N° de compte", s[14:25]), ("Clé RIB", s[25:27])]
    try:
        b = get_json(f"https://openiban.com/validate/{s}?getBIC=true&validateBankCode=true", 10).get("bankData", {})
        if b.get("name") or b.get("bic"):
            rows += [("Banque", b.get("name")), ("BIC", b.get("bic")), ("Ville", b.get("city"))]
    except Exception:
        pass
    ok = result.structurally_valid
    rows.append(("Verdict local", "structure et clé cohérentes" if ok else "invalide : longueur ou clé incohérente"))
    con.print(kv(rows, "🏦 IBAN", G if ok else R_STYLE))
    con.print(f"[{M}]Un IBAN valide ne prouve pas que le compte appartient à la personne : en cas de doute (faux RIB), appelle l'entreprise sur un numéro que tu connais déjà.")
    add_report("mod_iban", "IBAN", "\n".join(f"{k} : {v}" for k, v in rows if v))
    pause()


VIN_REG = {"1": "États-Unis", "2": "Canada", "3": "Mexique", "4": "États-Unis", "5": "États-Unis", "J": "Japon", "K": "Corée du Sud", "L": "Chine", "S": "Royaume-Uni",
           "T": "Suisse / Tchéquie / Hongrie", "V": "France / Espagne", "W": "Allemagne", "Y": "Suède / Finlande", "Z": "Italie", "U": "Roumanie", "N": "Turquie", "9": "Brésil"}
VIN_WMI = {"VF1": "Renault", "VF3": "Peugeot", "VF7": "Citroën", "VF6": "Renault Trucks", "VR1": "DS", "VR3": "Peugeot", "VR7": "Citroën", "WVW": "Volkswagen", "WAU": "Audi", "WBA": "BMW",
           "WDB": "Mercedes-Benz", "WDD": "Mercedes-Benz", "W0L": "Opel", "WP0": "Porsche", "ZFA": "Fiat", "ZAR": "Alfa Romeo", "ZFF": "Ferrari", "VSS": "Seat", "TMB": "Škoda",
           "JTD": "Toyota", "JHM": "Honda", "JN1": "Nissan", "KMH": "Hyundai", "KNA": "Kia", "5YJ": "Tesla", "7SA": "Tesla", "XP7": "Tesla (Berlin)", "LRW": "Tesla (Shanghai)",
           "UU1": "Dacia", "SAL": "Land Rover", "SAJ": "Jaguar", "YV1": "Volvo", "WF0": "Ford (Allemagne)", "1FA": "Ford", "1G1": "Chevrolet", "VNK": "Toyota (France)"}


def mod_vin():
    con.rule(f"[{G}]🚗 NUMÉRO DE SÉRIE D'UN VÉHICULE (VIN)")
    v = re.sub(r"[\s-]", "", ask_text("VIN (17 caractères, sur la carte grise case E ou le pare-brise)")).upper()
    result = decode_vin(v, VIN_REG, VIN_WMI)
    if not result.valid_format:
        log("Un VIN fait 17 caractères, sans les lettres I, O et Q.", Y)
        return pause()
    check_label = "valide" if result.check_digit_valid is True else "invalide" if result.check_digit_valid is False else "non applicable / non déterminable"
    rows = [("VIN", result.value), ("Contrôle de cohérence", check_label), ("Constructeur (WMI)", f"{v[:3]} · {result.manufacturer or 'inconnu de ma liste'}"), ("Zone de fabrication", result.region or "?"),
            ("Année-modèle (10e caractère)", result.model_year or "?"), ("Usine (11e caractère)", v[10]), ("N° de série", result.serial_number or "?")]
    try:
        with con.status(f"[{P}]Base NHTSA…", spinner="dots12"):
            d = get_json(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{v}?format=json", 20)["Results"][0]
        for k, lab in (("Make", "Marque"), ("Model", "Modèle"), ("ModelYear", "Année"), ("Manufacturer", "Fabricant"), ("PlantCountry", "Pays de l'usine"), ("PlantCity", "Ville de l'usine"),
                       ("VehicleType", "Type"), ("BodyClass", "Carrosserie"), ("FuelTypePrimary", "Énergie"), ("EngineCylinders", "Cylindres"), ("DisplacementL", "Cylindrée (L)")):
            if d.get(k):
                rows.append((lab, d[k]))
    except Exception:
        rows.append(("Base NHTSA", "pas de réponse"))
    con.print(kv(rows, f"🚗 {v}", G))
    con.print(f"[{M}]La base NHTSA est américaine : complète pour les modèles vendus aux États-Unis, partielle pour les autres. "
              "Historique d'un véhicule français : https://histovec.interieur.gouv.fr (avec le propriétaire).")
    add_report("mod_vin", f"VIN {v}", "\n".join(f"{k} : {x}" for k, x in rows))
    pause()


def mod_mac():
    con.rule(f"[{G}]🔌 ADRESSE MAC → FABRICANT")
    m = re.sub(r"[^0-9A-Fa-f]", "", ask_text("Adresse MAC (ex : 44:38:39:ff:ef:57)")).upper()
    if len(m) < 6:
        log("Il faut au moins les 6 premiers caractères.", Y)
        return pause()
    b = int(m[:2], 16)
    rows = [("MAC", ":".join(m[i:i + 2] for i in range(0, len(m), 2))), ("Préfixe (OUI)", m[:6]),
            ("Type", "adresse aléatoire / privée (téléphone récent, VM) : pas de fabricant fiable" if b & 2 else "adresse d'usine, unique au monde"),
            ("Diffusion", "multicast (groupe)" if b & 1 else "unicast (un seul appareil)")]
    if not b & 2:
        try:
            r = get(f"https://api.macvendors.com/{m[:6]}", 10)
            rows.append(("Fabricant", r.text.strip() if r.status_code == 200 else "inconnu"))
        except Exception:
            rows.append(("Fabricant", "pas de réponse"))
    con.print(kv(rows, "🔌 Adresse MAC", G))
    add_report("mod_mac", "MAC", "\n".join(f"{k} : {v}" for k, v in rows))
    pause()


def mod_wayurls():
    con.rule(f"[{G}]🗃 FICHIERS ARCHIVÉS D'UN DOMAINE")
    d = _dom(ask_text("Domaine (ex : exemple.fr)"))
    if "." not in d:
        return
    c = select("Chercher…", [{"label": "📄 Documents", "value": r"(pdf|docx?|xlsx?|pptx?|csv|txt)", "desc": "pdf, word, excel, csv"},
                             {"label": "🗝 Fichiers sensibles", "value": r"(sql|bak|old|zip|tar|gz|env|log|conf|ini|json|xml|yml)", "desc": "sauvegardes, config, logs"},
                             {"label": "🌐 Toutes les pages", "value": "", "desc": "liste des adresses connues"}])
    if c is None:
        return
    p = {"url": f"{d}/*", "fl": "timestamp,original,mimetype", "collapse": "urlkey", "limit": 2000, "output": "json"}
    if c:
        p["filter"] = rf"original:.*\.{c}(\?.*)?$"
    try:
        with con.status(f"[{P}]Wayback Machine (peut prendre 30 s)…", spinner="dots12"):
            rs = get_json("https://web.archive.org/cdx/search/cdx", 60, params=p)[1:]
    except Exception as e:
        log(f"La Wayback Machine ne répond pas ({sl_err(e) if 'sl_err' in globals() else e}). Réessaie dans une minute.", Y)
        return pause()
    if not rs:
        log("Rien d'archivé pour ce filtre.", Y)
        return pause()
    rows = [[f"{t[:4]}-{t[4:6]}-{t[6:8]}", u[:90], f"https://web.archive.org/web/{t}/{u}"] for t, u, _ in rs]
    table_pages(f"🗃 {len(rows)} adresse(s) archivée(s) · {d}", ["Archivé le", "Adresse", "Copie"], rows)
    f = OUT / f"archives_{d.replace('.', '_')}.csv"
    f.write_text("﻿date;adresse;copie\n" + "\n".join(";".join(r) for r in rows), encoding="utf-8")
    log(f"Liste complète : {f}", G)
    add_report("mod_wayurls", f"Fichiers archivés {d}", "\n".join(r[1] for r in rows[:80]))
    pause()


TUTOS = {
"mod_bodacc": """### 🎯 À quoi ça sert
Chercher dans le **BODACC**, le bulletin officiel des annonces légales : créations, ventes, changements de dirigeant, redressements et liquidations d'entreprises françaises.
### 🧰 Ce qu'il te faut
Un **nom d'entreprise**, un **nom de dirigeant** ou un **SIREN** (9 chiffres).
### ▶ Étapes
1. Tape le nom ou le SIREN.
2. Les annonces sortent de la plus récente à la plus ancienne (n / p pour les pages).
### 💡 Astuces
- Une **liquidation** ou un **redressement** récent sur un vendeur en ligne est un signal d'alerte.
- Chercher un nom de personne montre les sociétés où elle apparaît.""",
"mod_iban": """### 🎯 À quoi ça sert
Vérifier un **IBAN** avant un virement : clé de contrôle, pays, banque, guichet. Utile contre les **faux RIB**.
### 🧰 Ce qu'il te faut
L'IBAN (les espaces ne gênent pas).
### ▶ Étapes
1. Colle l'IBAN.
2. Lis la clé (valide ou fausse), le pays et la banque.
### 💡 Astuces
- Un pays inattendu (ex : un artisan français avec un IBAN LT ou MT) doit te faire vérifier.
- Un IBAN valide ne prouve pas à qui est le compte : rappelle l'entreprise sur un numéro connu.""",
"mod_vin": """### 🎯 À quoi ça sert
Décoder le **numéro de série d'un véhicule (VIN)** : constructeur, pays, année, modèle. Utile pour vérifier une annonce de voiture d'occasion.
### 🧰 Ce qu'il te faut
Le VIN de 17 caractères : case **E** de la carte grise, bas du pare-brise ou montant de porte.
### ▶ Étapes
1. Tape le VIN.
2. Compare avec l'annonce : marque, année, énergie.
### 💡 Astuces
- Un VIN qui ne correspond pas à l'annonce = fuis.
- Historique officiel en France : HistoVec (demande le rapport au vendeur).""",
"mod_mac": """### 🎯 À quoi ça sert
Trouver le **fabricant d'un appareil** à partir de son adresse MAC (box, caméra, téléphone, objet connecté inconnu sur ton Wi-Fi).
### 🧰 Ce qu'il te faut
L'adresse MAC : dans l'interface de ta box (appareils connectés) ou les réglages de l'appareil.
### ▶ Étapes
1. Colle l'adresse.
2. Lis le fabricant et le type d'adresse.
### 💡 Astuces
- Les téléphones récents utilisent une adresse **aléatoire** par réseau : pas de fabricant, c'est normal.
- Un fabricant de caméras inconnu sur ton Wi-Fi mérite une vérification.""",
"mod_wayurls": """### 🎯 À quoi ça sert
Lister les **fichiers et pages d'un site gardés par la Wayback Machine** : vieux PDF, tableaux, sauvegardes oubliées, pages supprimées.
### 🧰 Ce qu'il te faut
Un **domaine** (ex : `exemple.fr`).
### ▶ Étapes
1. Tape le domaine, choisis le type de fichiers.
2. Ouvre la colonne « Copie » pour voir le fichier tel qu'il était.
3. La liste complète est enregistrée en CSV (Excel).
### 💡 Astuces
- Les documents contiennent souvent des noms, emails et métadonnées : passe-les dans le module Métadonnées.
- Ne consulte que ce qui est public : pas de connexion à des espaces privés.""",

"mod_revimg": """### 🎯 À quoi ça sert
Retrouver **où une image apparaît sur internet** : l'original, sa première publication, ses copies recadrées. Comme Google Lens, sur 6 moteurs à la fois.
### 🧰 Ce qu'il te faut
- Soit le **lien direct de l'image** : clic droit sur l'image → *Copier l'adresse de l'image*.
- Soit la **photo sur ton PC** : l'outil ouvre les moteurs, tu glisses la photo dedans.
### ▶ Étapes
1. Choisis *Sur internet* ou *Sur mon PC*.
2. Colle le lien → les pages de résultats s'ouvrent.
### 💡 Astuces
- **Yandex** est souvent le meilleur pour les lieux et bâtiments, **TinEye** pour trouver la date la plus ancienne.
- Recadre sur un détail (bâtiment, logo, objet) pour de meilleurs résultats.
- Les moteurs reçoivent l'image : n'y mets pas de photo privée.""",
"mod_webcams": """### 🎯 À quoi ça sert
Trouver les **webcams publiques officielles** autour d'un lieu (météo, tourisme, stations de ski, ports) pour **vérifier un lieu** : météo, lumière, décor, comparaison avec une photo.
### 🧰 Ce qu'il te faut
- Un **lieu** (ville, adresse ou coordonnées).
- Facultatif : une **clé gratuite Windy** (api.windy.com/keys → Webcams API) pour avoir la carte avec aperçus. Sans clé, l'outil ouvre la carte Windy.
### ▶ Étapes
1. Tape le lieu et le rayon.
2. Avec clé : liste + carte avec aperçu et lecteur de chaque webcam (direct ou time-lapse de la journée).
### 💡 Astuces
- Le **time-lapse de la journée** permet de comparer la météo à l'heure d'une photo.
- À utiliser pour vérifier un lieu, pas pour suivre des personnes.""",
"mod_holehe": """### 🎯 À quoi ça sert
Savoir **sur quels sites un email a un compte** (Instagram, Spotify, Amazon…), comme l'outil **Holehe**. La personne n'est pas prévenue.
### 🧰 Ce qu'il te faut
- Un **email**.
- Rien d'autre : 7 sites sont testés directement (Gravatar, Duolingo, Chess.com, Spotify, WordPress, X, Adobe).
- Pour **120 sites de plus**, l'outil propose d'installer **Holehe** tout seul (version Python, pas le .exe).
### ▶ Étapes
1. Tape l'email.
2. Attends 20 à 60 s : la liste des sites où un compte existe s'affiche (avec email / téléphone de secours partiels quand le site les montre) et va dans le graphe.
### 💡 Astuces
- Certains sites bloquent les tests répétés : ils sont comptés à part.
- Continue avec **Epieos** (lien donné) pour le compte Google.
- Reste dans un cadre légal : ton email, ou une enquête autorisée.""",
"mod_harvest": """### 🎯 À quoi ça sert
Récolter tout ce qui est public sur un **domaine**, comme **theHarvester** : sous-domaines, emails, serveurs mail, personnes (avec Hunter).
### 🧰 Ce qu'il te faut
- Un **domaine** (ex : `exemple.fr`).
- Facultatif : une **clé Hunter.io** gratuite (50 recherches / mois) pour les noms et postes.
### ▶ Étapes
1. Tape le domaine.
2. L'outil interroge les certificats SSL, HackerTarget, CertSpotter, les pages contact / mentions légales du site, et Hunter.
### 💡 Astuces
- Les sous-domaines `dev`, `admin`, `vpn`, `mail` sont souvent les plus intéressants.
- Les emails trouvés donnent le **format** de l'entreprise (prenom.nom@…).""",
"mod_urlscan": """### 🎯 À quoi ça sert
Voir **ce que contient un site** sans le visiter : capture d'écran, IP, serveur, domaines contactés, verdict, avec **URLScan.io**.
### 🧰 Ce qu'il te faut
- Un **domaine ou un lien**.
- Pour un nouveau scan : une **clé gratuite urlscan.io**. L'historique public marche sans clé.
### ▶ Étapes
1. *Scans existants* : tous les scans publics du domaine (dates, IP, pays).
2. *Nouveau scan* : l'outil scanne le lien (en non listé) et donne capture + rapport.
### 💡 Astuces
- Idéal pour un **lien de phishing** : tu vois la page sans cliquer.
- Les anciennes IP du site s'ajoutent au graphe.""",
"mod_autoscan": """### 🎯 À quoi ça sert
Lancer **toutes les recherches d'un coup** sur une cible, comme **SpiderFoot** : l'outil détecte le type, lance toutes les transformations, puis recommence sur ce qu'il trouve.
### 🧰 Ce qu'il te faut
Une cible : pseudo, email, domaine, IP, lien, « Prénom Nom » ou coordonnées.
### ▶ Étapes
1. Tape la cible → le type est détecté.
2. Profondeur **1** (rapide) ou **2** (complet, plus long).
3. Ouvre le graphe pour voir la toile.
### 💡 Astuces
- Commence en profondeur 1, puis creuse à la main dans le graphe (clic droit).
- Vérifie toujours : un même pseudo n'est pas forcément la même personne.""",
"mod_prosrc": """### 🎯 À quoi ça sert
Ouvrir d'un coup les **sources pros** adaptées à ta cible : Censys, Hunter, Epieos, Intelligence X, DeHashed, SecurityTrails, GreyNoise, BuiltWith, OSINT Framework, Bellingcat…
### 🧰 Ce qu'il te faut
Une cible : email, domaine, IP, pseudo…
### ▶ Étapes
1. Tape la cible → l'outil détecte son type et prépare les bons liens.
2. *Tout ouvrir* les lance dans le navigateur.
### 💡 Astuces
- Certaines sources demandent un compte gratuit (Censys, Hunter, IntelX).
- **OSINT Framework** et **Bellingcat Toolkit** sont des annuaires d'outils à garder en favori.""",

"mod_anon": """### 🎯 À quoi ça sert
Réduire ce que les sites voient de toi : ton IP réelle est remplacée par une sortie Tor, et tu peux en changer à la demande.
**Ce n'est pas l'anonymat total** : te connecter à ton compte (Google, Instagram…) ou donner ton nom te reconnaît quand même.
### 🧰 Ce qu'il te faut
- **Tor Browser** (gratuit, officiel) : à télécharger sur torproject.org. Il lance Tor tout seul.
- Ou **Firefox** installé : l'outil le lance sur Tor, mais il est moins protégé.
- Le module **PySocks** : `pip install pysocks` (déjà dans requirements.txt).
### ▶ Étapes
1. Ouvre **Tor Browser** (ou Tor en fond).
2. **🔍 Test d'exposition** : compare ton IP réelle et ton IP via Tor. Si le statut dit « passé par Tor », c'est bon.
3. **🔄 Changer d'IP** : demande une nouvelle sortie Tor. Tor limite le rythme : attends une dizaine de secondes entre deux changements.
4. **🧅 Ouvrir un navigateur protégé** : lance Tor Browser (ou Firefox sur Tor).
5. **🧪 Tests de fuites** : ouvre les liens dans ce navigateur pour vérifier WebRTC et DNS.
### 💡 Astuces
- Ne te connecte pas à tes comptes perso dans le navigateur d'anonymat.
- Un VPN seul ne suffit pas : le fournisseur voit ton trafic. Tor sépare mieux.
- Le changement d'IP passe par le port de contrôle, que Tor Browser ouvre tout seul.""",

"mod_social": """### 🎯 À quoi ça sert
Sortir la **fiche détaillée** d'un pseudo sur 17 plateformes : date de création, bio, abonnés, liens, emails (GitHub), heures d'activité (Reddit)…
### 🧰 Ce qu'il te faut
Un **pseudo** (sans le @). Pour Mastodon : `pseudo@instance` (ex : `cat@piaille.fr`).
### 🔎 Où le trouver
- Dans l'URL du profil : `instagram.com/`**`pseudo`**, `tiktok.com/@`**`pseudo`**.
- Sur l'appli : profil → *Partager le profil* → *Copier le lien*.
- Dans une bio Linktree / un email (la partie avant le @ est souvent le pseudo).
### ▶ Étapes
1. Choisis **⚡ Toutes les plateformes** (ou une seule pour aller vite).
2. Colle le pseudo → la 1re page résume trouvé / absent, puis **n** pour voir une fiche par page.
### 💡 Astuces
- **GitHub** : regarde *Emails trouvés dans les commits* (souvent le vrai email).
- **Reddit** : le *creux d'activité* donne le fuseau horaire probable.
- Même pseudo ≠ même personne : compare photo, bio et liens.
- Instagram / Reddit bloquent parfois : réessaie plus tard ou sans VPN.""",

"mod_wmn": """### 🎯 À quoi ça sert
Tester un pseudo sur **plus de 600 sites** d'un coup (base **WhatsMyName**, utilisée par les pros).
### 🧰 Ce qu'il te faut
Un **pseudo** + internet. La base se télécharge toute seule (et se met à jour chaque semaine).
### ▶ Étapes
1. Tape le pseudo → barre de progression (≈ 20 s).
2. Résultats classés par catégorie, **n / p** pour tourner les pages.
3. Propose une **page HTML cliquable** pour ouvrir chaque compte.
### 💡 Astuces
- Teste aussi les **variantes** : `pseudo_`, `pseudo.fr`, `pseudo123`, ancien pseudo (module Prevname).
- Les résultats vont aussi dans le **Graphe d'enquête** : tu vois les recoupements.""",

"mod_person": """### 🎯 À quoi ça sert
À partir d'un **prénom + nom** : emails probables (vérifiés via Gravatar), pseudos probables et recherches prêtes (LinkedIn, Pages Blanches, Copains d'avant, dirigeants…).
### 🧰 Ce qu'il te faut
- Prénom et nom (obligatoires), ville (facultatif).
- **Domaine de l'entreprise** si tu cherches un email pro.
### 🔎 Comment trouver le domaine
Le site de l'entreprise (`societe.fr`) ou la fin d'un email d'un collègue (`@societe.fr`). Module **Entreprises** pour retrouver le site officiel.
### ▶ Étapes
1. Remplis les champs → 1re page : emails qui existent, serveur mail, pseudos.
2. **n** pour toutes les combinaisons d'emails, puis les recherches prêtes.
3. Le menu final ouvre la recherche choisie ou teste les pseudos sur les réseaux.
### ⚠️ Cadre
Pour toi-même, un contact pro ou une vérification. Jamais pour harceler quelqu'un (c'est puni par la loi).""",


"mod_user": """### 🎯 À quoi ça sert
Chercher un pseudo sur **95 sites** avec ses variantes (`_` `.` `-`) et donner un niveau d'exposition.
### 🧰 Ce qu'il te faut
Un pseudo (voir le tuto *Lookup réseaux sociaux* pour le trouver).
### 💡 Astuces
Plus rapide que *600+ sites*, avec une checklist IA pour réduire ton exposition. Pour aller plus loin : **Pseudo sur 600+ sites**.""",

"mod_prevname": """### 🎯 À quoi ça sert
Retrouver les **anciens pseudos** d'un compte (archives web, redirections, Bluesky, Steam…).
### 🧰 Ce qu'il te faut
Le pseudo **actuel** (et si tu en connais, des pseudos possibles).
### 💡 Astuces
- Les sites qui **redirigent** l'ancien pseudo vers le nouveau trahissent le changement.
- **Steam** : la page *steamhistory* liste les anciens noms.
- Un ancien pseudo ouvre souvent de **vieux comptes** oubliés : relance *600+ sites* dessus.""",

"mod_email": """### 🎯 À quoi ça sert
Vérifier un email : **fuites de données**, photo **Gravatar**, serveur mail, comptes liés.
### 🧰 Ce qu'il te faut
Une adresse email complète.
### 🔎 Où la trouver
Bio Instagram / TikTok (bouton *Email*), pied de page d'un site, mentions légales, CV, commits GitHub (module *Lookup réseaux sociaux*).
### 💡 Astuces
Si l'email apparaît dans une fuite : **change le mot de passe** partout où il était utilisé et active la double authentification.""",

"mod_pwned": """### 🎯 À quoi ça sert
Savoir si un **mot de passe** a déjà fuité, **sans jamais l'envoyer** (seuls 5 caractères de son empreinte partent : méthode k-anonymat de *Have I Been Pwned*).
### ▶ Étapes
Tape le mot de passe (il ne s'affiche pas) → nombre de fuites + force estimée.
### 💡 Astuces
Trouvé dans une fuite = **à changer partout**. Utilise le générateur de la *Boîte à outils* et un gestionnaire (Bitwarden, gratuit).""",

"mod_phone": """### 🎯 À quoi ça sert
Analyser un numéro : **pays, type** (mobile, fixe, VoIP), opérateur d'origine, format, recherches prêtes.
### 🧰 Ce qu'il te faut
Le numéro au format international de préférence : `+33 6 12 34 56 78`.
### 💡 Astuces
- Un numéro **VoIP** ou virtuel = souvent arnaque ou compte jetable.
- L'opérateur affiché est celui d'**origine** (le numéro a pu être porté ailleurs).
- Les recherches prêtes cherchent le numéro sur le web, WhatsApp, Telegram.""",

"mod_crypto": """### 🎯 À quoi ça sert
Voir le **solde et les transactions** d'une adresse Bitcoin / Ethereum (données publiques de la blockchain).
### 🔎 Où trouver l'adresse
Message d'arnaque, page de don, bio, QR code (scanne-le avec ton téléphone et copie le texte).
### 💡 Astuces
- Bitcoin commence par `1`, `3` ou `bc1` ; Ethereum par `0x`.
- Beaucoup d'entrées récentes sur une adresse d'« investissement » = arnaque qui tourne.""",

"mod_ids": """### 🎯 À quoi ça sert
Retrouver la **date cachée** dans un lien ou un ID : TikTok, X, Instagram, Bluesky, LinkedIn, Mastodon…
### 🔎 Où trouver l'ID
- **TikTok** : lien de la vidéo → le grand nombre après `/video/`.
- **X / Twitter** : le nombre après `/status/`.
- **LinkedIn** : lien du post (`activity-7234…`).
### 💡 Astuces
Colle **le lien entier**, l'outil trouve l'ID tout seul. Pratique pour savoir si une vidéo « d'aujourd'hui » date en fait de 2019.""",

"mod_img2gps": """### 🎯 À quoi ça sert
Donner une image → l'outil sort **directement ses coordonnées** : GPS du fichier, sinon estimation par IA locale (top 5 GeoCLIP + IA de vision), avec adresse et carte.
### 🧰 Ce qu'il te faut
Un fichier image (JPG, PNG, HEIC, WebP) **ou un lien direct** vers l'image.
""" + _ORIG_PHOTO + """
### 🔎 Récupérer une image d'un réseau social
- **PC** : clic droit → *Enregistrer l'image sous* ; ou *Copier l'adresse de l'image* et colle le lien.
- **Instagram** : ouvre le post sur PC → F12 → onglet *Réseau* → filtre *img* → la plus grande image.
- **Vidéo** : module **Vidéo → images** pour en sortir les meilleures images.
### 💡 Astuces
- L'IA donne une **zone probable**, pas une adresse : vérifie sur Street View (lien fourni).
- Pour une analyse poussée (monuments, ombres, triangulation) : réponds *oui* à la géoloc complète.
- L'IA locale s'installe au 1er usage (GeoCLIP ~1 Go, Ollama ~2 à 6 Go).""",

"mod_geo": """### 🎯 À quoi ça sert
La **géolocalisation complète** d'une photo : GPS, IA GeoCLIP, IA de vision (monuments, panneaux, langue), triangulation, carte interactive.
### 🧰 Ce qu'il te faut
Une photo (le mieux : l'**originale**). Un PC avec 8 Go de RAM pour l'IA locale.
""" + _ORIG_PHOTO + """
### ▶ Étapes
1. Glisse la photo dans la fenêtre → Entrée.
2. Si le GPS existe : position exacte. Sinon l'IA prend le relais (10 s à 2 min).
3. Ouvre la **carte** : chaque hypothèse est un point, avec Street View.
### 💡 Astuces (comme les pros de GeoGuessr)
- Regarde : **langue** des panneaux, côté de **conduite**, **plaques**, marquage au sol, poteaux, végétation.
- Confirme l'heure avec **Ombres & soleil**, la météo avec **Météo passée**.
- Inconnu ? Note les indices dans **Recherche par indices**.""",

"mod_video": """### 🎯 À quoi ça sert
Découper une vidéo en **images nettes** (pour les analyser) et lire les **métadonnées** (date, appareil, **GPS** caché des vidéos de téléphone).
### 🧰 Ce qu'il te faut
Le fichier vidéo (MP4, MOV, WebM…). **ffmpeg** se télécharge tout seul au 1er usage (version LANCER.bat).
### 🔎 Récupérer la vidéo
- **iPhone / Android** : envoie la vidéo **en fichier** (AirDrop, câble, Drive) pour garder le GPS.
- **TikTok** : bouton *Partager → Enregistrer la vidéo* (sans GPS, mais les images restent analysables).
- **YouTube / X / autres** : outils comme *yt-dlp* (gratuit) : `yt-dlp LIEN`.
### 💡 Astuces
Envoie ensuite la meilleure image dans **Image → coordonnées** ou **Recherche de logo**.""",

"mod_logo": """### 🎯 À quoi ça sert
Identifier une **marque / un logo** ou retrouver une image ailleurs sur le web (**recherche inversée** : Google Lens, Bing, Yandex, TinEye).
### 🧰 Ce qu'il te faut
Une image (le mieux : **recadrée sur le logo** ou l'objet).
### 💡 Astuces
- **Yandex** est le meilleur pour les visages et les lieux, **Google Lens** pour les objets, **TinEye** pour la 1re apparition d'une image.
- Retrouver l'image publiée plus tôt ailleurs = souvent la **vraie source** (et la fin d'une fausse info).""",

"mod_meta": """### 🎯 À quoi ça sert
Lire les **métadonnées** d'un fichier (photo, PDF, Word, Excel…) : auteur, logiciel, dates, appareil, GPS — et **les nettoyer** avant de publier.
### 🧰 Ce qu'il te faut
Le fichier original (voir ci-dessous pour les photos).
""" + _ORIG_PHOTO + """
### 💡 Astuces
- Un PDF ou un Word contient souvent le **nom de l'auteur** ou de l'entreprise.
- Nettoie **tes** photos avant de les poster : l'outil crée une copie sans données.""",

"mod_ela": """### 🎯 À quoi ça sert
Repérer une **retouche** (analyse ELA) : les zones collées ou modifiées ressortent plus claires.
### 🧰 Ce qu'il te faut
Un **JPG** le moins recompressé possible (l'original, pas une capture).
### 💡 Astuces
- Une zone **beaucoup plus lumineuse** que le reste = suspecte.
- Les images passées par WhatsApp / Facebook sont recompressées : l'ELA devient moins fiable.""",

"mod_sun": """### 🎯 À quoi ça sert
Utiliser le **soleil et les ombres** : trouver l'**heure** d'une photo connaissant le lieu, ou vérifier si une photo colle avec un lieu et une date.
### 🧰 Ce qu'il te faut
- Le **lieu** (adresse ou coordonnées) et la **date**.
- La **direction de l'ombre** : sur Google Maps, repère la rue et l'orientation (le nord est en haut).
- Optionnel : hauteur d'un objet et longueur de son ombre (rapport ombre / hauteur).
### 💡 Astuces
Ombre courte = midi ; ombre très longue = matin ou soir. Ombre vers le nord-ouest le matin en France ? Impossible → photo truquée ou lieu faux.""",

"mod_weather": """### 🎯 À quoi ça sert
Connaître la **météo d'un jour passé** à un endroit pour **vérifier une photo** (« il pleuvait ce jour-là ? »).
### 🧰 Ce qu'il te faut
Le **lieu** et la **date** (et l'heure si possible).
### 🔎 Où trouver la date
Métadonnées du fichier (module *Métadonnées*), date de publication, **Décodeur d'ID** pour la date d'un post.
### 💡 Astuces
Grand soleil sur la photo mais 12 mm de pluie ce jour-là = photo d'un autre jour.""",

"mod_place": """### 🎯 À quoi ça sert
Tout sur un lieu : **adresse**, coordonnées dans tous les formats, altitude, fuseau, et **12 cartes** (Google, Street View, satellite, cadastre, IGN…).
### 🧰 Ce qu'il te faut
Une adresse, un nom de lieu **ou** des coordonnées (`48.8584, 2.2945`, `48°51'30"N 2°17'40"E`, Plus Code…).
### 🔎 Copier des coordonnées
Google Maps : **clic droit** sur le point → clique sur les chiffres en haut, c'est copié.""",

"mod_satellite": """### 🎯 À quoi ça sert
Voir un lieu **en vue satellite à différentes dates depuis 2014** : constructions, travaux, bâtiments disparus…
### 🧰 Ce qu'il te faut
Une adresse ou des coordonnées (voir *Infos d'un lieu*).
### 💡 Astuces
Pratique pour **dater une photo** : si un bâtiment visible sur la photo n'existe pas sur l'image satellite de 2018, la photo est plus récente.""",

"mod_bearing": """### 🎯 À quoi ça sert
Calculer **distance et direction** entre deux points, et savoir si un objet est **visible** malgré la courbure de la Terre (montagne, tour, île vue depuis une côte).
### 🧰 Ce qu'il te faut
Deux positions (coordonnées) et, pour la visibilité, les **hauteurs** (altitude du regard, hauteur de l'objet).
### 🔎 Où trouver les hauteurs
Altitude : *Infos d'un lieu* ; hauteur d'un bâtiment : Wikipédia ou estimation (≈ 3 m par étage).""",

"mod_clues": """### 🎯 À quoi ça sert
Trouver un lieu **à partir d'indices** vus sur une image (enseigne, langue, plaque, paysage) : l'outil cherche et place les candidats sur la carte.
### 🧰 Ce qu'il te faut
Jusqu'à 4 indices précis : *« pharmacie verte + boulangerie Paul + rond-point »*, *« panneau en polonais + tramway »*…
### 💡 Astuces
Commence par l'indice **le plus rare** (nom d'enseigne locale, numéro de route).""",

"mod_planes": """### 🎯 À quoi ça sert
Voir les **avions en direct** (ADS-B) autour d'un lieu : immatriculation, altitude, vitesse, trajet.
### 🧰 Ce qu'il te faut
Un lieu. Pour identifier un avion sur une photo : **lieu + heure** de la photo, puis recoupe sur ADS-B Exchange / FlightRadar24 (historique).""",

"mod_iplookup": """### 🎯 À quoi ça sert
Tout sur une **IP ou un domaine** : pays, ville, opérateur, ASN, **VPN / proxy / Tor / datacenter**, ports ouverts et failles connues, autres sites sur la même IP.
### 🔎 Où trouver une IP
- **Ta propre IP** : laisse vide et appuie sur Entrée.
- **D'un email reçu** : module *En-têtes d'email* (l'IP de l'expéditeur est dans les en-têtes).
- **D'un site** : tape simplement le domaine (`exemple.fr`).
- **Logs** de ta box, de ton serveur ou d'un panneau d'administration.
### 💡 Astuces
- La position d'une IP = **l'opérateur**, jamais l'adresse d'une personne.
- *Datacenter* ou *VPN* = la personne cache sa vraie connexion.""",

"mod_domain": """### 🎯 À quoi ça sert
Audit d'un **domaine** : DNS, emails (SPF / DMARC), certificat SSL, sous-domaines, ports, failles connues, propriétaire (RDAP).
### 🧰 Ce qu'il te faut
Le domaine sans `https://` (ex : `exemple.fr`).
### 💡 Astuces
Les **sous-domaines** (via les certificats) révèlent souvent des pages oubliées : `test.`, `admin.`, `dev.`.""",

"mod_link": """### 🎯 À quoi ça sert
Vérifier un **lien suspect** avant de cliquer : redirections, vrai domaine, âge du domaine, ressemblance avec une marque (phishing).
### 🔎 Copier un lien sans l'ouvrir
- **PC** : clic droit → *Copier l'adresse du lien*.
- **Téléphone** : **appui long** sur le lien → *Copier*.
- **SMS** : appui long sur le message → *Copier*.
### 💡 Astuces
Domaine créé il y a quelques jours + nom qui imite une marque (`amaz0n-securite.com`) = **arnaque**.""",

"mod_headers": """### 🎯 À quoi ça sert
Lire les **en-têtes d'un email** pour savoir **d'où il vient vraiment** et s'il est du **phishing** (SPF, DKIM, DMARC, serveurs traversés, IP d'origine).
### 🔎 Récupérer les en-têtes
- **Gmail** : ouvre le mail → **⋮** → *Afficher l'original* → *Copier dans le presse-papiers*.
- **Outlook (web)** : **…** → *Afficher* → *Afficher la source du message*.
- **Outlook (appli)** : Fichier → *Propriétés* → zone *En-têtes Internet*.
- **Apple Mail** : *Présentation → Message → Toutes les en-têtes*.
- **Thunderbird** : *Ctrl + U*.
- **Orange / SFR / Free** : menu du message → *Afficher la source*.
### ▶ Étapes
Colle tout, puis tape **FIN** sur une ligne seule → verdict.""",

"mod_extract": """### 🎯 À quoi ça sert
Sortir **tous les indices** d'une page web, d'un fichier ou d'un texte : emails, réseaux, IP, téléphones, cryptos, IBAN, identifiants Google Analytics…
### 🧰 Ce qu'il te faut
Une **URL**, un **fichier** (PDF, Word, TXT, HTML…) ou du **texte collé**.
### 💡 Astuces
Le **code Google Analytics / Ads** d'un site permet de trouver ses **autres sites** (même propriétaire) via des recherches inversées.""",

"mod_archive": """### 🎯 À quoi ça sert
Voir les **anciennes versions** d'une page ou d'un site (Wayback Machine) : texte supprimé, ancienne équipe, anciens contacts.
### 🧰 Ce qu'il te faut
Une URL (page précise ou site entier).
### 💡 Astuces
Un profil supprimé ou une page « À propos » d'il y a 5 ans contient souvent noms, emails et téléphones.""",

"mod_net": """### 🎯 À quoi ça sert
Outils réseau : **ton IP publique**, propriétaire d'une IP (RIPE), **ASN**, et **fabricant d'un appareil** à partir de son adresse MAC.
### 🔎 Trouver une adresse MAC
- **Windows** : `ipconfig /all` (ligne *Adresse physique*).
- **Box internet** : page des appareils connectés (192.168.1.1 ou 192.168.1.254).
- **Téléphone** : Réglages → À propos → Wi-Fi (attention : adresse souvent **aléatoire**).""",

"mod_dorks": """### 🎯 À quoi ça sert
Générer des **recherches Google avancées** (dorks) : fichiers PDF d'un site, pages de connexion, mentions d'un pseudo, documents exposés…
### 💡 Les opérateurs à connaître
`site:exemple.fr` · `filetype:pdf` · `"phrase exacte"` · `-mot` (exclure) · `intitle:` · `inurl:` · `before:2020`.
### ⚠️ Cadre
Ne télécharge et n'utilise pas des documents qui ne te sont pas destinés.""",

"mod_decode": """### 🎯 À quoi ça sert
Décoder automatiquement un texte bizarre : **Base64, hexa, binaire, Morse, ROT13, César, URL, JWT…** même empilés.
### 🧰 Ce qu'il te faut
Le texte codé (copie-le tel quel).
### 💡 Reconnaître un codage
- Finit par `=` ou `==` → **Base64**.
- Que des 0 et 1 → **binaire** ; que `0-9 a-f` → **hexa**.
- Points et tirets → **Morse** ; trois blocs séparés par des points (`eyJ…`) → **JWT**.""",

"mod_toolbox": """### 🎯 À quoi ça sert
Outils **hors ligne** : stéganographie (message caché dans une image), strings d'un fichier, calculateur réseau, timestamps, mots de passe, coordonnées.
### 💡 Astuces
- **Stéganographie** : utilise le **fichier original** (une image recompressée perd le message). Regarde aussi le *plan de bits* créé.
- **Strings** : sur un `.exe` suspect, filtre `http` pour voir à quels sites il parle.
- **Timestamp** : les nombres à 10 chiffres sont des secondes, à 13 des millisecondes.""",

"mod_hash": """### 🎯 À quoi ça sert
Calculer l'**empreinte** (hash) d'un fichier, trouver son **vrai type** (un `.pdf` qui est en fait un `.exe`) et sa **réputation** (déjà connu comme virus ?).
### 💡 Astuces
- Ne double-clique jamais sur un fichier suspect : analyse-le ici d'abord.
- Le hash permet aussi de chercher le fichier sur **VirusTotal** (lien fourni) sans l'envoyer.""",

"mod_biz": """### 🎯 À quoi ça sert
Trouver une **entreprise** : SIREN, dirigeants, adresse, activité, annonces légales (BODACC), Pages Jaunes, Pappers.
### 🧰 Ce qu'il te faut
Un nom d'entreprise, un SIREN / SIRET ou un nom de dirigeant.
### 🔎 Où trouver le SIREN
Mentions légales d'un site, bas de facture ou de devis, Kbis.
### 💡 Astuces
Un « artisan » créé il y a 2 mois, sans avis et avec une adresse de domiciliation = prudence.""",


"mod_maplink": """### 🎯 À quoi ça sert
Transformer **n'importe quel lien de carte** en coordonnées précises, adresse et liens vers 8 autres cartes.
### 🔎 Récupérer le lien
- **Google Maps (téléphone)** : appui long sur le lieu → *Partager* → *Copier le lien* (lien court `maps.app.goo.gl`, accepté).
- **Google Maps (PC)** : copie l'adresse dans la barre du navigateur.
- **Waze** : *Partager le lieu* → *Copier*. **Apple Plans** : *Partager* → *Copier*.
- Un lien reçu par **SMS / WhatsApp** : appui long → *Copier*.
### 💡 Astuces
Ouvre ensuite le lieu dans **Mapillary** (photos de rue récentes) ou **Peakvisor** (identifier des montagnes à l'horizon).""",

"mod_photobatch": """### 🎯 À quoi ça sert
Lire **toutes les photos d'un dossier** : dates, GPS, appareils → **chronologie** + **trajet** sur une carte + fichier Excel.
### 🧰 Ce qu'il te faut
Un dossier de photos **originales** (pas des captures).
### 🔎 Récupérer les photos
- **iPhone → PC** : câble + application *Photos* de Windows → *Importer* (garde le GPS).
- **Google Photos** : *takeout.google.com* → exporte l'album (les fichiers gardent leurs données).
- **Android** : câble USB → dossier `DCIM/Camera`.
### 💡 Astuces
Plusieurs **appareils** différents dans un même lot = plusieurs auteurs. Un trou dans la chronologie = photos supprimées ?""",

"mod_imgcompare": """### 🎯 À quoi ça sert
Savoir si **deux images sont la même** (recadrée, recompressée, filtrée) et **où elles diffèrent** (retouche, objet ajouté ou effacé).
### 🧰 Ce qu'il te faut
Deux images : par exemple celle qui circule et celle trouvée par **recherche inversée** (module Recherche de logo).
### 💡 Astuces
- Ressemblance > 80 % = même photo de base.
- La version **la plus grande / la plus lourde / la plus ancienne** est souvent l'originale.
- Les zones claires de la *carte des différences* = parties modifiées.""",

"mod_vidinfo": """### 🎯 À quoi ça sert
Trouver la **date exacte** de mise en ligne d'une vidéo (YouTube, Shorts, TikTok), sa chaîne, ses vues, ses **mots-clés cachés**, et ses **miniatures** pour la recherche inversée (méthode InVID / Amnesty).
### 🔎 Récupérer le lien
- **YouTube** : *Partager* → *Copier le lien*. **TikTok** : *Partager* → *Copier le lien* (même le lien court `vm.tiktok.com`).
### 💡 Astuces
Lance la recherche inversée sur **chaque miniature** : si une version plus ancienne existe, la vidéo « du jour » est en fait une **vieille vidéo republiée**.""",

"mod_breaches": """### 🎯 À quoi ça sert
Savoir si un **site ou un service** a déjà été **piraté**, quand, combien de comptes, et quelles données ont fuité.
### 🧰 Ce qu'il te faut
Le nom du site (`deezer.com`) ou du service (`Canva`).
### 💡 Astuces
Tu avais un compte dessus ? Change ce mot de passe **partout** où tu l'as réutilisé, et teste-le avec **Fuite de mot de passe**.""",

"mod_graph": """### 🎯 À quoi ça sert
Une **fenêtre à part** (façon Obsidian / Maltego) qui dessine ton enquête en toile : pseudos, comptes, emails, IP, lieux, reliés entre eux.
### ▶ Étapes
1. **Ouvrir le graphe** → une fenêtre s'ouvre (Edge ou Chrome en mode application).
2. Laisse-la ouverte et lance d'autres modules : **elle se remplit toute seule**, en direct.
3. Dans la fenêtre : **clic** = fiche + notes, **double-clic** = ouvrir le lien, **molette** = zoom, **glisser** = déplacer.
4. **Clic droit** sur un élément = **transformations** (comme Maltego) : chercher un pseudo sur 17 réseaux ou 600+ sites, profil Gravatar d'un email, DNS et sous-domaines d'un domaine, IP lookup, sites sur la même IP… Les résultats s'ajoutent tout seuls.
5. **Ctrl + clic** sur deux éléments puis **🧭 Chemin** : ce qui les relie.
6. Dispositions : libre, arbre, cercle, par type · **▣ Regrouper** par type · **⇅ Données** : export JSON / Excel, import.
7. *+ Élément* et *⟷ Relier* pour ajouter tes propres trouvailles.
### 💡 Astuces
- Un point relié à **plusieurs pistes** (même email, même IP) = recoupement important.
- Une enquête par sujet : *Changer d'enquête*.
- *⇩ Image* pour exporter le graphe en PNG.""",

"mod_report": """### 🎯 À quoi ça sert
Regrouper **tout ce que tu as trouvé pendant la session** dans un rapport **PDF** (lisible sur iPhone) ou **HTML**, avec une synthèse IA.
### 💡 Astuces
Lance le rapport **avant de quitter** : la session n'est pas gardée à la fermeture (le graphe, lui, est sauvegardé).""",

"mod_settings": """### 🎯 À quoi ça sert
Choisir la **langue**, les **modèles d'IA locale** (Ollama) et les animations.
### 🧰 IA locale : ce qu'il faut savoir
- Tout tourne **sur ton PC** : rien n'est envoyé sur internet.
- **8 Go de RAM** : `qwen2.5:3b` (conseillé). **16 Go** : `qwen2.5:7b` (plus intelligent).
- Ollama s'installe depuis **ollama.com** (l'outil propose de l'ouvrir) ; le modèle se télécharge une fois.""",

"mod_learn": """### 🎯 À quoi ça sert
Apprendre à **programmer** et à **créer tes propres outils**, dans 23 langages, sans limite : cours, exercices corrigés, prof IA, parcours « crée ton outil OSINT ».
### 🧰 Ce qu'il te faut
Rien pour le cours **Python** (hors ligne). Pour les leçons générées et le prof : l'**IA locale** (Réglages).
### 💡 Astuces
Commence par **Python** : c'est le langage de cet outil. Fais les exercices, pas seulement la lecture.""",
}


def show_tuto(fn, name=""):
    from rich.markdown import Markdown
    t = TUTOS.get(fn)
    if not t:
        log("Pas de tuto pour ce module.", M)
        return False
    con.print(Panel(Markdown(tr(t)), title=f"[bold #050816 on #00e5ff] 📘 TUTO [/] [{G}]{escape(tr(name))}", title_align="left",
                    border_style="#00e5ff", box=box.ROUNDED, padding=(1, 3)))
    return True


def tuto_gate(fn, name):
    """1re ouverture d'un module : affiche son tuto, puis Lancer / Retour. Renvoie False si l'utilisateur revient."""
    vus = CFG.setdefault("tutos_vus", [])
    if fn in vus or fn not in TUTOS:
        return True
    show_tuto(fn, name)
    vus.append(fn)
    save_cfg()
    c = select("Et maintenant ?", [{"label": "▶ Lancer le module", "value": "go"}, {"label": "↩ Retour au menu", "value": "back"}],
               echo=False, hint="(ce tuto reste disponible avec la touche ? dans le menu)")
    return c == "go"


def mod_cyber_catalog():
    """Catalogue local de hacking-ethique ; aucune commande n’est exécutée."""
    path = BASE / "data" / "cyber_tools.json"
    try:
        catalog = load_catalog(path)
    except Exception as e:
        con.print(f"[{R_STYLE}]Catalogue cyber indisponible : {escape(str(e))}")
        pause()
        return
    tools = catalog["tools"]
    repo = catalog.get("source", {}).get("repository", "https://github.com/diego1505-Art/hacking-ethique")
    filters = {"category": None, "risk": None, "platform": None, "query": "", "mode": EXACT}
    while True:
        active = ", ".join(f"{k}={v}" for k, v in filters.items() if v and not (k == "mode" and v == EXACT)) or "aucun filtre"
        action = select("🛡️ CATALOGUE CYBER", [
            {"label": "🔎 Rechercher", "value": "search", "desc": "nom, description, catégorie, langage"},
            {"label": f"🎯 Mode de recherche : {'Exact' if filters['mode'] == EXACT else 'Approx'}", "value": "mode", "desc": "Approx tolère casse, accents et une modification d’un caractère (mots ≥ 4 lettres)"},
            {"label": "🗂️ Filtrer par catégorie", "value": "category", "desc": "catégories issues de la source"},
            {"label": "⚠️ Filtrer par risque", "value": "risk", "desc": "faible · moyen · élevé"},
            {"label": "💻 Filtrer par plateforme", "value": "platform", "desc": "Windows · Linux · macOS · Web · Docker"},
            {"label": f"📚 Voir les résultats ({len(search_tools(tools, **filters))})", "value": "list", "desc": active},
            {"label": "✕ Réinitialiser les filtres", "value": "reset", "desc": active},
            {"label": "↗ Ouvrir le dépôt source", "value": "source", "desc": repo},
            {"label": "↩ Retour", "value": "back", "desc": "aucune installation automatique"},
        ], back=False, echo=False, paged=True)
        if action in (None, "back"):
            return
        if action == "search":
            filters["query"] = ask_text("Recherche", filters["query"]).strip()
        elif action == "mode":
            value = select("Mode de recherche", [{"label": "Exact (par défaut)", "value": EXACT, "desc": "texte littéral, sensible à la casse et aux accents"},
                                                   {"label": "Approx", "value": APPROX, "desc": "insensible à la casse/aux accents, tolère une modification de caractère"}], default=filters["mode"])
            if value:
                filters["mode"] = value
        elif action == "category":
            value = select("Catégorie", [{"label": "Toutes", "value": None, "desc": "retirer le filtre"}] + [{"label": x, "value": x, "desc": ""} for x in cyber_categories(tools)], default=filters["category"])
            filters["category"] = value
        elif action == "risk":
            value = select("Niveau de risque", [{"label": "Tous", "value": None, "desc": "retirer le filtre"}, {"label": "Faible", "value": "low", "desc": "ressource généralement peu intrusive"}, {"label": "Moyen", "value": "medium", "desc": "vérifier le contexte et l’autorisation"}, {"label": "Élevé", "value": "high", "desc": "laboratoire ou autorisation explicite uniquement"}], default=filters["risk"])
            filters["risk"] = value
        elif action == "platform":
            value = select("Plateforme", [{"label": "Toutes", "value": None, "desc": "retirer le filtre"}] + [{"label": x, "value": x, "desc": ""} for x in cyber_platforms(tools)], default=filters["platform"])
            filters["platform"] = value
        elif action == "reset":
            filters = {"category": None, "risk": None, "platform": None, "query": "", "mode": EXACT}
        elif action == "source":
            webbrowser.open(repo)
        elif action == "list":
            results = search_tools(tools, **filters)
            if not results:
                con.print(f"[{Y}]Aucun outil ne correspond aux filtres.")
                pause()
                continue
            items = [{"label": f"{tool['name']} · risque {risk_label(tool.get('risk_level', ''))}", "value": tool["name"], "desc": f"{tool.get('category', '—')} · {', '.join(tool.get('platforms', []))}"} for tool in results]
            name = select(f"Résultats · {len(results)} outil(s)", items, echo=False, paged=True)
            tool = next((x for x in results if x["name"] == name), None)
            if not tool:
                continue
            favorite = tool["name"] in CFG.get("cyber_favs", [])
            while True:
                con.print(Panel(
                    f"[bold]{escape(tool['description'])}[/]\n\n"
                    f"Catégorie : {escape(str(tool.get('category', '—')))}\n"
                    f"Risque : {risk_label(tool.get('risk_level', ''))}\n"
                    f"Plateformes : {escape(', '.join(tool.get('platforms', [])))}\n"
                    f"Langage : {escape(str(tool.get('language', '—')))}\n"
                    f"Licence : {escape(str(tool.get('license', 'à vérifier')))}\n"
                    f"Installation : {escape(str(tool.get('installation', 'à vérifier')))}\n"
                    f"Accès réseau : {'oui' if tool.get('network_access') else 'non'} · privilèges root : {'oui' if tool.get('requires_root') else 'non'}\n"
                    f"Source : {escape(str(tool.get('source_ref', '—')))}\n\n"
                    f"URL : {escape(str(tool.get('source_url', '—')))}\n\n"
                    "Les instructions sont informatives : CAT.EXE ne les exécute jamais automatiquement.",
                    title=f"[bold #00e5ff]{escape(tool['name'])}[/]", border_style="#4a3fa0"))
                detail = select("Action", [{"label": "↗ Ouvrir la source", "value": "open", "desc": tool.get("source_url", "")}, {"label": ("★ Retirer des favoris" if favorite else "☆ Ajouter aux favoris"), "value": "fav", "desc": "préférences locales uniquement"}, {"label": "↩ Retour aux résultats", "value": "back", "desc": ""}], echo=False)
                if detail == "open":
                    webbrowser.open(tool.get("source_url", repo))
                elif detail == "fav":
                    favs = CFG.setdefault("cyber_favs", [])
                    if tool["name"] in favs:
                        favs.remove(tool["name"])
                        favorite = False
                    else:
                        favs.append(tool["name"])
                        favorite = True
                    save_cfg()
                else:
                    break


SECTIONS = build_sections(len(LEARN_LANGS))


def main_items():
    items = []
    allm = {fn: (lab, short, long, sec) for sec, lst in SECTIONS for fn, lab, short, long in lst}
    favs = [f for f in CFG.get("favs", []) if f in allm]
    rec = [f for f in CFG.get("recents", []) if f in allm and f not in favs][:4]
    for title, lst in (("★ FAVORIS", favs), ("RÉCENTS", rec)):
        if lst:
            items.append({"header": f"── {title}"})
            for fn in lst:
                lab, short, long, sec = allm[fn]
                items.append({"label": lab, "desc": short, "value": fn, "long": long, "section": sec, "tags": ""})
    for sec, lst in SECTIONS:
        items.append({"header": f"── {sec}"})
        for fn, lab, short, long in lst:
            short = f"{len(SITES)} sites" if fn == "mod_user" else f"{len(REPORT)} élément(s)" if fn == "mod_report" and REPORT else short
            items.append({"label": lab, "desc": short, "value": fn, "long": long, "section": sec, "tags": fn[4:] + " " + long + " " + KEYW.get(fn, "")})
    return items


def main_side(it):
    from rich.console import Group
    body = [Text(tr(it["label"]).strip(), style="bold #00e5ff"), Text(tr(it.get("desc", "")), style="#b388ff"), Text(""), Text(tr(it.get("long", "")), style="#e4e9ff")]
    if it["value"] == "mod_report" and REPORT:
        body += [Text(""), Text(tr("Dans le rapport : ") + ", ".join(dict.fromkeys(r["mod"] for r in REPORT)), style=M)]
    if it["value"] in TUTOS:
        body += [Text(""), Text.assemble((" ? ", "bold #050816 on #00e5ff"), (" " + tr("tuto : comment l'utiliser et où trouver les infos"), "#00e5ff"))]
    if str(it["value"]).startswith("mod_"):
        fav = it["value"] in CFG.get("favs", [])
        n = CFG.get("uses", {}).get(it["value"], 0)
        body += [Text.assemble((" * ", "bold #050816 on #b388ff"), (" " + tr("retirer des favoris" if fav else "ajouter aux favoris"), "#b388ff")),
                 Text(""), Text(tr(f"Utilisé {n} fois") if n else tr("Jamais utilisé"), style=M)]
    return Panel(Group(*body), border_style="#4a3fa0", box=box.ROUNDED, padding=(1, 2), title=f"[{M}]{escape(tr(it.get('section', '')))}", title_align="left")


def status_line():
    ai = f"[{G}]●[/] IA locale" if chk_ai() is True else f"[{M}]○ IA locale[/]"
    vis = ""
    rep = f"   [{P}]■[/] {len(REPORT)} dans le rapport" if REPORT else ""
    try:
        g = gload()
        ne = sum(1 for n in g["nodes"].values() if n.get("type") != "enquete")
        rep += f"   [{P}]▣[/] dossier « {escape(g['name'].replace('_', ' '))} » · {ne} entité(s)"
    except Exception:
        pass
    return f"  [{P}]// OSINT · GEOINT v{VERSION}[/]   {ai}   {rep}"


def ai_deepen_new_results(fn, label, report_start):
    """Propose une analyse locale commune aux modules qui viennent d'ajouter des résultats."""
    if fn == "mod_report":
        return
    entries = REPORT[report_start:]
    if not entries:
        return
    if not ask_yes(f"Lancer une analyse IA locale approfondie des {len(entries)} résultat(s) de « {label} » ?"):
        return
    facts = "\n\n".join(f"[{item['mod']}] {item['title']}\n{item['text']}" for item in entries)
    prompt = (
        "Tu es un assistant d'analyse OSINT et de vérification. Analyse uniquement les résultats factuels fournis. "
        "Sépare clairement faits, hypothèses et limites; ne complète jamais une donnée manquante par invention. "
        "Signale les contradictions, propose des pistes de recherche suivantes non exécutées et rappelle quand une vérification humaine est nécessaire. "
        "Réponds en français, de façon concise et structurée. Ces données sont traitées par l'IA locale de l'utilisateur.\n\n"
        f"Module : {label}\nRésultats :\n{facts[:14000]}"
    )
    analysis = ai_print(prompt, f"Analyse approfondie · {label}", task="analysis")
    if analysis:
        add_report("IA locale", f"Analyse approfondie · {label}", analysis)


def main():
    if not CFG.get("lang"):
        con.clear()
        lang_choose(first=True)
    boot()
    last = "mod_social"
    names = {fn: lab for _, lst in SECTIONS for fn, lab, _, _ in lst}
    while True:
        con.clear()
        small = con.size.height < 32
        if small:
            con.print(Text.assemble(("  CAT.EXE", "bold #00e5ff"), ("  // OSINT · GEOINT TOOL", "bold #b388ff")))
        else:
            con.print(banner_text(1), end="")
        con.print(status_line())
        con.print()
        fn = select("MENU PRINCIPAL", main_items(), default=last, back=True, side=main_side, echo=False, height=con.size.height - (4 if small else 10),
                    hint="↑↓ naviguer · Entrée ouvrir · ? tuto · * favori · tape pour chercher", paged=True, keys=("?", "*"))
        if isinstance(fn, dict) and fn.get("key") == "*":
            last = fn["value"]
            if str(last).startswith("mod_"):
                favs = CFG.setdefault("favs", [])
                favs.remove(last) if last in favs else favs.append(last)
                save_cfg()
            continue
        if isinstance(fn, dict):
            last = fn["value"]
            con.clear()
            if show_tuto(fn["value"], names.get(fn["value"], "")):
                pause()
            continue
        if fn is None:
            if ask_yes("Quitter Cat.exe ?"):
                fn = "quit"
            else:
                continue
        if fn == "quit":
            if CFG.get("anim", True):
                typewrite("  Déconnexion… à plus 🐱", P, .02)
            break
        last = fn
        con.clear()
        if not tuto_gate(fn, names[fn]):
            continue
        con.clear()
        CFG["recents"] = ([fn] + [x for x in CFG.get("recents", []) if x != fn])[:6]
        CFG.setdefault("uses", {})[fn] = CFG.get("uses", {}).get(fn, 0) + 1
        save_cfg()
        transition(re.sub(r"^\S+\s+", "", tr(names[fn])))
        report_start = len(REPORT)
        ai_calls_start = AI_CALLS
        try:
            globals()[fn]()
        except KeyboardInterrupt:
            con.print(f"\n[{Y}]Annulé.")
            time.sleep(.6)
        except Exception as e:
            con.print(f"[{R_STYLE}]Erreur : {escape(str(e))}")
            pause()
        else:
            if AI_CALLS == ai_calls_start:
                ai_deepen_new_results(fn, names.get(fn, fn), report_start)


def lang_choose(first=False):
    items = [{"label": name + ("" if code == "fr" or (LANG_DIR / f"{code}.json").exists() else "  ↓"), "value": code,
              "desc": "inclus" if code in ("fr", "en") else ("téléchargée" if (LANG_DIR / f"{code}.json").exists() else "se télécharge une fois")} for code, name in LANGS]
    code = select("🌍 Langue / Language / Idioma", items, default=CFG.get("lang", "fr"), back=not first) or CFG.get("lang") or "fr"
    if code != "fr" and not (LANG_DIR / f"{code}.json").exists():
        _con_print(f"[{M}]↓ {dict(LANGS)[code]} : téléchargement de la traduction (une seule fois)…")
        if not lang_download(code):
            code = "fr"
    CFG["lang"] = code
    save_cfg()
    lang_load(code)


def save_cfg():
    try:
        CFG_FILE.write_text(json.dumps(CFG, indent=1), encoding="utf-8")
    except Exception:
        pass


def theme_preview(it):
    from rich.console import Group
    nm = lambda c: c[:-1] + ("e" if c[-1].lower() == "f" else "f") if c.lower() in theme_colors("cyber") else c  # évite une 2e conversion
    cols = {k: nm(v) for k, v in theme_colors(it["value"]).items()}
    p, a, bg = (nm(x) for x in THEMES[it["value"]][:3])
    grad = [cols[g] for g in ("#00e5ff", "#33ccff", "#66b3ff", "#8c9eff", "#a78bfa", "#c084fc")]
    logo = Text()
    for i, line in enumerate(BANNER.strip("\n").split("\n")):
        logo.append(line + "\n", style=f"{grad[i % 6]} on {bg}")
    sw = Text.assemble(*[(" ███ ", c) for c in (p, cols["#33ccff"], cols["#8c9eff"], a, cols["#4a3fa0"], cols["#7480a8"])])
    demo = Text.assemble((" MENU ", f"bold {cols['#050816']} on {p}"), "  ", ("❯ 🧭 IP lookup", f"bold {p}"), "   ", ("géo · VPN · Tor", a))
    return Panel(Group(logo, sw, Text(""), demo, Text(""), Text(THEMES[it["value"]][3], style=cols["#7480a8"])), border_style=cols["#2b3158"],
                 title=f"[{p}]aperçu", box=box.ROUNDED, style=f"on {bg}")


def model_install_mark(model, installed):
    if installed is None:
        return "○ Ollama non détecté"
    return "☑ installé" if ollama_has(installed, model) else "☐ non installé"


def mod_settings():
    last = None
    while True:
        con.clear()
        con.rule(f"[{G}]🔧 RÉGLAGES")
        installed = ollama_models()
        items = [{"label": f"🌍 Langue : {dict(LANGS).get(CFG.get('lang', 'fr'), 'Français')}", "value": "lang", "desc": "13 langues"},
                 {"label": f"🎨 Thème : {CFG.get('theme', DEFAULT_THEME)}", "value": "theme", "desc": f"{len(THEMES)} palettes de couleurs"},
                 {"label": f"🧾 Style : {'sobre (sans emojis)' if CFG.get('sobre', True) else 'avec emojis'}", "value": "sobre", "desc": "affichage du terminal"},
                 {"label": "📘 Réafficher les tutos", "value": "tuto", "desc": "à la prochaine ouverture de chaque module"},
                 {"label": f"🤖 IA locale (texte) : {CFG.get('ollama_text', 'qwen2.5:3b')} · {model_install_mark(CFG.get('ollama_text', 'qwen2.5:3b'), installed)}", "value": "ai", "desc": "analyses, cours, rapports"},
                 {"label": f"👀 Vision locale : {CFG.get('ollama_model', 'qwen2.5vl:7b')} · {model_install_mark(CFG.get('ollama_model', 'qwen2.5vl:7b'), installed)}", "value": "vis", "desc": "géoloc auto, logos"},
                 {"label": f"🪶 IA légère : {CFG.get('ollama_light', 'qwen2.5:1.5b')} · {model_install_mark(CFG.get('ollama_light', 'qwen2.5:1.5b'), installed)}", "value": "light", "desc": "extraction rapide"},
                 {"label": f"🔤 IA OCR : {CFG.get('ollama_ocr', 'qwen2.5vl:3b')} · {model_install_mark(CFG.get('ollama_ocr', 'qwen2.5vl:3b'), installed)}", "value": "ocr", "desc": "texte dans les images"},
                 {"label": f"🛡️ IA cyber : {CFG.get('ollama_cyber', 'qwen2.5:7b')} · {model_install_mark(CFG.get('ollama_cyber', 'qwen2.5:7b'), installed)}", "value": "cyber", "desc": "logs et analyse défensive"},
                 {"label": f"💻 IA code : {CFG.get('ollama_code', 'qwen2.5:7b')} · {model_install_mark(CFG.get('ollama_code', 'qwen2.5:7b'), installed)}", "value": "code", "desc": "Python, Bash, PowerShell, JS"},
                 {"label": f"✨ Animations : {'oui' if CFG['anim'] else 'non'}", "value": "anim", "desc": "démarrage, transitions"},
                 {"label": "📂 Ouvrir le dossier des résultats", "value": "out", "desc": str(OUT)},
                 {"label": "🔄 Actualiser les modèles installés", "value": "models", "desc": "Vérifier l’inventaire Ollama sur cet ordinateur"},
                 {"label": "🧪 Tester l'IA", "value": "test", "desc": ""},
                 {"label": "← Retour au menu", "value": None}]
        c = select("Réglages", items, default=last, echo=False)
        if c is None:
            return
        last = c
        if c == "lang":
            lang_choose()
        elif c == "ai":
            con.print(f"[{M}]Toute l'IA tourne sur ton PC avec Ollama : gratuit, sans clé, rien ne part sur internet.")
            choices = [("qwen2.5:3b", "conseillé · ~2 Go · PC 8 Go de RAM"), ("qwen2.5:7b", "plus intelligent · ~4,7 Go · PC 16 Go"),
                       ("llama3.2:3b", "alternative · ~2 Go"), ("qwen2.5:1.5b", "très léger · vieux PC")]
            v = select("Modèle de texte", [{"label": f"{model} · {model_install_mark(model, installed)}", "value": model, "desc": desc} for model, desc in choices], default=CFG.get("ollama_text"))
            if v:
                CFG["ollama_text"] = v
                ollama_setup(True, v)
        elif c == "sobre":
            CFG["sobre"] = not CFG.get("sobre", True)
            save_cfg()
        elif c == "theme":
            old = CFG.get("theme", DEFAULT_THEME)
            v = select("Thème de couleurs", [{"label": f"{k.capitalize()}" + ("  ✓" if k == old else ""), "value": k, "desc": d[3]} for k, d in THEMES.items()], default=old, side=theme_preview, side_min=60)
            if v:
                CFG["theme"] = v
                apply_theme(v)
                save_cfg()
                con.clear()
                con.print(banner_text(1))
                log(f"Thème « {v} » appliqué partout (terminal, cartes, graphe).", G)
        elif c == "tuto":
            CFG["tutos_vus"] = []
            log("Les tutos s'afficheront de nouveau à l'ouverture de chaque module.", G)
        elif c == "vis":
            choices = [("qwen2.5vl:7b", "le plus précis · PC 16 Go de RAM"), ("qwen2.5vl:3b", "léger · PC 8 Go de RAM")]
            v = select("Modèle de vision", [{"label": f"{model} · {model_install_mark(model, installed)}", "value": model, "desc": desc} for model, desc in choices], default=CFG.get("ollama_model"))
            if v:
                CFG["ollama_model"] = v
        elif c in ("light", "ocr", "cyber", "code"):
            profile = AI_PROFILES[c]
            current = CFG.get(profile.config_key, profile.default_model)
            alternatives = [profile.default_model]
            if c in ("cyber", "code"):
                alternatives += ["qwen2.5:3b", "llama3.2:3b"]
            elif c == "ocr":
                alternatives += ["qwen2.5vl:7b"]
            else:
                alternatives += ["llama3.2:3b", "qwen2.5:3b"]
            v = select(profile.label, [{"label": f"{model} · {model_install_mark(model, installed)}", "value": model, "desc": "modèle local · téléchargement demandé seulement au premier usage"} for model in dict.fromkeys(alternatives)], default=current)
            if v:
                CFG[profile.config_key] = v
        elif c == "anim":
            CFG["anim"] = not CFG["anim"]
        elif c == "out":
            open_file(OUT)
        elif c == "models":
            installed = ollama_models(refresh=True)
            if installed is None:
                log("Ollama n’est pas joignable sur cet ordinateur. Lance Ollama puis actualise à nouveau.", Y)
            elif installed:
                log("Modèles Ollama installés : " + ", ".join(installed), G)
            else:
                log("Ollama est actif, mais aucun modèle n’est installé.", Y)
        elif c == "test":
            ai_print('Réponds juste : "IA opérationnelle ✓" suivi du nom de ton modèle.', "Test")
            pause()
        save_cfg()
