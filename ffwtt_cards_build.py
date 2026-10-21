#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ffwtt_cards_build.py — Construit la table complete des cartes : cartes.json

Source : le CLIENT (FFWTT.exe). Son code d'initialisation remplit en memoire un tableau d'enregistrements de
529 octets, indexe par identifiant de carte (id = index + 2) :

    [nom ShortString 256][deck ShortString 256][niveau dword][Haut][Gauche][Droite][Bas][element][8 octets nuls]

On reconstruit ce tableau en rejouant les ecritures immediates du code -> identifiant, nom, deck, niveau, les 4 VALEURS
EXACTES et l'ELEMENT de chaque carte (1 Eau, 2 Feu, 3 Glace, 4 Poison, 5 Terre, 6 Sacre, 7 Tenebres, 8 Tonnerre,
9 Vent ; 0 = aucun). Trouve le 2026-09-23 : jusque-la les champs numeriques etaient lus AVANT le nom, donc ceux de la
carte precedente (« 4 octets inexplicables ») ; decales d'une carte, ils sont exactement les chiffres dessines sur les
images des cartes. Le deck de chaque carte est celui du dossier qui contient son image (Cartes\<Deck>\).

Usage :
  py ffwtt_cards_build.py                          # -> cartes.json (+ rapport)
  py ffwtt_cards_build.py --exe CHEMIN\FFWTT.exe --cartes CHEMIN\Cartes
"""
import argparse, json, os, re, struct, sys, unicodedata, collections

ICI = os.path.dirname(os.path.abspath(__file__))
EXE_DEFAUT = r"C:\Program Files (x86)\FFWorld Triple Triad\FFWTT.exe"
CARTES_DEFAUT = r"C:\Program Files (x86)\FFWorld Triple Triad\Cartes"
STRIDE = 529

# ------------------------------------------------------------------ 1. client
def _sections(d):
    pe = struct.unpack_from("<I", d, 0x3c)[0]; opt = pe + 24
    ib = struct.unpack_from("<I", d, opt + 28)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]; optsize = struct.unpack_from("<H", d, pe + 20)[0]
    so = opt + optsize; secs = {}
    for i in range(nsec):
        s = d[so + 40*i: so + 40*i + 40]; nm = s[:8].rstrip(b"\0").decode()
        vsz, va, rsz, ra = struct.unpack_from("<IIII", s, 8); secs[nm] = (ib + va, vsz, ra, rsz)
    return secs

def extraire_client(exe):
    """Rejoue les ecritures memoire du code d'initialisation et renvoie
    {id: (deck, nom, niveau, [Haut, Droite, Bas, Gauche], element)}."""
    d = open(exe, "rb").read(); secs = _sections(d)
    bss0 = secs["BSS"][0]; bss1 = bss0 + secs["BSS"][1]
    _, _, cra, crs = secs["CODE"]
    def va2raw(v):
        for nm, (va, vsz, ra, rsz) in secs.items():
            if va <= v < va + max(vsz, rsz) and rsz: return ra + (v - va)
    mem = {}
    def put(a, bs):
        for k, b in enumerate(bs): mem[a + k] = b
    i = cra; end = cra + crs - 12; eax = None
    while i < end:
        b0 = d[i]
        if b0 == 0x33 and d[i+1] == 0xC0: eax = 0; i += 2; continue
        if b0 == 0xB8: eax = struct.unpack_from("<I", d, i+1)[0]; i += 5; continue
        if b0 == 0xC7 and d[i+1] == 0x05:
            a = struct.unpack_from("<I", d, i+2)[0]
            if bss0 <= a < bss1: put(a, d[i+6:i+10]); i += 10; continue
        if b0 == 0x66 and d[i+1] == 0xC7 and d[i+2] == 0x05:
            a = struct.unpack_from("<I", d, i+3)[0]
            if bss0 <= a < bss1: put(a, d[i+7:i+9]); i += 9; continue
        if b0 == 0xC6 and d[i+1] == 0x05:
            a = struct.unpack_from("<I", d, i+2)[0]
            if bss0 <= a < bss1: put(a, d[i+6:i+7]); i += 7; continue
        if b0 == 0xA3:
            a = struct.unpack_from("<I", d, i+1)[0]
            if bss0 <= a < bss1 and eax is not None: put(a, struct.pack("<I", eax)); i += 5; continue
        if b0 == 0xBE and d[i+5] == 0xBF:
            src = struct.unpack_from("<I", d, i+1)[0]; dst = struct.unpack_from("<I", d, i+6)[0]
            if bss0 <= dst < bss1:
                # copie de chaine : movsd/movsw/movsb deroules, ou 'mov ecx,n ; rep movsd' pour les longues
                ecx = struct.unpack_from("<I", d, i-4)[0] if d[i-5] == 0xB9 else None
                j = i + 10; n = 0
                while True:
                    if d[j] == 0xB9: ecx = struct.unpack_from("<I", d, j+1)[0]; j += 5
                    elif d[j] == 0xF3 and d[j+1] == 0xA5 and ecx is not None: n += 4*ecx; j += 2
                    elif d[j] == 0xF3 and d[j+1] == 0xA4 and ecx is not None: n += ecx; j += 2
                    elif d[j] == 0xA5: n += 4; j += 1
                    elif d[j] == 0x66 and d[j+1] == 0xA5: n += 2; j += 2
                    elif d[j] == 0xA4: n += 1; j += 1
                    else: break
                r = va2raw(src)
                if r is not None and 0 < n <= 260: put(dst, d[r:r+n]); i = j; continue
        i += 1
    lo = min(mem); hi = max(mem); img = bytearray(hi - lo + 1)
    for a, b in mem.items(): img[a - lo] = b
    def pr(x): return 0x20 <= x <= 0x7e or 0x80 <= x <= 0xff
    def sstr(k):
        if k < 0 or k >= len(img): return None
        L = img[k]
        if 1 <= L <= 255 and k+1+L <= len(img) and all(pr(x) for x in img[k+1:k+1+L]):
            return img[k+1:k+1+L].decode("cp1252", "replace")
    # base du tableau : residu mod 529 le plus frequent des chaines (deck en +0, nom en +273)
    strs = []; k = 0
    while k < len(img) - 2:
        L = img[k]
        if 2 <= L <= 40 and all(pr(x) for x in img[k+1:k+1+L]) and (k+1+L >= len(img) or img[k+1+L] == 0):
            strs.append(k); k += 1 + L
        else: k += 1
    res = collections.Counter(s % STRIDE for s in strs).most_common(2)
    r0, r1 = res[0][0], res[1][0]
    deck_res = r0 if (r0 + 273) % STRIDE == r1 else r1
    base = min(s for s in strs if s % STRIDE == deck_res)
    # Un enregistrement = [nom 256][deck 256][niveau 4][H G D B][element][8 octets nuls]. Notre « base » tombe sur le
    # deck de la carte PRECEDENTE (r+0) : le nom est en r+273, SON deck en nom+256, et ses champs numeriques en nom+512.
    # Les lire en r+256 (avant le nom) donnait ceux de la carte precedente : deck, niveau, valeurs et element decales
    # d'une carte (d'ou, longtemps, « 4 octets qui ne sont pas les valeurs »).
    cartes = {}; idx = 0
    while base + idx*STRIDE + 273 < len(img):
        r = base + idx*STRIDE
        nom = sstr(r + 273); deck = sstr(r + STRIDE); q = r + 273 + 512
        if nom and q + 9 <= len(img):
            niveau = int.from_bytes(img[q:q+4], "little")
            h, g, d_, b = img[q+4:q+8]
            cartes[idx + 2] = (deck or "", nom, niveau, [h, d_, b, g], img[q+8])
        idx += 1
    return cartes


# ------------------------------------------------------------------ fusion
def normaliser(s):
    s = unicodedata.normalize("NFKD", s); s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", s.lower())

def main():
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=EXE_DEFAUT); ap.add_argument("--cartes", default=CARTES_DEFAUT)
    ap.add_argument("--sortie", default=os.path.join(ICI, "cartes.json"))
    a = ap.parse_args()

    print("1) Lecture du client…"); cli = extraire_client(a.exe)
    print(f"   {len(cli)} cartes (id, deck, nom, niveau, valeurs, element)")
    # Index des images : nom normalise -> [(deck, nom de fichier)]. Le DECK d'une carte est
    # resolu par le dossier qui contient son image (c'est ce que le client affiche) : le champ
    # deck reconstruit depuis le client est decale sur les ajouts de 2010 et les cartes
    # « Speciales » portent le nom de leur deck alors que l'image vit dans Special/.
    images = collections.defaultdict(list)
    for deck in os.listdir(a.cartes):
        p = os.path.join(a.cartes, deck)
        if not os.path.isdir(p): continue
        for f in os.listdir(p):
            if f.endswith(".bleue.jpg"): images[normaliser(f[:-10])].append((deck, f[:-10]))
    table = {}; st = collections.Counter(); deck_prec = None
    for cid, (deck_cli, nom, niveau, chiffres, element) in sorted(cli.items()):
        rec = {"deck": deck_cli, "name": nom, "level": niveau}
        # --- resolution du deck et de l'image ---
        cands = images.get(normaliser(nom), [])
        if len(cands) == 1:
            deck, fichier = cands[0]
        elif cands:
            pref = [c for c in cands if c[0] == deck_cli] or [c for c in cands if c[0] == deck_prec] or cands
            deck, fichier = pref[0]
            if pref[0][0] != deck_cli: st["deck_ambigu"] += 1     # nom multi-decks sans le deck du client
        else:
            deck, fichier = deck_cli, None
        if deck != deck_cli: rec["deck_client"] = deck_cli; st["deck_corrige"] += 1
        rec["deck"] = deck
        if fichier and fichier != nom: rec["image"] = fichier
        deck_prec = deck
        # --- valeurs et element : ceux du client, exacts ---
        rec.update(digits=chiffres, element=element, src="client", conf=1.0); st["client"] += 1
        if fichier is None: st["sans_image"] += 1
        table[str(cid)] = {k: v for k, v in rec.items() if v is not None}
    # corrections manuelles (lectures verifiees a l'oeil) : cartes_corrections.json = {"id": {"digits": [...]}}
    chemin_corr = os.path.join(ICI, "cartes_corrections.json")
    if os.path.exists(chemin_corr):
        for sid, v in json.load(open(chemin_corr, encoding="utf-8")).items():
            if sid in table and v.get("digits") and v["digits"] != table[sid].get("digits"):
                table[sid].update(digits=v["digits"], src="manuel", conf=1.0); st["manuel"] += 1
    json.dump(table, open(a.sortie, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"\n=> {a.sortie} : {len(table)} cartes ; {dict(st)}")
    print(f"   elements : {dict(collections.Counter(v['element'] for v in table.values()))}")

if __name__ == "__main__":
    main()
