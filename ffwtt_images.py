#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ffwtt_images.py — Fabrique les petits logos que le client affiche a cote des pseudos.

Lu dans le binaire du client (gestionnaires op87 et op88) : a la reception d'un grade ou d'une
categorie de notoriete, il cherche un fichier PNG **sur le disque du joueur** :

    %APPDATA%\FFWorld Triple Triad\Images\<NomDuServeur>_SpecCateg_<id du grade>.png
    %APPDATA%\FFWorld Triple Triad\Images\<NomDuServeur>_Notoriety_<id de la categorie>.png

Le protocole ne les transmet pas : sans eux, aucun logo. Ce script les cree (PNG ecrits sans dependance) :
    grades 11..14  -> pastilles « 1 » a « 4 » des operateurs      grade 21 -> « A » (animateur)
    grade 5        -> « Q » (quizz)                                notorietes 1..6 -> etoile
    grade 41       -> drapeau britannique (joueurs anglophones)

    py ffwtt_images.py --serveur Balamb        (le nom passe a --name ; relancer le client ensuite)
Le serveur l'appelle tout seul au demarrage quand le dossier du client existe sur la machine.
"""
import argparse, os, struct, zlib

POLICE = {   # 5 x 7
    "1": ["..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."],
    "2": [".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"],
    "3": ["####.", "....#", "....#", ".###.", "....#", "....#", "####."],
    "4": ["...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."],
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "Q": [".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"],
    "P": ["####.", "#...#", "#...#", "####.", "#....", "#....", "#...."],
}
ETOILE = ["......#......", "......#......", ".....###.....", ".....###.....", "#############",
          ".###########.", "..#########..", "...#######...", "...#######...", "..####.####..",
          "..###...###..", ".##.......##.", ".#.........#."]

def png(pixels):
    """pixels : liste de lignes de (r, g, b, a) -> octets d'un PNG RGBA."""
    h = len(pixels); w = len(pixels[0])
    brut = b"".join(b"\x00" + bytes(v for px in ligne for v in px) for ligne in pixels)
    def bloc(nom, data):
        return struct.pack(">I", len(data)) + nom + data + struct.pack(">I", zlib.crc32(nom + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + bloc(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + bloc(b"IDAT", zlib.compress(brut, 9)) + bloc(b"IEND", b""))

def _pixels_drapeau(largeur, hauteur, couleur, ss=3):
    """Pixels d'un drapeau : couleur(X, Y) donne la couleur en un point du drapeau ramene a 60 x 30 unites ; chaque
    pixel moyenne ss x ss points (bords adoucis)."""
    lignes = []
    for y in range(hauteur):
        ligne = []
        for x in range(largeur):
            pts = [couleur(60 * (x + (i + .5) / ss) / largeur, 30 * (y + (j + .5) / ss) / hauteur) for i in range(ss) for j in range(ss)]
            ligne.append(tuple(round(sum(p[k] for p in pts) / len(pts)) for k in range(3)) + (255,))
        lignes.append(ligne)
    return lignes

def _drapeau(largeur, hauteur, couleur, ss=3):
    return png(_pixels_drapeau(largeur, hauteur, couleur, ss))

def _france(X, Y):
    return (0, 35, 149) if X < 20 else (255, 255, 255) if X < 40 else (237, 41, 57)

def _royaume_uni(X, Y):
    """Union Jack simplifie (lisible en 24 x 12) : sautoirs blanc et rouge, croix blanche et rouge sur fond bleu."""
    bleu, blanc, rouge = (1, 33, 105), (255, 255, 255), (200, 16, 46)
    d = min(abs(30 * X - 60 * Y), abs(30 * X + 60 * Y - 1800)) / 67.08      # distance aux diagonales
    c = bleu
    if d < 3: c = blanc
    if d < 1: c = rouge
    if abs(X - 30) < 5 or abs(Y - 15) < 5: c = blanc
    if abs(X - 30) < 3 or abs(Y - 15) < 3: c = rouge
    return c


def logo_drapeau(taille=16):
    """Logo du grade « English speaker » (41) : le drapeau britannique, 16 x 10, centre dans un carre transparent de la
    taille des pastilles."""
    haut = 10; vide = (0, 0, 0, 0); marge = (taille - haut) // 2
    return png([[vide] * taille for _ in range(marge)] + _pixels_drapeau(taille, haut, _royaume_uni)
               + [[vide] * taille for _ in range(taille - haut - marge)])

def pastille(lettre, fond, taille=16):
    vide = (0, 0, 0, 0); img = [[vide] * taille for _ in range(taille)]
    for y in range(1, taille - 1):
        for x in range(1, taille - 1):
            if (x in (1, taille - 2)) and (y in (1, taille - 2)): continue          # coins arrondis
            img[y][x] = fond + (255,)
    g = POLICE[lettre]; ox = (taille - 5) // 2 + 1; oy = (taille - 7) // 2
    for j, ligne in enumerate(g):
        for i, c in enumerate(ligne):
            if c == "#": img[oy + j][ox + i - 1] = (255, 255, 255, 255)
    return png(img)

# LARGEUR DES LOGOS DE NOTORIETE. La fenetre « Edition de la notoriete » du client (TfrmEditNotoriety.FormCreate,
# 0x625CA8) est construite a partir des logos : chaque categorie recoit une colonne dont le libelle « %d / %d » et
# l'ascenseur font « largeur du logo + 16 » pixels, et la colonne suivante commence « largeur + 24 » plus loin. Avec
# un logo de 16 pixels, le libelle (32 px) ne pouvait pas afficher « 0 / 1000 » et l'ascenseur etait inutilisable
# (signale le 2026-09-20). L'etoile reste la meme, centree dans une image transparente plus large : 56 px donnent
# des colonnes de 72 px. Le profil aligne aussi ces logos cote a cote (6 x 56 px).
LARGEUR_NOTO = 56

def etoile(couleur, taille=16, largeur=None):
    largeur = largeur or taille
    vide = (0, 0, 0, 0); img = [[vide] * largeur for _ in range(taille)]
    ox = (largeur - taille) // 2
    for j, ligne in enumerate(ETOILE):
        for i, c in enumerate(ligne):
            if c == "#": img[j + 1][ox + i + 1] = couleur + (255,)
    return png(img)

GRADES = {11: ("1", (77, 132, 245)), 12: ("2", (60, 110, 230)), 13: ("3", (40, 85, 210)), 14: ("4", (200, 40, 40)),
          21: ("A", (204, 51, 102)), 5: ("Q", (255, 128, 0)), 31: ("P", (10, 156, 118))}
GRADE_ANGLO = 41            # « English speaker » (ffwtt_server.GRADE_ANGLO) : un petit drapeau britannique
NOTORIETES = {i + 1: (250, 200 - 12 * i, 20) for i in range(6)}     # ids 1..6 : une image d'id 0 est ignoree

LIBELLES = {("SpecCateg", 11): "Opérateur 1", ("SpecCateg", 12): "Opérateur 2", ("SpecCateg", 13): "Opérateur 3",
            ("SpecCateg", 14): "Opérateur 4", ("SpecCateg", 21): "Animateur", ("SpecCateg", 5): "Quizz",
            ("SpecCateg", 31): "Enseignant"}

def images_speciales(dossier_perso=None, sans_marge=False):
    """{(type, id): (libelle, octets PNG)} : les logos a ranger dans Images/<Serveur>_<type>_<id>.png.
    Un fichier <dossier_perso>/<type>_<id>.png (ex. SpecCateg_14.png) remplace le logo fabrique : c'est la facon
    de mettre ses propres pastilles. sans_marge=True : l'etoile de notoriete sans ses marges transparentes.
    """
    out = {("SpecCateg", gid): (LIBELLES.get(("SpecCateg", gid), f"Grade {gid}"), pastille(l, c))
           for gid, (l, c) in GRADES.items()}
    out[("SpecCateg", GRADE_ANGLO)] = ("English speaker", logo_drapeau())
    out.update({("Notoriety", i): (f"Notoriété {i}", etoile(c, largeur=None if sans_marge else LARGEUR_NOTO))
                for i, c in NOTORIETES.items()})
    if dossier_perso and os.path.isdir(dossier_perso):
        for (typ, ident), (lib, _data) in list(out.items()):
            p = os.path.join(dossier_perso, f"{typ}_{ident}.png")
            if os.path.isfile(p):
                with open(p, "rb") as f: out[(typ, ident)] = (lib, f.read())
    return out

def dossier_client():
    base = os.environ.get("APPDATA")
    return os.path.join(base, "FFWorld Triple Triad", "Images") if base else None

def installer(serveur, dossier=None, force=False, dossier_perso=None):
    """Ecrit les logos pour ce nom de serveur (logos personnalises de <dossier_perso> compris). Un fichier deja present n'est reecrit que si son contenu a change : c'est ce qui
    met a jour les logos quand ce script evolue. Retourne le nombre de fichiers ecrits."""
    dossier = dossier or dossier_client()
    if not dossier or not os.path.isdir(os.path.dirname(dossier)): return 0
    os.makedirs(dossier, exist_ok=True); n = 0
    for (typ, ident), (_lib, data) in images_speciales(dossier_perso).items():
        chemin = os.path.join(dossier, f"{serveur}_{typ}_{ident}.png")
        try:
            with open(chemin, "rb") as f: pareil = (f.read() == data)
        except OSError: pareil = False
        if force or not pareil:
            with open(chemin, "wb") as f: f.write(data)
            n += 1
    return n

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--serveur", default="Balamb", help="le nom donne au serveur par --name")
    ap.add_argument("--dossier", default=None, help="dossier Images du client (par defaut : celui de cette machine)")
    a = ap.parse_args()
    n = installer(a.serveur, a.dossier, force=True)
    print(f"{n} logo(s) ecrit(s) dans {a.dossier or dossier_client()}" if n else
          "Dossier du client introuvable : precise --dossier.")
