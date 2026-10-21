#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffwtt_regles.py — Les regles de capture du FFWorld Triple Triad.

SOURCES
  * Le texte officiel : page « Regle du jeu » du wiki ffwtt.net (archive web, 2013). Les
    citations ci-dessous en viennent mot pour mot.
  * Une partie complete capturee (regles 0x3ee : Aleatoire,
    Elementaire, Bataille, Identique, Plus, Meme mur, Mur additionnel, Mur puissant), rejouee
    coup par coup par test_regles.py : les 9 coups, les 3 deplacements et les 8 retournements
    sortent identiques a la capture.

CONVENTIONS
  cotes d'une carte : (H, D, B, G) ; A = 10.
  plateau : liste de 9 cases, indice y*3 + x ; une case = None ou (id_carte, proprietaire, (H,D,B,G), origine) ;
  l'origine (le joueur qui a pose la carte) survit aux retournements et aux deplacements : regle du vainqueur Directe.
  Sur le fil, les tableaux 3x3 du client (elements op137, restrictions op138) sont ranges
  [x][y], c'est-a-dire dans l'ordre x*3 + y (lu dans le binaire, cas 905 et 906).
"""
import random

A = 10
DIRS = [(0, -1, 0, 2), (1, 0, 1, 3), (0, 1, 2, 0), (-1, 0, 3, 1)]   # dx, dy, mon cote, son cote

# types de retournement envoyes dans op143 (observes : 1, 2 et 3)
T_NORMAL, T_IDENTIQUE, T_PLUS = 1, 2, 3
# restrictions du Mur puissant (op138) : 1 et 2 observes, 3 par elimination
R_SUP, R_INF, R_EGAL = 1, 2, 3
# Numerotation du jeu (celle des cartes, lue dans la table du client, et du plateau op137) : verifiee sur les icones
# dessinees en haut a droite des images de cartes (2026-09-23). L'ordre du wiki (Eau, Feu, Neige, Vent, Tonnerre...)
# n'est PAS celui des numeros : les noms 4 a 9 etaient faux ici.
ELEMENTS = {1: "Eau", 2: "Feu", 3: "Glace", 4: "Poison", 5: "Terre", 6: "Sacre",
            7: "Tenebres", 8: "Tonnerre", 9: "Vent"}


def cell(x, y): return y * 3 + x


# ---------------------------------------------------------------------------
# Tirages de debut de partie
# ---------------------------------------------------------------------------
def tirer_elements(rng=random):
    """ELEMENTAIRE. « des elements [...] sont choisis au hasard (ils peuvent aller de 0 a 6
    elements differents) et sont places sur les cases du tapis. »  -> {indice de case: element}"""
    n = rng.randint(0, 6)
    return {c: rng.randint(1, 9) for c in rng.sample(range(9), n)}


def tirer_restrictions(rng=random):
    """MUR PUISSANT. « les cases du plateau se voient attribuer aleatoirement des restrictions
    [...] suivi d'un nombre (de 2 a 30 ; 100). Toutes les cases, exceptees la 5 [le centre],
    peuvent theoriquement avoir une restriction [...] de 0 (tres rare) a 8. »
    -> {indice de case: (nombre, type, orientation)} ; orientation 1 = la LIGNE se deplace,
    0 = la COLONNE se deplace. Une case de bord ne peut pousser que vers le cote oppose."""
    out = {}
    for c in range(9):
        x, y = c % 3, c // 3
        if (x, y) == (1, 1) or rng.random() < 0.35: continue
        if x == 1:   orient = 0                 # haut/bas milieu : deplacement vertical
        elif y == 1: orient = 1                 # gauche/droite milieu : deplacement horizontal
        else:        orient = rng.randint(0, 1) # coin : l'un ou l'autre
        nombre = 100 if rng.random() < 0.05 else rng.randint(2, 30)
        out[c] = (nombre, rng.choice((R_SUP, R_INF, R_EGAL)), orient)
    return out


def restriction_remplie(restr, power):
    nombre, typ, _ = restr
    return (power > nombre) if typ == R_SUP else (power < nombre) if typ == R_INF else (power == nombre)


# ---------------------------------------------------------------------------
# Un coup
# ---------------------------------------------------------------------------
def jouer(board, x, y, carte, side, R, elements=None, restrictions=None, infos=None):
    """Pose `carte` = (id, (H,D,B,G)) en (x, y) pour le joueur `side` et applique les regles.
    `infos(id_carte)` -> {"power": n, "element": e} (facultatif).
    Modifie `board`. Retourne un dict :
        pos        (x, y) final de la carte posee (apres un eventuel deplacement)
        mouvement  None, ou (axe, indice, sens) : axe 1 = colonne / 0 = ligne ; sens 0 = vers
                   l'indice 0, 1 = vers l'indice 2  (tel qu'envoye dans op143)
        flips      [(x, y, nouveau_proprietaire, type)] dans l'ordre, coordonnees APRES deplacement
    """
    R = R or {}
    elements = elements or {}; restrictions = restrictions or {}
    infos = infos or (lambda _id: {})
    cid, vals = carte
    board[cell(x, y)] = (cid, side, tuple(vals), side)          # 4e element : a qui la carte appartenait au depart
    mouvement = None

    # --- MUR PUISSANT : « un deplacement des cartes d'une case sur une meme ligne ou sur une
    #     meme colonne [...] depuis la case a restriction vers le cote oppose du plateau »,
    #     la carte qui sort d'un cote « reapparait de l'autre cote, a la maniere d'un tapis roulant ».
    if R.get("mur_puissant") and cell(x, y) in restrictions:
        restr = restrictions[cell(x, y)]
        if restriction_remplie(restr, int((infos(cid) or {}).get("power") or 0)):
            ligne = restr[2] == 1
            pos = x if ligne else y                     # position de la case sur l'axe qui bouge
            if pos != 1:
                pas = -1 if pos == 2 else 1
                cases = [cell(i, y) for i in range(3)] if ligne else [cell(x, i) for i in range(3)]
                avant = [board[c] for c in cases]
                for i, c in enumerate(cases):
                    board[c] = avant[(i - pas) % 3]
                if ligne: x = (x + pas) % 3
                else:     y = (y + pas) % 3
                mouvement = (0 if ligne else 1, y if ligne else x, 0 if pas < 0 else 1)

    casse = bool(R.get("mur_casse"))

    def voisins(cx, cy):
        """[(nx, ny, mon_cote, son_cote)] ; MUR CASSE : « la partie se joue sur une sphere [...]
        le haut et le bas, la gauche et la droite sont relies »."""
        out = []
        for dx, dy, ms, ts in DIRS:
            nx, ny = cx + dx, cy + dy
            if casse: nx %= 3; ny %= 3
            if 0 <= nx < 3 and 0 <= ny < 3 and (nx, ny) != (cx, cy): out.append((nx, ny, ms, ts))
        return out

    def valeur(c, cote):
        """ELEMENTAIRE : +1 sur son element, -1 sinon (carte sans element comprise)."""
        v = board[c][2][cote]
        if R.get("elementaire") and c in elements:
            v += 1 if int((infos(board[c][0]) or {}).get("element") or 0) == elements[c] else -1
        return v

    flips = []
    def retourner(nx, ny, qui, typ):
        b = board[cell(nx, ny)]
        if b[1] != qui:
            board[cell(nx, ny)] = (b[0], qui, b[2]) + tuple(b[3:]); flips.append((nx, ny, qui, typ))
            return True
        return False

    ici = cell(x, y); vs = voisins(x, y)
    occupes = [(nx, ny, ms, ts) for nx, ny, ms, ts in vs if board[cell(nx, ny)]]
    # nombre de cotes contre un mur (aucun en Mur casse)
    murs = [] if casse else [ms for dx, dy, ms, ts in DIRS if not (0 <= x + dx < 3 and 0 <= y + dy < 3)]
    brut = board[ici][2]                       # « les bonus/malus n'entrent pas en compte pour
    speciaux = []                              #   bataille, identique, plus, meme mur et mur additionnel »

    # --- IDENTIQUE (+ MEME MUR : les murs « agissent comme des cartes non retournables ayant
    #     uniquement des bords de valeur A ») : au moins 2 cotes egaux, dont une carte adverse.
    if R.get("identique"):
        egaux = [(nx, ny) for nx, ny, ms, ts in occupes if brut[ms] == board[cell(nx, ny)][2][ts]]
        n_murs = sum(1 for ms in murs if brut[ms] == A) if R.get("mur_meme") else 0
        if len(egaux) + n_murs >= 2 and any(board[cell(nx, ny)][1] != side for nx, ny in egaux):
            for nx, ny in egaux:
                if retourner(nx, ny, side, T_IDENTIQUE): speciaux.append((nx, ny))

    # --- PLUS (+ MUR ADDITIONNEL) : au moins 2 sommes egales, dont une carte adverse.
    if R.get("plus"):
        sommes = {}
        for nx, ny, ms, ts in occupes:
            sommes.setdefault(brut[ms] + board[cell(nx, ny)][2][ts], []).append((nx, ny))
        if R.get("mur_add"):
            for ms in murs: sommes.setdefault(brut[ms] + A, []).append(None)
        for total, groupe in sommes.items():
            cartes = [g for g in groupe if g]
            if len(groupe) >= 2 and any(board[cell(nx, ny)][1] != side for nx, ny in cartes):
                for nx, ny in cartes:
                    if retourner(nx, ny, side, T_PLUS): speciaux.append((nx, ny))

    # --- REGLE DE BASE : « celle ayant la plus grande valeur retourne l'autre carte »
    for nx, ny, ms, ts in occupes:
        if board[cell(nx, ny)][1] != side and valeur(ici, ms) > valeur(cell(nx, ny), ts):
            retourner(nx, ny, side, T_NORMAL)

    # --- BATAILLE : « si les chiffres qui se "touchent" sont les memes, alors la carte ayant la
    #     plus faible somme sera retournee » — y compris la carte que l'on vient de poser
    #     (capture, coup 8 : la carte posee est retournee par sa voisine de plus forte somme).
    #     Chaque paire se regle sur le plateau d'AVANT les batailles, du cote du joueur qui pose ; la carte posee est
    #     reprise (en dernier) si elle perd au moins une bataille. Jusqu'au 2026-10-21, une fois la carte reprise, la
    #     lecture des voisins suivants (haut, droite, bas, gauche) continuait avec son NOUVEAU proprietaire : elle se
    #     battait contre les cartes de son propre joueur, et le resultat dependait du sens du plateau (verification
    #     differentielle contre une implementation independante des regles ; la partie capturee, ou Identique est
    #     actif, ne pouvait pas le montrer).
    if R.get("bataille"):
        perdue_contre = None
        for nx, ny, ms, ts in occupes:
            autre = board[cell(nx, ny)]
            if autre[1] == side or brut[ms] != autre[2][ts]: continue
            if sum(brut) > sum(autre[2]): retourner(nx, ny, side, T_NORMAL)
            elif sum(brut) < sum(autre[2]) and perdue_contre is None: perdue_contre = autre[1]
        if perdue_contre is not None: retourner(x, y, perdue_contre, T_NORMAL)

    # --- COMBO : « une carte retournee par combo peut retourner les cartes l'entourant si elle
    #     est plus puissante que celles-ci : ce sera une veritable reaction en chaine »
    file_attente = list(speciaux)
    while file_attente:
        cx, cy = file_attente.pop(0)
        for nx, ny, ms, ts in voisins(cx, cy):
            b = board[cell(nx, ny)]
            if b and b[1] != side and valeur(cell(cx, cy), ms) > valeur(cell(nx, ny), ts):
                if retourner(nx, ny, side, T_NORMAL): file_attente.append((nx, ny))

    return {"pos": (x, y), "mouvement": mouvement, "flips": flips}
