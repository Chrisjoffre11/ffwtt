#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_regles.py — Rejoue coup par coup une partie capturee et verifie que le moteur de
regles (ffwtt_regles.py) produit EXACTEMENT ce que la capture contient :
deplacements du Mur puissant, retournements (case, nouveau proprietaire, type) et scores.

Regles de la partie (masque 0x3ee) : Aleatoire, Elementaire, Bataille, Identique, Plus,
Meme mur, Mur additionnel, Mur puissant.           py test_regles.py
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ffwtt_regles as RG
import ffwtt_game as G

ICI = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("FFWTT_DB", os.path.join(ICI, "ffwtt_test_regles.db"))
from ffwtt_db import prix_client
CARTES = json.load(open(os.path.join(ICI, "cartes.json"), encoding="utf-8"))
pw = lambda k: prix_client(CARTES[k]["name"], CARTES[k]["deck"], CARTES[k]["level"], CARTES[k]["digits"])
# power = celui que le serveur range dans refcards (prix_client), jamais un champ « power » de cartes.json : une table
# reconstruite depuis le client seul (ffwtt_cards_build.py) n'en a pas
infos = lambda cid: {"power": pw(str(cid))[1], "element": CARTES[str(cid)].get("element") or 0}
vals = lambda cid: tuple(CARTES[str(cid)]["digits"])

MOI, LUI = 0, 1
# op137 et op138 tels que captures (ordre du fil : x*3 + y)
ELEMENTS_FIL = [0, 0, 3, 0, 3, 8, 0, 5, 6]
RESTRICTIONS_FIL = {0: (16, 1, 1), 1: (22, 2, 1), 2: (29, 2, 0), 7: (17, 2, 1), 8: (2, 1, 0)}
fil = lambda i: RG.cell(i // 3, i % 3)
ELEMENTS = {fil(i): e for i, e in enumerate(ELEMENTS_FIL) if e}
RESTRICTIONS = {fil(i): r for i, r in RESTRICTIONS_FIL.items()}

# (joueur, carte, x, y, deplacement attendu, retournements attendus, MON score annonce par op233)
COUPS = [
    (LUI, 3516, 1, 1, None,      [],                                   5),
    (MOI, 3710, 1, 2, None,      [(1, 1, MOI, 1)],                     6),
    (LUI, 4553, 1, 0, None,      [(1, 1, LUI, 1)],                     5),
    (MOI, 2670, 2, 1, (0, 1, 0), [(1, 0, MOI, 3), (0, 1, MOI, 3)],     7),   # Plus apres deplacement
    (LUI, 3777, 2, 2, (1, 2, 0), [],                                   7),
    (MOI, 3454, 0, 0, None,      [],                                   7),   # restriction +16 non remplie
    (LUI,  718, 2, 2, (1, 2, 0), [(1, 1, LUI, 2)],                     6),   # Identique avec le mur
    (MOI, 2630, 2, 2, (1, 2, 0), [(2, 0, MOI, 1), (2, 1, LUI, 1)],     6),   # Bataille : la carte posee est reprise
    (LUI, 1861, 0, 2, (1, 0, 0), [(0, 0, LUI, 1)],                     5),
]

def main():
    R = G.rules_from_mask(0x3EE)
    board = [None] * 9; ok = True; en_main = 5
    for n, (qui, cid, x, y, mouv, flips, score) in enumerate(COUPS, 1):
        r = RG.jouer(board, x, y, (cid, vals(cid)), qui, R, ELEMENTS, RESTRICTIONS, infos)
        if qui == MOI: en_main -= 1
        mon_score = sum(1 for b in board if b and b[1] == MOI) + en_main
        bon = (r["mouvement"] == mouv and r["flips"] == flips and mon_score == score)
        ok &= bon
        print(f"  [{'OK ' if bon else 'ECHEC'}] coup {n} : carte {cid} en ({x},{y}) -> deplacement {r['mouvement']}, "
              f"retournements {r['flips']}, score {mon_score}"
              + ("" if bon else f"\n          attendu : {mouv}, {flips}, {score}"))
    # regles seules, d'apres le texte du wiki
    b = [None] * 9
    RG.jouer(b, 0, 0, (1, (1, 2, 1, 1)), LUI, {"mur_casse": True})
    r = RG.jouer(b, 2, 0, (2, (1, 1, 1, 6)), MOI, {"mur_casse": True})     # le 6 (D) touche le 2... par le mur casse
    bon = r["flips"] == []                                                  # D de (2,0) touche G de (0,0) = 1 : 1 > 1 faux
    r2 = RG.jouer(b, 0, 2, (3, (1, 1, 3, 1)), MOI, {"mur_casse": True})    # B=3 touche H=1 de (0,0) par le bas
    bon &= r2["flips"] == [(0, 0, MOI, 1)]
    ok &= bon; print(f"  [{'OK ' if bon else 'ECHEC'}] Mur casse : le bas du plateau touche le haut")
    # Bataille : chaque paire se regle sur le plateau d'avant les batailles, du cote du joueur qui pose. La carte posee
    # (somme 20) touche une carte adverse de somme 32 (elle est reprise) et une carte AMIE de somme 8 avec un chiffre
    # egal : l'amie ne change pas de camp, et le plateau retourne (miroir) donne le meme resultat. Avant le 2026-10-21,
    # une fois reprise, la carte posee « combattait » ensuite les cartes de son propre joueur selon le sens de lecture.
    resultats = []
    for adv, ami in (((2, 0), (0, 0)), ((0, 0), (2, 0))):
        b = [None] * 9
        b[RG.cell(*adv)] = (1, LUI, (9, 9, 9, 5) if adv == (2, 0) else (9, 5, 9, 9), LUI)
        b[RG.cell(*ami)] = (2, MOI, (1, 5, 1, 1) if ami == (0, 0) else (1, 1, 1, 5), MOI)
        RG.jouer(b, 1, 0, (3, (5, 5, 5, 5)), MOI, {"bataille": True})
        resultats.append((b[RG.cell(*adv)][1], b[RG.cell(1, 0)][1], b[RG.cell(*ami)][1]))
    bon = resultats == [(LUI, LUI, MOI)] * 2
    ok &= bon; print(f"  [{'OK ' if bon else 'ECHEC'}] Bataille : resultat independant du sens du plateau {resultats}")

    # La table des cartes (cartes.json, lue dans le client) : 4884 cartes, et un element pour environ 29 % d'entre elles
    # (sans lui, la regle Elementaire donnait -1 a presque toutes).
    avec = sum(1 for v in CARTES.values() if v.get("element"))
    bon = len(CARTES) == 4884 and 1400 < avec < 1450
    ok &= bon; print(f"  [{'OK ' if bon else 'ECHEC'}] cartes.json : 4884 cartes, {avec} avec element")
    # Le prix et le power calcules comme le client (ffwtt_db.prix_client, lu dans le binaire) : la carte FFWorld
    # (4 x A) au prix maximal affiche par le client, 113503 gils.
    ffworld = next(k for k, v in CARTES.items() if v["name"] == "FFWorld")
    bon = pw(ffworld) == (113503, 1135)
    ok &= bon; print(f"  [{'OK ' if bon else 'ECHEC'}] prix et power du client : FFWorld {pw(ffworld)}")
    print("\n" + ("TOUT EST CONFORME A LA CAPTURE" if ok else "ECARTS AVEC LA CAPTURE"))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
