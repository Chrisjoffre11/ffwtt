#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffwtt_game.py — Deroulement d'un duel : mains, trames de partie, IA.

Les regles de capture elles-memes sont dans ffwtt_regles.py (texte officiel du wiki + partie
capturee rejouee par test_regles.py). Ce fichier fabrique les trames, dans l'ordre observe :

    op36  partie creee      03 | int(adversaire) | b1 | b(choix des cartes) | int(numero)
    op137 elements          9 x v(element)                  (regle Elementaire, ordre x*3+y)
    op138 restrictions      9 x [int16(nombre) v(type) v(orientation)]   (regle Mur puissant)
    op135 ma main           5 x int16(carte)
    op136 main adverse      5 x int16 : 0x1316 (dos de carte), ou les vraies cartes en Open
    op232 annonce, op139 tour

op36, 3e champ (lu dans le binaire du client, cas 804) : b1 ouvre la fenetre « Jeu avec %s -
Choix des cartes » et le client envoie ses 5 cartes (op133) ; b0 ouvre directement le plateau.
Wiki : « Aleatoire : les cartes seront choisies de facon aleatoire [...] La partie demarre
directement (car sans alea, le jeu demande a choisir 5 cartes) ».
"""
import struct, random, time
import ffwtt_protocol as P
import ffwtt_regles as RG

HIDDEN = 0x1316
CARD_MIN, CARD_MAX = 1, 3400

def _int16(v): return b"\x04" + struct.pack("<H", v & 0xFFFF)
def rand_card(): return random.randint(CARD_MIN, CARD_MAX)
def rand_vals(): return tuple(random.randint(1, 10) for _ in range(4))   # H,D,B,G

def real_hand(n=5, niveaux=None):
    """(ids, vals) tires des cartes REELLES si disponibles, sinon des cartes aleatoires.
    niveaux = (mini, maxi) : fourchette de niveaux des cartes (main d'un robot selon sa difficulte)."""
    try:
        import ffwtt_db as _db
        pick = _db.sample_ref(n, *niveaux) if niveaux else _db.sample_ref(n)
    except Exception:
        pick = []
    if len(pick) >= n:
        return ([c["card_id"] for c in pick],
                [(c["h"], c["d"], c["b"], c["g"]) for c in pick])
    return [rand_card() for _ in range(n)], [rand_vals() for _ in range(n)]

_INFOS = {}
def infos_carte(card_id):
    """power et element d'une carte (Mur puissant, Elementaire). power = prix / 100.
    Gardes en memoire : l'IA des robots appelle cette fonction des milliers de fois par coup (une requete SQLite
    sous le verrou global a chaque fois : 23 a 42 s par coup du robot Extreme avec Elementaire / Mur puissant, et
    tout le serveur ralenti pendant ce temps -- signale le 2026-09-23)."""
    r = _INFOS.get(card_id)
    if r is None:
        try:
            import ffwtt_db as _db
            brut = _db.ref_info(card_id) or {}
        except Exception:
            brut = {}
        r = _INFOS[card_id] = {"power": max(0, int(brut.get("price") or 0) // 100), "element": int(brut.get("element") or 0)}
    return r

class _Temps(Exception):
    """Le temps de reflexion d'un robot est ecoule."""

def valeurs_de(card_id, collection):
    """Valeurs (H,D,B,G) : celles de la collection, sinon celles de la table des cartes."""
    for c in (collection or []):
        if c["card_id"] == card_id: return (c["h"], c["d"], c["b"], c["g"])
    try:
        import ffwtt_db as _db
        return _db.ref_vals(card_id) or rand_vals()
    except Exception:
        return rand_vals()

def main_valide(card_ids, collection):
    """Les 5 cartes envoyees par op133 doivent etre possedees (en nombre suffisant)."""
    if len(card_ids) != 5: return False
    dispo = {}
    for c in (collection or []): dispo[c["card_id"]] = dispo.get(c["card_id"], 0) + (c.get("qty") or 1)
    for cid in card_ids:
        if dispo.get(cid, 0) <= 0: return False
        dispo[cid] -= 1
    return True

def main_au_hasard(collection):
    """Aleatoire : 5 cartes tirees dans la collection du joueur (avec leurs exemplaires)."""
    sac = []
    for c in (collection or []):
        sac += [c] * max(1, c.get("qty") or 1)
    if len(sac) >= 5:
        pick = random.sample(sac, 5)
        return [c["card_id"] for c in pick], [(c["h"], c["d"], c["b"], c["g"]) for c in pick]
    return real_hand(5)


# ---------------------------------------------------------------------------
# LES ROBOTS. Quatre adversaires toujours presents, du plus facile au plus fort. Ils acceptent TOUTES les
# regles choisies par le joueur (l'IA essaie ses coups dans le vrai moteur de regles, donc Identique, Plus,
# les murs, Elementaire, Mur puissant... sont pris en compte), jouent sans mise ni enjeu de cartes, et
# rapportent d'autant plus que le robot est fort (`gain` multiplie l'experience et les gils d'une victoire
# ou d'un nul).
#   niveaux     fourchette de niveaux (1 a 10) des cartes de sa main
#   profondeur  nombre de demi-coups explores : 1 = son coup seul, 2 = + la meilleure reponse du joueur,
#               0 = profondeur variable (« Extreme » : de plus en plus loin a mesure que le plateau se remplit,
#               jusqu'a la fin de partie complete)
#   hasard      probabilite de jouer un coup au hasard plutot que le meilleur trouve
# ---------------------------------------------------------------------------
ROBOTS = {
    # noms choisis par l'utilisateur (2026-09-23) : des monstres de Final Fantasy, du plus doux au plus redoutable, avec
    # la difficulte dans le pseudo. Les pseudos partent en latin-1 : l'accent d'« Extrême » passe.
    999: {"nom": "Mog-Facile",      "libelle": "Facile",  "niveaux": (1, 3),  "profondeur": 1, "hasard": 0.55, "gain": 1.0},
    998: {"nom": "Chocobo-Moyen",   "libelle": "Moyen",   "niveaux": (3, 6),  "profondeur": 1, "hasard": 0.10, "gain": 1.5},
    997: {"nom": "Tonberry-Dur",    "libelle": "Dur",     "niveaux": (5, 8),  "profondeur": 2, "hasard": 0.0,  "gain": 2.5},
    996: {"nom": "Bahamut-Extrême", "libelle": "Extrême", "niveaux": (8, 10), "profondeur": 0, "hasard": 0.0,  "gain": 4.0},
}
ROBOT_PAR_DEFAUT = 998          # cible absente ou inconnue : le robot « Medium »
TEMPS_REFLEXION = 1.5           # secondes au plus pour un coup du robot Extreme
# Moins de temps en debut de partie : avec 9 ou 8 cases libres on ne voit de toute facon pas la fin (4 a 5 demi-coups),
# alors qu'a partir de 6 ou 7 cases la fin est calculee exactement en moins d'une seconde. Valeurs retenues apres des
# matchs robot contre robot (voir la note de ffwtt_game du 2026-09-23 dans CLAUDE.md).
TEMPS_PAR_CASES = {9: 0.3, 8: 0.5, 7: 0.8}
MEMOIRE_MAX = 100_000           # positions retenues pendant la reflexion d'un coup (quelques dizaines de Mo au plus)

def robot(pid): return ROBOTS.get(pid) or ROBOTS[ROBOT_PAR_DEFAUT]


# ---------------------------------------------------------------------------
# Masque des regles (cases a cocher du client, champ Tag)
# ---------------------------------------------------------------------------
DEFAULT_RULES = {
    "open": False, "random": False, "elementaire": False, "bataille": False, "mur_casse": False,
    "identique": False, "plus": False, "mur_meme": False, "mur_add": False, "mur_puissant": False,
    "combo": True,      # les combos accompagnent toujours Identique / Plus / murs
}
RULE_BITS = [
    (1,   "open"),        (2,   "random"),   (4,   "elementaire"),
    (8,   "bataille"),    (16,  "mur_casse"),(32,  "identique"),
    (64,  "plus"),        (128, "mur_meme"), (256, "mur_add"),
    (512, "mur_puissant"),
]

def rules_from_mask(mask):
    R = dict(DEFAULT_RULES)
    for bit, nom in RULE_BITS:
        if mask & bit: R[nom] = True
    return R

def mask_from_rules(R):
    return sum(bit for bit, nom in RULE_BITS if R and R.get(nom))

def apply_rules(board, x, y, vals, side, rules=None):
    """Compatibilite : pose une carte deja inscrite sur le plateau, retourne les cases prises."""
    cid = board[RG.cell(x, y)][0] if board[RG.cell(x, y)] else 0
    r = RG.jouer(board, x, y, (cid, vals), side, rules or {})
    return [(fx, fy) for fx, fy, _q, _t in r["flips"]]


class _Partie:
    """Ce que les deux sortes de parties ont en commun : plateau, tirages, trames."""
    HID = HIDDEN

    def _init_plateau(self):
        self.board = [None] * 9
        self.placed = 0
        R = self.rules or {}
        self.elements = RG.tirer_elements() if R.get("elementaire") else {}
        self.restrictions = RG.tirer_restrictions() if R.get("mur_puissant") else {}

    def _gid(self): return P.field_int(self.game_id) + b"\x00"
    def cell(self, x, y): return y * 3 + x
    @property
    def choix_des_cartes(self): return not (self.rules or {}).get("random")

    def trame_creation(self, pid_adverse):
        """op36 : le 3e champ demande au client de choisir ses 5 cartes (sans Aleatoire)."""
        return P.build_frame(36, b"\x03" + P.field_int(pid_adverse) + P.field_byte(1)
                             + P.field_byte(1 if self.choix_des_cartes else 0) + P.field_int(self.made))

    def trames_plateau(self):
        """op137 / op138, seulement si la regle est active. Ordre du fil : x*3 + y."""
        f = []
        if (self.rules or {}).get("elementaire"):
            f.append(P.build_frame(137, self._gid() + b"".join(
                P.field_v(self.elements.get(RG.cell(i // 3, i % 3), 0)) for i in range(9))))
        if (self.rules or {}).get("mur_puissant"):
            corps = b""
            for i in range(9):
                n, t, o = self.restrictions.get(RG.cell(i // 3, i % 3), (0, 0, 0))
                corps += _int16(n) + P.field_v(t) + P.field_v(o)
            f.append(P.build_frame(138, self._gid() + corps))
        return f

    def trame_main_adverse(self, main):
        """op136 : dos de cartes, ou les vraies cartes avec la regle Open (« les cartes de
        l'adversaire sont visibles »). Meme gestionnaire que op135 dans le client."""
        ouvert = (self.rules or {}).get("open")
        return P.build_frame(136, self._gid() + b"".join(_int16(c if ouvert else self.HID) for c in main))

    def corps_143(self, res, pid_de, score):
        """op143 : b(deplacement) [b(axe) v(indice) v(sens) int16(1)] puis les retournements
        [v(x) v(y) int(pid du nouveau proprietaire) v(type)] et le score DU DESTINATAIRE."""
        m = res["mouvement"]
        corps = P.field_byte(1 if m else 0)
        if m: corps += P.field_byte(m[0]) + P.field_v(m[1]) + P.field_v(m[2]) + _int16(1)
        for fx, fy, qui, typ in res["flips"]:
            corps += P.field_v(fx) + P.field_v(fy) + P.field_int(pid_de(qui)) + P.field_v(typ)
        return corps + P.field_v(score)

    # ----- spectateurs (lu dans le binaire du client : gestionnaires 157, 161, 135/136, 142) -----
    # Chez un spectateur le joueur « 0 » est celui dont la main arrive par op135 (a gauche), le joueur « 1 »
    # celui d'op136 : le proprietaire d'op142, le tour d'op139 et le score d'op143/op233 sont donc exprimes
    # par rapport au PREMIER joueur de la partie, pas par rapport au destinataire.
    def trame_etat_spectateur(self):
        """op161 : 03 | int(partie) | v(score du joueur 0) | int16(masque des regles) | v(regle du vainqueur)
        | int(mise) | 9 x [int16(carte, 0 = case vide) v(proprietaire)], cases dans l'ordre du fil x*3+y.
        Jamais capturee : format lu dans le gestionnaire du client (cas 929, 0x646A68), qui range ces champs
        la ou op33/op36, op143 et op142 rangent les leurs."""
        corps = (P.field_v(self.score(0)) + _int16(mask_from_rules(self.rules)) + P.field_v(self.winner_rule)
                 + P.field_int(self.bet))
        for i in range(9):
            c = self.board[RG.cell(i // 3, i % 3)]
            corps += _int16(c[0] if c else 0) + P.field_v(c[1] if c else 0)
        return P.build_frame(161, self._gid() + corps)

    def trames_mains_spectateur(self):
        """op135 / op136 pour un spectateur : dos de cartes (vraies cartes en Open), 0 = carte deja jouee
        (le gestionnaire du client saute explicitement l'identifiant 0)."""
        ouvert = (self.rules or {}).get("open")
        f = []
        for op, (main, jouees) in zip((135, 136), self.mains()):
            f.append(P.build_frame(op, self._gid() + b"".join(
                _int16(0 if u else (c if ouvert else self.HID)) for c, u in zip(main, jouees))))
        return f

    def annonce_de(self, pid_a, pid_b):
        return (P.field_int(pid_a) + P.field_int(pid_b)
                + P.field_v(5) + P.field_int(0) + b"\x06\x01"
                + b"\x02" + struct.pack("<I", mask_from_rules(self.rules)) + P.field_v(1))


class Game(_Partie):
    """Duel contre un robot (voir ROBOTS). Le joueur est le cote 0, l'IA le cote 1."""
    def __init__(self, my_pid, room, op32_rest, ai_pid=999, collection=None, rules=None,
                 made=814, timer=60, winner_rule=0, bet=0, spectators=1):
        self.rules = rules
        self.my_pid = my_pid; self.ai_pid = ai_pid if ai_pid in ROBOTS else ROBOT_PAR_DEFAUT
        self.robot = robot(self.ai_pid)
        self.room = room; self.op32_rest = op32_rest
        self.timer = timer; self.winner_rule = winner_rule; self.bet = bet; self.spectators = spectators
        self.made = made; self.game_id = (self.made << 8) | 3
        self._init_plateau()
        self.my_hand, self.my_vals = main_au_hasard(collection)
        self.ai_hand, self.ai_vals = real_hand(5, self.robot["niveaux"])
        self.my_used = [False] * 5; self.ai_used = [False] * 5
        self.pret = not self.choix_des_cartes        # sans Aleatoire : on attend op133

    def pid_of(self, owner): return self.my_pid if owner == 0 else self.ai_pid
    def mains(self): return [(self.my_hand, self.my_used), (self.ai_hand, self.ai_used)]
    @property
    def tour_spectateur(self): return 0          # l'IA joue aussitot : on attend toujours le joueur
    def score(self, owner):
        ob = sum(1 for b in self.board if b and b[1] == owner)
        ih = sum(1 for u in (self.my_used if owner == 0 else self.ai_used) if not u)
        return ob + ih

    def deal_frames(self):
        # op33 = 03 | int(cible) | b1 | echo des parametres du defi  (compare a la capture)
        f = [P.build_frame(33, b"\x03" + P.field_int(self.room) + P.field_byte(1) + (self.op32_rest or b"")),
             self.trame_creation(self.room)]
        if self.pret: f += self.start_frames()
        return f

    def set_hand(self, card_ids, collection):
        """Le joueur a choisi ses 5 cartes (op133). Main refusee -> main tiree au hasard."""
        if main_valide(card_ids, collection):
            self.my_hand = list(card_ids)
            self.my_vals = [valeurs_de(cid, collection) for cid in card_ids]
        self.pret = True
        return main_valide(card_ids, collection)

    def start_frames(self):
        f = self.trames_plateau()
        f.append(P.build_frame(135, self._gid() + b"".join(_int16(c) for c in self.my_hand)))
        f.append(self.trame_main_adverse(self.ai_hand))
        f.append(P.build_frame(232, self._gid() + self.annonce()))
        f.append(P.build_frame(139, self._gid() + P.field_v(0) + _int16(self.timer)))
        return f

    def annonce(self): return self.annonce_de(self.my_pid, self.ai_pid)

    def place(self, hand_index, x, y, owner):
        f = []
        deja = (self.my_used if owner == 0 else self.ai_used)
        if not (0 <= hand_index < 5 and 0 <= x < 3 and 0 <= y < 3) or deja[hand_index]                 or self.board[self.cell(x, y)] is not None:
            return []                                # coup impossible : on l'ignore
        if owner == 0:
            card_id = self.my_hand[hand_index]; vals = self.my_vals[hand_index]; self.my_used[hand_index] = True
        else:
            card_id = self.ai_hand[hand_index]; vals = self.ai_vals[hand_index]; self.ai_used[hand_index] = True
        res = RG.jouer(self.board, x, y, (card_id, vals), owner, self.rules,
                       self.elements, self.restrictions, infos_carte)
        self.placed += 1
        if owner == 0: f.append(P.build_frame(141, self._gid() + b"\x06\x01"))
        f.append(P.build_frame(142, self._gid() + _int16(card_id)
                 + P.field_v(x) + P.field_v(y) + P.field_v(owner) + P.field_v(hand_index)))
        sc = self.score(0)                       # le score annonce est celui du DESTINATAIRE
        f.append(P.build_frame(143, self._gid() + self.corps_143(res, self.pid_of, sc)))
        f.append(P.build_frame(233, self._gid() + P.field_v(sc)))
        return f

    # ----- l'IA -----
    def _coups(self, board, cote, jouees):
        return [(hi, c) for hi in range(5) if not jouees[cote][hi] for c in range(9) if board[c] is None]

    def _poser(self, board, cote, hi, c):
        """Copie du plateau apres ce coup (le vrai moteur de regles : toutes les regles comptent)."""
        essai = list(board)
        main, vals = (self.my_hand, self.my_vals) if cote == 0 else (self.ai_hand, self.ai_vals)
        RG.jouer(essai, c % 3, c // 3, (main[hi], vals[hi]), cote, self.rules,
                 self.elements, self.restrictions, infos_carte)
        return essai

    @staticmethod
    def _bilan(board):
        """Avantage de l'IA : ses cartes moins celles du joueur."""
        return sum((1 if b[1] == 1 else -1) for b in board if b)

    def _coups_distincts(self, board, cote, jouees):
        """Comme _coups, mais deux cartes equivalentes pour les regles (memes valeurs, element et power) ne sont
        essayees qu'une fois : les poser l'une ou l'autre donne la meme partie."""
        main, vals = (self.my_hand, self.my_vals) if cote == 0 else (self.ai_hand, self.ai_vals)
        vues = set(); cartes = []
        for hi in range(5):
            if jouees[cote][hi]: continue
            inf = infos_carte(main[hi])
            k = (tuple(vals[hi]), inf["element"], inf["power"])
            if k not in vues: vues.add(k); cartes.append(hi)
        libres = [c for c in range(9) if board[c] is None]
        return [(hi, c) for hi in cartes for c in libres]

    def _cle(self, board, cote, jouees, prof):
        """Position (pour la memoire des positions deja evaluees) : cartes et proprietaires des cases, cartes deja
        jouees, trait, profondeur restante. L'origine des cartes (regle Directe) ne change pas l'evaluation."""
        cases = tuple(b[0] * 2 + b[1] + 1 if b else 0 for b in board)
        jeu = sum(1 << i for i, u in enumerate(jouees[0] + jouees[1]) if u)
        return cases + (cote, jeu, prof)

    def _explorer(self, board, cote, jouees, prof, alpha, beta, limite=None):
        """Minimax alpha-beta : l'IA (cote 1) maximise le bilan, le joueur (cote 0) le minimise. Les coups sont
        essayes du plus prometteur au moins prometteur (bilan immediat), ce qui coupe beaucoup plus de branches, et
        les positions deja evaluees pendant ce coup sont retenues (une meme position s'atteint par plusieurs ordres de
        jeu). Meme resultat que la recherche complete, en bien moins de temps."""
        if limite and time.time() > limite: raise _Temps()
        coups = self._coups_distincts(board, cote, jouees)
        if prof == 0 or not coups: return self._bilan(board)
        prof = min(prof, board.count(None))                 # au-dela de la fin de partie, rien ne change
        cle = self._cle(board, cote, jouees, prof)
        connu = self._memoire.get(cle)
        if connu:
            v, borne = connu
            if borne == 0: return v
            if borne == 1 and v > alpha: alpha = v           # borne basse
            elif borne == 2 and v < beta: beta = v           # borne haute
            if alpha >= beta: return v
        a0, b0 = alpha, beta
        enfants = []
        for hi, c in coups:
            apres = self._poser(board, cote, hi, c)
            enfants.append((self._bilan(apres), hi, apres))
        if prof == 1:                                        # feuilles : le bilan de chaque coup suffit
            meilleur = max(e[0] for e in enfants) if cote == 1 else min(e[0] for e in enfants)
        else:
            enfants.sort(key=lambda e: e[0], reverse=(cote == 1))
            meilleur = -99 if cote == 1 else 99
            for _b, hi, apres in enfants:
                jouees[cote][hi] = True
                v = self._explorer(apres, 1 - cote, jouees, prof - 1, alpha, beta, limite)
                jouees[cote][hi] = False
                if cote == 1:
                    if v > meilleur: meilleur = v
                    if meilleur > alpha: alpha = meilleur
                else:
                    if v < meilleur: meilleur = v
                    if meilleur < beta: beta = meilleur
                if alpha >= beta: break
        if len(self._memoire) < MEMOIRE_MAX:
            self._memoire[cle] = (meilleur, 2 if meilleur <= a0 else 1 if meilleur >= b0 else 0)
        return meilleur

    def choisir_coup(self):
        """(index en main, x, y) selon la difficulte du robot, ou None."""
        jouees = [list(self.my_used), list(self.ai_used)]
        coups = self._coups(self.board, 1, jouees)
        if not coups: return None
        if random.random() < self.robot["hasard"]:
            hi, c = random.choice(coups); return hi, c % 3, c // 3
        self._memoire = {}                                   # positions evaluees : le temps d'un coup seulement
        coups = self._coups_distincts(self.board, 1, jouees)
        prof = self.robot["profondeur"]
        if prof:
            return self._meilleur_coup(coups, jouees, prof)[0]
        # « Extreme » : approfondissement progressif (1, 2, 3... demi-coups) tant que le temps de reflexion le permet ;
        # on garde le meilleur coup de la derniere profondeur TERMINEE, et chaque profondeur essaie d'abord les coups
        # que la precedente a trouves les meilleurs. Le temps est borne quelles que soient les regles cochees.
        libres = sum(1 for b in self.board if b is None)
        limite = time.time() + TEMPS_PAR_CASES.get(libres, TEMPS_REFLEXION)
        choix, ordre = self._meilleur_coup(coups, jouees, 1)
        for p in range(2, libres + 1):
            try: choix, ordre = self._meilleur_coup(ordre, jouees, p, limite)
            except _Temps: break
        self._memoire = {}
        return choix

    def _meilleur_coup(self, coups, jouees, prof, limite=None):
        """(meilleur coup, coups ranges du meilleur au pire). Un coup qui ne peut pas egaler le meilleur connu n'est
        pas evalue precisement (fenetre alpha = meilleur - 1 : les ex aequo gardent leur valeur exacte)."""
        meilleur = None; notes = []
        for hi, c in coups:
            jouees[1][hi] = True
            try:
                apres = self._poser(self.board, 1, hi, c)
                seuil = meilleur[0][0] - 1 if meilleur else -99
                v = self._explorer(apres, 0, jouees, prof - 1, seuil, 99, limite)
            finally:
                jouees[1][hi] = False
            x, y = c % 3, c // 3
            bord = 1 if (x in (0, 2) or y in (0, 2)) else 0
            note = (v, self._bilan(apres), bord, random.random())
            notes.append((note, hi, c))
            if meilleur is None or note > meilleur[0]: meilleur = (note, hi, x, y)
        notes.sort(key=lambda n: n[0], reverse=True)
        return meilleur[1:], [(hi, c) for _n, hi, c in notes]

    def ai_play(self):
        """Le coup du robot : op139 (c'est a lui) puis les trames de sa pose."""
        coup = self.choisir_coup()
        if not coup: return []
        hi, x, y = coup
        f = [P.build_frame(139, self._gid() + P.field_v(1) + _int16(self.timer))]
        f += self.place(hi, x, y, 1); return f

    def next_turn_frame(self):
        return P.build_frame(139, self._gid() + P.field_v(0) + _int16(self.timer))

    def end_frames(self):
        """Fin d'une partie contre un robot : aucun enjeu, donc gains (146) et pertes (147) vides, puis 148."""
        f = [P.build_frame(144, self._gid() + _int16(self.score(0)) + P.field_v(0))]   # « votre score : %d »
        f.append(P.build_frame(235, self._gid() + b"\x06\x01"))
        for op in (146, 147, 148): f.append(P.build_frame(op, self._gid()))
        return f


class PvpGame(_Partie):
    """Duel entre DEUX joueurs humains (deux connexions)."""
    def __init__(self, room, pid_a, coll_a, pid_b, coll_b, rules=None,
                 made=814, timer=60, winner_rule=0, bet=0, spectators=1):
        self.rules = rules
        self.room = room; self.made = made; self.game_id = (self.made << 8) | 3
        self.timer = timer; self.winner_rule = winner_rule; self.bet = bet; self.spectators = spectators
        self.pids = [pid_a, pid_b]
        self._init_plateau()
        self.hands = [[], []]; self.vals = [[], []]; self.used = [[False] * 5, [False] * 5]
        for side, coll in ((0, coll_a), (1, coll_b)):
            self.hands[side], self.vals[side] = main_au_hasard(coll)
        self.turn = 0          # 0 = joueur A commence
        self.trames_spectateur = []        # le dernier coup, tel que le voit un spectateur
        # sans Aleatoire, chaque joueur doit envoyer ses 5 cartes (op133) avant le debut
        self.submitted = [not self.choix_des_cartes] * 2

    def side_of(self, pid): return 0 if pid == self.pids[0] else 1
    def mains(self): return [(self.hands[0], self.used[0]), (self.hands[1], self.used[1])]
    @property
    def tour_spectateur(self): return self.turn
    @property
    def pret(self): return all(self.submitted)
    def score(self, side):
        ob = sum(1 for b in self.board if b and b[1] == side)
        ih = sum(1 for u in self.used[side] if not u)
        return ob + ih

    def set_hand(self, side, card_ids, collection):
        """Les 5 cartes choisies par le joueur (op133). Main refusee -> main tiree au hasard."""
        ok = main_valide(card_ids, collection)
        if ok:
            self.hands[side] = list(card_ids)
            self.vals[side] = [valeurs_de(cid, collection) for cid in card_ids]
        self.submitted[side] = True
        return ok

    def start_frames(self, side):
        """Debut de partie vu par `side` (les deux mains sont pretes)."""
        f = self.trames_plateau()
        f.append(P.build_frame(135, self._gid() + b"".join(_int16(c) for c in self.hands[side])))
        f.append(self.trame_main_adverse(self.hands[1 - side]))
        f.append(P.build_frame(232, self._gid() + self.annonce()))
        # 0 = c'est a TOI de jouer (de ton point de vue), 1 = c'est a l'adversaire
        f.append(P.build_frame(139, self._gid() + P.field_v(0 if self.turn == side else 1) + _int16(self.timer)))
        return f

    def annonce(self): return self.annonce_de(self.pids[0], self.pids[1])

    def place(self, side, hand_index, x, y):
        """Retourne (trames pour le poseur, trames pour l'adversaire)."""
        if not (0 <= hand_index < 5 and 0 <= x < 3 and 0 <= y < 3) or self.used[side][hand_index]                 or self.board[self.cell(x, y)] is not None:
            return [], []                            # coup impossible : on l'ignore
        card_id = self.hands[side][hand_index]; vals = self.vals[side][hand_index]
        self.used[side][hand_index] = True
        res = RG.jouer(self.board, x, y, (card_id, vals), side, self.rules,
                       self.elements, self.restrictions, infos_carte)
        self.placed += 1
        self.turn = 1 - side

        def build(view):
            """view = le destinataire ; dans op142, 0 = « ma » carte, 1 = celle de l'adversaire."""
            fr = []
            if view == side: fr.append(P.build_frame(141, self._gid() + b"\x06\x01"))
            fr.append(P.build_frame(142, self._gid() + _int16(card_id) + P.field_v(x) + P.field_v(y)
                      + P.field_v(0 if view == side else 1) + P.field_v(hand_index)))
            fr.append(P.build_frame(143, self._gid() + self.corps_143(res, lambda q: self.pids[q], self.score(view))))
            fr.append(P.build_frame(233, self._gid() + P.field_v(self.score(view))))
            if self.placed < 9:
                fr.append(P.build_frame(139, self._gid() + P.field_v(0 if self.turn == view else 1) + _int16(self.timer)))
            return fr
        # spectateurs : proprietaire, score et tour par rapport au joueur 0 (voir _Partie)
        sp = [P.build_frame(142, self._gid() + _int16(card_id) + P.field_v(x) + P.field_v(y)
                            + P.field_v(side) + P.field_v(hand_index)),
              P.build_frame(143, self._gid() + self.corps_143(res, lambda q: self.pids[q], self.score(0))),
              P.build_frame(233, self._gid() + P.field_v(self.score(0)))]
        if self.placed < 9:
            sp.append(P.build_frame(139, self._gid() + P.field_v(self.turn) + _int16(self.timer)))
        self.trames_spectateur = sp
        return build(side), build(1 - side)

    def end_frames(self, view, gains=True):
        """op144 (score) + op235 (onglet Parties). `gains` = envoyer tout de suite des gains et des pertes vides
        (regle du vainqueur sans enjeu) ; sinon c'est le serveur qui enverra 145/146/147/148 apres le transfert."""
        f = [P.build_frame(144, self._gid() + _int16(self.score(view)) + P.field_v(0))]
        f.append(P.build_frame(235, self._gid() + b"\x06\x01"))
        if gains:
            for op in (146, 147, 148): f.append(P.build_frame(op, self._gid()))
        return f

    def main_de(self, side):
        """Les 5 cartes engagees par un joueur (celles de la partie, jouees ou non)."""
        return list(self.hands[side])

    def cartes_du_plateau(self, side):
        """Les cartes posees par `side` que l'ADVERSAIRE detient a la fin (regle Directe : « les joueurs remportent les
        cartes qu'ils ont retournees au cours de la partie »). Par l'origine de chaque case, pas par l'identifiant :
        deux exemplaires d'une meme carte (ou la meme carte des deux cotes) ne se confondent pas."""
        return [b[0] for b in self.board if b and len(b) > 3 and b[3] == side and b[1] != side]
