#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ffwtt_guildes.py — Les guildes, d'apres le binaire du client (rien n'a jamais ete capture : voir la spec, § Guildes).

Deroulement (celui du client) :
  1. Un joueur ayant 2500 powers cree un TABLEAU de guilde (Capacites -> Guilde) : nom definitif + mot de passe
     facultatif (op119). Le client ouvre alors la page web du tableau (guildroster.php?id=N), par laquelle les autres
     joueurs le rejoignent. Le maitre peut l'annuler (op123, powers rendus) ou le finaliser (op121) quand il a assez de membres.
  2. Une guilde finalisee apparait dans la liste de tous (op74), ses membres la voient dans la fenetre Guilde :
     membres (op78), experience (op84), caisse (op85), topic (op98), logo (op95).
  3. Invitation (op104 -> op105 / op107 -> op108 -> op106), expulsion (op109), depart (op112), dissolution (op86,
     ou op212 par un operateur), titres (op100), pouvoirs (op102), logo (op94), topic (op97), caisse (op115/117),
     chat de guilde (op81 -> op82).

Toutes les trames sont en categorie 4 (octet 04), sauf la liste des guildes et l'appartenance des joueurs, en
categorie 1 : op74 (guilde connue), op57 (MA guilde), op75 (un joueur change de guilde), op76 (guilde supprimee),
op92 (j'ai un tableau en cours : le bouton devient « Finaliser »).  Et la fiche op59 porte la guilde du joueur
(5e champ).
"""
import struct, time, threading, zlib
import ffwtt_protocol as P
import ffwtt_db as db

# pouvoirs d'un membre (cases de TfrmChangePowers, champ Tag)
INVITER, EXPULSER, TOPIC, RETIRER_GILS, PROTEGE, MAITRE_SECONDAIRE = 1, 2, 4, 8, 16, 32
# Le client affiche une capacite de 50 membres au plus (table des capacites de TfrmGuild : 10 a 50 membres ; ce
# client ne la remplit jamais, elle vaut toujours 50). Un seul pseudo par compte dans une guilde ou un tableau
# (erreurs 117 / 118 : « le maximum de pseudos possibles avec une guilde »).
CAPACITE = 50
PSEUDOS_PAR_COMPTE = 1
TITRE_MAX, TOPIC_MAX = 30, 0x8000       # le client compte 32768 caracteres de topic (« %d caractere(s) restant(s) »)
OPS = {81, 86, 94, 97, 100, 102, 104, 108, 109, 112, 115, 117, 119, 121, 123, 212}

def membres_minimum():
    """Membres inscrits sur un tableau (maitre compris) pour pouvoir finaliser (reglage « guilde_membres_min »)."""
    try: return max(1, int(db.reglage("guilde_membres_min", "5")))
    except ValueError: return 5


# ------------------------------------------------------------------ trames
C1, C4 = bytes([1]), bytes([4])
def _i16(v): return b"\x04" + struct.pack("<H", v & 0xFFFF)

def bloc(donnees):
    """Champ « x » : 08 + uint16(longueur) + zlib. Meme fabrication que les notes du profil (op241, verifiee en jeu)."""
    if isinstance(donnees, str): donnees = donnees.encode("latin-1", "replace")
    co = zlib.compressobj(9)
    z = co.compress(donnees) + co.flush(zlib.Z_SYNC_FLUSH)
    return b"\x08" + struct.pack("<H", len(z)) + z

# Taille maximale d'un bloc « x » une fois decompresse. Les plus gros envois legitimes : logo de guilde (60 Ko au plus),
# notes (30 000 caracteres), topic (32 768). Sans limite, quelques Ko compresses donnaient des dizaines de Mo en memoire.
BLOC_MAX = 100_000

def decompresser(brut):
    """Le contenu d'un bloc « x », ou None (flux illisible, ou plus grand que BLOC_MAX une fois decompresse)."""
    d = zlib.decompressobj()
    try: sortie = d.decompress(brut, BLOC_MAX)
    except zlib.error: return None
    return None if d.unconsumed_tail else sortie

def champs(payload):
    """Champs d'une trame recue (sans l'octet de contexte) ; un bloc « x » est rendu decompresse (bytes), ou None."""
    out = []; i = 1; n = len(payload)
    while i < n:
        t = payload[i]
        try:
            if t == 0x01: s, i = P.decode_string(payload, i); out.append(s); continue
            if t in (0x02, 0x03): out.append(struct.unpack_from("<i" if t == 2 else "<I", payload, i + 1)[0]); i += 5; continue
            if t == 0x04: out.append(struct.unpack_from("<H", payload, i + 1)[0]); i += 3; continue
            if t in (0x05, 0x06): out.append(payload[i + 1]); i += 2; continue
            if t == 0x08:
                ln = struct.unpack_from("<H", payload, i + 1)[0]; brut = payload[i + 3:i + 3 + ln]; i += 3 + ln
                out.append(decompresser(brut))
                continue
        except (struct.error, IndexError, AssertionError):
            pass
        break
    return out

def f_ack(op, ok, code=None, pid=None):
    """Accuse commun : 04 | b1, ou 04 | b0 | v(code) [| int(pid) pour les messages « %s ... »]."""
    pl = C4 + P.field_byte(1 if ok else 0)
    if not ok and code is not None: pl += P.field_v(code)
    if not ok and pid is not None: pl += P.field_int(pid)
    return P.build_frame(op, pl)

def f_liste(gid, nom):      return P.build_frame(74, C1 + P.field_int(gid) + P.field_str(nom))     # guilde connue
def f_ma_guilde(gid):       return P.build_frame(57, C1 + P.field_int(gid))                        # « Votre guilde est %s »
def f_joueur(pid, gid):     return P.build_frame(75, C1 + P.field_int(pid) + P.field_int(gid))     # 0 = sans guilde
def f_supprimee(gid):       return P.build_frame(76, C1 + P.field_int(gid))
def f_tableau(actif):       return P.build_frame(92, C1 + P.field_byte(1 if actif else 0))
def f_exp(exp):             return P.build_frame(84, C4 + P.field_int(exp))
def f_fin():                return P.build_frame(80, C4)

def f_gils(total, ajout=None, pid=0, montant=0):
    pl = C4 + P.field_int(total)
    if ajout is not None: pl += P.field_byte(1 if ajout else 0) + P.field_int(pid) + P.field_int(montant)
    return P.build_frame(85, pl)

def f_membre(m, maitre, invite_par=None):
    """op78 : la fiche d'un membre (gestionnaire 0x6478D3 ; ordre des champs = offsets de l'enregistrement de 0x3B octets).
    pid, nom, titre, cartes, exp, gils, powers, victoires, defaites, nuls, int16(pouvoirs), date d'entree, derniere
    connexion (dates Unix), b(maitre) [, int(pid de l'inviteur) : « Nouveau membre %s dans la guilde, invite par %s »]."""
    pid = m["pseudo_id"]; st = db.get_stats(pid) or {}; acc = db.get_account(m["account_id"]) or {}
    pl = (C4 + P.field_int(1000 + pid) + P.field_str(m["name"]) + P.field_str(m.get("titre") or "")
          + P.field_int(db.nb_cartes(pid)) + P.field_int(st.get("noto", 0)) + P.field_int(acc.get("gils", 0))
          + P.field_int(db.get_powers(pid)) + P.field_int(st.get("wins", 0)) + P.field_int(st.get("losses", 0))
          + P.field_int(st.get("draws", 0)) + _i16(m.get("pouvoirs") or 0) + P.field_int(m.get("entree") or 0)
          + P.field_int(m.get("vu") or m.get("entree") or 0) + P.field_byte(1 if maitre else 0))
    if invite_par: pl += P.field_int(invite_par)
    return P.build_frame(78, pl)

def f_topic(g):
    return P.build_frame(98, C4 + bloc(g["topic"]) + P.field_str(g.get("topic_par") or "") + P.field_int(g.get("topic_ts") or 0))

def f_logo(png): return P.build_frame(95, C4 + bloc(png))


class Guildes:
    """Etat des invitations et reactions aux trames. Le serveur fournit ses outils (pas d'import circulaire :
    ffwtt_server tourne en __main__)."""

    def __init__(self, clients, find_client, broadcast, log, sess, annoncer_gils, permissions, filtre_chat=None):
        self.clients, self.find_client, self.broadcast, self.log = clients, find_client, broadcast, log
        self.sess, self.annoncer_gils, self.permissions = sess, annoncer_gils, permissions
        # filtre_chat(conn, sess, moi, message) -> le message a diffuser (tronque), ou None : joueur muet, flood...
        self.filtre_chat = filtre_chat or (lambda conn, sess, moi, msg: msg)
        self.invitations = {}          # pid de l'inviteur -> (pid de l'invite, id de guilde)
        self.verrou = threading.RLock()

    # ---------------------------------------------------------------- outils
    def _envoyer(self, conn, *trames):
        try: conn.sendall(b"".join(trames))
        except OSError: pass

    def _aux_membres(self, gid, *trames, sauf=None):
        """A tous les membres EN LIGNE de la guilde."""
        pids = {1000 + m["pseudo_id"] for m in db.guilde_membres(gid)}
        for c in self.clients():
            if c["pid"] in pids and c["conn"] is not sauf: self._envoyer(c["conn"], *trames)

    def trames_guilde(self, gid):
        """Ce qu'un membre recoit en entrant au salon, ou quand il rejoint la guilde : op57 d'abord (le client y
        rattache sa fenetre Guilde, que op78 et les autres supposent), puis exp, caisse, membres, topic, logo, op80."""
        g = db.guilde(gid)
        if not g: return []
        t = [f_ma_guilde(gid), f_exp(g["exp"]), f_gils(g["gils"])]
        t += [f_membre(m, m["pseudo_id"] == g["maitre"]) for m in db.guilde_membres(gid)]
        if g["topic"]: t.append(f_topic(g))
        if g["logo"]: t.append(f_logo(g["logo"]))
        t.append(f_fin())
        return t

    def trames_entree(self, pseudo_id):
        """Pour la rafale d'entree (apres les fiches op59) : la guilde du joueur, ou l'etat de son tableau."""
        g, m = db.membre_de(pseudo_id)
        if not g: return []
        if g["finalisee"]: return self.trames_guilde(g["id"])
        return [f_tableau(True)] if g["maitre"] == pseudo_id else []

    def liste(self):
        """op74 de toutes les guildes finalisees (remplace la liste de la capture dans la rafale)."""
        return [f_liste(g["id"], g["nom"]) for g in db.liste_guildes()]

    def guilde_du_joueur(self, pseudo_id):
        """5e champ de la fiche op59 : l'identifiant de la guilde finalisee du joueur, 0 sinon."""
        g, _m = db.membre_de(pseudo_id)
        return g["id"] if g and g["finalisee"] else 0

    def _ecrire(self, gid, qui, action, detail=""):
        db.journal_guilde(gid, qui, action, detail)
        self.log(f"    GUILDE #{gid} : {qui} {action} {detail}".rstrip())

    # ---------------------------------------------------------------- evenements du serveur
    def connexion(self, pseudo_id):
        db.noter_connexion(pseudo_id)

    def deconnexion(self, pid):
        """Invitation en cours abandonnee ; date de derniere connexion (op125) pour les autres membres."""
        with self.verrou:
            self.invitations.pop(pid, None)
            for k, (invite, _g) in list(self.invitations.items()):
                if invite == pid: self.invitations.pop(k, None)
        db.noter_connexion(pid - 1000)
        g, _m = db.membre_de(pid - 1000)
        if g and g["finalisee"]:
            self._aux_membres(g["id"], P.build_frame(125, C4 + P.field_int(pid) + P.field_int(int(time.time()))))

    def apres_partie(self, pseudo_id, exp_gagnee):
        """Experience de la guilde = experience gagnee par ses membres depuis leur entree ; les fiches suivent
        (op91 : exp, gils, powers ; op92 : victoires, defaites, nuls)."""
        g, m = db.membre_de(pseudo_id)
        if not (g and g["finalisee"]): return
        exp = db.ajouter_exp_guilde(g["id"], max(0, exp_gagnee))
        st = db.get_stats(pseudo_id) or {}
        acc = db.account_of_pseudo(pseudo_id) or {}
        pid = 1000 + pseudo_id
        self._aux_membres(g["id"], f_exp(exp),
                          P.build_frame(91, C4 + P.field_int(pid) + P.field_int(st.get("noto", 0))
                                        + P.field_int((acc or {}).get("gils", 0)) + P.field_int(db.get_powers(pseudo_id))),
                          P.build_frame(92, C4 + P.field_int(pid) + P.field_int(st.get("wins", 0))
                                        + P.field_int(st.get("losses", 0)) + P.field_int(st.get("draws", 0))))


    # ---------------------------------------------------------------- trames recues (categorie 4)
    def react(self, conn, op, payload, sess, moi):
        """Retourne True si la trame etait une requete de guilde."""
        if op not in OPS or payload[:1] != C4: return False
        pdb = moi.get("db_id")
        if not pdb: return True
        v = champs(payload)
        with self.verrou:
            getattr(self, f"op{op}")(conn, v, sess, moi, pdb)
        return True

    # -- tableau : creer / finaliser / annuler ----------------------------------------------------
    def op119(self, conn, v, sess, moi, pdb):
        nom = (v[0] if v and isinstance(v[0], str) else "").strip(); mdp = v[1] if len(v) > 1 and isinstance(v[1], str) else ""
        acc = db.account_of_pseudo(pdb)
        if db.membre_de(pdb)[0]: code = 64
        elif not db.nom_guilde_valide(nom): code = 66
        elif db.guilde_par_nom(nom): code = 63
        elif acc and db.pseudos_en_guilde(acc["id"]) >= PSEUDOS_PAR_COMPTE: code = 117
        elif db.get_powers(pdb) < db.GUILDE_COUT: code = 17
        else: code = 0
        if code:
            self._envoyer(conn, f_ack(120, False, code)); self.log(f"    GUILDE : creation refusee ({nom!r}) code {code}"); return
        db.add_powers(pdb, -db.GUILDE_COUT)
        gid = db.creer_tableau(nom, pdb, mdp[:20])
        self._envoyer(conn, P.build_frame(48, C1 + P.field_int(db.get_powers(pdb))),
                      P.build_frame(120, C4 + P.field_byte(1) + P.field_int(gid)))    # le client ouvre guildroster.php?id=gid
        self._ecrire(gid, moi["name"], "cree le tableau", f"« {nom} »" + (" (mot de passe)" if mdp else ""))

    def _mon_tableau(self, pdb):
        g, _m = db.membre_de(pdb)
        return g if g and not g["finalisee"] and g["maitre"] == pdb else None

    def op121(self, conn, v, sess, moi, pdb):
        g = self._mon_tableau(pdb)
        if not g: return self._envoyer(conn, f_ack(122, False, 119))
        membres = db.guilde_membres(g["id"])
        if len(membres) < membres_minimum(): return self._envoyer(conn, f_ack(122, False, 120))
        db.finaliser_guilde(g["id"]); gid = g["id"]
        self._ecrire(gid, moi["name"], "finalise la guilde", f"{len(membres)} membres")
        self.broadcast(f_liste(gid, g["nom"]))                       # tout le monde connait la nouvelle guilde
        for m in membres: self.broadcast(f_joueur(1000 + m["pseudo_id"], gid))
        self._envoyer(conn, f_ack(122, True))
        bloc_ = b"".join(self.trames_guilde(gid))
        self._aux_membres(gid, bloc_)

    def op123(self, conn, v, sess, moi, pdb):
        g = self._mon_tableau(pdb)
        if not g: return self._envoyer(conn, f_ack(124, False, 119))
        db.supprimer_guilde(g["id"]); db.add_powers(pdb, db.GUILDE_COUT)                  # « Vos powers vous seront recredites »
        self._envoyer(conn, P.build_frame(48, C1 + P.field_int(db.get_powers(pdb))), f_ack(124, True))
        self._ecrire(g["id"], moi["name"], "annule le tableau", "powers rendus")

    # -- membres ----------------------------------------------------------------------------
    def _ma_guilde(self, conn, pdb, op_ack, pouvoir=0, maitre_seul=False):
        """(guilde, membre) si le joueur est dans une guilde finalisee avec le pouvoir voulu ; sinon envoie le refus."""
        g, m = db.membre_de(pdb)
        if not g or not g["finalisee"]: self._envoyer(conn, f_ack(op_ack, False, 67)); return None, None
        maitre = g["maitre"] == pdb
        second = bool(m["pouvoirs"] & MAITRE_SECONDAIRE)
        ok = maitre or (not maitre_seul and (second or (pouvoir and m["pouvoirs"] & pouvoir == pouvoir)))
        if not ok: self._envoyer(conn, f_ack(op_ack, False, 68)); return None, None
        return g, m

    def _cible(self, conn, g, pid, op_ack):
        m = next((x for x in db.guilde_membres(g["id"]) if 1000 + x["pseudo_id"] == pid), None)
        if not m: self._envoyer(conn, f_ack(op_ack, False, 72))
        return m

    def op104(self, conn, v, sess, moi, pdb):                  # inviter : u(pid)
        g, m = self._ma_guilde(conn, pdb, 105, INVITER)
        if not g: return
        cible_pid = v[0] if v else 0; cible = self.find_client(cible_pid)
        if moi["id"] in self.invitations: return self._envoyer(conn, f_ack(105, False, 75))
        if not cible: return self._envoyer(conn, f_ack(105, False, 95))
        if db.membre_de(cible_pid - 1000)[0]: return self._envoyer(conn, f_ack(105, False, 74, cible_pid))
        if any(inv == cible_pid for inv, _ in self.invitations.values()): return self._envoyer(conn, f_ack(105, False, 76, cible_pid))
        acc = db.account_of_pseudo(cible_pid - 1000)
        if acc and db.pseudos_en_guilde(acc["id"]) >= PSEUDOS_PAR_COMPTE: return self._envoyer(conn, f_ack(105, False, 118, cible_pid))
        if len(db.guilde_membres(g["id"])) >= CAPACITE: return self._envoyer(conn, f_ack(105, False, 82))
        self.invitations[moi["id"]] = (cible_pid, g["id"])
        self._envoyer(conn, P.build_frame(105, C4 + P.field_byte(1) + P.field_int(cible_pid)))
        self._envoyer(cible["conn"], P.build_frame(107, C4 + P.field_int(moi["id"]) + P.field_int(g["id"])))
        self.log(f"    GUILDE : {moi['name']} invite {cible['name']} dans « {g['nom']} »")

    def op108(self, conn, v, sess, moi, pdb):                  # reponse a une invitation (ou annulation par l'inviteur)
        oui = bool(v and v[0])
        if moi["id"] in self.invitations:                       # l'inviteur ferme sa fenetre : invitation annulee
            self.invitations.pop(moi["id"], None); return
        inviteur = next((k for k, (inv, _g) in self.invitations.items() if inv == moi["id"]), None)
        if inviteur is None: return
        _inv, gid = self.invitations.pop(inviteur)
        cl = self.find_client(inviteur)
        g = db.guilde(gid)
        if not oui or not g or db.membre_de(pdb)[0] or len(db.guilde_membres(gid)) >= CAPACITE:
            if cl: self._envoyer(cl["conn"], P.build_frame(106, C4 + P.field_byte(0) + P.field_byte(1)))
            return
        db.ajouter_membre(gid, pdb, invite_par=inviteur - 1000)
        if cl: self._envoyer(cl["conn"], P.build_frame(106, C4 + P.field_byte(1) + P.field_byte(1)))
        nouveau = next(x for x in db.guilde_membres(gid) if x["pseudo_id"] == pdb)
        self._aux_membres(gid, f_membre(nouveau, False, inviteur), sauf=conn)         # « Nouveau membre ... invite par »
        self.broadcast(f_joueur(moi["id"], gid))
        self._envoyer(conn, *self.trames_guilde(gid))
        self._ecrire(gid, moi["name"], "rejoint la guilde", f"invite par {cl['name'] if cl else inviteur}")

    def op109(self, conn, v, sess, moi, pdb):                  # expulser : u(pid) s(raison)
        g, m = self._ma_guilde(conn, pdb, 110, EXPULSER)
        if not g: return
        pid = v[0] if v else 0; raison = v[1] if len(v) > 1 and isinstance(v[1], str) else ""
        c = self._cible(conn, g, pid, 110)
        if not c: return
        if c["pseudo_id"] == g["maitre"] or (c["pouvoirs"] & PROTEGE and g["maitre"] != pdb) or c["pseudo_id"] == pdb:
            return self._envoyer(conn, f_ack(110, False, 78))
        self._envoyer(conn, f_ack(110, True))
        self._aux_membres(g["id"], P.build_frame(111, C4 + P.field_int(pid) + P.field_int(moi["id"]) + P.field_str(raison)))
        db.retirer_membre(c["pseudo_id"])
        self.broadcast(f_joueur(pid, 0))
        self._ecrire(g["id"], moi["name"], "expulse", f"{c['name']} : {raison}")

    def op112(self, conn, v, sess, moi, pdb):                  # quitter : s(raison)
        g, m = db.membre_de(pdb)
        if not g or not g["finalisee"]: return self._envoyer(conn, f_ack(113, False, 67))
        if g["maitre"] == pdb: return self._envoyer(conn, f_ack(113, False, 79))
        raison = v[0] if v and isinstance(v[0], str) else ""
        db.retirer_membre(pdb)
        self._envoyer(conn, f_ack(113, True))
        self._aux_membres(g["id"], P.build_frame(114, C4 + P.field_int(moi["id"]) + P.field_str(raison)))
        self.broadcast(f_joueur(moi["id"], 0))
        self._ecrire(g["id"], moi["name"], "quitte la guilde", raison)

    def _dissoudre(self, g, auteur_pid, auteur_nom, raison):
        """op88 aux membres (leur client referme la fenetre Guilde), PUIS op76 a tous (retire la guilde de la liste)."""
        self._aux_membres(g["id"], P.build_frame(88, C4 + P.field_int(auteur_pid) + P.field_str(raison)))
        db.supprimer_guilde(g["id"])
        self.broadcast(f_supprimee(g["id"]))
        self._ecrire(g["id"], auteur_nom, "dissout la guilde", raison)

    def op86(self, conn, v, sess, moi, pdb):                   # dissoudre (le maitre) : s(raison)
        g, m = self._ma_guilde(conn, pdb, 87, maitre_seul=True)
        if not g: return
        self._envoyer(conn, f_ack(87, True))
        self._dissoudre(g, moi["id"], moi["name"], v[0] if v and isinstance(v[0], str) else "")

    def op212(self, conn, v, sess, moi, pdb):                  # dissoudre (operateur, /dissolve) : s(guilde) s(raison)
        if "dissolveguild" not in self.permissions(sess): return self._envoyer(conn, f_ack(213, False, 87))
        g = db.guilde_par_nom((v[0] if v and isinstance(v[0], str) else "").strip('" '))
        if not g or not g["finalisee"]: return self._envoyer(conn, f_ack(213, False, 94))
        self._envoyer(conn, f_ack(213, True))
        raison = v[1] if len(v) > 1 and isinstance(v[1], str) else ""
        self._dissoudre(g, moi["id"], moi["name"], raison)
        self.log(f"    *** ADMIN {moi['name']} : dissolution de la guilde {g['nom']} ({raison!r})")

    def op100(self, conn, v, sess, moi, pdb):                  # titre : u(pid) s(titre)
        g, m = self._ma_guilde(conn, pdb, 101, maitre_seul=False, pouvoir=MAITRE_SECONDAIRE)
        if not g: return
        pid = v[0] if v else 0; titre = (v[1] if len(v) > 1 and isinstance(v[1], str) else "").strip()
        c = self._cible(conn, g, pid, 101)
        if not c: return
        if len(titre) > TITRE_MAX or any(ord(ch) < 32 for ch in titre): return self._envoyer(conn, f_ack(101, False, 73))
        db.maj_membre(c["pseudo_id"], titre=titre)
        self._envoyer(conn, f_ack(101, True))
        self._aux_membres(g["id"], P.build_frame(89, C4 + P.field_int(pid) + P.field_str(titre) + P.field_int(moi["id"])))
        self._ecrire(g["id"], moi["name"], "donne un titre", f"{c['name']} : {titre}")

    def op102(self, conn, v, sess, moi, pdb):                  # pouvoirs : u(pid) 2(masque)
        g, m = self._ma_guilde(conn, pdb, 103, maitre_seul=False, pouvoir=MAITRE_SECONDAIRE)
        if not g: return
        pid = v[0] if v else 0; masque = (v[1] if len(v) > 1 else 0) & 63
        c = self._cible(conn, g, pid, 103)
        if not c: return
        if c["pseudo_id"] == g["maitre"] or (masque & MAITRE_SECONDAIRE and g["maitre"] != pdb) \
                or (c["pouvoirs"] & MAITRE_SECONDAIRE and g["maitre"] != pdb):
            return self._envoyer(conn, f_ack(103, False, 68))     # seul le maitre fait (ou defait) un maitre secondaire
        db.maj_membre(c["pseudo_id"], pouvoirs=masque)
        self._envoyer(conn, f_ack(103, True))
        self._aux_membres(g["id"], P.build_frame(93, C4 + P.field_int(pid) + _i16(masque) + P.field_int(moi["id"])))
        self._ecrire(g["id"], moi["name"], "change les pouvoirs", f"{c['name']} : {masque}")

    def op94(self, conn, v, sess, moi, pdb):                   # logo : x(PNG 64x64)
        g, m = self._ma_guilde(conn, pdb, 96, maitre_seul=True)
        if not g: return
        png = v[0] if v and isinstance(v[0], (bytes, bytearray)) else None
        if not png or not png.startswith(b"\x89PNG") or len(png) > 60000: return self._envoyer(conn, f_ack(96, False, 69))
        if time.time() - (g["logo_ts"] or 0) < 24 * 3600: return self._envoyer(conn, f_ack(96, False, 70))
        db.maj_guilde(g["id"], logo=bytes(png), logo_ts=int(time.time()))
        self._envoyer(conn, f_ack(96, True))
        self._aux_membres(g["id"], f_logo(png))
        self._ecrire(g["id"], moi["name"], "change le logo")

    def op97(self, conn, v, sess, moi, pdb):                   # topic : x(texte)
        g, m = self._ma_guilde(conn, pdb, 99, TOPIC)
        if not g: return
        brut = v[0] if v else None
        if not isinstance(brut, (bytes, bytearray)): return self._envoyer(conn, f_ack(99, False, 69))
        texte = bytes(brut).decode("latin-1")
        if len(texte) > TOPIC_MAX: return self._envoyer(conn, f_ack(99, False, 71))
        db.maj_guilde(g["id"], topic=texte, topic_par=moi["name"], topic_ts=int(time.time()))
        self._envoyer(conn, f_ack(99, True))
        self._aux_membres(g["id"], f_topic(db.guilde(g["id"])))
        self._ecrire(g["id"], moi["name"], "change le topic")

    def op115(self, conn, v, sess, moi, pdb):                  # deposer des gils : u(montant)
        g, m = db.membre_de(pdb)
        if not g or not g["finalisee"]: return self._envoyer(conn, f_ack(116, False, 67))
        montant = v[0] if v else 0; acc = db.account_of_pseudo(pdb)
        if not acc or montant <= 0 or montant > 10 ** 9: return self._envoyer(conn, f_ack(116, False, 116))
        if (db.get_account(acc["id"]) or {}).get("gils", 0) < montant: return self._envoyer(conn, f_ack(116, False, 14))
        db.add_gils(acc["id"], -montant); total = db.ajouter_gils_guilde(g["id"], montant)
        self._envoyer(conn, f_ack(116, True)); self.annoncer_gils(conn, acc["id"])
        self._aux_membres(g["id"], f_gils(total, True, moi["id"], montant))
        self._ecrire(g["id"], moi["name"], "depose des gils", str(montant))

    def op117(self, conn, v, sess, moi, pdb):                  # retirer des gils : u(montant)
        g, m = self._ma_guilde(conn, pdb, 118, RETIRER_GILS)
        if not g: return
        montant = v[0] if v else 0; acc = db.account_of_pseudo(pdb)
        if not acc or montant <= 0: return self._envoyer(conn, f_ack(118, False, 116))
        total = db.ajouter_gils_guilde(g["id"], -montant)
        if total is None: return self._envoyer(conn, f_ack(118, False, 26))
        db.add_gils(acc["id"], montant)
        self._envoyer(conn, f_ack(118, True)); self.annoncer_gils(conn, acc["id"])
        self._aux_membres(g["id"], f_gils(total, False, moi["id"], montant))
        self._ecrire(g["id"], moi["name"], "retire des gils", str(montant))

    def op81(self, conn, v, sess, moi, pdb):                   # chat de guilde : s(message) b(action)
        g, m = db.membre_de(pdb)
        if not g or not g["finalisee"]: return self._envoyer(conn, P.build_frame(83, C4 + P.field_v(67)))
        msg = v[0] if v and isinstance(v[0], str) else ""; action = v[1] if len(v) > 1 else 0
        if msg: msg = self.filtre_chat(conn, sess, moi, msg)
        if not msg: return
        self._aux_membres(g["id"], P.build_frame(82, C4 + P.field_int(moi["id"]) + P.field_str(msg)
                                                 + P.field_byte(1 if action else 0) + P.field_byte(0)))
        self.log(f"    GUILDE {g['nom']} <{moi['name']}> {msg!r}")
