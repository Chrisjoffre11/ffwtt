#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_serveur.py — Verification de bout en bout du serveur FFWTT.

Lance le serveur sur un port de test, simule un client qui parcourt toute la
sequence (connexion, login, pseudos, salon, chat, duel, boutique) et verifie
les reponses. A lancer apres toute modification.

    python3 test_serveur.py

Sortie : une ligne par etape, puis un bilan. Code de retour 0 si tout passe.
"""
import os, socket, struct, subprocess, sys, time

DOSSIER = os.path.dirname(os.path.abspath(__file__))
os.chdir(DOSSIER)
sys.path.insert(0, DOSSIER)

PORT = 27899                      # port de test, distinct du port de jeu
AVEC_SITE = False
BASE_TEST = "ffwtt_test.db"
JOURNAL_TEST = "ffwtt_test.log"

import ffwtt_protocol as P

resultats = []
def verifier(etape, condition, detail=""):
    resultats.append((etape, bool(condition)))
    print(f"  [{'OK ' if condition else 'ECHEC'}] {etape}" + (f"  ({detail})" if detail else ""))

def lire(sock, duree=1.2):
    """Accumule ce que le serveur envoie pendant 'duree' secondes."""
    sock.settimeout(duree); donnees = b""
    fin = time.time() + duree
    while time.time() < fin:
        try:
            morceau = sock.recv(65536)
            if not morceau: break
            donnees += morceau
        except socket.timeout:
            break
    return donnees

def opcodes(donnees):
    return [op for op, _ in P.parse_frames(bytearray(donnees))]

def frames(donnees):
    return P.parse_frames(bytearray(donnees))

def champ_ints(payload):
    """Extrait les entiers (tag 0x03) d'une charge utile qui commence par 1 octet de
    contexte (que decode_fields confond avec un tag). Parseur robuste local."""
    ints = []; i = 1 if payload else 0; n = len(payload)
    while i < n:
        t = payload[i]
        if t == 0x01:
            try: _, i = P.decode_string(payload, i); continue
            except Exception: break
        if t == 0x03 and i + 5 <= n:
            ints.append(struct.unpack_from("<I", payload, i + 1)[0]); i += 5; continue
        if t == 0x02 and i + 5 <= n: i += 5; continue
        if t == 0x04 and i + 3 <= n: i += 3; continue
        if t in (0x05, 0x06) and i + 2 <= n: i += 2; continue
        break
    return ints

def entrer(login, mdp="secret", pseudo_db=None, version=P.VERSION_CLIENT):
    """Ouvre une connexion et deroule tout le protocole jusqu'au salon (avec le pseudo principal, ou le
    pseudo d'identifiant `pseudo_db`). Retourne (socket, pid_reseau)."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=8)
    lire(s, 0.6)                                   # accueil
    s.sendall(P.build_frame(5, b"\x00" + P.field_int(version)))
    s.sendall(P.build_frame(100, b"\x00" + P.field_str(login) + P.field_str(mdp)))
    data = lire(s); VERSIONS[login] = frames(data)
    pid = 0
    for op, pl in frames(data):
        if op == 101:
            ii = champ_ints(pl)
            if ii: pid = ii[0]
    if pseudo_db: pid = 1000 + pseudo_db
    s.sendall(P.build_frame(207, b"\x00" + P.field_int(pid - 1000)))  # choisir le pseudo (le principal par defaut)
    lire(s)
    s.sendall(P.build_frame(44, b"\x01")); RAFALES[login] = lire(s, 1.2)   # rafale du salon
    s.sendall(P.build_frame(71, b"\x01" + P.field_byte(1)))          # entree
    ENTREES[login] = lire(s, 1.2)
    COLLECTIONS[login] = cartes_de(ENTREES[login])
    TAILLES[login] = taille_collection(ENTREES[login])
    return s, pid

def taille_collection(donnees):
    """Nombre de cases du tableau op52 (= cartes connues du client destinataire)."""
    import zlib
    for op, pl in frames(donnees):
        if op == 52 and pl[1:2] == b"\x08":
            return len(zlib.decompressobj().decompress(pl[4:4 + struct.unpack_from("<H", pl, 2)[0]]))
    return 0

VERSIONS = {}
TAILLES = {}

COLLECTIONS = {}
ENTREES = {}
RAFALES = {}
def cartes_de(donnees):
    """Identifiants des cartes possedees, lus dans op52 (01 | 08 | taille | zlib(tableau))."""
    import zlib
    for op, pl in frames(donnees):
        if op == 52 and pl[1:2] == b"\x08":
            taille = struct.unpack_from("<H", pl, 2)[0]
            tab = zlib.decompressobj().decompress(pl[4:4+taille])
            return [i + 1 for i, q in enumerate(tab) if q]     # case i = carte i + 1 (capture)
    return []

def main():
    for f in (BASE_TEST, "ffwtt_test.db-journal"):
        if os.path.exists(f): os.remove(f)

    env = dict(os.environ)
    env["FFWTT_DB"] = os.path.join(DOSSIER, BASE_TEST)      # base jetable : ne touche pas ffwtt.db
    # Le journal va dans un FICHIER : un tube non lu se remplit (64 Ko) et bloque le serveur
    # sur son premier print() suivant -- toutes les verifications d'apres echouent alors.
    env["PYTHONIOENCODING"] = "utf-8"
    env["FFWTT_TIMER_TEST"] = "2"        # temps par coup raccourci : le serveur joue apres 2 + 2 s
    env["PYTHONUNBUFFERED"] = "1"        # sinon la fin du journal est perdue a l'arret du serveur
    # Une enchere de robot deja en base AVANT le demarrage (mauvais prix, sans mise) : le serveur doit la realigner au
    # demarrage. Sans elle, le test ne voyait pas l'interblocage de realigner_encheres_robots (serveur bloque au lancement).
    # Gerant est le premier compte de la base : il est administrateur d'office (premier compte d'un serveur neuf), et
    # --admin le confirme. --admin ne vaut que pour un compte qui EXISTE au demarrage (aucun niveau n'est reserve a un nom
    # libre) : « Fantome », qui n'existe pas, ne doit rien recevoir quand quelqu'un prendra ce nom.
    subprocess.run([sys.executable, "-c", "import ffwtt_db as d; d.init(); d.create_auction(-1, 'Mog-Facile', 10, 1, 1); "
                    "d.login_or_create('Gerant', 'secret')"],
                   env=env, check=True, capture_output=True)
    env["FFWTT_MAX_PAR_IP"] = "64"           # le test ouvre beaucoup de connexions, toutes depuis 127.0.0.1...
    env["FFWTT_CREATIONS_PAR_IP"] = "1000"   # ... et y cree tous ses comptes (les plafonds se testent a part, plus bas)
    fichier_journal = open(JOURNAL_TEST, "w", encoding="utf-8")
    commande = [sys.executable, "ffwtt_server.py", "--port", str(PORT), "--name", "Test",
                "--admin", "Gerant", "--admin", "Fantome"]          # aucun administrateur n'est code en dur
    serveur = subprocess.Popen(commande, stdout=fichier_journal, stderr=subprocess.STDOUT, env=env)
    time.sleep(2.5)

    try:
        c = socket.create_connection(("127.0.0.1", PORT), timeout=8)
        verifier("connexion au serveur", True)

        ops = opcodes(lire(c, 0.8))
        verifier("message d'accueil : op1 et op4, op6 attend la version (capture)",
                 ops[:2] == [1, 4] and 6 not in ops, str(ops))

        c.sendall(P.build_frame(5, b"\x00" + P.field_int(23082001)))
        verifier("version (op5) -> op6 b1 « Session initialisee », identique a la capture (00 06 01)",
                 frames(lire(c, 0.6)) == [(6, bytes.fromhex("000601"))])
        c.sendall(P.build_frame(100, b"\x00" + P.field_str("Testeur") + P.field_str("motdepasse")))
        r101 = [pl for o, pl in frames(lire(c)) if o == 101]
        verifier("login accepte", bool(r101) and r101[0][:3] == b"\x00\x06\x01")
        pid_t = (champ_ints(r101[0]) or [0])[0] if r101 else 0     # Gerant, cree avant le serveur (--admin), a le n° 1

        c.sendall(P.build_frame(200, b"\x00"))
        ops = opcodes(lire(c))
        verifier("liste des pseudos", 201 in ops and 202 in ops)

        c.sendall(P.build_frame(203, b"\x00" + P.field_str("SecondPseudo")))
        r204 = [pl for o, pl in frames(lire(c)) if o == 204]
        verifier("creation d'un pseudo", bool(r204) and r204[0][:3] == b"\x00\x06\x01")
        id_second = (champ_ints(r204[0]) or [0])[0] if r204 else 0
        c.sendall(P.build_frame(203, b"\x00" + P.field_str("mog-facile")))
        verifier("creation d'un pseudo : le nom d'un robot est refuse (op204 b0 v5)",
                 (204, bytes([0, 6, 0, 5, 5])) in frames(lire(c)))

        c.sendall(P.build_frame(207, b"\x00" + P.field_int(pid_t - 1000)))
        verifier("choix du pseudo", 208 in opcodes(lire(c)))

        c.sendall(P.build_frame(44, b"\x01"))
        rafale = lire(c, 1.5)
        verifier("rafale du salon", len(rafale) > 500, f"{len(rafale)} octets")
        # Ordre observe : op45 (identite) puis les fiches op59, PUIS op62.
        # Une fiche recue apres op62 est annoncee « X vient d'entrer » ; une fiche op59 pour
        # soi-meme cree un doublon dans la liste du client.
        tr = frames(rafale); ops = [o for o, _ in tr]
        i62 = ops.index(62) if 62 in ops else -1
        verifier("rafale : identite (op45) et liste (op59) avant la fin de liste (op62)",
                 i62 > 0 and 45 in ops[:i62] and 59 in ops[:i62] and 59 not in ops[i62:])
        moi = b"\x01" + P.field_int(pid_t)
        verifier("rafale : pas de fiche op59 pour soi-meme",
                 not any(o == 59 and pl.startswith(moi) for o, pl in tr))
        verifier("rafale : compteurs reels (op49 victoires = 0, pas ceux de la capture)",
                 (49, bytes([1]) + P.field_int(0)) in tr)
        # La rafale est generee (plus de fichier tire d'une capture) : ses groupes techniques (onglets de notes 1 a 3,
        # groupe de couleur 31) doivent rester identiques, octet par octet, a ceux de la capture d'origine.
        capture86 = [bytes.fromhex(h) for h in (
            "01030100000001d7551f25333e3a2520332401ce55103e3e2636270a26223a35332a29382d03ff009900",
            "01030200000001ce552b357136ba22303a3828293f3639332a01d455103e3e2636270a3b36320348c62500",
            "01030300000001d7551e253831383a30212401ce55103e3e2636270a2722313a3135392a2d03b7b53700",
            "01031f00000001d4550c3f3d3d21132739222801d05510333e3e3c263224382d2905686d03ffffff00")]
        recus86 = [pl for o, pl in tr if o == 86]
        verifier("rafale generee : groupes des notes et de couleur identiques a la capture, en tete des op86",
                 recus86[:4] == capture86, " ".join(pl[:12].hex() for pl in recus86[:4]))

        c.sendall(P.build_frame(71, b"\x01" + P.field_byte(1)))
        tr = frames(lire(c, 1.5)); ops = [o for o, _ in tr]
        verifier("entree dans le salon", 72 in ops and 73 in ops)
        verifier("entree : ni op45 tardif ni fiche de soi-meme", 45 not in ops and 59 not in ops)
        verifier("collection envoyee", 52 in ops)

        c.sendall(P.build_frame(144, b"\x01" + P.field_str("bonjour") + P.field_byte(0)))
        verifier("chat", 145 in opcodes(lire(c)))

        # profil : dans la capture, op65 est toujours suivi des notes (op66 pour soi, puis op241)
        c.sendall(P.build_frame(64, b"\x01" + P.field_int(pid_t)))
        tr = frames(lire(c, 1.0)); ops = [o for o, _ in tr]
        verifier("profil : le mien (op65 + op66 + op241)", ops[:3] == [65, 66, 241], str(ops))
        # les 33 derniers entiers : nombre de cartes par power (0..31) puis power total
        import ffwtt_server as _S
        fin = [v for k, v in _S.parse_typed(tr[0][1]) if k == "int"][-33:] if tr else []
        verifier("profil : histogramme des cartes par power (20 cartes)", len(fin) == 33 and sum(fin[:32]) == 20,
                 str(fin))
        c.sendall(P.build_frame(64, b"\x01" + P.field_int(999)))
        ops = opcodes(lire(c, 1.0))
        verifier("profil : un robot (op65 + op241)", ops[:2] == [65, 241], str(ops))

        # duel contre l'IA : MEME trame que le vrai client (capture) :
        #   op32 = 03 | int(cible=999) | int16(regles) | v(vainqueur) | int(mise) | v(temps) | b(spect.)
        params = bytes.fromhex("04ee030501030000000005000601")   # regles 0x3ee, comme la capture
        c.sendall(P.build_frame(32, b"\x03" + P.field_int(999) + params))
        tr = frames(lire(c, 1.5)); ops = [o for o, _ in tr]
        verifier("duel : distribution", 135 in ops and 139 in ops)
        i36 = ops.index(36) if 36 in ops else 99
        verifier("duel : plateau Elementaire (op137) et Mur puissant (op138) entre op36 et op135",
                 137 in ops and 138 in ops and i36 < ops.index(137) < ops.index(138) < ops.index(135), str(ops))
        # op33/op36 compares OCTET PAR OCTET au format capture (un octet de travers = client muet)
        #   capture op33 : 03 0316040000 0601 04ee03 0501 0300000000 0500 0601
        #   capture op36 : 03 0316040000 0601 0600 03 1a040000
        # Contre un robot il n'y a jamais d'enjeu, mais la regle demandee ici (v1 = « Aucune » dans l'ordre du
        # client) n'en met pas : l'echo est donc IDENTIQUE a la capture, octet par octet.
        p33 = next((pl for o, pl in tr if o == 33), b"")
        p36 = next((pl for o, pl in tr if o == 36), b"")
        verifier("duel : op33 identique a la capture",
                 p33 == b"\x03" + P.field_int(999) + b"\x06\x01" + params, p33.hex())
        verifier("duel : op36 identique a la capture",
                 p36 == b"\x03" + P.field_int(999) + b"\x06\x01\x06\x00" + P.field_int(814), p36.hex())
        # op232 : ... int(0) b1 i32(masque des regles) v1  (capture : 02ee030000 pour 0x3ee)
        p232 = next((pl for o, pl in tr if o == 232), b"")
        verifier("duel : op232 porte le masque des regles", p232.endswith(bytes.fromhex("060102ee0300000501")),
                 p232.hex())

        # identifiant de partie = (numero de partie << 8) | 3, avec numero = 814
        partie = (814 << 8) | 3
        c.sendall(P.build_frame(140, P.field_int(partie) + b"\x00"
                                + P.field_v(0) + P.field_v(1) + P.field_v(1)))
        ops = opcodes(lire(c, 1.5))
        verifier("duel : pose d'une carte", 142 in ops or 141 in ops)

        # les quatre robots : defi au plus fort avec une mise de 500 gils et la regle « Two » (v3) -> l'echo
        # d'op33 revient sans enjeu (vainqueur « Aucune » = 1) ; l'ancienne partie est refermee (op235).
        mise = bytes.fromhex("0402000503") + P.field_int(500) + bytes.fromhex("05000601")     # regles 2 = Aleatoire
        c.sendall(P.build_frame(32, b"\x03" + P.field_int(996) + mise))
        tr = frames(lire(c, 1.5))
        p33 = next((pl for o, pl in tr if o == 33), b"")
        verifier("robots : ni mise ni cartes en jeu (op33 : vainqueur 0, mise 0), partie lancee",
                 p33 == b"\x03" + P.field_int(996) + b"\x06\x01" + bytes.fromhex("0402000501") + P.field_int(0)
                 + bytes.fromhex("05000601") and 135 in [o for o, _ in tr] and 235 in [o for o, _ in tr], p33.hex())
        c.sendall(P.build_frame(144, b"\x01" + P.field_str("!robots") + P.field_byte(0)))
        txt = lire(c, 0.8)
        c.sendall(P.build_frame(144, b"\x01" + P.field_str("!envoi 37 01") + P.field_byte(0)))
        txt2 = frames(lire(c, 0.8))
        verifier("commandes : !robots pour tous, les commandes de sondage reservees aux operateurs de niveau 4",
                 opcodes(txt).count(145) >= 5 and 37 not in [o for o, _ in txt2] and len(txt2) == 1)

        # boutique : v2 = achat
        c.sendall(P.build_frame(66, b"\x01" + b"\x04" + struct.pack("<H", 1234) + P.field_v(2)))
        ops = opcodes(lire(c))
        verifier("boutique : achat", 63 in ops or 67 in ops)


        c.close()

        # ================= UN SEUL DECK PAR COMPTE ; SECTION « ROBOT » =================
        # Comme sur le serveur officiel, un second pseudo ne recoit PAS de nouveau deck : il joue avec les cartes du compte.
        s1, _ = entrer("Testeur", mdp="motdepasse"); cartes_principal = sorted(COLLECTIONS["Testeur"]); s1.close()
        s2, pid2 = entrer("Testeur", mdp="motdepasse", pseudo_db=id_second); cartes_second = sorted(COLLECTIONS["Testeur"])
        verifier("second pseudo : memes cartes que le pseudo principal (un seul deck par compte)",
                 pid2 == 1000 + id_second and len(cartes_principal) >= 20 and cartes_second == cartes_principal,
                 f"{len(cartes_principal)} cartes / {len(cartes_second)} cartes")
        import sqlite3 as _sq
        _c = _sq.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        orphelines = _c.execute("SELECT COUNT(*) FROM collection WHERE pseudo_id=?", (id_second,)).fetchone()[0]; _c.close()
        verifier("second pseudo : aucune carte creee pour lui en base", orphelines == 0)
        # Les quatre robots ont chacun leur grade (102 Bahamut, 103 Tonberry, 104 Chocobo, 105 Mog), tous du groupe 9
        # « Robot » : une seule section. Le client classe la liste par RANG du meilleur grade (le premier grade defini est
        # tout en haut), puis par nom : les operateurs d'abord, les robots apres l'equipe, du plus fort au plus faible.
        tr = frames(RAFALES["Testeur"]); ops_r = [o for o, _ in tr]
        bots = [pl for o, pl in tr if o == 59 and champ_ints(pl)[:1][0] in (996, 997, 998, 999)]
        grades87 = [champ_ints(pl)[0] for o, pl in tr if o == 87]
        groupes86 = [champ_ints(pl)[0] for o, pl in tr if o == 86]
        verifier("liste des joueurs : 4 robots dans la section « Robot » (grades 102 a 105, du plus fort au plus faible), avant op62",
                 sorted(champ_ints(pl)[0] for pl in bots) == [996, 997, 998, 999]
                 and all(pl.endswith(bytes([5, {996: 102, 997: 103, 998: 104, 999: 105}[champ_ints(pl)[0]]])) for pl in bots)
                 and grades87.index(102) < grades87.index(103) < grades87.index(104) < grades87.index(105)
                 and groupes86.count(9) == 1
                 and max(i for i, o in enumerate(ops_r) if o == 59) < ops_r.index(62), str(len(bots)))
        verifier("liste des joueurs : operateurs en tete, robots apres l'equipe (ordre des grades et des groupes)",
                 grades87[:1] == [14] and grades87.index(102) > max(grades87.index(g) for g in (14, 13, 12, 11, 21, 31))
                 and groupes86.index(9) > max(groupes86.index(g) for g in (11, 12, 13)), str(grades87))
        s2.close()

        # Suppression d'un pseudo (fenetre des pseudos) : op205 int(pseudo) + str(e-mail) -> op206 b1 | b0 v(code).
        _c = _sq.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        _c.execute("UPDATE accounts SET email='testeur@exemple.org' WHERE lower(login)='testeur'"); _c.commit()
        sp = socket.create_connection(("127.0.0.1", PORT), timeout=8); lire(sp, 0.6)
        sp.sendall(P.build_frame(100, b"\x00" + P.field_str("Testeur") + P.field_str("motdepasse"))); lire(sp, 0.8)
        reponses = []
        for pseudo_x, mail in ((id_second, "autre@exemple.org"), (pid_t - 1000, "testeur@exemple.org"), (id_second, " Testeur@Exemple.org ")):
            sp.sendall(P.build_frame(205, b"\x00" + P.field_int(pseudo_x) + P.field_str(mail)))
            reponses.append([pl for o, pl in frames(lire(sp, 0.6)) if o == 206])
        reste = _c.execute("SELECT COUNT(*) FROM pseudos WHERE id=?", (id_second,)).fetchone()[0]; _c.close(); sp.close()
        verifier("suppression de pseudo : e-mail faux (v8), pseudo principal (v30), puis supprime (op206 b1)",
                 reponses == [[bytes([0, 6, 0, 5, 8])], [bytes([0, 6, 0, 5, 30])], [bytes([0, 6, 1])]] and reste == 0,
                 f"{[[x.hex() for x in r] for r in reponses]}, second pseudo en base : {reste}")

        # ================= DUEL JOUEUR CONTRE JOUEUR =================
        # Deux vrais clients : Alice defie Bob (pid brut, pas (pid<<8|3)).
        a, pid_a = entrer("Alice")
        b, pid_b = entrer("Bob")
        carol, _pid_c = entrer("Carol")            # une spectatrice : elle ne joue pas, elle regarde l'onglet Parties
        verifier("PvP : deux joueurs connectes", pid_a > 1000 and pid_b > 1000 and pid_a != pid_b)
        # Un compte deja connecte ne peut pas l'etre une seconde fois (code 4 « Ce compte est deja connecte sur le
        # serveur ») ; la premiere connexion n'est pas touchee.
        double = socket.create_connection(("127.0.0.1", PORT), timeout=8); lire(double, 0.6)
        double.sendall(P.build_frame(100, b"\x00" + P.field_str("Bob") + P.field_str("secret")))
        rep = [pl for o, pl in frames(lire(double, 0.8)) if o == 101]; double.close()
        b.sendall(P.build_frame(64, b"\x01" + P.field_int(pid_b)))
        verifier("double connexion : refusee (op101 b0 v4), la premiere reste en jeu",
                 rep == [bytes([0, 6, 0, 5, 4])] and 65 in opcodes(lire(b, 0.8)), str([x.hex() for x in rep]))

        lire(a, 0.4); lire(b, 0.4)  # vider les annonces d'arrivee
        # Alice defie Bob : op32 ctx3 + int(cible) + int16(regles) + v(rv) + int(mise) + v(temps) + b(spec)
        defi = (b"\x03" + P.field_int(pid_b) + P.field_int16(96)   # 96 = Identique(32)+Plus(64)
                + P.field_v(0) + P.field_int(0) + P.field_v(0) + P.field_byte(1))
        a.sendall(P.build_frame(32, defi))
        rb = lire(b, 1.0)
        verifier("PvP : Bob recoit l'invitation (op34)", 34 in opcodes(rb))
        lire(a, 0.4)

        # Bob accepte : op35 ctx3 + int(defiant) + b1
        b.sendall(P.build_frame(35, b"\x03" + P.field_int(pid_a) + P.field_byte(1)))
        ra = lire(a, 1.0); rb = lire(b, 1.0)
        # Sans la regle Aleatoire : op36 avec le 3e champ a 1 (« Choix des cartes »), et rien
        # d'autre tant que les deux joueurs n'ont pas envoye leurs 5 cartes (op133).
        p36 = next((pl for o, pl in frames(ra) if o == 36), b"")
        verifier("PvP : sans Aleatoire, op36 demande le choix des cartes et la partie attend",
                 p36[:10] == b"\x03" + P.field_int(pid_b) + b"\x06\x01\x06\x01"
                 and 135 not in opcodes(ra) and 135 not in opcodes(rb), p36.hex())
        main_a, main_b = COLLECTIONS["Alice"][:5], COLLECTIONS["Bob"][:5]
        a.sendall(P.build_frame(133, b"\x03" + P.field_int(champ_ints(p36)[-1])
                                + b"".join(P.field_int16(c) for c in main_a)))
        ra2 = lire(a, 0.8)
        verifier("PvP : main acceptee (op134), on attend l'adversaire",
                 134 in opcodes(ra2) and 135 not in opcodes(ra2))
        b.sendall(P.build_frame(133, b"\x03" + P.field_int(champ_ints(p36)[-1])
                                + b"".join(P.field_int16(c) for c in main_b)))
        ra += lire(a, 1.0); rb += lire(b, 1.0)
        opa, opb = opcodes(ra), opcodes(rb)
        m135 = next((pl for o, pl in frames(ra) if o == 135), b"")
        verifier("PvP : partie creee et distribuee (op36+op135), avec la main CHOISIE",
                 36 in opa and 135 in opa and 36 in opb and 135 in opb
                 and m135.endswith(b"".join(P.field_int16(c) for c in main_a)))

        # L'annonce de la partie (op232, onglet Parties) : UNE fois chez chaque joueur (dans ses trames de
        # debut) et UNE fois chez les autres — elle s'affichait en double chez les deux adversaires.
        rc = lire(carol, 0.3)                      # (court : le chronometre d'Alice tourne deja)
        verifier("Parties : la partie est annoncee une seule fois a chacun (op232)",
                 opa.count(232) == 1 and opb.count(232) == 1 and opcodes(rc).count(232) == 1,
                 f"Alice {opa.count(232)}, Bob {opb.count(232)}, spectatrice {opcodes(rc).count(232)}")

        # Recuperer l'identifiant de partie depuis op36 (2e entier) recu par Alice
        gid = None
        for op, pl in frames(ra):
            if op == 36:
                ii = champ_ints(pl)
                if len(ii) >= 2: gid = ii[-1]
        verifier("PvP : identifiant de partie transmis", gid is not None)

        # Alice (elle commence) pose sa 1re carte : op140 ctx3 + int(gid<<8|3) + v(idx) v(x) v(y)
        if gid is not None:
            partie_pvp = (gid << 8) | 3
            a.sendall(P.build_frame(140, P.field_int(partie_pvp) + b"\x00"
                                    + P.field_v(0) + P.field_v(0) + P.field_v(0)))
            opa = opcodes(lire(a, 1.0)); opb = opcodes(lire(b, 1.0))
            verifier("PvP : coup relaye aux deux joueurs (op142)", 142 in opa and 142 in opb)
            # temps ecoule : Bob ne joue pas, le serveur pose une carte a sa place (capture)
            ra_t = frames(lire(a, 6.0)); rb_t = frames(lire(b, 1.0))
            auto_a = [pl for o, pl in ra_t if o == 142]; auto_b = [pl for o, pl in rb_t if o == 142]
            verifier("PvP : temps ecoule, le serveur joue a la place du retardataire",
                     bool(auto_a) and bool(auto_b) and auto_a[0][-4:-2] == bytes([5, 1]) and auto_b[0][-4:-2] == bytes([5, 0]),
                     (auto_a[0].hex() if auto_a else "rien"))

        # ----- SPECTATRICE. Formats lus dans le client (jamais captures) : op157 porte le PETIT numero de partie
        # (celui d'op232), op161 l'etat complet, op135/136 les mains (0 = carte jouee), op160 les spectateurs.
        if gid is not None:
            lire(a, 0.3); lire(b, 0.3); lire(carol, 0.3)
            carol.sendall(P.build_frame(156, b"\x03" + P.field_int(gid) + P.field_byte(0)))
            rc = frames(lire(carol, 1.0)); ra_s = frames(lire(a, 0.3))
            p157 = next((pl for o, pl in rc if o == 157), b""); p161 = next((pl for o, pl in rc if o == 161), b"")
            verifier("spectateur : accord op157 = 03 | b1 | int(numero de partie)",
                     p157 == b"\x03" + b"\x06\x01" + P.field_int(gid), p157.hex())
            import ffwtt_server as _S2
            ch = _S2.parse_typed(p161)
            cases = [(ch[6 + 2 * i][1], ch[7 + 2 * i][1]) for i in range(9)] if len(ch) == 24 else []
            verifier("spectateur : etat op161 = partie, score, regles, vainqueur, mise, 9 x (carte, proprietaire)",
                     [k for k, _ in ch[:6]] == ["ctx", "int", "v", "h16", "v", "int"] and ch[1][1] == gid and ch[3][1] == 96
                     and sum(1 for cid, _ in cases if cid) >= 2 and main_a[0] in [cid for cid, _ in cases], p161.hex())
            # (le chronometre du test fait jouer le serveur toutes les 4 s : le nombre de cartes posees varie)
            mains = [[v for k, v in _S2.parse_typed(next((pl for o, pl in rc if o == op_), b""))[2:]] for op_ in (135, 136)]
            verifier("spectateur : mains masquees, 0 pour chaque carte deja jouee (op135 / op136), liste op160",
                     all(len(m) == 5 and set(m) <= {0, 0x1316} for m in mains) and mains[0][0] == 0
                     and sum(m.count(0) for m in mains) == sum(1 for cid, _ in cases if cid)
                     and (160, b"\x03" + P.field_int(gid) + P.field_int(_pid_c)) in rc, str(mains))
            verifier("spectateur : annonce aux joueurs (op158) et compteur de l'onglet Parties (op234 = 1)",
                     (158, b"\x03" + P.field_int(gid) + P.field_int(_pid_c)) in ra_s
                     and (234, b"\x03" + P.field_int(gid) + P.field_int(1)) in ra_s, str([o for o, _ in ra_s]))
            # Le joueur dont c'est le tour (op139 : 0 = Alice, joueur 0 de la partie ; 1 = Bob) pose une carte. Que ce
            # soit lui ou le serveur a sa place (temps ecoule), la spectatrice doit voir op142 avec CE proprietaire.
            tour = next((pl for o, pl in reversed(rc) if o == 139), bytes(4))[-4]
            libre = next(i for i, (cid, _) in enumerate(cases) if not cid) if cases else 8      # ordre du fil : x*3 + y
            idx = next((i for i, cid in enumerate(mains[tour]) if cid), 4)
            (a if tour == 0 else b).sendall(P.build_frame(140, P.field_int((gid << 8) | 3) + b"\x00"
                                    + P.field_v(idx) + P.field_v(libre // 3) + P.field_v(libre % 3)))
            rc = frames(lire(carol, 1.0))
            if 142 not in [o for o, _ in rc]: rc += frames(lire(carol, 5.0))
            p142 = next((pl for o, pl in rc if o == 142), b"")
            verifier("spectateur : coup relaye avec le proprietaire ABSOLU (joueur 0 ou 1 de la partie), sans l'accuse op141",
                     p142[-4:-2] == bytes([5, tour]) and 141 not in [o for o, _ in rc] and 143 in [o for o, _ in rc],
                     f"tour {tour} : {p142.hex()}")
            lire(a, 0.3)
            carol.sendall(P.build_frame(162, b"\x03" + P.field_int(gid)))
            rc = frames(lire(carol, 0.8)); ra_s = frames(lire(a, 0.3))
            verifier("spectateur : arret (op162 -> op163 b1), depart annonce (op159), compteur a 0 (op234)",
                     (163, b"\x03" + P.field_int(gid) + b"\x06\x01") in rc
                     and (159, b"\x03" + P.field_int(gid) + P.field_int(_pid_c)) in ra_s
                     and (234, b"\x03" + P.field_int(gid) + P.field_int(0)) in ra_s, str([o for o, _ in ra_s]))
        carol.close()

        dave, _pid_d = entrer("Dave")              # arrive APRES le debut : il doit voir la partie en cours
        verifier("Parties : un joueur arrive en cours de partie la voit aussi (op232 a l'entree)",
                 opcodes(ENTREES["Dave"]).count(232) == 1)
        dave.close(); lire(a, 0.4); lire(b, 0.4)

        # ================= LANGUE : les anglophones ont leur section dans la liste =================
        # Langue du compte (accounts.langue) : grade 41 « English speaker » (groupe 40), en op61 pour soi et en fin
        # de fiche op59 chez les autres ; les francophones restent sans grade (rangs d'etoiles de notoriete du client).
        import ffwtt_server as _SV, sqlite3 as _sql
        emily, _pid_e = entrer("Emily"); emily.close(); lire(a, 0.4); lire(b, 0.4)
        _c = _sql.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        _c.execute("UPDATE accounts SET langue='en' WHERE login='emily'"); _c.commit(); _c.close()
        emily, _pid_e = entrer("Emily")
        vue_a = frames(lire(a, 0.6)); lire(b, 0.4)
        r_e = frames(RAFALES["Emily"])
        typ = lambda pl: [v for _k, v in _SV.parse_typed(pl)]
        verifier("langue : groupe 40 « English speakers » (op86) et grade 41 « English speaker » du groupe 40 (op87)",
                 any(o == 86 and typ(pl)[1:3] == [40, "English speakers"] for o, pl in r_e)
                 and any(o == 87 and typ(pl)[1:4] == [41, "English speaker", 40] for o, pl in r_e))
        verifier("langue : l'anglophone recoit son grade (op61 int(pid) v41)",
                 (61, b"\x01" + P.field_int(_pid_e) + P.field_v(41)) in r_e)
        fiche_e = [pl for o, pl in vue_a if o == 59 and typ(pl)[1] == _pid_e]
        fiche_a = [pl for o, pl in r_e if o == 59 and typ(pl)[1] == pid_a]
        verifier("langue : les autres le voient avec le grade 41 (fin de fiche op59), un francophone reste sans grade",
                 len(fiche_e) == 1 and fiche_e[0].endswith(P.field_v(41))
                 and len(fiche_a) == 1 and not fiche_a[0].endswith(P.field_v(41)), f"{len(fiche_e)} / {len(fiche_a)}")
        # ce que le SERVEUR ecrit lui-meme lui arrive en anglais (le client, lui, reste en francais)
        libelles = lambda r, op: {typ(pl)[1]: typ(pl)[2] for o, pl in r if o == op and len(typ(pl)) > 2}
        r_a = frames(RAFALES["Alice"])
        verifier("langue : sections, grades et notoriete en anglais pour lui, en francais pour les autres",
                 libelles(r_e, 86).get(11) == "Operators" and libelles(r_e, 87).get(21) == "Event host"
                 and libelles(r_e, 88).get(1) == "Tournaments" and libelles(r_a, 86).get(11) == "Opérateurs"
                 and libelles(r_a, 88).get(1) == "Tournois", f"{libelles(r_e, 86)} {libelles(r_a, 86)}")
        try:
            with open("motd_en.txt", encoding="utf-8") as _f: motd_en = [l.rstrip("\n") for l in _f if l.strip()]
        except OSError: motd_en = []
        accueil = lambda r: [typ(pl)[-1] for o, pl in r if o == 166]
        verifier("langue : message d'accueil anglais (motd_en.txt) pour lui, francais pour les autres",
                 motd_en and accueil(r_e) == motd_en and accueil(r_a) and accueil(r_a) != motd_en, str(accueil(r_e))[:120])
        emily.sendall(P.build_frame(144, b"\x01" + P.field_str("!help") + P.field_byte(0)))
        aide = [typ(pl)[2] for o, pl in frames(lire(emily, 0.8)) if o == 145]
        emily.sendall(P.build_frame(146, b"\x01" + P.field_int(999) + P.field_str("hello") + P.field_byte(0)))
        rep_robot = [typ(pl)[3] for o, pl in frames(lire(emily, 0.8)) if o == 147 and typ(pl)[1] == 1]
        verifier("langue : !help et les reponses des robots en anglais",
                 aide[:1] == ["!help    : this list"] and rep_robot[:1] == ["Hello. I am a robot that can play games."],
                 f"{aide[:1]} {rep_robot[:1]}")
        emily.sendall(P.build_frame(144, b"\x01" + P.field_str("!langue fr") + P.field_byte(0)))
        rep_l = [typ(pl)[2] for o, pl in frames(lire(emily, 0.8)) if o == 145]
        _c = _sql.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        langue_base = _c.execute("SELECT langue FROM accounts WHERE login='emily'").fetchone()[0]; _c.close()
        emily.sendall(P.build_frame(144, b"\x01" + P.field_str("!zzz") + P.field_byte(0)))
        rep_z = [typ(pl)[2] for o, pl in frames(lire(emily, 0.8)) if o == 145]
        verifier("langue : !langue fr dans le jeu change la langue du compte, les messages suivent aussitot",
                 langue_base == "fr" and rep_l[:1] and rep_l[0].startswith("Langue : francais")
                 and rep_z == ["Commande inconnue. Tape !aide"], f"{langue_base} {rep_l[:1]} {rep_z}")
        emily.close(); lire(a, 0.4); lire(b, 0.4)

        # ================= COMPETENCES, SACRIFICE, ENCHERES =================
        # Tables lues dans le client : op244 + v(Tag du bouton) ; niveau renvoye par un opcode PROPRE a la
        # competence (0 Souk->53, 2 Connaisseur->55, 3 Profiteur->89, 4 Encheres->56, 7 Initie->90, 8 Chanceux->91).
        import sqlite3
        lire(a, 0.5); lire(b, 0.5)
        _c = sqlite3.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        _c.execute("INSERT INTO powers(pseudo_id,points) VALUES(?,5000) "
                   "ON CONFLICT(pseudo_id) DO UPDATE SET points=5000", (pid_a - 1000,))
        _c.commit()
        # Regle d'origine : 2000 points d'experience pour sacrifier / vendre / jeter / echanger / mettre aux encheres.
        _c.execute("UPDATE stats SET noto=0 WHERE pseudo_id IN (?,?)", (pid_a - 1000, pid_b - 1000)); _c.commit()
        a.sendall(P.build_frame(66, b"\x01" + P.field_int16(COLLECTIONS["Alice"][-1]) + P.field_v(1)))
        verifier("experience : sacrifice refuse sous 2000 points (op67 b0 v99)",
                 (67, bytes([1, 6, 0, 5, 99])) in frames(lire(a, 0.6)))
        _c.execute("UPDATE stats SET noto=2000 WHERE pseudo_id=?", (pid_a - 1000,)); _c.commit()
        a.sendall(P.build_frame(88, b"\x02" + P.field_int(pid_b)))
        verifier("experience : echange refuse si le partenaire a moins de 2000 points (op89 b0 v100)",
                 (89, b"\x02" + P.field_int(pid_b) + bytes([6, 0, 5, 100])) in frames(lire(a, 0.6)))
        _c.execute("UPDATE stats SET noto=2000 WHERE pseudo_id=?", (pid_b - 1000,))
        _c.commit(); _c.close()                 # fermer : sinon la base jetable ne peut pas etre supprimee a la fin
        attendus = {0: 53, 2: 55, 3: 89, 4: 56, 7: 90, 8: 91}; recus = {}; bavard = False
        # La partie PvP d'Alice continue toute seule (le serveur joue pour les retardataires) et peut se terminer
        # pendant ces verifications : son resultat (« Victoire (6-4) : ... ») est une annonce legitime, pas un bavardage.
        def annonce(o, pl):
            if o != 145: return False
            try: texte = P.decode_string(pl, 6)[0]
            except Exception: return True
            return not texte.startswith(("Victoire", "Defaite", "Match nul", "Entrainement"))
        for comp in attendus:
            a.sendall(P.build_frame(244, b"\x01" + P.field_v(comp)))
            for o, pl in frames(lire(a, 0.6)):
                if o in attendus.values() and pl == b"\x01\x05\x01": recus[comp] = o
                if annonce(o, pl): bavard = True
        verifier("competences : chaque achat renvoie SON opcode de niveau (53 55 89 56 90 91)", recus == attendus, str(recus))
        a.sendall(P.build_frame(244, b"\x01" + P.field_v(7)))                      # Initie niveau 2
        r = frames(lire(a, 0.6))
        verifier("competences : Initie monte au niveau 2 (op90 « 01 05 02 ») + accuse op245 (b1 v7 v2)",
                 (90, b"\x01\x05\x02") in r and (245, b"\x01\x06\x01\x05\x07\x05\x02") in r)
        a.sendall(P.build_frame(244, b"\x01" + P.field_v(6)))                      # capacite inexistante
        verifier("competences : capacite inconnue refusee (op245 b0 v18)", (245, b"\x01\x06\x00\x05\x12") in frames(lire(a, 0.6)))
        bavard = bavard or any(annonce(o, pl) for o, pl in r)
        sacrifiee = COLLECTIONS["Alice"][-1]
        a.sendall(P.build_frame(66, b"\x01" + P.field_int16(sacrifiee) + P.field_v(1)))
        r = frames(lire(a, 0.8)); ops = [o for o, _ in r]
        verifier("sacrifice : powers (op48), carte retiree (op63), accuse (op67)", all(o in ops for o in (48, 63, 67)))
        verifier("sacrifice et competences : aucune annonce dans le chat (op145)", not bavard and not any(annonce(o, pl) for o, pl in r))
        # Les autres boutons de « Mes cartes » partagent op66 (v = Tag du bouton) : 0 Jeter, 3 Vendre. Ils ACHETAIENT la
        # carte (tout ce qui n'etait pas 1 passait pour un achat).
        _c = sqlite3.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        sql_gils = "SELECT a.gils FROM accounts a JOIN pseudos p ON p.account_id=a.id WHERE p.id=?"
        sql_qte = "SELECT COALESCE(SUM(qty),0) FROM collection WHERE pseudo_id=? AND card_id=?"
        for nom_action, v, carte_v in (("vente", 3, COLLECTIONS["Alice"][-2]), ("jeter", 0, COLLECTIONS["Alice"][-3])):
            gils_avant = _c.execute(sql_gils, (pid_a - 1000,)).fetchone()[0]
            qte_avant = _c.execute(sql_qte, (pid_a - 1000, carte_v)).fetchone()[0]
            prix = _c.execute("SELECT price FROM refcards WHERE card_id=?", (carte_v,)).fetchone()[0] or 100
            a.sendall(P.build_frame(66, b"\x01" + P.field_int16(carte_v) + P.field_v(v)))
            r = frames(lire(a, 0.8)); _c.commit()
            r63 = [pl for o, pl in r if o == 63]; r47 = [struct.unpack_from("<I", pl, 2)[0] for o, pl in r if o == 47]
            gils_apres = _c.execute(sql_gils, (pid_a - 1000,)).fetchone()[0]
            qte_apres = _c.execute(sql_qte, (pid_a - 1000, carte_v)).fetchone()[0]
            gain = max(1, round(prix * 0.15)) if v == 3 else 0
            verifier(f"mes cartes : {nom_action} (op66 v{v}) retire la carte (op63 b0, accuse op67 b1)"
                     + (f", +15 % du prix en gils (op47, comme l'affiche le client)" if v == 3 else ", sans gils ni powers"),
                     len(r63) == 1 and r63[0][:3] == b"\x01\x06\x00" and (67, b"\x01\x06\x01") in r
                     and qte_apres == qte_avant - 1 and gils_apres == gils_avant + gain
                     and r47 == ([gils_apres] if v == 3 else []) and 48 not in [o for o, _ in r],
                     f"qte {qte_avant}->{qte_apres}, gils {gils_avant}->{gils_apres} (attendu +{gain}), op47 {r47}, op63 {[x.hex() for x in r63]}")
        _c.close()
        vendue = COLLECTIONS["Alice"][1]
        a.sendall(P.build_frame(188, b"\x02" + P.field_int16(vendue) + bytes([2]) + struct.pack("<I", 10)
                                + bytes([2]) + struct.pack("<I", 500)))
        ra = frames(lire(a, 0.8)); rb = frames(lire(b, 0.8))
        fa = [pl for o, pl in ra if o == 190]; fb = [pl for o, pl in rb if o == 190]
        verifier("enchere : la fiche (op190) arrive UNE fois au vendeur et une fois aux autres",
                 len(fa) == 1 and len(fb) == 1 and fa == fb and 189 in [o for o, _ in ra], f"vendeur {len(fa)}, autre {len(fb)}")
        n_ench = struct.unpack_from("<I", fa[0], 2)[0] if fa else 0
        a.sendall(P.build_frame(194, b"\x02" + bytes([2]) + struct.pack("<I", n_ench) + P.field_byte(1)))
        ra = frames(lire(a, 0.8)); rb = frames(lire(b, 0.8))
        verifier("enchere : annulation, retrait (op196) une seule fois chez chacun",
                 [o for o, _ in ra].count(196) == 1 and [o for o, _ in rb].count(196) == 1 and 195 in [o for o, _ in ra])
        # Encheres des robots : 3 chacun, cartes des niveaux de sa main, prix boutique - 10 % (mise de depart comprise) ;
        # une enchere de robot vendue est aussitot remplacee par une autre carte.
        import ffwtt_server as _SV, sqlite3 as _sq5
        fiche = lambda pl: [v for _k, v in _SV.parse_typed(pl)]        # ctx, id, vendeur, nom, carte, depart, immediat, offre...
        rob = [fiche(pl) for o, pl in frames(RAFALES["Alice"]) if o == 190 and fiche(pl)[2] in (996, 997, 998, 999)]
        _c = _sq5.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        ref = lambda cid: _c.execute("SELECT price, level FROM refcards WHERE card_id=?", (cid,)).fetchone()
        niveaux = {999: (1, 3), 998: (3, 6), 997: (5, 8), 996: (8, 10)}
        verifier("encheres des robots : 3 par robot, niveaux de sa main, -10 % du prix boutique (depart et achat immediat)",
                 sorted(f[2] for f in rob) == [996] * 3 + [997] * 3 + [998] * 3 + [999] * 3
                 and all(f[6] == max(1, round(ref(f[4])[0] * 0.9)) and f[5] == f[6]
                         and niveaux[f[2]][0] <= ref(f[4])[1] <= niveaux[f[2]][1] for f in rob), str([f[2:7] for f in rob][:4]))
        mog = next(f for f in rob if f[2] == 999)
        a.sendall(P.build_frame(191, b"\x02" + bytes([2]) + struct.pack("<I", mog[1]) + bytes([2]) + struct.pack("<I", mog[6])))
        ra = frames(lire(a, 1.0)); lire(b, 0.4)
        nouvelles = [fiche(pl) for o, pl in ra if o == 190 and fiche(pl)[2] == 999]
        encore = _c.execute("SELECT COUNT(*) FROM auctions WHERE seller_pseudo=-1 AND actif=1").fetchone()[0]; _c.close()
        verifier("encheres des robots : achat immediat -> la carte (op63), fin de l'enchere (op196), et le robot remet une carte en vente",
                 63 in [o for o, _ in ra] and (196, b"\x02" + b"\x02" + struct.pack("<I", mog[1])) in ra
                 and len(nouvelles) == 1 and nouvelles[0][1] != mog[1] and encore == 3, f"{[o for o, _ in ra]} {encore}")

        # La regle d'origine « plus de 10 cartes » : Bob sacrifie jusqu'a la limite, puis se heurte au refus.
        # (Bob, parce qu'Alice doit garder de quoi offrir une carte dans l'echange qui suit.)
        refus = None; faits = 0
        for carte_s in COLLECTIONS["Bob"]:
            b.sendall(P.build_frame(66, bytes([1]) + P.field_int16(carte_s) + P.field_v(1)))
            r67 = [pl for o, pl in frames(lire(b, 0.35)) if o == 67]
            if r67 and r67[0] != bytes([1, 6, 1]): refus = r67[0]; break
            faits += 1
        verifier("sacrifice : refuse des qu'il ne reste que 10 cartes (op67 b0 v101, message du client)",
                 refus == bytes([1, 6, 0, 5, 101]) and faits == len(COLLECTIONS["Bob"]) - 10,
                 f"{faits} sacrifices, refus {refus.hex() if refus else None}")
        b.sendall(P.build_frame(188, bytes([2]) + P.field_int16(COLLECTIONS["Bob"][-1]) + bytes([2]) + struct.pack("<I", 10)
                                + bytes([2]) + struct.pack("<I", 500)))
        verifier("enchere : refusee aussi avec 10 cartes (op189 b0 v101)",
                 (189, bytes([2, 6, 0, 5, 101])) in frames(lire(b, 0.6)))
        lire(a, 0.3)

        # ================= ECHANGE DE CARTES (formats de la capture) ========================
        lire(a, 0.5); lire(b, 0.5)
        carte = COLLECTIONS["Alice"][0]
        a.sendall(P.build_frame(88, b"\x02" + P.field_int(pid_b)))
        ra = frames(lire(a, 0.8)); rb = frames(lire(b, 0.8))
        verifier("echange : demande (op89 a l'initiateur, op90 a la cible)",
                 (89, b"\x02" + P.field_int(pid_b) + b"\x06\x01") in ra
                 and (90, b"\x02" + P.field_int(pid_a)) in rb)
        b.sendall(P.build_frame(91, b"\x02" + P.field_int(pid_a) + P.field_byte(1)))
        ra = frames(lire(a, 0.8)); rb = frames(lire(b, 0.8))
        verifier("echange : acceptation (op92 aux deux)",
                 (92, b"\x02" + P.field_int(pid_b) + b"\x06\x01") in ra
                 and (92, b"\x02" + P.field_int(pid_a) + b"\x06\x01") in rb)
        # Alice offre UNE carte : op93 = int(partenaire) int(gils) int16(carte) v(quantite)
        offre = P.field_int(0) + P.field_int16(carte) + P.field_v(1)
        a.sendall(P.build_frame(93, b"\x02" + P.field_int(pid_b) + offre))
        ra = frames(lire(a, 0.8)); rb = frames(lire(b, 0.8))
        recu = next((pl for o, pl in rb if o == 95), b"")
        verifier("echange : l'offre arrive au partenaire avec le BON identifiant de carte (op95)",
                 recu == b"\x02" + P.field_int(pid_a) + offre and 94 in [o for o, _ in ra],
                 f"carte {carte} -> {recu.hex()}")
        # Bob n'offre rien (cadeau) : op95 = 02 | int | int(0), exactement la trame capturee
        b.sendall(P.build_frame(93, b"\x02" + P.field_int(pid_a) + P.field_int(0)))
        ra = frames(lire(a, 0.8)); lire(b, 0.5)
        verifier("echange : offre vide identique a la capture",
                 (95, b"\x02" + P.field_int(pid_b) + P.field_int(0)) in ra)
        a.sendall(P.build_frame(96, b"\x02" + P.field_int(pid_b) + P.field_byte(1)))
        lire(a, 0.5)
        b.sendall(P.build_frame(96, b"\x02" + P.field_int(pid_a) + P.field_byte(1)))
        da = lire(a, 1.0); dbb = lire(b, 1.0)
        verifier("echange : conclu (op97 b1) et la carte a change de main",
                 (97, b"\x02" + P.field_int(pid_b) + b"\x06\x01") in frames(da)
                 and (97, b"\x02" + P.field_int(pid_a) + b"\x06\x01") in frames(dbb)
                 and carte not in cartes_de(da) and carte in cartes_de(dbb))
        # annulation : op96 avec b0 -> op97 b0 aux deux (« X a refuse ou annule l'echange »)
        a.sendall(P.build_frame(88, b"\x02" + P.field_int(pid_b))); lire(a, 0.5); lire(b, 0.5)
        b.sendall(P.build_frame(91, b"\x02" + P.field_int(pid_a) + P.field_byte(1))); lire(a, 0.5); lire(b, 0.5)
        a.sendall(P.build_frame(96, b"\x02" + P.field_int(pid_b) + P.field_byte(0)))
        ra = frames(lire(a, 0.8)); rb = frames(lire(b, 0.8))
        verifier("echange : annulation (op97 b0 aux deux, rien n'est echange)",
                 (97, b"\x02" + P.field_int(pid_b) + b"\x06\x00") in ra
                 and (97, b"\x02" + P.field_int(pid_a) + b"\x06\x00") in rb)

        # deconnexion d'Alice : Bob doit recevoir op60 (« Alice a quitte le FFWTT »)
        lire(b, 0.3); a.close()
        depart = [pl for o, pl in frames(lire(b, 1.2)) if o == 60]
        verifier("depart annonce aux autres (op60, format capture)",
                 depart == [bytes([1]) + P.field_int(pid_a) + bytes([5, 0, 5, 0])],
                 depart[0].hex() if depart else "rien")
        b.close()

        # ================= ADMINISTRATEUR : ordre de la rafale et grade =================
        # Le compte 'Gerant' est administrateur d'office. Ordre impose par le client (binaire) :
        #   op81 en tete (la fenetre de chargement qui l'affiche est detruite a op62),
        #   op87 (grades) avant op61, op45 (« moi ») avant op61 et avant toute fiche op59.
        s = socket.create_connection(("127.0.0.1", PORT), timeout=8); lire(s, 0.6)
        s.sendall(P.build_frame(5, b"\x00" + P.field_int(23082001)))
        s.sendall(P.build_frame(100, b"\x00" + P.field_str("Gerant") + P.field_str("secret")))
        pid_adm = 0
        for op, pl in frames(lire(s)):
            if op == 101: pid_adm = (champ_ints(pl) or [0])[0]
        s.sendall(P.build_frame(207, b"\x00" + P.field_int(pid_adm - 1000))); lire(s)
        s.sendall(P.build_frame(44, b"\x01"))
        tr = frames(lire(s, 1.5)); ops = [o for o, _ in tr]
        avec_accueil = False
        verifier("admin : op81 (page d'accueil) en tete de rafale" if avec_accueil else "admin : pas d'op81 sans --accueil",
                 ops[:1] == [81] if avec_accueil else 81 not in ops, str(ops[:3]))
        i45 = ops.index(45) if 45 in ops else -1
        # un operateur de niveau 4 recoit ses grades par op61 : 14 (pastille « 4 »), 3 (salon des operateurs) et 5
        # (responsable des quizz : le panneau Quizz). Pas 21 (animateur) : le niveau 4 en a deja toutes les permissions,
        # et chaque op61 fait ecrire au client « X est maintenant un(e) ... » a chaque connexion.
        recus61 = [pl[-1] for o, pl in tr[i45+1:i45+10] if o == 61 and pl[:6] == bytes([1]) + P.field_int(pid_adm)]
        verifier("admin : grades par op61 juste apres op45 et les panneaux (op177), apres les op87",
                 i45 > 0 and recus61 == [14, 3, 5] and 87 in ops[:i45]
                 and all(o in (177, 211, 231) for o in ops[i45 + 1:next((i for i, o in enumerate(ops) if o == 61), 0)]),
                 str(recus61))
        import ffwtt_server as _S
        groupes = {([v for k, v in _S.parse_typed(pl) if k == "int"] or [0])[0]:
                   ([v for k, v in _S.parse_typed(pl) if k == "str"] or [""])[0] for o, pl in tr if o == 86}
        notos = [([v for k, v in _S.parse_typed(pl) if k == "str"] or [""])[0] for o, pl in tr if o == 88]
        verifier("rafale : groupes Operateurs / Animateurs et 6 categories de notoriete",
                 groupes.get(11, "").startswith("Op") and groupes.get(12, "").startswith("Anim")
                 and 20 not in groupes and len(notos) == 6 and notos[2] == "Quizz", f"{groupes} {notos}")
        verifier("admin : toutes les fiches op59 apres op45 et avant op62",
                 62 in ops and all(i45 < i < ops.index(62) for i, o in enumerate(ops) if o == 59))
        s.sendall(P.build_frame(71, bytes([1]) + P.field_byte(1)))
        entree = frames(lire(s, 1.2))
        # op177 porte un GRADE (3), pas un groupe, et part dans la rafale AVANT les grades (op61)
        # et avant toute fiche op59 : sinon le client plante (00649EF3, puis 0063CF31).
        i177 = ops.index(177) if 177 in ops else -1
        verifier("operateur : panneau du salon ouvert par op177(grade 3) entre op45 et les op61/op59",
                 i177 == i45 + 1 and tr[i177][1] == bytes([4, 6, 1]) + P.field_int(3)
                 and all(i > i177 for i, o in enumerate(ops) if o in (59, 61)) and 177 not in [o for o, _ in entree],
                 tr[i177][1].hex() if i177 >= 0 else "pas d'op177")

        # ---- commandes d'administration (categorie 4, formats envoyes par le vrai client) ----
        v, pid_v = entrer("Bob"); lire(s, 0.5)
        ok4 = b"\x04\x06\x01"                                         # accuse : 04 | b1
        s.sendall(P.build_frame(198, b"\x04" + P.field_int(pid_v) + P.field_str("attention")))
        rs = frames(lire(s, 0.8)); rv = frames(lire(v, 0.8))
        verifier("admin : avertissement op198 (op78 a la cible, accuse op199)",
                 (199, ok4) in rs and (78, b"\x01" + P.field_int(pid_adm) + P.field_str("attention")) in rv)
        s.sendall(P.build_frame(245, b"\x04" + P.field_byte(1) + P.field_int(pid_v)))
        rs = frames(lire(s, 0.8))
        v.sendall(P.build_frame(144, b"\x01" + P.field_str("je parle") + P.field_byte(0)))
        parle = [pl for o, pl in frames(lire(s, 0.8)) if o == 145 and P.field_str("je parle") in pl]
        verifier("admin : mute (accuse op246 b1 b1, la cible ne peut plus parler)",
                 (246, ok4 + b"\x06\x01") in rs and not parle)
        s.sendall(P.build_frame(226, b"\x04" + P.field_int(pid_v) + b"".join(
            P.field_int16(n) for n in (1500, 50, 1375, 50, 50, 50))))
        rs = frames(lire(s, 0.8)); rv = frames(lire(v, 0.8))
        valeurs = b"".join(P.field_int16(n) for n in (1500, 50, 1375, 50, 50, 50))
        verifier("admin : edition de notoriete (accuse op227)", (227, ok4) in rs)
        verifier("notoriete : diffusee a tous (op84 cat. 1 : pid + valeurs), et op83 au joueur concerne",
                 (84, b"\x01" + P.field_int(pid_v) + valeurs) in rs and (84, b"\x01" + P.field_int(pid_v) + valeurs) in rv
                 and (83, b"\x01" + valeurs) in rv, str([o for o, _ in rs]))
        s.sendall(P.build_frame(206, b"\x04" + P.field_int(pid_v)))
        rs = frames(lire(s, 0.8)); dv = lire(v, 0.8)
        fin52 = next((pl[-7:] for o, pl in frames(dv) if o == 52), b"")
        verifier("admin : nouveau deck (op52 termine par v1 + int(auteur), accuse op207)",
                 (207, ok4) in rs and fin52 == b"\x05\x01" + P.field_int(pid_adm) and len(cartes_de(dv)) >= 10,
                 fin52.hex())
        s.sendall(P.build_frame(217, b"\x04" + P.field_str("maintenance")))
        rs = frames(lire(s, 0.8)); rv = frames(lire(v, 0.8))
        verifier("admin : message global (op80 a tous, accuse op218)",
                 (218, ok4) in rs and (80, b"\x01" + P.field_str("maintenance")) in rv)
        # un joueur sans grade ne peut rien faire
        v.sendall(P.build_frame(181, b"\x04" + P.field_int(pid_adm) + P.field_str("coup d'etat")))
        rv = frames(lire(v, 0.8)); rs = lire(s, 0.5)
        verifier("admin : kick refuse a un simple joueur (accuse negatif, code 87 = privileges)",
                 (182, bytes([4, 6, 0, 5, 87])) in rv and 77 not in opcodes(rs))
        # kick : la cible recoit op77 puis est deconnectee ; les autres recoivent op60
        s.sendall(P.build_frame(181, b"\x04" + P.field_int(pid_v) + P.field_str("dehors")))
        rs = frames(lire(s, 3.0)); dv = lire(v, 1.0)     # la deconnexion est vue au tour de boucle suivant (1 s)
        try: v.sendall(b"\x03\x00\x00\x03\x00"); ferme = lire(v, 0.5) == b""
        except OSError: ferme = True
        verifier("admin : kick op181 (op77 a la cible, deconnexion, op60 aux autres, accuse op182)",
                 (182, ok4) in rs and (77, b"\x01" + P.field_int(pid_adm) + P.field_str("dehors")) in frames(dv)
                 and ferme and 60 in [o for o, _ in rs],
                 f"accuse={(182, ok4) in rs} op77={77 in opcodes(dv)} ferme={ferme} op60={60 in [o for o, _ in rs]}")
        # ban de pseudo : le pseudo apparait « (banni) » dans la liste (op201, 6e champ) et son
        # choix est refuse par op208 b0 v11 (« Ce pseudo est banni »)
        s.sendall(P.build_frame(191, bytes([4]) + P.field_byte(1) + P.field_str("Bob") + P.field_str("test")))
        verifier("admin : ban de pseudo (accuse op192 b1 b1)", (192, ok4 + bytes([6, 1])) in frames(lire(s, 0.8)))
        t = socket.create_connection(("127.0.0.1", PORT), timeout=8); lire(t, 0.6)
        t.sendall(P.build_frame(100, bytes([0]) + P.field_str("Bob") + P.field_str("secret"))); lire(t, 0.8)
        t.sendall(P.build_frame(200, bytes([0])))
        f201 = next((pl for o, pl in frames(lire(t, 0.8)) if o == 201), b"")
        t.sendall(P.build_frame(207, bytes([0]) + P.field_int(pid_v - 1000)))
        verifier("admin : pseudo banni signale (op201 ...b1) et refuse (op208 b0 v11)",
                 f201.endswith(bytes([6, 1])) and (208, bytes([0, 6, 0, 5, 11])) in frames(lire(t, 0.8)), f201.hex())
        t.close()
        s.sendall(P.build_frame(191, bytes([4]) + P.field_byte(0) + P.field_str("Bob") + P.field_str(""))); lire(s, 0.6)
        # ban de compte : refus a la reconnexion (code 2), puis levee du ban
        s.sendall(P.build_frame(195, b"\x04" + P.field_byte(1) + P.field_str("Bob") + P.field_str("triche")))
        verifier("admin : ban de compte (accuse op196 b1 b1)", (196, ok4 + b"\x06\x01") in frames(lire(s, 0.8)))
        t = socket.create_connection(("127.0.0.1", PORT), timeout=8); lire(t, 0.6)
        t.sendall(P.build_frame(100, b"\x00" + P.field_str("Bob") + P.field_str("secret")))
        verifier("admin : compte banni refuse a la connexion",
                 (101, b"\x00\x06\x00\x05\x02") in frames(lire(t, 0.8)))
        t.close()
        s.sendall(P.build_frame(195, b"\x04" + P.field_byte(0) + P.field_str("Bob") + P.field_str("")))
        verifier("admin : levee du ban (accuse op196 b1 b0)", (196, ok4 + b"\x06\x00") in frames(lire(s, 0.8)))
        v.close()
        # ---- salon des operateurs : message, diffusion (sans historique) ----
        s.sendall(P.build_frame(178, bytes([4]) + P.field_int(10) + P.field_str("reunion a 21h") + P.field_byte(0)))
        verifier("salon des operateurs : message diffuse aux membres (op179)",
                 (179, bytes([4]) + P.field_int(10) + P.field_int(pid_adm) + P.field_str("reunion a 21h") + bytes([6, 0]))
                 in frames(lire(s, 0.8)))
        # ---- quizz : demarrage, question, bonne reponse ----
        s.sendall(P.build_frame(144, bytes([1]) + P.field_str("!quiz demarrer triple") + P.field_byte(0)))
        rq = frames(lire(s, 5.0))
        q220 = [pl for o, pl in rq if o == 220]; q223 = [pl for o, pl in rq if o == 223]
        verifier("quizz : annonce (op220) puis premiere question (op223)",
                 bool(q220) and q220[0][:6] == bytes([5]) + P.field_int(pid_adm) and bool(q223))
        import json as _json
        banque = _json.load(open("quiz.json", encoding="utf-8"))
        texte_q = next((q for t in banque.values() for q in t if q223 and P.field_str(q["q"]) in q223[0]), None)
        if texte_q:
            s.sendall(P.build_frame(144, bytes([1]) + P.field_str(texte_q["r"][0].upper()) + P.field_byte(0)))
            rq = frames(lire(s, 1.5))
            verifier("quizz : bonne reponse reconnue (op224, 1 point)",
                     (224, bytes([5]) + P.field_int(pid_adm) + P.field_int(1) + P.field_str(texte_q["r"][0])) in rq)
        else:
            verifier("quizz : question retrouvee dans quiz.json", False)
        s.sendall(P.build_frame(144, bytes([1]) + P.field_str("!quiz arreter") + P.field_byte(0))); lire(s, 0.8)
        s.close()
        # reconnexion : le salon ne garde pas d'historique, rien n'est rejoue
        s2 = socket.create_connection(("127.0.0.1", PORT), timeout=8); lire(s2, 0.6)
        s2.sendall(P.build_frame(100, bytes([0]) + P.field_str("Gerant") + P.field_str("secret"))); lire(s2, 0.8)
        s2.sendall(P.build_frame(207, bytes([0]) + P.field_int(pid_adm - 1000))); lire(s2, 0.6)
        s2.sendall(P.build_frame(44, bytes([1]))); lire(s2, 1.2)
        s2.sendall(P.build_frame(71, bytes([1]) + P.field_byte(1)))
        hist = [pl for o, pl in frames(lire(s2, 1.5)) if o == 179]
        verifier("salon des operateurs : aucun historique rejoue a la reconnexion", hist == [],
                 f"{len(hist)} ligne(s)")
        # ping du salon : op2, auquel le client repond par op3 (cas 2 de son repartiteur). op512, envoye jusqu'au
        # 2026-10-24, n'a pas de gestionnaire : sans reponse, un joueur silencieux etait coupe au bout de 900 s.
        r_ping = [o for o, _ in frames(lire(s2, 11.5))]
        verifier("ping du salon : op2 toutes les 10 s (le client y repond par op3), plus d'op512",
                 2 in r_ping and 512 not in r_ping, str(r_ping))
        s2.close()

        # ================= REQUETES DU CLIENT RESTEES SANS REPONSE JUSQU'AU 2026-10-12 =================
        # Requetes : py ffwtt_envois.py ; reponses : gestionnaires du client (ffwtt_binaire.py). Jamais capturees.
        import zlib as _zl, sqlite3 as _sq6
        def bloc_x(texte):
            co = _zl.compressobj(9); z = co.compress(texte.encode("latin1")) + co.flush(_zl.Z_SYNC_FLUSH)
            return bytes([8]) + struct.pack("<H", len(z)) + z
        op_s, pid_op = entrer("Gerant")
        jo, pid_jo = entrer("Gaspard")                   # un joueur sans grade
        lire(op_s, 0.3); lire(jo, 0.3)
        # -- aiguillage par categorie : une trame de categorie 5 ou 6 ne descend plus dans les branches 0 a 3
        jo.sendall(P.build_frame(32, bytes([5])))        # « Arreter le quizz » (panneau Quizz) = cat5 op32
        jo.sendall(P.build_frame(35, bytes([5])))        # « Remise a zero des points » = cat5 op35
        rf = frames(lire(jo, 0.8)); r = [o for o, _ in rf]
        # op34 / op36 de categorie 5 sont les refus du panneau Quizz (pas de panneau : 87), pas des trames de duel
        verifier("aiguillage : cat5 op32 / op35 ne lancent plus de duel (ni op33, ni op36 de duel, ni main)",
                 not any(o in (33, 36) and pl[:1] != bytes([5]) for o, pl in rf) and 135 not in r
                 and (34, bytes([5, 6, 0, 5, 87])) in rf and (36, bytes([5, 6, 0, 5, 87])) in rf, str(r))
        jo.sendall(P.build_frame(227, bytes([5])))       # /points
        verifier("/points (cat5 op227) : op228 05 int(points)", (228, bytes([5]) + P.field_int(0)) in frames(lire(jo, 0.6)))
        # -- notes personnelles : cat6 op64 x(texte) -> op65 06 b1 ; rendues dans op66 sur son propre profil
        jo.sendall(P.build_frame(64, bytes([6]) + bloc_x("mes secrets")))
        r = frames(lire(jo, 0.6))
        verifier("notes personnelles : enregistrees (op65 06 b1), sans ouvrir de profil (pas d'op65 categorie 1)",
                 (65, bytes([6, 6, 1])) in r and not any(o == 65 and pl[:1] == bytes([1]) for o, pl in r), str(r)[:120])
        jo.sendall(P.build_frame(64, bytes([1]) + P.field_int(pid_jo)))
        n66 = next((pl for o, pl in frames(lire(jo, 0.8)) if o == 66), b"")
        verifier("notes personnelles : rendues dans op66 (categorie 6) a l'ouverture de son profil",
                 n66[:2] == bytes([6, 8]) and _zl.decompressobj().decompress(n66[4:]) == b"mes secrets", n66.hex())
        # -- note publique : 04 int(groupe) int(pid du PROFIL) x(texte) ; le profil d'un autre demande « editnotes »
        jo.sendall(P.build_frame(239, bytes([4]) + P.field_int(1) + P.field_int(pid_op) + bloc_x("graffiti")))
        verifier("note publique : le profil d'un autre sans « editnotes » est refuse (op240 04 b0 v87)",
                 (240, bytes([4, 6, 0, 5, 87])) in frames(lire(jo, 0.6)))
        jo.sendall(P.build_frame(239, bytes([4]) + P.field_int(1) + P.field_int(pid_jo) + bloc_x("ma presentation")))
        ok_jo = (240, bytes([4, 6, 1])) in frames(lire(jo, 0.6))
        op_s.sendall(P.build_frame(239, bytes([4]) + P.field_int(1) + P.field_int(pid_jo) + bloc_x("corrigee par l'equipe")))
        ok_op = (240, bytes([4, 6, 1])) in frames(lire(op_s, 0.6))
        _c = _sq6.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        note = lambda pid_: (_c.execute("SELECT note FROM pseudos WHERE id=?", (pid_ - 1000,)).fetchone() or [""])[0]
        verifier("note publique : rangee sur le profil VISE (l'operateur ne remplace plus sa propre note)",
                 ok_jo and ok_op and note(pid_jo) == "corrigee par l'equipe" and note(pid_op) != "corrigee par l'equipe",
                 f"{note(pid_jo)!r} / {note(pid_op)!r}")
        # -- /ident <groupe> <mot de passe> (cat4 op176) -> op177 04 b0 v(code)
        jo.sendall(P.build_frame(176, bytes([4]) + P.field_str("staff") + P.field_str("MdpIdentSecret")))
        op_s.sendall(P.build_frame(176, bytes([4]) + P.field_str("staff") + P.field_str("MdpIdentSecret")))
        verifier("/ident : 83 « Groupe ou mot de passe incorrect » pour un joueur, 86 « deja membre » pour l'equipe",
                 (177, bytes([4, 6, 0, 5, 83])) in frames(lire(jo, 0.6))
                 and (177, bytes([4, 6, 0, 5, 86])) in frames(lire(op_s, 0.6)))
        # -- news rapides (cat6 op164) -> op165 ; op166 « *** Infos : %s » a tous, et rappel a l'entree au salon
        jo.sendall(P.build_frame(164, bytes([6]) + P.field_str("pirate")))
        verifier("/quicknews : refuse sans la permission (op165 06 b0 v87)",
                 (165, bytes([6, 6, 0, 5, 87])) in frames(lire(jo, 0.6)))
        op_s.sendall(P.build_frame(164, bytes([6]) + P.field_str("Tournoi ce soir 21h")))
        ro = frames(lire(op_s, 0.6)); rj = frames(lire(jo, 0.6))
        info = (166, bytes([6]) + P.field_str("Tournoi ce soir 21h"))
        verifier("/quicknews : accuse (op165 06 b1), « *** Infos » diffuse a tous (op166)",
                 (165, bytes([6, 6, 1])) in ro and info in ro and info in rj)
        h, _pid_h = entrer("Hector")
        verifier("/quicknews : la news rapide est rappelee a l'entree au salon", info in frames(RAFALES["Hector"]))
        op_s.sendall(P.build_frame(164, bytes([6]) + P.field_str(""))); lire(op_s, 0.4); lire(jo, 0.3); lire(h, 0.3)
        # -- mode modere (cat4 op223) -> op224 04 b1 b(actif) ; op82 01 b(actif) a tous
        jo.sendall(P.build_frame(223, bytes([4])))
        verifier("/moderate : refuse sans la permission (op224 04 b0 v87)",
                 (224, bytes([4, 6, 0, 5, 87])) in frames(lire(jo, 0.6)))
        op_s.sendall(P.build_frame(223, bytes([4])))
        ro = frames(lire(op_s, 0.6)); rj = frames(lire(jo, 0.6))
        verifier("/moderate : active (op224 04 b1 b1 a l'operateur, op82 01 b1 a tous)",
                 (224, bytes([4, 6, 1, 6, 1])) in ro and (82, bytes([1, 6, 1])) in rj and (82, bytes([1, 6, 1])) in ro)
        jo.sendall(P.build_frame(144, bytes([1]) + P.field_str("je parle") + P.field_byte(0))); time.sleep(0.2)
        op_s.sendall(P.build_frame(144, bytes([1]) + P.field_str("silence") + P.field_byte(0)))
        rj = frames(lire(jo, 0.6)); rh = frames(lire(h, 0.6))
        dit = lambda r_, texte: any(o == 145 and P.field_str(texte) in pl for o, pl in r_)
        verifier("mode modere : le joueur n'est plus diffuse, l'operateur (talkwhilemoderate) l'est",
                 not dit(rj, "je parle") and not dit(rh, "je parle") and dit(rj, "silence") and dit(rh, "silence"))
        h.close(); lire(op_s, 0.3)
        op_s.sendall(P.build_frame(223, bytes([4])))
        ro = frames(lire(op_s, 0.6)); rj = frames(lire(jo, 0.6))
        verifier("/moderate : desactive (op224 04 b1 b0, op82 01 b0)",
                 (224, bytes([4, 6, 1, 6, 0])) in ro and (82, bytes([1, 6, 0])) in rj)
        # -- panneau d'equipe : onglets Topic et Caisse (fonctions « topic » / « gilsbank » du groupe 10, viewgilsbank du grade 3)
        tr_op = frames(RAFALES["Gerant"]); ops_op = [o for o, _ in tr_op]
        g10 = next((pl for o, pl in tr_op if o == 86 and champ_ints(pl)[:1] == [10]), b"")
        i177 = ops_op.index(177) if 177 in ops_op else -1
        verifier("panneau d'equipe : onglets topic et gilsbank declares, caisse (op231) juste apres op177, avant les op61",
                 P.field_str("topic") in g10 and P.field_str("gilsbank") in g10 and i177 >= 0
                 and tr_op[i177 + 1] == (231, bytes([4]) + P.field_int(10) + P.field_int(0))
                 and all(i > i177 + 1 for i, o in enumerate(ops_op) if o in (59, 61)), str(ops_op[i177:i177 + 4]))
        groupe10 = bytes([4]) + P.field_int(10)
        jo.sendall(P.build_frame(209, groupe10 + bloc_x("pirate")))
        rj = frames(lire(jo, 0.6))
        # sans panneau, AUCUNE reponse : op210 lirait le panneau du groupe sans verifier qu'il existe (plantage du client)
        verifier("topic : ignore pour qui n'a pas le panneau (ni op210, ni op211)",
                 210 not in [o for o, _ in rj] and 211 not in [o for o, _ in rj])
        op_s.sendall(P.build_frame(209, groupe10 + bloc_x("Reunion samedi 21h")))
        ro = frames(lire(op_s, 0.6))
        p211 = next((pl for o, pl in ro if o == 211), b"")
        verifier("topic : accuse (op210 04 int(10) b1) et op211 = groupe, texte, auteur, date",
                 (210, groupe10 + bytes([6, 1])) in ro and p211[:6] == groupe10 and p211[6] == 8
                 and _zl.decompressobj().decompress(p211[9:9 + struct.unpack_from("<H", p211, 7)[0]]) == b"Reunion samedi 21h"
                 and P.field_str("Gerant") in p211, p211[:40].hex())
        _c.execute("UPDATE accounts SET gils=5000 WHERE id=(SELECT account_id FROM pseudos WHERE id=?)", (pid_op - 1000,)); _c.commit()
        caisse = lambda op_, montant: P.build_frame(op_, groupe10 + P.field_int(montant))
        op_s.sendall(caisse(232, 500)); r1 = frames(lire(op_s, 0.6))
        op_s.sendall(caisse(234, 200)); r2 = frames(lire(op_s, 0.6))
        op_s.sendall(caisse(234, 1000)); r3 = frames(lire(op_s, 0.6))
        op_s.sendall(caisse(232, 0)); r4 = frames(lire(op_s, 0.6))
        gils_op = _c.execute("SELECT gils FROM accounts WHERE id=(SELECT account_id FROM pseudos WHERE id=?)", (pid_op - 1000,)).fetchone()[0]
        verifier("caisse : depot (op233 b1, op231 total 500 + « depose ») puis retrait (op235 b1, op231 total 300 + « retire »)",
                 (233, groupe10 + bytes([6, 1])) in r1
                 and (231, groupe10 + P.field_int(500) + bytes([6, 1]) + P.field_int(pid_op) + P.field_int(500)) in r1
                 and (235, groupe10 + bytes([6, 1])) in r2
                 and (231, groupe10 + P.field_int(300) + bytes([6, 0]) + P.field_int(pid_op) + P.field_int(200)) in r2
                 and 47 in [o for o, _ in r1] and gils_op == 5000 - 500 + 200, f"gils {gils_op}")
        verifier("caisse : retrait plus grand que la caisse (v26), montant hors de 1 a 50 000 (v116)",
                 (235, groupe10 + bytes([6, 0, 5, 26])) in r3 and (233, groupe10 + bytes([6, 0, 5, 116])) in r4)
        generer = P.build_frame(236, groupe10 + bytes([2]) + struct.pack("<I", 1000))
        jo.sendall(generer)
        verifier("caisse : /gengils refuse sans « generategilsbank » (op237 04 int(10) b0 v87)",
                 (237, groupe10 + bytes([6, 0, 5, 87])) in frames(lire(jo, 0.6)))
        op_s.sendall(generer); ro = frames(lire(op_s, 0.6))
        verifier("caisse : /gengils 1000 (op237 b1, op231 total 1300 sans ligne de mouvement)",
                 (237, groupe10 + bytes([6, 1])) in ro and (231, groupe10 + P.field_int(1300)) in ro)
        op_s.close(); time.sleep(0.6)                    # un compte ne se connecte qu'une fois (code 4)
        op_s, pid_op = entrer("Gerant")
        tr2 = [(o, pl) for o, pl in frames(RAFALES["Gerant"]) if o in (211, 231)]
        verifier("panneau d'equipe : a la connexion, la caisse (1300) puis le topic sont rappeles",
                 tr2[:1] == [(231, groupe10 + P.field_int(1300))] and len(tr2) == 2 and tr2[1][0] == 211, str([o for o, _ in tr2]))
        lire(jo, 0.3)
        # -- retrait reserve aux operateurs de niveau 3 et 4 : Hector, operateur de niveau 2, depose mais ne retire pas
        compte_de = "UPDATE accounts SET admin=? WHERE id=(SELECT account_id FROM pseudos WHERE id=?)"
        _c.execute(compte_de, (2, _pid_h - 1000)); _c.commit()
        h2, _ = entrer("Hector")
        h2.sendall(caisse(232, 10)); rh1 = frames(lire(h2, 0.6))
        h2.sendall(caisse(234, 10)); rh2 = frames(lire(h2, 0.6))
        verifier("caisse : un operateur de niveau 2 depose (op233 b1) mais ne retire pas (op235 b0 v87), le niveau 4 retire",
                 (233, groupe10 + bytes([6, 1])) in rh1 and (235, groupe10 + bytes([6, 0, 5, 87])) in rh2
                 and (235, groupe10 + bytes([6, 1])) in r2, str([o for o, _ in rh2]))
        h2.close(); _c.execute(compte_de, (0, _pid_h - 1000)); _c.commit(); lire(op_s, 0.3)
        # -- infos offline (cat4 op242 int(pid) / op215 str) : profil op65 d'apres la base ; erreurs op216 04 v(code).
        #    Champs texte d'op65 : pseudo, titre de guilde, nom de compte, host, e-mail (vide = « (cache) »), note.
        import ffwtt_server as _SP
        textes = lambda pl: [v_ for k_, v_ in _SP.parse_typed(pl) if k_ == "str"]
        time.sleep(0.4)                                  # Hector est bien deconnecte
        jo.sendall(P.build_frame(242, bytes([4]) + P.field_int(_pid_h)))
        verifier("infos offline : refusees sans « viewoffinfos » (op216 04 v87)",
                 (216, bytes([4, 5, 87])) in frames(lire(jo, 0.6)))
        op_s.sendall(P.build_frame(242, bytes([4]) + P.field_int(_pid_h)))
        ro = frames(lire(op_s, 0.8))
        p65 = next((pl for o, pl in ro if o == 65), b""); t65 = textes(p65)
        verifier("infos offline : profil op65 d'un joueur DECONNECTE (pseudo, nom de compte visible pour l'equipe) + note op241",
                 champ_ints(p65)[:1] == [_pid_h] and t65[:1] == ["Hector"] and len(t65) >= 5 and t65[2] == "hector"
                 and 241 in [o for o, _ in ro], str(t65[:5]))
        op_s.sendall(P.build_frame(215, bytes([4]) + P.field_str("HECTOR"))); r215 = frames(lire(op_s, 0.8))
        op_s.sendall(P.build_frame(215, bytes([4]) + P.field_str("Personne")))
        verifier("/offinfos <pseudo> : par le nom, sans tenir compte des majuscules ; inconnu -> op216 04 v9",
                 any(o == 65 and champ_ints(pl)[:1] == [_pid_h] for o, pl in r215)
                 and (216, bytes([4, 5, 9])) in frames(lire(op_s, 0.6)))
        # -- la fiche « Infos » ordinaire masque compte, host et e-mail a qui n'a pas la permission, pas a soi-meme
        jo.sendall(P.build_frame(64, bytes([1]) + P.field_int(pid_op)))
        t_jo = textes(next((pl for o, pl in frames(lire(jo, 0.8)) if o == 65), b""))
        op_s.sendall(P.build_frame(64, bytes([1]) + P.field_int(pid_op)))
        t_soi = textes(next((pl for o, pl in frames(lire(op_s, 0.8)) if o == 65), b""))
        verifier("profil : compte, host et e-mail masques a un joueur (« (cache) »), le nom de compte visible pour soi",
                 len(t_jo) >= 5 and t_jo[0] == "Gerant" and t_jo[2:5] == ["", "", ""] and len(t_soi) >= 5
                 and t_soi[2] == "gerant", f"{t_jo[:5]} / {t_soi[:5]}")
        # -- arreter une partie (cat4 op202, onglet Parties) : Gaspard joue contre Mog (regle Aleatoire : aussitot lancee)
        jo.sendall(P.build_frame(32, bytes([3]) + P.field_int(999) + P.field_int16(2) + P.field_v(1) + P.field_int(0)
                                 + P.field_v(7) + P.field_byte(1)))
        p36 = next((pl for o, pl in frames(lire(jo, 1.0)) if o == 36), b"")
        made = champ_ints(p36)[-1] if p36 else -1
        lire(op_s, 0.3)
        jo.sendall(P.build_frame(202, bytes([4]) + P.field_int(made)))
        verifier("arret de partie : refuse sans « stopgame » (op203 04 b0 v87)",
                 (203, bytes([4, 6, 0, 5, 87])) in frames(lire(jo, 0.5)))
        op_s.sendall(P.build_frame(202, bytes([4]) + P.field_int(made)))
        ro = frames(lire(op_s, 0.8)); rj = frames(lire(jo, 0.8))
        p144 = next((pl for o, pl in rj if o == 144), b"")
        verifier("arret de partie : accuse (op203 04 b1) ; op144 motif 2 + pid de l'operateur, op235 b0, op148 chez le joueur",
                 (203, bytes([4, 6, 1])) in ro and p144[:6] == bytes([3]) + P.field_int(made)
                 and p144.endswith(P.field_v(2) + P.field_int(pid_op)) and 148 in [o for o, _ in rj]
                 and (235, bytes([3]) + P.field_int(made) + bytes([6, 0])) in rj
                 and (235, bytes([3]) + P.field_int(made) + bytes([6, 0])) in ro, p144.hex())
        op_s.sendall(P.build_frame(202, bytes([4]) + P.field_int(made)))
        verifier("arret de partie : partie inexistante -> op203 04 b0 v12 int(numero) (« *** ID %d inexistant »)",
                 (203, bytes([4, 6, 0, 5, 12]) + P.field_int(made)) in frames(lire(op_s, 0.6)))
        # -- encheres : « Vente aux encheres » niveau 1 = une seule vente a la fois (table du client : 1, 3, 5)
        _c.execute("INSERT INTO powers(pseudo_id,points,skills) VALUES(?,0,'4:1') "
                   "ON CONFLICT(pseudo_id) DO UPDATE SET skills='4:1'", (pid_jo - 1000,))
        _c.execute("UPDATE stats SET noto=2000 WHERE pseudo_id=?", (pid_jo - 1000,)); _c.commit()
        vente = lambda cid: P.build_frame(188, bytes([2]) + P.field_int16(cid) + bytes([2]) + struct.pack("<I", 10)
                                          + bytes([2]) + struct.pack("<I", 500))
        jo.sendall(vente(COLLECTIONS["Gaspard"][0])); r1 = frames(lire(jo, 0.6))
        jo.sendall(vente(COLLECTIONS["Gaspard"][1])); r2 = frames(lire(jo, 0.6))
        _c.execute("UPDATE powers SET skills='' WHERE pseudo_id=?", (pid_jo - 1000,)); _c.commit()
        jo.sendall(vente(COLLECTIONS["Gaspard"][2])); r3 = frames(lire(jo, 0.6))
        fiche = next((pl for o, pl in r1 if o == 190), b"")
        verifier("encheres : niveau 1 = une vente a la fois (2e : op189 02 b0 v31) ; sans la capacite : v32",
                 any(o == 189 and pl[:3] == bytes([2, 6, 1]) for o, pl in r1)
                 and (189, bytes([2, 6, 0, 5, 31])) in r2 and (189, bytes([2, 6, 0, 5, 32])) in r3, str(r2)[:80])
        if fiche:                                        # retirer la vente : les sections suivantes comptent les encheres
            jo.sendall(P.build_frame(194, bytes([2]) + bytes([2]) + fiche[2:6] + P.field_byte(1))); lire(jo, 0.5)

        # ================= PANNEAU QUIZZ DU CLIENT (cat5 op21 a op40, lu dans le binaire le 2026-10-22, jamais capture) =====
        # Groupe 30 « Quizz » avec les fonctions de la capture (chat, topic, quizz), ouvert par op177(grade 5) ; categories
        # et questions en base, importees de quiz.json a la premiere mise en route.
        q5 = lambda op_, corps=b"": P.build_frame(op_, bytes([5]) + corps)
        cat5 = lambda r_, op_: [pl for o, pl in r_ if o == op_ and pl[:1] == bytes([5])]
        def attendre(sock, op_, duree):
            """Lit jusqu'a recevoir une trame de categorie 5 de cet opcode (au plus 'duree' secondes)."""
            fin = time.time() + duree; brut = b""
            while time.time() < fin and not cat5(frames(brut), op_): brut += lire(sock, 0.5)
            return frames(brut)
        lire(op_s, 0.3); lire(jo, 0.3)
        tr_q = frames(RAFALES["Gerant"]); ops_q = [o for o, _ in tr_q]
        g30 = next((pl for o, pl in tr_q if o == 86 and champ_ints(pl)[:1] == [30]), b"")
        i177q = next((i for i, (o, pl) in enumerate(tr_q) if o == 177 and pl == bytes([4, 6, 1]) + P.field_int(5)), -1)
        mes61 = [pl[-1] for o, pl in tr_q if o == 61 and pl[:6] == bytes([1]) + P.field_int(pid_op)]
        verifier("panneau Quizz : groupe 30 (chat, topic, quizz) ouvert par op177(grade 5) avant op61 / op59, grade 5 une seule fois",
                 all(P.field_str(f) in g30 for f in ("chat", "topic", "quizz")) and i177q > 0 and mes61.count(5) == 1
                 and all(i > i177q for i, o in enumerate(ops_q) if o in (59, 61)), f"{i177q} {mes61}")
        cats_db = _c.execute("SELECT k.id, k.nom, (SELECT COUNT(*) FROM quiz_questions q WHERE q.categorie=k.id) "
                             "FROM quiz_categories k ORDER BY k.id").fetchall()
        i62 = ops_q.index(62) if 62 in ops_q else len(ops_q)
        pos20 = [i for i, (o, pl) in enumerate(tr_q) if o == 20 and pl[:1] == bytes([5])]
        i28 = next((i for i, (o, pl) in enumerate(tr_q) if o == 28 and pl == bytes([5])), -1)
        verifier("panneau Quizz : a l'entree, apres op62, les 3 themes de quiz.json (op20 int(id) str(nom) int(nombre)), op28, op39",
                 len(cats_db) == 3 and sum(n for _, _, n in cats_db) == 40
                 and [tr_q[i][1] for i in pos20] == [bytes([5]) + P.field_int(i) + P.field_str(nom) + P.field_int(n)
                                                     for i, nom, n in cats_db]
                 and pos20 and min(pos20) > i62 and i28 > max(pos20) and cat5(tr_q[i28:], 39), str(cats_db))
        r_g = frames(RAFALES["Gaspard"])
        verifier("panneau Quizz : rien pour un joueur sans grade (ni op177, ni categories)",
                 177 not in [o for o, _ in r_g] and not cat5(r_g, 20) and not cat5(r_g, 28))
        # -- droits : le client ne verifie rien, le serveur refuse a qui n'a pas le panneau
        jo.sendall(q5(21, P.field_byte(1) + P.field_str("Pirate")))
        jo.sendall(q5(40, P.field_int(30) + P.field_int(cats_db[0][0])))
        jo.sendall(q5(29, P.field_int(45) + P.field_int(15) + P.field_int(cats_db[0][0])))
        rj = frames(lire(jo, 0.8))
        verifier("panneau Quizz : refuse sans le panneau (op22 05 b1 b0 v87, op42 05 b0 v87 sans op41, op31 05 b0 v87)",
                 (22, bytes([5, 6, 1, 6, 0, 5, 87])) in rj and (42, bytes([5, 6, 0, 5, 87])) in rj
                 and (31, bytes([5, 6, 0, 5, 87])) in rj and not cat5(rj, 41) and not cat5(rj, 220), str(rj)[:150])
        # -- categories
        op_s.sendall(q5(21, P.field_byte(1) + P.field_str("  Culture   G ")))
        ro = frames(lire(op_s, 0.8)); rj = frames(lire(jo, 0.4))
        cid_q = (_c.execute("SELECT id FROM quiz_categories WHERE nom='Culture G'").fetchone() or [0])[0]
        verifier("panneau Quizz : categorie ajoutee (op22 05 b1 b1 ; op20 05 int(id) str(nom) int(0) au panneau, pas aux joueurs)",
                 cid_q > 0 and (22, bytes([5, 6, 1, 6, 1])) in ro
                 and (20, bytes([5]) + P.field_int(cid_q) + P.field_str("Culture G") + P.field_int(0)) in ro
                 and not cat5(rj, 20), str(ro)[:150])
        op_s.sendall(q5(21, P.field_byte(1) + P.field_str("culture g"))); r1 = frames(lire(op_s, 0.6))
        op_s.sendall(q5(21, P.field_byte(1) + P.field_str("   "))); r2 = frames(lire(op_s, 0.6))
        op_s.sendall(q5(21, P.field_byte(1) + P.field_str("Piege#10"))); r3 = frames(lire(op_s, 0.6))
        verifier("panneau Quizz : nom existant (v109, majuscules comprises), vide ou contenant « #10 » (v0)",
                 (22, bytes([5, 6, 1, 6, 0, 5, 109])) in r1 and (22, bytes([5, 6, 1, 6, 0, 5, 0])) in r2
                 and (22, bytes([5, 6, 1, 6, 0, 5, 0])) in r3)
        # -- questions
        t0 = int(time.time()); enonce = "Combien de cartes dans une main ?"
        op_s.sendall(q5(25, P.field_byte(1) + P.field_int(cid_q) + P.field_str(enonce) + P.field_str("Cinq | 5")))
        ro = frames(lire(op_s, 0.8))
        qid_q, ts_q = _c.execute("SELECT id, ts FROM quiz_questions WHERE categorie=?", (cid_q,)).fetchone() or (0, 0)
        p24 = next(iter(cat5(ro, 24)), b"")
        attendu24 = (bytes([5]) + P.field_int(qid_q) + P.field_int(cid_q) + P.field_str(enonce) + P.field_str("Cinq | 5")
                     + P.field_str("Gerant") + P.field_int(ts_q))
        verifier("panneau Quizz : question ajoutee (op26 05 b1 b1 ; op24 id, categorie, question, reponses, auteur, date Unix)",
                 (26, bytes([5, 6, 1, 6, 1])) in ro and p24 == attendu24 and abs(ts_q - t0) <= 5, p24.hex())
        op_s.sendall(q5(25, P.field_byte(1) + P.field_int(999999) + P.field_str("Q ?") + P.field_str("R")))
        r1 = frames(lire(op_s, 0.6))
        op_s.sendall(q5(25, P.field_byte(1) + P.field_int(cid_q) + P.field_str("Q ?") + P.field_str("A#10B")))
        r2 = frames(lire(op_s, 0.6))
        verifier("panneau Quizz : categorie inconnue (op26 05 b1 b0 v110 int(numero)), reponse avec « #10 » (v0)",
                 (26, bytes([5, 6, 1, 6, 0, 5, 110]) + P.field_int(999999)) in r1 and (26, bytes([5, 6, 1, 6, 0, 5, 0])) in r2)
        op_s.sendall(q5(40, P.field_int(30) + P.field_int(cid_q)))
        ro = frames(lire(op_s, 0.8)); ops_r = [o for o, _ in ro]
        p41 = next(iter(cat5(ro, 41)), b"")
        texte41 = (_zl.decompressobj().decompress(p41[14:14 + struct.unpack_from("<H", p41, 12)[0]])
                   if p41[:11] == bytes([5]) + P.field_int(30) + P.field_int(cid_q) and p41[11:12] == b"\x08" else b"")
        verifier("panneau Quizz : questions d'une categorie (op41 groupe, categorie, x « id#10question#10reponse#10auteur#10date »"
                 " puis op42 05 b1 int(30) int(categorie))",
                 texte41 == f"{qid_q}#10{enonce}#10Cinq | 5#10Gerant#10{ts_q}".encode("latin1")
                 and (42, bytes([5, 6, 1]) + P.field_int(30) + P.field_int(cid_q)) in ro and ops_r.index(41) < ops_r.index(42),
                 texte41[:80])
        op_s.sendall(q5(40, P.field_int(10) + P.field_int(cid_q)))
        verifier("panneau Quizz : questions demandees pour un autre groupe -> op42 05 b0 v87",
                 (42, bytes([5, 6, 0, 5, 87])) in frames(lire(op_s, 0.6)))
        import ffwtt_server as _SQ
        _questions = _SQ.db.quiz_questions
        _SQ.db.quiz_questions = lambda _cid: [{"id": i, "question": "Q" * 250, "reponses": ["R" * 100], "auteur": "Gerant",
                                               "ts": 1760000000} for i in range(1, 401)]
        try: morceaux = _SQ.fiches_quiz(1)
        finally: _SQ.db.quiz_questions = _questions
        verifier("panneau Quizz : 400 questions -> plusieurs op41 de moins de 64 Ko, faits de fiches entieres (5 champs)",
                 len(morceaux) >= 2 and all(len(m.encode("latin1")) <= 65535 for m in morceaux)
                 and all(len(m.split("#10")) % 5 == 0 for m in morceaux)
                 and sum(len(m.split("#10")) for m in morceaux) == 400 * 5, str([len(m) for m in morceaux]))
        # -- points, demarrage, refus pendant le quizz, bonne reponse, fin naturelle
        op_s.sendall(q5(35)); ro = frames(lire(op_s, 0.8)); rj = frames(lire(jo, 0.4))
        verifier("panneau Quizz : remise a zero (op36 05 b1 ; op226 int(pid) a tous ; op39 vide au panneau seulement)",
                 (36, bytes([5, 6, 1])) in ro and (226, bytes([5]) + P.field_int(pid_op)) in rj and (39, bytes([5])) in ro
                 and not cat5(rj, 39))
        op_s.sendall(q5(32)); r_stop = frames(lire(op_s, 0.6))
        op_s.sendall(q5(21, P.field_byte(1) + P.field_str("Vide"))); lire(op_s, 0.6)
        cid_v = (_c.execute("SELECT id FROM quiz_categories WHERE nom='Vide'").fetchone() or [0])[0]
        op_s.sendall(q5(29, P.field_int(45) + P.field_int(15) + P.field_int(cid_v))); r115 = frames(lire(op_s, 0.6))
        verifier("panneau Quizz : arreter sans quizz (op34 05 b0 v113), demarrer sans question (op31 05 b0 v115)",
                 (34, bytes([5, 6, 0, 5, 113])) in r_stop and (31, bytes([5, 6, 0, 5, 115])) in r115)
        op_s.sendall(q5(29, P.field_int(2) + P.field_int(1) + P.field_int(cid_q) + P.field_int(cid_v)))
        ro = frames(lire(op_s, 0.6)); rj = frames(lire(jo, 0.3))
        verifier("panneau Quizz : demarrer (op31 05 b1 ; op30 temps bornes a 5 s + categories utilisees, au panneau ; op220 a tous)",
                 (31, bytes([5, 6, 1])) in ro and (30, bytes([5]) + P.field_int(5) + P.field_int(5) + P.field_int(cid_q)) in ro
                 and any(pl[:6] == bytes([5]) + P.field_int(pid_op) for pl in cat5(rj, 220)) and not cat5(rj, 30), str(ro)[:150])
        op_s.sendall(q5(29, P.field_int(45) + P.field_int(15) + P.field_int(cid_q))); r114 = frames(lire(op_s, 0.3))
        op_s.sendall(q5(21, P.field_byte(0) + P.field_int(cid_q))); r112a = frames(lire(op_s, 0.3))
        op_s.sendall(q5(25, P.field_byte(0) + P.field_int(cid_q) + P.field_int(qid_q))); r112b = frames(lire(op_s, 0.3))
        op_s.sendall(q5(25, P.field_byte(1) + P.field_int(cid_q) + P.field_str("Autre ?") + P.field_str("Oui")))
        r112c = frames(lire(op_s, 0.3))
        verifier("panneau Quizz : pendant le quizz, 2e demarrage (v114) ; suppression ou ajout dans une categorie utilisee (v112)",
                 (31, bytes([5, 6, 0, 5, 114])) in r114 and (22, bytes([5, 6, 0, 6, 0, 5, 112])) in r112a
                 and (26, bytes([5, 6, 0, 6, 0, 5, 112])) in r112b and (26, bytes([5, 6, 1, 6, 0, 5, 112])) in r112c)
        rj = attendre(jo, 223, 8.0)
        jo.sendall(P.build_frame(144, bytes([1]) + P.field_str("cinq") + P.field_byte(0)))
        ro = attendre(op_s, 39, 3.0)
        verifier("panneau Quizz : la question (op223), puis bonne reponse -> op224 et points au panneau (op39 int(pid) int(1))",
                 any(P.field_str(enonce) in pl for pl in cat5(rj, 223))
                 and (224, bytes([5]) + P.field_int(pid_jo) + P.field_int(1) + P.field_str("Cinq")) in ro
                 and (39, bytes([5]) + P.field_int(pid_jo) + P.field_int(1)) in ro, str([o for o, _ in ro]))
        ro = attendre(op_s, 33, 9.0)
        verifier("panneau Quizz : plus de question -> op33 05 au panneau (le bouton Demarrer revient) et top 5 (op222)",
                 (33, bytes([5])) in ro and (222, bytes([5]) + P.field_int(pid_jo) + P.field_int(1)) in ro, str(ro)[-150:])
        op_s.sendall(q5(29, P.field_int(500) + P.field_int(4000) + P.field_int(cid_q))); ro = frames(lire(op_s, 0.5))
        op_s.sendall(q5(32)); ro2 = frames(lire(op_s, 0.6)); rj = frames(lire(jo, 0.5))
        verifier("panneau Quizz : temps bornes a 300 s (op30), arret (op34 05 b1, op33 au panneau, op221 int(pid) a tous)",
                 (30, bytes([5]) + P.field_int(300) + P.field_int(300) + P.field_int(cid_q)) in ro
                 and (34, bytes([5, 6, 1])) in ro2 and (33, bytes([5])) in ro2 and (221, bytes([5]) + P.field_int(pid_op)) in rj)
        op_s.sendall(q5(37)); ro = frames(lire(op_s, 0.6)); rj = frames(lire(jo, 0.4))
        verifier("panneau Quizz : « Afficher le top5 actuel » (op38 05 b1 ; op222 a tous)",
                 (38, bytes([5, 6, 1])) in ro and (222, bytes([5]) + P.field_int(pid_jo) + P.field_int(1)) in rj)
        # -- suppressions (« Editer » = suppression puis ajout)
        op_s.sendall(q5(25, P.field_byte(0) + P.field_int(cid_q) + P.field_int(qid_q + 1000))); r111 = frames(lire(op_s, 0.5))
        op_s.sendall(q5(25, P.field_byte(0) + P.field_int(cid_q) + P.field_int(qid_q))); rdq = frames(lire(op_s, 0.5))
        op_s.sendall(q5(21, P.field_byte(0) + P.field_int(cid_q))); rdc = frames(lire(op_s, 0.5))
        op_s.sendall(q5(21, P.field_byte(0) + P.field_int(cid_q))); r110 = frames(lire(op_s, 0.5))
        verifier("panneau Quizz : suppressions (op26 05 b0 b1 + op27 ; op22 05 b0 b1 + op23), inconnues v111 / v110 + numero",
                 (26, bytes([5, 6, 0, 6, 0, 5, 111]) + P.field_int(qid_q + 1000)) in r111
                 and (26, bytes([5, 6, 0, 6, 1])) in rdq and (27, bytes([5]) + P.field_int(cid_q) + P.field_int(qid_q)) in rdq
                 and (22, bytes([5, 6, 0, 6, 1])) in rdc and (23, bytes([5]) + P.field_int(cid_q)) in rdc
                 and (22, bytes([5, 6, 0, 6, 0, 5, 110]) + P.field_int(cid_q)) in r110
                 and not _c.execute("SELECT 1 FROM quiz_categories WHERE id=?", (cid_q,)).fetchone())
        op_s.sendall(q5(21, P.field_byte(0) + P.field_int(cid_v))); lire(op_s, 0.4)
        # -- salon du groupe Quizz (fonction « chat » de la capture) : reserve a ses membres
        op_s.sendall(P.build_frame(178, bytes([4]) + P.field_int(30) + P.field_str("questions pour samedi") + P.field_byte(0)))
        jo.sendall(P.build_frame(178, bytes([4]) + P.field_int(30) + P.field_str("intrus") + P.field_byte(0)))
        ro = frames(lire(op_s, 0.6)); rj = frames(lire(jo, 0.5))
        verifier("panneau Quizz : salon du groupe 30 (op179 a ses membres), refuse a un joueur",
                 (179, bytes([4]) + P.field_int(30) + P.field_int(pid_op) + P.field_str("questions pour samedi") + bytes([6, 0])) in ro
                 and not any(o == 179 for o, _ in ro + rj if P.field_str("intrus") in _))
        _c.close(); jo.close(); op_s.close()

        import ffwtt_server as _SV
        # ================= REGLE DU VAINQUEUR : L'ENJEU EN CARTES =================
        # Ordre des regles = celui du client (0 Entrainement, 1 Aucune, 2 One ... 6 Totale, 7 Directe, 8 Change,
        # 9 Aleatoire). Ici : une partie « One » entre deux joueurs, jusqu'au choix des gains (op145 / op149 /
        # op150 / op146 / op147 / op148) et au transfert reel de la carte.
        import sqlite3 as _sq4
        karl, pid_k = entrer("Karl"); lena, pid_l = entrer("Lena")
        _c = _sq4.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        for p_ in (pid_k - 1000, pid_l - 1000):
            _c.execute("INSERT INTO stats(pseudo_id,noto) VALUES(?,3000) ON CONFLICT(pseudo_id) DO UPDATE SET noto=3000", (p_,))
        _c.commit(); _c.close()
        lire(karl, 0.3); lire(lena, 0.3)

        # Refus et annulation d'un defi : le client ne referme sa fenetre de defi qu'a reception d'op36 « refuse »
        # (03 | int(l'autre) | b0 | b(message)), lu dans son gestionnaire. Sans lui la fenetre restait bloquee.
        defi_a = (b"\x03" + P.field_int(pid_l) + P.field_int16(2) + P.field_v(1) + P.field_int(0)
                  + P.field_v(0) + P.field_byte(1))
        karl.sendall(P.build_frame(32, defi_a)); lire(karl, 0.6); lire(lena, 0.6)
        lena.sendall(P.build_frame(35, b"\x03" + P.field_int(pid_k) + P.field_byte(0)))
        rk, rl = frames(lire(karl, 0.8)), frames(lire(lena, 0.8))
        verifier("defi refuse : la fenetre du refusant se ferme (op36 b0 b0), le defiant est prevenu (op36 b0 b1)",
                 (36, b"\x03" + P.field_int(pid_k) + bytes([6, 0, 6, 0])) in rl
                 and (36, b"\x03" + P.field_int(pid_l) + bytes([6, 0, 6, 1])) in rk, f"{rl} / {rk}")
        karl.sendall(P.build_frame(32, defi_a)); lire(karl, 0.6); lire(lena, 0.6)
        karl.sendall(P.build_frame(35, b"\x03" + P.field_int(pid_l) + P.field_byte(0)))     # « Annuler le defi »
        rk, rl = frames(lire(karl, 0.8)), frames(lire(lena, 0.8))
        verifier("defi annule par le defiant : les deux fenetres se ferment (op36 b0 b0)",
                 (36, b"\x03" + P.field_int(pid_l) + bytes([6, 0, 6, 0])) in rk
                 and (36, b"\x03" + P.field_int(pid_k) + bytes([6, 0, 6, 0])) in rl, f"{rk} / {rl}")

        # Echange refuse / annule : op92 02 | int(l'autre) | b0 | b(message) ; celui qui clique attend cette reponse.
        karl.sendall(P.build_frame(88, b"\x02" + P.field_int(pid_l))); lire(karl, 0.6); lire(lena, 0.6)
        lena.sendall(P.build_frame(91, b"\x02" + P.field_int(pid_k) + P.field_byte(0)))           # « Refuser »
        rk, rl = frames(lire(karl, 0.8)), frames(lire(lena, 0.8))
        verifier("echange refuse : la fenetre du refusant se ferme (op92 b0 b0), le proposant est prevenu (op92 b0 b1)",
                 (92, b"\x02" + P.field_int(pid_k) + bytes([6, 0, 6, 0])) in rl
                 and (92, b"\x02" + P.field_int(pid_l) + bytes([6, 0, 6, 1])) in rk, f"{rl} / {rk}")
        karl.sendall(P.build_frame(88, b"\x02" + P.field_int(pid_l))); lire(karl, 0.6); lire(lena, 0.6)
        karl.sendall(P.build_frame(91, b"\x02" + P.field_int(pid_l) + P.field_byte(0)))           # « Annuler »
        rk, rl = frames(lire(karl, 0.8)), frames(lire(lena, 0.8))
        verifier("echange annule par celui qui le propose : les deux fenetres se ferment sans message (op92 b0 b0)",
                 (92, b"\x02" + P.field_int(pid_l) + bytes([6, 0, 6, 0])) in rk
                 and (92, b"\x02" + P.field_int(pid_k) + bytes([6, 0, 6, 0])) in rl, f"{rk} / {rl}")

        # Directe : chacun garde les cartes ADVERSES qu'il detient a la fin, reconnues par leur origine (4e element de la
        # case), meme quand les deux joueurs ont le meme identifiant de carte.
        import ffwtt_game as _G
        gd = _G.PvpGame(0, 1001, [], 1002, [], rules=_G.rules_from_mask(2), made=990, winner_rule=7)
        gd.hands = [[500, 500, 501, 502, 503], [500, 600, 601, 602, 603]]
        gd.vals = [[(10, 10, 10, 10)] * 5, [(1, 1, 1, 1)] * 5]; gd.submitted = [True, True]
        for cote, idx, x, y in ((0, 0, 0, 0), (1, 0, 1, 0), (0, 1, 2, 0), (1, 1, 2, 1), (0, 2, 1, 1)):
            gd.place(cote, idx, x, y)
        verifier("directe : cartes prises reconnues par leur origine (meme identifiant des deux cotes)",
                 sorted(gd.cartes_du_plateau(1)) == [500, 600] and gd.cartes_du_plateau(0) == [],
                 f"{gd.cartes_du_plateau(1)} / {gd.cartes_du_plateau(0)}")

        # experience exigee des DEUX joueurs (seuils fixes par l'administrateur le 2026-10-22 : One 1000, Two 2000, Three
        # 3000, Four 4000, Totale 5000, Directe / Change / Aleatoire 1000). Karl (3000) ne peut pas lancer « Totale » (6) :
        # op33 b0 v107 ; Lena a 0 : « One » (2) refusee a cause d'elle (v108).
        _c = _sq4.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        _c.execute("UPDATE stats SET noto=0 WHERE pseudo_id=?", (pid_l - 1000,)); _c.commit(); _c.close()
        defi_r = lambda regle: (b"\x03" + P.field_int(pid_l) + P.field_int16(2) + P.field_v(regle) + P.field_int(0)
                                + P.field_v(0) + P.field_byte(1))
        karl.sendall(P.build_frame(32, defi_r(6)))
        p33_t = next((pl for o, pl in frames(lire(karl, 0.8)) if o == 33), b"")
        karl.sendall(P.build_frame(32, defi_r(2)))
        p33_o = next((pl for o, pl in frames(lire(karl, 0.8)) if o == 33), b"")
        verifier("vainqueur : experience insuffisante, « Totale » a 3000 (op33 b0 v107), « One » face a 0 (op33 b0 v108)",
                 p33_t == b"\x03" + P.field_int(pid_l) + bytes([6, 0, 5, 107])
                 and p33_o == b"\x03" + P.field_int(pid_l) + bytes([6, 0, 5, 108]), f"{p33_t.hex()} / {p33_o.hex()}")
        verifier("vainqueur : seuils d'experience One 1000 ... Totale 5000, Directe / Change / Aleatoire 1000",
                 _SV.EXP_REGLE == {2: 1000, 3: 2000, 4: 3000, 5: 4000, 6: 5000, 7: 1000, 8: 1000, 9: 1000}
                 and not _SV.EXP_REGLE.get(0) and not _SV.EXP_REGLE.get(1))
        class _Partie:
            def main_de(self, cote): return [[11, 12, 13, 14, 15], [21, 22, 23, 24, 25]][cote]
        tirages = [_SV.cartes_en_jeu(_Partie(), 0, _SV.ALEATOIRE, 4) for _ in range(200)]
        verifier("vainqueur « Aleatoire » : UNE carte de la main du perdant tiree au sort, prise sans choix (0 a choisir)",
                 all(n == 0 and len(c) == 1 and c[0] in range(21, 26) for n, c in tirages)
                 and len({c[0] for _, c in tirages}) > 1, str(tirages[:3]))
        _c = _sq4.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        _c.execute("UPDATE stats SET noto=3000 WHERE pseudo_id=?", (pid_l - 1000,)); _c.commit(); _c.close()

        # defi « One » (2) avec la regle Aleatoire (masque 2) : la partie demarre sans choix de cartes. Les mains sont tirees
        # au hasard et un match nul ne donne rien a choisir : on donne a Karl des cartes a 10 et a Lena des cartes a 1, pour
        # que le vainqueur ne depende pas du tirage (un test qui echoue une fois sur trois ne prouve rien).
        _c = _sq4.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        _c.execute("UPDATE collection SET h=10, d=10, b=10, g=10 WHERE pseudo_id=?", (pid_k - 1000,))
        _c.execute("UPDATE collection SET h=1, d=1, b=1, g=1 WHERE pseudo_id=?", (pid_l - 1000,))
        _c.commit(); _c.close()
        defi = (b"\x03" + P.field_int(pid_l) + P.field_int16(2) + P.field_v(2) + P.field_int(0)
                + P.field_v(0) + P.field_byte(1))
        for essai_v in range(4):
            karl.sendall(P.build_frame(32, defi))
            rk = frames(lire(karl, 0.8)); lire(lena, 0.5)
            p33 = next((pl for o, pl in rk if o == 33), b"")
            if essai_v == 0:
                verifier("vainqueur : defi « One » accepte (op33 reprend la regle v2)",
                         p33 == b"\x03" + P.field_int(pid_l) + b"\x06\x01" + P.field_int16(2) + P.field_v(2)
                         + P.field_int(0) + P.field_v(0) + P.field_byte(1), p33.hex())
            lena.sendall(P.build_frame(35, b"\x03" + P.field_int(pid_k) + P.field_byte(1)))
            rk, rl = frames(lire(karl, 1.0)), frames(lire(lena, 1.0))
            gid_v = None
            for o, pl in rk:
                if o == 36: gid_v = champ_ints(pl)[-1]
            mains = {}
            for qui, rr in (("K", rk), ("L", rl)):
                m = next((pl for o, pl in rr if o == 135), b"")
                mains[qui] = [struct.unpack_from("<H", m, i + 1)[0] for i in range(6, len(m), 3) if m[i] == 0x04]
            if essai_v == 0:
                verifier("vainqueur : partie lancee, chacun a ses 5 cartes",
                         gid_v and len(mains["K"]) == 5 and len(mains["L"]) == 5, str(mains))
            # les 9 coups : chacun joue a son tour (le chien de garde du serveur jouerait a leur place apres 4 s)
            partie_v = (gid_v << 8) | 3
            socks = {0: karl, 1: lena}
            for coup in range(9):
                cote = coup % 2
                socks[cote].sendall(P.build_frame(140, P.field_int(partie_v) + b"\x00"
                                                  + P.field_v(coup // 2) + P.field_v(coup % 3) + P.field_v(coup // 3)))
                rk += frames(lire(karl, 0.45)); rl += frames(lire(lena, 0.45))
            rk += frames(lire(karl, 1.0)); rl += frames(lire(lena, 1.0))
            # op145 existe aussi en categorie 1 (les annonces du chat) : ne garder que la categorie 3
            p145 = [(qui, pl) for qui, rr in (("K", rk), ("L", rl)) for o, pl in rr if o == 145 and pl[:1] == bytes([3])]
            if p145: break
            verifier_nul = all(any(o == 148 for o, _ in rr) for rr in (rk, rl))
            print(f"   (match nul, essai {essai_v + 1} : fin propre {verifier_nul} ; on rejoue)")
        verifier("vainqueur : le gagnant recoit le choix des gains (op145 : partie, nombre, 5 cartes)",
                 len(p145) == 1 and [k for k, _ in _SV.parse_typed(p145[0][1])] == ["ctx", "int", "v"] + ["h16"] * 5
                 and _SV.parse_typed(p145[0][1])[2][1] == 1, str([_SV.parse_typed(p[1])[:3] for p in p145]))
        gagnant, perdant = (karl, lena) if p145[0][0] == "K" else (lena, karl)
        pid_gagnant = pid_k if p145[0][0] == "K" else pid_l
        pid_perdant = pid_l if p145[0][0] == "K" else pid_k
        proposees = [v for k, v in _SV.parse_typed(p145[0][1]) if k == "h16"]
        verifier("vainqueur : les cartes proposees sont la main du perdant",
                 sorted(proposees) == sorted(mains["L" if p145[0][0] == "K" else "K"]), str(proposees))
        verifier("vainqueur : rien n'est transfere avant le choix (pas encore d'op146/op148)",
                 not any(o in (146, 148) for o, _ in rk + rl))
        # l'enjeu reste reserve jusqu'au choix : le perdant vendait la carte que le vainqueur allait prendre (audit)
        perdant.sendall(P.build_frame(66, bytes([1]) + P.field_int16(proposees[2]) + P.field_v(3)))
        verifier("securite : enjeu reserve, le perdant ne vend pas une carte de sa main avant le choix (op67 b0 v46)",
                 (67, bytes([1, 6, 0, 5, 46])) in frames(lire(perdant, 0.6)))

        # choix d'une carte : op149 03 int(partie) v(indice) -> op150 b1, op146 (gains) / op147 (pertes), op148, op52
        gagnant.sendall(P.build_frame(149, b"\x03" + P.field_int(gid_v) + P.field_v(2)))
        rg, rp = frames(lire(gagnant, 1.0)), frames(lire(perdant, 1.0))
        carte = proposees[2]
        p146 = next((pl for o, pl in rg if o == 146), b""); p147 = next((pl for o, pl in rp if o == 147), b"")
        verifier("vainqueur : choix accepte (op150 b1) et gains / pertes annonces (op146 / op147 : la carte choisie)",
                 (150, P.field_int((gid_v << 8) | 3) + b"\x00" + b"\x06\x01") in rg
                 and p146 == P.field_int((gid_v << 8) | 3) + b"\x00" + P.field_int16(carte)
                 and p147 == p146, f"{p146.hex()} / {p147.hex()}")
        verifier("vainqueur : fin definitive (op148) et collections mises a jour (op52) des deux cotes",
                 all(any(o == x for o, _ in rr) for rr in (rg, rp) for x in (148, 52)))
        _c = _sq4.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
        _c.row_factory = _sq4.Row
        q = lambda pid: _c.execute("SELECT qty FROM collection WHERE pseudo_id=? AND card_id=?",
                                   (pid - 1000, carte)).fetchone()
        gagne, perdu = q(pid_gagnant), q(pid_perdant)
        _c.close()
        verifier("vainqueur : la carte a vraiment change de collection", gagne and gagne["qty"] >= 1 and not perdu,
                 f"gagnant {gagne['qty'] if gagne else 0} / perdant {perdu['qty'] if perdu else 0}")

        # « Aleatoire » (9), regle donnee par l'administrateur du serveur (2026-10-22) : comme One, mais le vainqueur ne
        # choisit pas. UNE carte de la main du perdant, tiree au sort, passe directement au gagnant : ni op145 ni op149,
        # op146 (gains) au gagnant et op147 (pertes) au perdant portent cette carte, puis op148.
        defi9 = (b"\x03" + P.field_int(pid_l) + P.field_int16(2) + P.field_v(9) + P.field_int(0)
                 + P.field_v(0) + P.field_byte(1))
        g146 = []; p145a = []
        for essai_a in range(4):
            karl.sendall(P.build_frame(32, defi9)); lire(karl, 0.8); lire(lena, 0.5)
            lena.sendall(P.build_frame(35, b"\x03" + P.field_int(pid_k) + P.field_byte(1)))
            rk, rl = frames(lire(karl, 1.0)), frames(lire(lena, 1.0))
            gid_a = next((champ_ints(pl)[-1] for o, pl in rk if o == 36), 0)
            mains_a = {}
            for qui, rr in (("K", rk), ("L", rl)):
                m = next((pl for o, pl in rr if o == 135), b"")
                mains_a[qui] = [struct.unpack_from("<H", m, i + 1)[0] for i in range(6, len(m), 3) if m[i] == 0x04]
            partie_a = (gid_a << 8) | 3
            for coup in range(9):
                socks[coup % 2].sendall(P.build_frame(140, P.field_int(partie_a) + b"\x00"
                                                      + P.field_v(coup // 2) + P.field_v(coup % 3) + P.field_v(coup // 3)))
                rk += frames(lire(karl, 0.45)); rl += frames(lire(lena, 0.45))
            rk += frames(lire(karl, 1.0)); rl += frames(lire(lena, 1.0))
            pref = P.field_int(partie_a) + b"\x00"
            g146 = [(qui, pl[len(pref):]) for qui, rr in (("K", rk), ("L", rl)) for o, pl in rr
                    if o == 146 and pl.startswith(pref) and len(pl) > len(pref)]
            p145a = [pl for rr in (rk, rl) for o, pl in rr if o == 145 and pl[:1] == bytes([3])]
            if g146 or p145a: break
            print(f"   (Aleatoire : match nul, essai {essai_a + 1} : on rejoue)")
        qui_g = g146[0][0] if g146 else "?"
        carte_a = struct.unpack_from("<H", g146[0][1], 1)[0] if g146 and len(g146[0][1]) == 3 else None
        r_perdant = rl if qui_g == "K" else rk
        p147a = [pl for o, pl in r_perdant if o == 147]
        verifier("vainqueur « Aleatoire » : sans choix (pas d'op145), UNE carte de la main du perdant au gagnant (op146 = op147)",
                 not p145a and len(g146) == 1 and carte_a in mains_a.get("L" if qui_g == "K" else "K", [])
                 and p147a[:1] == [pref + P.field_int16(carte_a or 0)]
                 and all(any(o == 148 for o, _ in rr) for rr in (rk, rl)), f"{g146} {p147a[:1]} {mains_a}")
        karl.close(); lena.close()


        # ================= ADRESSE BANNIE =================
        # Capture : S->C op1 « 00 », op4 « 00 str(nom du serveur) », op10 « 00 », fermeture.
        # En local toutes les adresses valent 127.0.0.1 (jamais bannies) : on compare donc la sequence elle-meme.
        import ffwtt_server as _S3
        verifier("adresse bannie : op1, op4 (nom du serveur), op10, identiques a la capture",
                 _S3.trames_host_banni("MonServeur") == P.build_frame(1, b"\x00") + P.build_frame(4, bytes.fromhex("0001d455023f3f0136262333222a"))
                 + P.build_frame(10, b"\x00"), _S3.trames_host_banni("MonServeur").hex())

        verifier("client d'origine : collection op52 de 4885 cases", TAILLES.get("Alice") == 4885, str(TAILLES.get("Alice")))

        # ================= SECURITE (audit du 2026-10-21) =================
        # Chaque faille trouvee par l'audit, envoyee comme un script l'enverrait (sans passer par le vrai client) : elle
        # doit echouer. Les delais (identification, silence) et la boucle d'acceptation ne se testent pas ici.
        import sqlite3 as _sq9, hashlib as _hl9, zlib as _zl9
        import ffwtt_server as _S9
        fiche9 = lambda pl: [v for _k, v in _S9.parse_typed(pl)]      # ctx, id, vendeur, nom, carte, depart, immediat...
        def sql(req, *args):
            base9 = _sq9.connect(os.path.join(DOSSIER, BASE_TEST), timeout=10)
            try:
                r_ = base9.execute(req, args).fetchall(); base9.commit(); return r_
            finally: base9.close()
        def gils_de(login): return sql("SELECT gils FROM accounts WHERE login=?", login.lower())[0][0]
        def qte_de(pid, carte): return (sql("SELECT qty FROM collection WHERE pseudo_id=? AND card_id=?", pid - 1000, carte)
                                        or [(0,)])[0][0]
        def identification(login, mdp, port=PORT):
            s_ = socket.create_connection(("127.0.0.1", port), timeout=8); lire(s_, 0.6)
            s_.sendall(P.build_frame(5, b"\x00" + P.field_int(P.VERSION_CLIENT))); lire(s_, 0.4)
            s_.sendall(P.build_frame(100, b"\x00" + P.field_str(login) + P.field_str(mdp)))
            return s_, frames(lire(s_, 0.8))
        refus101 = lambda code: (101, bytes([0, 6, 0, 5, code]))
        miser9 = lambda aid, montant: P.build_frame(191, b"\x02" + bytes([2]) + struct.pack("<I", aid) + bytes([2])
                                                  + struct.pack("<I", montant))

        # -- avant l'identification : ni salon, ni liste des joueurs, ni chat (identite par defaut « Joueur », pid 310)
        temoin, pid_tm = entrer("Temoin"); lire(temoin, 0.3)
        intrus = socket.create_connection(("127.0.0.1", PORT), timeout=8); lire(intrus, 0.6)
        intrus.sendall(P.build_frame(5, b"\x00" + P.field_int(P.VERSION_CLIENT))); lire(intrus, 0.4)
        intrus.sendall(P.build_frame(44, b"\x01")); r_in = lire(intrus, 1.0)
        intrus.sendall(P.build_frame(71, b"\x01" + P.field_byte(1)))
        intrus.sendall(P.build_frame(144, b"\x01" + P.field_str("sans compte") + P.field_byte(0)))
        r_tm = frames(lire(temoin, 1.0)); intrus.close()
        verifier("securite : sans identification, op44 / op71 / op144 ignores (ni salon, ni liste, ni chat)",
                 r_in == b"" and not any(o in (59, 145) for o, _ in r_tm), str([o for o, _ in r_tm]))

        # -- creation en jeu : regles d'un nouveau compte (mot de passe de 4 a 20 caracteres, nom de 3 a 20 caracteres simples)
        s_, r_court = identification("Nouveau", "abc"); s_.close()
        s_, r_geant = identification("x" * 3000, "secret"); s_.close()
        s_, r_espace = identification("Faux Nom", "secret"); s_.close()
        verifier("securite : creation en jeu soumise aux regles d'un nouveau compte (mot de passe court v3, nom invalide ou geant v91)",
                 refus101(3) in r_court and refus101(91) in r_geant and refus101(91) in r_espace
                 and not sql("SELECT 1 FROM accounts WHERE login IN ('nouveau', 'faux nom')"),
                 f"{r_court} {r_geant} {r_espace}")

        # -- un compte SANS mot de passe (ancien ffwtt_admin.py) n'accepte plus n'importe quel mot de passe
        sql("INSERT INTO accounts(login, pw, admin, gils, created) VALUES('sansmdp', ?, 3, 0, 0)", _hl9.sha256(b"").hexdigest())
        sql("INSERT INTO pseudos(account_id, name, is_main) VALUES((SELECT id FROM accounts WHERE login='sansmdp'), 'SansMdp', 1)")
        s_, r_ = identification("SansMdp", "nimportequoi"); s_.close()
        verifier("securite : compte sans mot de passe refuse quel que soit le mot de passe (v3)", refus101(3) in r_, str(r_))
        adm9 = subprocess.run([sys.executable, "ffwtt_admin.py", "niveau", "Inconnu", "3"], env=env, capture_output=True,
                              text=True, timeout=60)
        verifier("securite : ffwtt_admin.py ne cree plus de compte d'avance (nom inconnu : refus)",
                 adm9.returncode == 1 and not sql("SELECT 1 FROM accounts WHERE login='inconnu'"),
                 (adm9.stdout + adm9.stderr).strip()[-90:])

        # -- --admin Fantome : le nom n'existait pas au demarrage, celui qui le prend reste un simple joueur
        fa_s, pid_fa = entrer("Fantome")
        g61 = [pl[-1] for o, pl in frames(RAFALES["Fantome"]) if o == 61 and pl[1:6] == P.field_int(pid_fa)]
        verifier("securite : --admin ne reserve aucun niveau a un nom libre (Fantome reste joueur)",
                 sql("SELECT admin FROM accounts WHERE login='fantome'")[0][0] == 0 and 14 not in g61, str(g61))
        fa_s.close()

        # -- mots de passe essayes a la chaine : apres 5 refus, meme le bon est refuse (10 minutes)
        vi_s, _ = entrer("Victime"); vi_s.close(); time.sleep(0.6)
        essais = []
        for _ in range(5):
            s_, r_ = identification("Victime", "mauvais"); s_.close(); essais.append(refus101(3) in r_)
        s_, r_bon = identification("Victime", "secret"); s_.close()
        s_, r_autre = identification("Temoin2", "secret"); s_.close()
        verifier("securite : 5 mots de passe faux -> ce compte est bloque depuis cette adresse, pas les autres",
                 all(essais) and refus101(3) in r_bon and any(o == 101 and pl[:3] == b"\x00\x06\x01" for o, pl in r_autre),
                 f"{essais} {r_bon} {r_autre}")

        # -- mises en gils : jamais plus que son solde (le solde devenait negatif, la mise se doublait au gagnant)
        pa, pid_pa = entrer("Parieur"); pb, pid_pb = entrer("Adversaire"); lire(pa, 0.3); lire(pb, 0.3)
        defi_m = lambda regle, montant: P.build_frame(32, b"\x03" + P.field_int(pid_pb) + P.field_int16(0) + P.field_v(regle)
                                                      + P.field_int(montant) + P.field_v(0) + P.field_byte(1))
        a33 = lambda code: (33, b"\x03" + P.field_int(pid_pb) + bytes([6, 0, 5, code]))
        pa.sendall(defi_m(1, gils_de("Parieur") + 1))
        r_trop = frames(lire(pa, 0.6))
        sql("UPDATE accounts SET gils=1000 WHERE login='adversaire'")
        pa.sendall(defi_m(1, 3000))
        r_lui = frames(lire(pa, 0.6))
        verifier("securite : mise refusee au-dela du solde du defiant (op33 v14) ou de l'adversaire (v40)",
                 a33(14) in r_trop and a33(40) in r_lui, f"{r_trop} {r_lui}")
        sql("UPDATE accounts SET gils=5000 WHERE login='adversaire'")
        pa.sendall(defi_m(1, 3000)); lire(pa, 0.6); lire(pb, 0.6)
        sql("UPDATE accounts SET gils=100 WHERE login='adversaire'")            # il a depense entre-temps
        pb.sendall(P.build_frame(35, b"\x03" + P.field_int(pid_pa) + P.field_byte(1)))
        r_pb, r_pa = frames(lire(pb, 0.8)), frames(lire(pa, 0.8))
        verifier("securite : acceptation sans les gils de la mise : defi referme (op36 v14 / v40), rien n'est debite",
                 (36, b"\x03" + P.field_int(pid_pa) + bytes([6, 0, 6, 1, 5, 14])) in r_pb
                 and (36, b"\x03" + P.field_int(pid_pb) + bytes([6, 0, 6, 1, 5, 40])) in r_pa
                 and gils_de("Parieur") == 5000 and gils_de("Adversaire") == 100 and 135 not in [o for o, _ in r_pa],
                 f"{gils_de('Parieur')} {gils_de('Adversaire')}")
        pa.sendall(defi_m(0, 3000))                                             # Entrainement : jamais de mise
        p33 = next((pl for o, pl in frames(lire(pa, 0.6)) if o == 33), b"")
        verifier("securite : « Entrainement » ramene la mise a 0 (elle n'etait jamais rendue)",
                 p33 == b"\x03" + P.field_int(pid_pb) + b"\x06\x01" + P.field_int16(0) + P.field_v(0) + P.field_int(0)
                 + P.field_v(0) + P.field_byte(1), p33.hex())
        pa.sendall(P.build_frame(35, b"\x03" + P.field_int(pid_pb) + P.field_byte(0))); lire(pa, 0.4); lire(pb, 0.4)
        pa.close(); pb.close()

        # -- encheres : une enchere close n'accepte plus de mise (chaque mise livrait un exemplaire de plus pour 1 gil)
        ach, pid_ach = entrer("Acheteur")
        sql("UPDATE accounts SET gils=500000 WHERE login='acheteur'")
        e_rob = next(fiche9(pl) for o, pl in frames(RAFALES["Acheteur"]) if o == 190 and fiche9(pl)[2] in (996, 997, 998, 999))
        aid_r, carte_r, depart_r, immediat_r = e_rob[1], e_rob[4], e_rob[5], e_rob[6]
        avant_q = qte_de(pid_ach, carte_r)
        ach.sendall(miser9(aid_r, depart_r - 1)); r_bas = frames(lire(ach, 0.6))
        verifier("securite : mise sous le prix de depart refusee (rien n'est debite)",
                 not any(o == 192 for o, _ in r_bas) and gils_de("Acheteur") == 500000, str([o for o, _ in r_bas]))
        ach.sendall(miser9(aid_r, immediat_r)); lire(ach, 1.0)
        ach.sendall(miser9(aid_r, immediat_r + 1)); r_re = frames(lire(ach, 1.0))
        ach.sendall(miser9(aid_r, immediat_r + 2)); r_re += frames(lire(ach, 1.0))
        verifier("securite : achat immediat conclu une fois, les mises suivantes sur l'enchere close sont refusees",
                 qte_de(pid_ach, carte_r) == avant_q + 1 and gils_de("Acheteur") == 500000 - immediat_r
                 and not any(o in (63, 192) for o, _ in r_re),
                 f"exemplaires {avant_q}->{qte_de(pid_ach, carte_r)}, gils {gils_de('Acheteur')}")
        ach.sendall(P.build_frame(66, bytes([1]) + P.field_int16(60000) + P.field_v(2)))
        verifier("securite : achat d'une carte qui n'existe pas refuse (op67 b0 v46)",
                 (67, bytes([1, 6, 0, 5, 46])) in frames(lire(ach, 0.6)) and gils_de("Acheteur") == 500000 - immediat_r)

        # -- en pleine partie : pas de changement de pseudo ; le chat d'une partie n'est pas ouvert a tous
        ach.sendall(P.build_frame(32, b"\x03" + P.field_int(999) + P.field_int16(0) + P.field_v(1) + P.field_int(0)
                                  + P.field_v(7) + P.field_byte(1)))
        p36r = next((pl for o, pl in frames(lire(ach, 1.2)) if o == 36), b"")
        partie_r = (champ_ints(p36r)[-1] << 8) | 3 if p36r else 0
        ach.sendall(P.build_frame(207, b"\x00" + P.field_int(pid_ach - 1000)))
        verifier("securite : changer de pseudo en pleine partie est refuse (op208 b0 v87)",
                 (208, bytes([0, 6, 0, 5, 87])) in frames(lire(ach, 0.6)))
        chat_p = lambda texte: P.build_frame(151, P.field_int(partie_r) + b"\x00" + P.field_str(texte))
        lire(temoin, 0.2)
        temoin.sendall(chat_p("intrusion")); ach.sendall(chat_p("bonne partie"))
        r_ach, r_tm = frames(lire(ach, 0.8)), frames(lire(temoin, 0.5))
        verifier("securite : chat de partie reserve a ses joueurs et spectateurs (op151)",
                 any(o == 153 and P.field_str("bonne partie") in pl for o, pl in r_ach)
                 and not any(o == 153 and P.field_str("intrusion") in pl for o, pl in r_ach + r_tm))

        # -- anti-flood et longueur des messages
        lire(temoin, 0.3)
        for i in range(15): ach.sendall(P.build_frame(144, b"\x01" + P.field_str(f"flood {i}") + P.field_byte(0)))
        flood = [pl for o, pl in frames(lire(temoin, 1.5)) if o == 145 and any(P.field_str(f"flood {i}") in pl for i in range(15))]
        temoin.sendall(P.build_frame(144, b"\x01" + P.field_str("y" * 3000) + P.field_byte(0)))
        long_ = [pl for o, pl in frames(lire(ach, 1.0)) if o == 145 and P.field_str("y" * 1000) in pl]
        verifier("securite : anti-flood (8 messages en 10 s) et message coupe a 1000 caracteres",
                 len(flood) == 8 and len(long_) == 1 and P.field_str("y" * 1001) not in long_[0], f"{len(flood)} relayes")
        ach.close()

        # -- operateurs : muet sur TOUS les canaux, pas d'action sur un niveau superieur, « !grade » sans pouvoir
        time.sleep(0.6)
        adm, pid_adm9 = entrer("Gerant"); bav, pid_bav = entrer("Bavard"); lire(adm, 0.3); lire(temoin, 0.3)
        adm.sendall(P.build_frame(245, b"\x04" + P.field_byte(1) + P.field_int(pid_bav))); lire(adm, 0.6)
        bav.sendall(P.build_frame(146, b"\x01" + P.field_int(pid_tm) + P.field_str("message prive") + P.field_byte(0)))
        verifier("securite : un joueur rendu muet n'envoie plus de message prive (op146)",
                 not any(o == 147 for o, _ in frames(lire(temoin, 0.8))))
        adm.sendall(P.build_frame(245, b"\x04" + P.field_byte(0) + P.field_int(pid_bav))); lire(adm, 0.6); lire(bav, 0.3)
        adm.sendall(P.build_frame(144, b"\x01" + P.field_str("!grade 14") + P.field_byte(0))); lire(adm, 0.6); lire(bav, 0.3)
        bav.sendall(P.build_frame(181, b"\x04" + P.field_int(pid_tm) + P.field_str("dehors")))
        verifier("securite : « !grade » ne donne aucun droit (un simple joueur ne peut toujours pas expulser, v87)",
                 (182, bytes([4, 6, 0, 5, 87])) in frames(lire(bav, 0.8)))
        bav.close()
        mo, _ = entrer("Moderateur"); mo.close(); time.sleep(0.6)
        sql("UPDATE accounts SET admin=2 WHERE login='moderateur'")
        mo, _ = entrer("Moderateur"); lire(adm, 0.3)
        mo.sendall(P.build_frame(181, b"\x04" + P.field_int(pid_adm9) + P.field_str("putsch")))
        verifier("securite : un operateur n'agit pas sur un operateur de niveau superieur (kick refuse, v87)",
                 (182, bytes([4, 6, 0, 5, 87])) in frames(lire(mo, 0.8)) and 77 not in opcodes(lire(adm, 0.5)))
        mo.close(); adm.close()

        # -- donnees compressees : un bloc qui se decompresse en 20 Mo est refuse
        bombe = _zl9.compress(bytes(20_000_000), 9)
        temoin.sendall(P.build_frame(64, bytes([6]) + b"\x08" + struct.pack("<H", len(bombe)) + bombe))
        r_bombe = frames(lire(temoin, 1.0))
        temoin.sendall(P.build_frame(64, b"\x01" + P.field_int(pid_tm)))
        verifier("securite : bombe de decompression refusee (op65 b0 v69), le serveur repond toujours",
                 (65, bytes([6, 6, 0, 5, 69])) in r_bombe and 65 in opcodes(lire(temoin, 0.8)), f"{len(bombe)} octets")


        # -- un pseudo banni n'entre pas au salon, meme en sautant le choix du pseudo (op207)
        bn_s, _ = entrer("Bannable"); bn_s.close(); time.sleep(0.6)
        sql("INSERT OR REPLACE INTO bans(kind, value) VALUES('nick', 'bannable')")
        s_, _ = identification("Bannable", "secret")
        s_.sendall(P.build_frame(44, b"\x01")); r_bn = lire(s_, 1.0); s_.close()
        verifier("securite : pseudo principal banni, op207 saute : pas de salon (op44 ignore)", r_bn == b"", f"{len(r_bn)} octets")

        # -- echange : une offre modifiee apres la validation du partenaire annule cette validation
        tq, pid_tq = entrer("Troqueur"); du, pid_du = entrer("Dupe")
        sql("UPDATE stats SET noto=5000 WHERE pseudo_id IN (?, ?)", pid_tq - 1000, pid_du - 1000)
        carte_tq, carte_du = COLLECTIONS["Troqueur"][0], COLLECTIONS["Dupe"][0]
        avant_du, avant_tq = qte_de(pid_du, carte_du), qte_de(pid_tq, carte_du)
        offre = lambda part, carte: P.build_frame(93, b"\x02" + P.field_int(part) + P.field_int(0)
                                                  + (P.field_int16(carte) + P.field_v(1) if carte else b""))
        valider = lambda part: P.build_frame(96, b"\x02" + P.field_int(part) + P.field_byte(1))
        tq.sendall(P.build_frame(88, b"\x02" + P.field_int(pid_du))); lire(tq, 0.5); lire(du, 0.5)
        tq.sendall(offre(pid_du, carte_tq))
        verifier("securite : pas d'offre avant que l'echange soit accepte (op94 b0 v22)",
                 (94, b"\x02" + P.field_int(pid_du) + bytes([6, 0, 5, 22])) in frames(lire(tq, 0.6)))
        du.sendall(P.build_frame(91, b"\x02" + P.field_int(pid_tq) + P.field_byte(1))); lire(tq, 0.5); lire(du, 0.5)
        tq.sendall(offre(pid_du, carte_tq)); du.sendall(offre(pid_tq, carte_du)); lire(tq, 0.5); lire(du, 0.5)
        du.sendall(valider(pid_tq)); lire(du, 0.4)                    # Dupe valide l'echange carte contre carte...
        tq.sendall(offre(pid_du, 0)); tq.sendall(valider(pid_du))     # ... Troqueur retire sa carte et valide aussitot
        r_tq, r_du = frames(lire(tq, 0.8)), frames(lire(du, 0.8))
        conclu = [pl for o, pl in r_tq + r_du if o == 97 and pl.endswith(b"\x06\x01")]
        verifier("securite : echange modifie apres la validation de l'autre : rien n'est conclu, chacun garde ses cartes",
                 not conclu and qte_de(pid_du, carte_du) == avant_du and qte_de(pid_tq, carte_du) == avant_tq, str(conclu))
        tq.sendall(P.build_frame(96, b"\x02" + P.field_int(pid_du) + P.field_byte(0))); lire(tq, 0.4); lire(du, 0.4)
        tq.close(); du.close(); temoin.close()

        # -- un serveur aux plafonds bas : 3 connexions par adresse, 2 comptes crees par heure et par adresse ; et une
        # connexion muette remplacee apres 4 s au lieu de 30 (FFWTT_DELAI_SESSION_MUETTE)
        base_st = os.path.join(DOSSIER, "ffwtt_test_strict.db")
        for f in (base_st, base_st + "-journal"):
            if os.path.exists(f): os.remove(f)
        env_st = dict(env); env_st.update(FFWTT_DB=base_st, FFWTT_MAX_PAR_IP="3", FFWTT_CREATIONS_PAR_IP="2",
                                          FFWTT_DELAI_SESSION_MUETTE="4")
        journal_st = open("ffwtt_test_strict.log", "w", encoding="utf-8")
        srv_st = subprocess.Popen([sys.executable, "ffwtt_server.py", "--port", str(PORT + 5), "--name", "Strict"],
                                  stdout=journal_st, stderr=subprocess.STDOUT, env=env_st)
        time.sleep(3)
        def ferme_aussitot(s_):
            try: s_.settimeout(1.5); return s_.recv(1) == b""
            except ConnectionError: return True
            except (socket.timeout, OSError): return False
        try:
            ouvertes = [socket.create_connection(("127.0.0.1", PORT + 5), timeout=8) for _ in range(3)]
            accueils = [opcodes(lire(s_, 0.6))[:2] for s_ in ouvertes]
            quatrieme = socket.create_connection(("127.0.0.1", PORT + 5), timeout=8)
            verifier("securite : au plus 3 connexions par adresse (--max-par-ip) : la 4e est fermee sans accueil",
                     accueils == [[1, 4]] * 3 and ferme_aussitot(quatrieme), str(accueils))
            quatrieme.close()
            reps = []
            for s_, nom in zip(ouvertes, ("Premier", "Second", "Troisieme")):
                s_.sendall(P.build_frame(5, b"\x00" + P.field_int(P.VERSION_CLIENT)))
                s_.sendall(P.build_frame(100, b"\x00" + P.field_str(nom) + P.field_str("secret")))
                reps.append(frames(lire(s_, 1.0)))
            verifier("securite : 2 comptes crees en jeu par adresse et par heure, le 3e refuse (v91)",
                     all(any(o == 101 and pl[:3] == b"\x00\x06\x01" for o, pl in r_) for r_ in reps[:2])
                     and refus101(91) in reps[2], str([[o for o, _ in r_] for r_ in reps]))
            st = _sq9.connect(base_st, timeout=10)
            niveaux_st = dict(st.execute("SELECT login, admin FROM accounts").fetchall()); st.close()
            verifier("serveur neuf : le premier compte cree est administrateur (niveau 4), pas les suivants",
                     niveaux_st.get("premier") == 4 and niveaux_st.get("second") == 0, str(niveaux_st))
            for s_ in ouvertes: s_.close()
            time.sleep(1.5)
            s_ = socket.create_connection(("127.0.0.1", PORT + 5), timeout=8)
            verifier("securite : une connexion fermee libere sa place", opcodes(lire(s_, 0.6))[:2] == [1, 4]); s_.close()

            # -- reconnexion d'un compte dont l'ancienne connexion est ouverte mais muette (client fige, connexion tombee
            # sans fermeture) : refusee (v4) tant qu'elle a parle recemment ; au-dela du delai, l'ancienne est fermee
            # comme une deconnexion ordinaire (op60 aux autres joueurs) et la nouvelle acceptee.
            def salon_st(nom):
                s_ = socket.create_connection(("127.0.0.1", PORT + 5), timeout=8); lire(s_, 0.6)
                s_.sendall(P.build_frame(5, b"\x00" + P.field_int(P.VERSION_CLIENT)))
                s_.sendall(P.build_frame(100, b"\x00" + P.field_str(nom) + P.field_str("secret")))
                pid_ = next((champ_ints(pl)[0] for o, pl in frames(lire(s_, 1.0)) if o == 101 and champ_ints(pl)), 0)
                s_.sendall(P.build_frame(207, b"\x00" + P.field_int(pid_ - 1000))); lire(s_, 0.6)
                s_.sendall(P.build_frame(44, b"\x01")); lire(s_, 1.0)
                s_.sendall(P.build_frame(71, b"\x01" + P.field_byte(1))); lire(s_, 1.0)
                return s_, pid_
            def fermee_par_le_serveur(s_):
                s_.settimeout(1.5)
                try:
                    while s_.recv(65536): pass
                    return True
                except ConnectionError: return True
                except (socket.timeout, OSError): return False
            vu, _ = salon_st("Premier")
            muet, pid_muet = salon_st("Second"); lire(vu, 0.5)
            depart_muet = (60, b"\x01" + P.field_int(pid_muet) + P.field_v(0) + P.field_v(0))
            muet.sendall(P.build_frame(768, b"\x00"))            # sa derniere trame (un pong), puis plus rien : ni pong ni rien
            s_, r_tot = identification("Second", "secret", port=PORT + 5); s_.close()
            r_vu_tot = frames(lire(vu, 0.5))
            verifier("reconnexion : refusee (op101 b0 v4) quand l'ancienne connexion du compte a parle il y a moins de 4 s,"
                     " et l'ancienne reste en place", refus101(4) in r_tot and depart_muet not in r_vu_tot and pid_muet > 1000,
                     str([(o, pl.hex()) for o, pl in r_tot if o == 101]))
            time.sleep(4.5)                                       # le delai de FFWTT_DELAI_SESSION_MUETTE est depasse
            nouvelle, r_tard = identification("Second", "secret", port=PORT + 5)
            r_tard += frames(lire(nouvelle, 3.0))     # op101 attend le menage du fil de l'ancienne (1 s au plus)
            r_vu_tard = frames(lire(vu, 1.0))
            journal_muet = open("ffwtt_test_strict.log", encoding="utf-8", errors="replace").read()
            verifier("reconnexion : ancienne connexion muette depuis plus de 4 s fermee (op60 aux autres, journal), la "
                     "nouvelle acceptee (op101 b1)",
                     any(o == 101 and pl[:3] == b"\x00\x06\x01" for o, pl in r_tard) and depart_muet in r_vu_tard
                     and fermee_par_le_serveur(muet)
                     and "ancienne connexion du compte fermee pour une nouvelle (aucune trame depuis" in journal_muet,
                     f"{[(o, pl.hex()) for o, pl in r_tard if o == 101]} op60 vu : {depart_muet in r_vu_tard}")
            for s_ in (vu, muet, nouvelle): s_.close()
        finally:
            srv_st.terminate()
            try: srv_st.wait(timeout=5)
            except subprocess.TimeoutExpired: srv_st.kill()
            journal_st.close()
        texte_st = open("ffwtt_test_strict.log", encoding="utf-8", errors="replace").read()
        verifier("serveur neuf : annonce au demarrage, puis le premier compte au journal de moderation",
                 "Serveur neuf" in texte_st and "Premier : premier compte du serveur" in texte_st)
        err_st = [l for l in texte_st.splitlines() if "!!" in l or "Traceback" in l]
        verifier("securite : aucune erreur dans le journal du serveur aux plafonds bas", not err_st,
                 err_st[0].strip() if err_st else "")
        for f in (base_st, base_st + "-journal") + (("ffwtt_test_strict.log",) if "--journal" not in sys.argv else ()):
            if os.path.exists(f): os.remove(f)

        # ================= DEUXIEME SERVEUR SUR LE MEME PORT =================
        doublon = subprocess.run([sys.executable, "ffwtt_server.py", "--port", str(PORT)],
                                 capture_output=True, text=True, env=env, timeout=30)
        verifier("second serveur sur le meme port : refus explicite",
                 doublon.returncode == 1 and "deja utilise" in doublon.stdout
                 and "Traceback" not in (doublon.stdout + doublon.stderr),
                 (doublon.stdout + doublon.stderr).strip().splitlines()[-1][:80] if (doublon.stdout + doublon.stderr).strip() else "")
    except Exception as e:
        verifier(f"exception : {type(e).__name__} {e}", False)
    finally:
        time.sleep(0.5)
        serveur.terminate()
        try: serveur.wait(timeout=5)
        except subprocess.TimeoutExpired: serveur.kill()
        fichier_journal.close()
        journal = open(JOURNAL_TEST, encoding="utf-8", errors="replace").read()

    erreurs = [l for l in journal.splitlines() if "!!" in l or "Traceback" in l]
    verifier("aucune erreur dans le journal", not erreurs,
             erreurs[0].strip() if erreurs else "")
    # Ni mot de passe (connexion op100, /ident op176) ni texte de message prive (op146) dans le journal du serveur
    fuites = [m for m in ("motdepasse", "'secret'", "MdpIdentSecret") if m in journal]
    lignes_mp = [l for l in journal.splitlines() if "C->S" in l and "opcode=146 " in l]
    verifier("journal : aucun mot de passe ni texte de message prive (masques : '***')",
             not fuites and lignes_mp and all("'***'" in l and "hello" not in l for l in lignes_mp)
             and any("opcode=100 " in l and "'Testeur'" in l and "'***'" in l for l in journal.splitlines()),
             f"{fuites} {lignes_mp[:1]}")

    for f in (BASE_TEST,) + ((JOURNAL_TEST,) if "--journal" not in sys.argv else ()):
        if os.path.exists(f): os.remove(f)

    reussis = sum(1 for _, ok in resultats if ok)
    print(f"\n{reussis}/{len(resultats)} verifications reussies")
    if erreurs:
        print("\n--- erreurs du serveur ---")
        for l in erreurs[:10]: print("   ", l.strip())
    if reussis != len(resultats) and "--journal" in sys.argv:
        print("\n--- fin du journal du serveur ---")
        for l in journal.splitlines()[-int(os.environ.get("LIGNES", "60")):]: print("   ", l[:200])
    return 0 if reussis == len(resultats) else 1

if __name__ == "__main__":
    sys.exit(main())
