#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffwtt_server.py — Serveur FFWorld Triple Triad (squelette v0).

Implementation INDEPENDANTE batie sur le protocole observe (cadrage + chiffre
de chaine retro-concus depuis le client). But de cette v0 : faire passer le
client de "Connecte" a l'ecran d'identification, et journaliser/dechiffrer tout
ce qu'il envoie pour qu'on complete la suite (login, liste des joueurs, parties).

Lance :  python ffwtt_server.py --name Balamb
Puis le client :  ffwtt://127.0.0.1:27888

Necessite ffwtt_protocol.py dans le meme dossier.
"""
import argparse, socket, threading, datetime, struct, time, os, random
import ffwtt_protocol as P
import ffwtt_game as G
import ffwtt_db as db
import ffwtt_guildes as GU
import unicodedata
db.NOMS_RESERVES.update(n for r in G.ROBOTS.values() for n in (r["nom"].lower(),                # personne ne prend le
                        unicodedata.normalize("NFKD", r["nom"].lower()).encode("ascii", "ignore").decode()))   # pseudo
                                                                       # d'un robot, ni sans ses accents (Bahamut-Extreme)
import zlib

MARQUE_ADMIN = "    *** ADMIN "
LIGNE_MAX = 2000          # une trame de 64 Ko ne remplit plus le journal (disque d'un VPS) : la ligne est coupee
def log(l):
    ts=datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] {l if len(l) <= LIGNE_MAX else l[:LIGNE_MAX] + f' [... {len(l) - LIGNE_MAX} caracteres]'}")
    if l.startswith(MARQUE_ADMIN):       # « *** ADMIN <auteur> : <action> » -> journal de moderation (en base)
        auteur, _, action = l[len(MARQUE_ADMIN):].partition(" : ")
        try: db.journal_ajouter(auteur, "jeu", "", action)
        except Exception: pass

def describe(op, payload):
    try:
        fields=P.decode_fields(payload)
    except Exception:
        fields=[("raw",payload.hex())]
    return f"opcode={op} (0x{op:x})  " + " ; ".join(f"{k}={v!r}" for k,v in fields)

# Ce que le journal ne doit jamais contenir : mots de passe et texte des messages prives. Le journal (console, journal
# systeme d'un VPS, fichier de redirection) n'est pas un lieu sur ; en base, les mots de passe ne sont qu'un hache PBKDF2.
# (categorie, opcode) -> rangs des chaines masquees (formats : py ffwtt_envois.py).
CHAINES_MASQUEES = {(0, 100): {1},     # connexion : s(login) s(mot de passe)
                    (4, 176): {1},     # /ident : s(groupe) s(mot de passe)
                    (4, 119): {1},     # tableau de guilde : s(nom) s(mot de passe facultatif)
                    (1, 146): {0},     # message prive : u(destinataire) s(texte) b
                    (0, 205): {0}}     # suppression de pseudo : u(pseudo) s(e-mail de verification)

def describe_entrant(op, payload):
    masque = CHAINES_MASQUEES.get((payload[0], op)) if payload else None
    if not masque:
        return describe(op, payload)
    champs, rang = [], 0
    for k, v in parse_typed(payload):
        if k == "str":
            if rang in masque: v = "***"
            rang += 1
        elif k == "raw":
            v = "***"                  # chaine illisible : on ne l'ecrit pas non plus en hexadecimal
        champs.append(f"{k}={v!r}")
    return f"opcode={op} (0x{op:x})  " + " ; ".join(champs)

def send(conn, frame, note=""):
    conn.sendall(frame)
    log(f"  S->C  {note}  [{frame.hex()}]")

def send_greeting(conn, server_name):
    # Sequence d'accueil observee : op1, op4(nom du serveur) ; le client envoie alors sa version (op5) et le serveur
    # lui repond op6 (voir react, op5).
    # op1 : trame de controle (charge utile minimale observee = octet de contexte 0x00)
    send(conn, P.build_frame(1, b"\x00"), "op1 (accueil)")
    # op4 : le serveur annonce son nom (chaine, contexte 0x00)
    send(conn, P.build_string_msg(4, server_name, ctx=0), f"op4 nom='{server_name}'")

def cartes_connues(conn):
    """Nombre de cartes que connait le client de cette connexion (4885 pour le client d'origine)."""
    return SESSIONS.get(id(conn), {}).get("cartes_client", P.CARTES_CLIENT)

def trames_host_banni(server_name):
    """Refus d'une adresse bannie. CAPTURE : op1 « 00 », op4 « 00 str(nom du serveur) », puis
    op10 « 00 » a la place d'op6, et le serveur ferme la connexion. Le client affiche alors (cas 10, 0x639F13) :
    « Votre nom d'hote est banni de ce serveur. Acceptez votre sanction : le ban n'en sera leve que plus vite
    (quelques heures generalement). Si vous pensez ne pas etre concerne par ce ban, veuillez nous en excuser et
    reessayer de vous connecter au serveur un peu plus tard. »"""
    return (P.build_frame(1, b"\x00") + P.build_string_msg(4, server_name, ctx=0) + P.build_frame(10, b"\x00"))

# ---------- connexions : plafonds et delais (audit de securite du 2026-10-21) ----------
# Sans eux, un millier de connexions muettes epuisaient les descripteurs du processus, et la boucle d'acceptation, qui ne
# rattrapait que Ctrl+C, s'arretait : tout le serveur tombait. Plafonds reglables (--max-connexions, --max-par-ip).
MAX_CONNEXIONS = int(os.environ.get("FFWTT_MAX_CONNEXIONS") or 300)
MAX_PAR_IP = int(os.environ.get("FFWTT_MAX_PAR_IP") or 12)
DELAI_IDENTIFICATION = 600    # s : une connexion qui ne s'est pas identifiee (op100) est fermee
DELAI_SILENCE = 900           # s sans aucune trame (le client repond au ping op512, envoye toutes les 10 s, par op768)
CONNEXIONS = {}               # adresse IP -> connexions ouvertes
_CONNEXIONS_LOCK = threading.Lock()
_REFUS_JOURNALISES = {}       # adresse IP -> dernier refus ecrit au journal (une ligne par minute au plus)

def accepter(conn, addr, server_name):
    """Appelee par la boucle d'acceptation : demarre la session, ou ferme aussitot une connexion de trop."""
    ip = addr[0]
    with _CONNEXIONS_LOCK:
        refus = (sum(CONNEXIONS.values()) >= MAX_CONNEXIONS or CONNEXIONS.get(ip, 0) >= MAX_PAR_IP)
        if not refus: CONNEXIONS[ip] = CONNEXIONS.get(ip, 0) + 1
    if refus:
        if time.time() - _REFUS_JOURNALISES.get(ip, 0) > 60:
            _REFUS_JOURNALISES[ip] = time.time()
            log(f"*** connexion refusee : {ip} a deja {CONNEXIONS.get(ip, 0)} connexion(s) "
                f"(au plus {MAX_PAR_IP} par adresse, {MAX_CONNEXIONS} en tout)")
        try: conn.close()
        except OSError: pass
        return
    try:
        threading.Thread(target=handle, args=(conn, addr, server_name), daemon=True).start()
    except RuntimeError:                       # plus de fil disponible : on ferme, le serveur continue
        _liberer(ip)
        try: conn.close()
        except OSError: pass

def _liberer(ip):
    with _CONNEXIONS_LOCK:
        CONNEXIONS[ip] = CONNEXIONS.get(ip, 1) - 1
        if CONNEXIONS[ip] <= 0: CONNEXIONS.pop(ip, None)

def handle(conn, addr, server_name):
    try: _session(conn, addr, server_name)
    finally: _liberer(addr[0])

def _session(conn, addr, server_name):
    log(f">>> client connecte {addr[0]}:{addr[1]}")
    if not addr[0].startswith("127.") and db.is_banned("host", addr[0]):
        log(f"    *** HOST BANNI : {addr[0]} -> connexion refusee (op1, op4, op10)")
        try: conn.sendall(trames_host_banni(server_name)); time.sleep(0.3); conn.close()
        except OSError: pass
        return
    _sess(conn)["ip"] = addr[0]
    send_greeting(conn, server_name)
    buf=bytearray()
    conn.settimeout(1.0)
    debut = derniere = time.time()
    while True:
        try:
            data=conn.recv(4096)
        except socket.timeout:
            maintenant = time.time()
            if not _sess(conn).get("account_id") and maintenant - debut > DELAI_IDENTIFICATION:
                log(f"<<< {addr[0]} : pas d'identification en {DELAI_IDENTIFICATION} s, connexion fermee"); break
            if maintenant - derniere > DELAI_SILENCE:
                log(f"<<< {addr[0]} : aucune trame depuis {DELAI_SILENCE} s, connexion fermee"); break
            continue
        except OSError:
            break
        if not data:
            log("<<< client deconnecte"); break
        derniere = time.time()
        buf.extend(data)
        for op,payload in P.parse_frames(buf):
            log(f"  C->S  {describe_entrant(op,payload)}")
            try:
                react(conn, op, payload, server_name)
            except Exception as e:
                # une erreur serveur ne doit jamais couper la session du joueur
                import traceback
                log(f"  !! erreur sur op{op} : {e}")
                log("     " + traceback.format_exc().splitlines()[-2].strip())
    # deconnexion : retirer le joueur de la liste en ligne et liberer son etat
    with CLIENTS_LOCK:
        gone = CLIENTS.pop(id(conn), None)
    if gone:
        log(f"<<< {gone['name']} (id {gone['pid']}) quitte le salon")
        # Capture (partenaire d'echange qui se deconnecte) : op97 d'annulation, puis op60.
        etat = ECHANGES.pop(gone["pid"], None)
        if etat:
            ECHANGES.pop(etat["partenaire"], None)
            cl = find_client(etat["partenaire"])
            if cl:
                try: cl["conn"].sendall(echange_annule_frame(gone["pid"], parti=True))
                except OSError: pass
        for (de, vers), p_ in list(PENDING.items()):
            if gone["pid"] in (de, vers):
                PENDING.pop((de, vers), None)
                autre = p_["to_conn"] if de == gone["pid"] else p_["from_conn"]
                try: autre.sendall(defi_ferme(gone["pid"]))
                except OSError: pass
        # op60 = « X a quitte le FFWTT » : retire le joueur de la liste des autres clients
        broadcast(P.build_frame(60, b"\x01"+P.field_int(gone["pid"])+P.field_v(0)+P.field_v(0)))
        try: GUILDES.deconnexion(gone["pid"])
        except Exception as e: log(f"    (guilde : {e})")
    try: quitter_spectateur(conn)
    except Exception as e: log(f"    (depart de spectateur non annonce : {e})")
    abandonnee = GAMES.pop(id(conn), None)
    if abandonnee is not None and gone:
        try: partie_abandonnee(abandonnee, conn, gone)
        except Exception as e: log(f"    (abandon de partie : {e})")
    if abandonnee is not None and not any(g is abandonnee for g in GAMES.values()):
        try:
            fin_pour_spectateurs(abandonnee, 1, gone["pid"] if gone else None)
            annoncer_fin_partie(abandonnee, [conn], terminee=False)      # plus aucun joueur : « - / - »
        except Exception as e: log(f"    (fin de partie non annoncee : {e})")
    SESSIONS.pop(id(conn), None); conn_state.pop(id(conn), None)
    conn.close()

conn_state = {}
GAMES = {}   # id(conn) -> partie en cours
NEXT_MADE = 814           # numero de partie courant (le 1er duel = 814, comme la capture)
_MADE_LOCK = threading.Lock()
def next_made():
    """Numero de partie unique et croissant (evite les collisions d'identifiants)."""
    global NEXT_MADE
    with _MADE_LOCK:
        m = NEXT_MADE; NEXT_MADE += 1
        return m

def parse_typed(payload):
    """Decoupe une charge utile 'octet de contexte + champs types' en liste.
    Retourne [('ctx',n), ('int',v), ('i32',v), ('h16',v), ('v',n), ('b',n), ('str',s), ...].
    Robuste : gere le tag d'entier (0x03) contrairement a l'ancien payload[1:5]."""
    out=[]; i=0; n=len(payload)
    if n:
        out.append(("ctx", payload[0])); i=1   # ces trames commencent toujours par 1 octet de contexte
    while i < n:
        t=payload[i]
        try:
            if t==0x01: s,i=P.decode_string(payload,i); out.append(("str",s)); continue
            if t==0x03: out.append(("int",struct.unpack_from("<I",payload,i+1)[0])); i+=5; continue
            if t==0x02: out.append(("i32",struct.unpack_from("<I",payload,i+1)[0])); i+=5; continue
            if t==0x04: out.append(("h16",struct.unpack_from("<H",payload,i+1)[0])); i+=3; continue
            if t==0x05: out.append(("v",payload[i+1])); i+=2; continue
            if t==0x06: out.append(("b",payload[i+1])); i+=2; continue
        except Exception:
            pass
        out.append(("raw",payload[i:])); break
    return out
# Identifiants des competences = champ Tag des boutons « + » du formulaire TfrmSkills du client, tous
# branches sur btnUpDCClick qui envoie op244 + v(Tag) :
#   btnUpDC (Souk) n'a PAS de Tag dans le DFM, donc 0 ; btnUpPU=2 Connaisseur, btnUpWG=3 Profiteur,
#   btnUpAC=4 Vente aux encheres, btnUpWE=7 Initie, btnUpLK=8 Chanceux.
SKILL_BY_ID = {0: "souk", 2: "connaisseur", 3: "profiteur", 4: "encheres", 7: "initie", 8: "chanceux"}

# Opcode de NIVEAU (S->C, categorie 1, « 01 05 <niveau> ») propre a chaque competence. op55 et op56 ont
# ete observes ; les quatre autres sont lus dans le binaire (py ffwtt_binaire.py --ctx 1
# --op 53 : le gestionnaire charge le nom de la competence et affiche « Capacite %s niveau %d »).
# Sans le bon opcode le client ne voit jamais le niveau monter (Initie, signale le 2026-09-19).
SKILL_LEVEL_OP = {0: 53, 2: 55, 4: 56, 3: 89, 7: 90, 8: 91}

# couts en powers par niveau (d'apres la table du jeu)
SKILL_TABLE = {
    "souk":        {"couts": [125,250,375,500,625,750], "libelle": "Souk"},
    "connaisseur": {"couts": [300,600,900],             "libelle": "Connaisseur"},
    "profiteur":   {"couts": [100,150,200,250,300,350], "libelle": "Profiteur"},
    "initie":      {"couts": [100,150,200,250,300,350], "libelle": "Initie"},
    "chanceux":    {"couts": [250,500,750,1000,1250],   "libelle": "Chanceux"},
    "encheres":    {"couts": [150,200,250],             "libelle": "Vente aux encheres"},
    "guilde":      {"couts": [2500],                    "libelle": "Guilde"},
}
COUTS_PAR_DEFAUT = [100,150,200,250,300,350]

# Effets lus dans le client (fenetre des competences, bulle « Plus d'infos », fonction 0x61C3F0) :
#   Initie, table 0x6671A4 (3 valeurs par niveau) : « Victoire : +%d%% exp ; Nul : +%d%% exp ; Defaite : +%d%% exp »
#   Vente aux encheres, tables 0x667194 / 0x667198 : « %d encheres ; Perte : %d%% du prix final »
# Avant le 2026-10-12 le serveur donnait +3,3 % d'exp par niveau d'Initie quel que soit le resultat, et ne limitait
# pas le nombre de ventes simultanees (le client annonce 1, 3 puis 5 ; erreur 31 « Vous avez deja le maximum d'encheres
# en cours »).
INITIE_BONUS = {0: (0, 0, 0), 1: (10, 0, 0), 2: (10, 10, 0), 3: (10, 10, 10),
                4: (20, 10, 10), 5: (20, 20, 10), 6: (20, 20, 20)}       # % (victoire, nul, defaite)
ENCHERES_MAX = {0: 0, 1: 1, 2: 3, 3: 5}                                  # ventes simultanees par niveau

def cout_competence(skill_id, niveau_actuel):
    """Cout du prochain niveau, ou None si le maximum est atteint."""
    nom = SKILL_BY_ID.get(skill_id)
    couts = SKILL_TABLE.get(nom, {}).get("couts", COUTS_PAR_DEFAUT)
    if niveau_actuel >= len(couts): return None, nom
    return couts[niveau_actuel], nom

# ===========================================================================
# GROUPES (op86), GRADES (op87) ET NOTORIETES (op88) — generes ici, plus rejoues de la capture.
#   op86 : int(id) str(libelle) str(cle) int(couleur) [str(fonction du panneau)]*
#          cles « $op », « $anim », « $prof » = lignes d'en-tete de la liste des joueurs ;
#          un groupe qui a des fonctions (chat, topic, joins...) possede un PANNEAU d'equipe,
#          que le client ouvre quand il recoit op177 (int groupe) — c'etait l'effet de /ident.
#   op87 : int(id) str(libelle) int(groupe) [str(permission)]*   ; le client cherche le logo
#          Images\<Serveur>_SpecCateg_<id>.png (voir ffwtt_images.py) : les pastilles 4 3 2 1.
#   op88 : int(id) str(libelle) int(seuil) : une ETOILE par categorie dont le joueur atteint le
#          seuil (lu dans le gestionnaire d'op59 : il compte les categories ou valeur >= seuil).
# ===========================================================================
_TOUT = ["viewaccount","viewhost","viewemail","viewoffinfos","global","stopgame","spygame",
         "moderatemode","notoriety","newdeck","resetaccount","warn","kick","mute","banhost",
         "bannick","banaccount","dissolveguild","viewgilsbank","generategilsbank",
         "talkwhilemoderate","editnotes","anytrade","quicknews","canflood"]
GROUPE_EQUIPE, GROUPE_OPER, GROUPE_ANIM, GROUPE_PROF, GROUPE_QUIZZ, GROUPE_ROBOT = 10, 11, 12, 13, 30, 9
GRADE_ROBOT = 102          # « Robot duelliste » (groupe 9, cle « bot »)
# Un grade PAR ROBOT, tous dans le groupe « Robot » : a grade egal, le client classe la liste par ordre ALPHABETIQUE
# (routine d'insertion 0x6379C0 : poids du grade, puis comparaison des noms ; les en-tetes de section suivent le GROUPE),
# ce qui donnait Bahamut, Chocobo, Mog, Tonberry. Avec un grade chacun, l'ordre de GRADES impose du plus fort au plus
# faible (choix de l'utilisateur, 2026-09-24), sous une seule ligne « Robot ».
GRADES_ROBOTS = {996: 102, 997: 103, 998: 104, 999: 105}       # Bahamut, Tonberry, Chocobo, Mog
# Joueurs anglophones (langue du compte, « !langue en ») : une section a eux, sous les robots, avec un petit
# drapeau pour logo (ffwtt_images). Les francophones restent SANS grade : le client range les joueurs sans grade par
# nombre d'etoiles de notoriete (lstNicksDrawItem), un grade « francophone » ferait disparaitre ces rangs d'etoiles.
GROUPE_ANGLO, GRADE_ANGLO = 40, 41
GROUPES = [
    # Fonctions du panneau : DES QU'UN DE MES GRADES appartient a un groupe qui a « joins » ou
    # « chat », les gestionnaires d'op59 / op60 / op70 du client ecrivent dans le panneau du groupe
    # SANS verifier qu'il existe (« Access violation at 0063CF31, read of 00000374 »). Le panneau
    # n'est cree que par op177 : il doit donc partir AVANT toute fiche op59 (voir la rafale).
    # Une fonction affiche l'onglet du panneau qui porte son nom (op177, 0x649FB4 : nom du composant sans « tab »,
    # en minuscules) : « topic » -> tabTopic, « gilsbank » -> tabGilsBank (qui exige en plus la permission
    # « viewgilsbank » du grade envoye par op177, voir GRADE_SALON). Les deux mots-cles ne servent nulle part ailleurs
    # dans le client (verifie le 2026-10-12) : pas de risque d'ecriture dans un panneau absent.
    (GROUPE_EQUIPE, "Salon des opérateurs", "staff", 12863488, ["chat", "joins", "topic", "gilsbank"]),
    (GROUPE_OPER,  "Opérateurs",  "$op",   255,      []),
    (GROUPE_ANIM,  "Animateurs",  "$anim", 16711680, []),
    (GROUPE_PROF,  "Enseignants", "$prof", 760886,   []),
    (GROUPE_ROBOT, "Robot", "bot", 2579545, []),               # section « Robot » de la liste : APRES l'equipe
    (GROUPE_ANGLO, "English speakers", "en", 11161630, []),   # puis les anglophones (bleu), avant les joueurs sans grade
    # Le groupe « Quizz » a son propre panneau, avec les fonctions de la capture : « quizz » affiche les onglets
    # « Questions des quizz » et « Quizz en cours » (prefixe : tabQuizz, tabQuizzCurrent), « chat » et « topic » ceux du
    # salon et du topic du groupe. Ouvert par op177 avec le grade 5 (trames_ouverture_salon), avant toute fiche op59.
    (GROUPE_QUIZZ, "Quizz",       "quizz", 8421504,  ["chat", "topic", "quizz"]),
]
# L'ORDRE COMPTE : c'est lui qui classe la liste des joueurs. Le client donne a chaque joueur un poids
# « nombre de grades - rang de son meilleur grade » (fonctions 0x635298 / 0x635330 : il parcourt les grades du
# joueur et garde celui dont l'index dans la collection des grades est le plus faible), et fait de meme avec les
# groupes (0x635374). Le premier grade defini est donc TOUT EN HAUT de la liste : les operateurs d'abord (demande
# du 2026-09-20), puis animateurs, enseignants, et seulement ensuite les robots ; les joueurs sans grade suivent.
GRADES = [
    (14, "Opérateur de niveau 4", GROUPE_OPER, _TOUT),
    (13, "Opérateur de niveau 3", GROUPE_OPER, ["viewaccount","viewhost","viewoffinfos","global","stopgame",
          "spygame","moderatemode","notoriety","newdeck","warn","kick","mute","banhost","bannick",
          "talkwhilemoderate","editnotes"]),
    (12, "Opérateur de niveau 2", GROUPE_OPER, ["viewaccount","viewoffinfos","stopgame","spygame",
          "moderatemode","warn","kick","mute","talkwhilemoderate"]),
    (11, "Opérateur de niveau 1", GROUPE_OPER, ["viewoffinfos","warn","mute","talkwhilemoderate"]),
    (21, "Animateur", GROUPE_ANIM, ["viewaccount","viewoffinfos","stopgame","spygame","moderatemode",
          "notoriety","global","quicknews","talkwhilemoderate","editnotes","anytrade"]),
    (31, "Enseignant", GROUPE_PROF, ["viewoffinfos","talkwhilemoderate"]),
    (102, "Robot extrême", GROUPE_ROBOT, ["canflood"]),       # Bahamut-Extrême : en haut de la section
    (103, "Robot difficile", GROUPE_ROBOT, ["canflood"]),     # Tonberry-Dur
    (104, "Robot moyen", GROUPE_ROBOT, ["canflood"]),         # Chocobo-Moyen
    (105, "Robot facile", GROUPE_ROBOT, ["canflood"]),        # Mog-Facile : en bas
    (GRADE_ANGLO, "English speaker", GROUPE_ANGLO, []),
    (3,  "Membre du salon des opérateurs", GROUPE_EQUIPE, ["viewgilsbank"]),   # l'onglet Caisse du panneau
    (5,  "Responsable des quizz", GROUPE_QUIZZ, ["talkwhilemoderate","viewoffinfos"]),
]
# niveau d'administration du compte (0-4) -> grade d'operateur
NIVEAU_VERS_GRADE = {1: 11, 2: 12, 3: 13, 4: 14}
GRADE_QUIZZ = 5           # « Responsable des quizz » (groupe GROUPE_QUIZZ) : le panneau Quizz
NIVEAU_QUIZZ = 3          # operateurs qui pilotent le quizz (comme les animateurs), panneau ou commande !quiz
# categories de notoriete : (id, libelle, seuil de l'etoile = maximum du curseur d'edition).
# Les VALEURS des fiches sont positionnelles (la i-eme valeur va a la i-eme categorie recue : le
# gestionnaire d'op59 lit « Count » valeurs et prend la categorie par son rang) ; l'id ne sert qu'au
# nom du logo (Images/<Serveur>_Notoriety_<id>.png). Il commence a 1 : une image d'identifiant 0 est ignoree.
NOTORIETES = [(1, "Tournois", 1000), (2, "Animations", 1000), (3, "Quizz", 1000),
              (4, "Duels", 1000), (5, "Fair-play", 1000), (6, "Entraide", 1000)]
NOTO_QUIZZ, NOTO_DUELS = 2, 3          # RANGS (et non ids) dans la liste ci-dessus

def grades_de(niveau, anim=False, langue="fr"):
    """Tous les grades d'un compte : operateur (+ salon), animateur, responsable des quizz, anglophone.
    Chaque grade donne au joueur lui-meme passe par op61, et le client ecrit a chaque fois « *** X est maintenant
    un(e) <grade> » dans le chat (gestionnaire 0x63D825 : affichage inconditionnel, rien dans la trame ne permet
    de le taire). On ne donne donc que les grades utiles : un operateur de niveau 4 a deja toutes les permissions
    de l'animateur, il ne recoit pas son grade. Le grade 5 « Responsable des quizz », lui, ouvre le panneau Quizz : les
    trames du panneau ne passent que par un grade du groupe Quizz (voir react_quizz). Animateurs et operateurs de
    niveau 3 et 4 le recoivent, UNE fois : chaque grade d'un groupe a « quizz » fait traiter les trames du panneau
    une fois de plus par le client (categories et questions en double)."""
    g = []
    if NIVEAU_VERS_GRADE.get(niveau): g.append(NIVEAU_VERS_GRADE[niveau])
    if niveau: g.append(3)
    if anim: g.append(21)
    if anim or niveau >= NIVEAU_QUIZZ: g.append(GRADE_QUIZZ)
    if langue == "en": g.append(GRADE_ANGLO)      # un operateur anglophone reste range chez les operateurs (meilleur rang)
    return g

# Libelles pour les comptes anglophones : le serveur envoie groupes, grades et categories de notoriete a CHAQUE entree au
# salon, donc chacun peut les recevoir dans sa langue (le client ne s'en sert que pour l'affichage ; logos et
# classement suivent les identifiants).
GROUPES_EN = {GROUPE_EQUIPE: "Operators' lounge", GROUPE_OPER: "Operators", GROUPE_ANIM: "Event hosts",
              GROUPE_PROF: "Teachers", GROUPE_ROBOT: "Robots", GROUPE_QUIZZ: "Quiz"}
GRADES_EN = {14: "Level 4 operator", 13: "Level 3 operator", 12: "Level 2 operator", 11: "Level 1 operator",
             21: "Event host", 31: "Teacher", 102: "Extreme robot", 103: "Hard robot", 104: "Medium robot", 105: "Easy robot", 3: "Operators' lounge member", 5: "Quiz master"}
NOTORIETES_EN = {1: "Tournaments", 2: "Events", 3: "Quiz", 4: "Duels", 5: "Fair play", 6: "Helpfulness"}

def groupe_frames(langue="fr"):
    out = []
    for gid, libelle, cle, couleur, fonctions in GROUPES:
        if langue == "en": libelle = GROUPES_EN.get(gid, libelle)
        pl = bytes([1]) + P.field_int(gid) + P.field_str(libelle) + P.field_str(cle) + P.field_int(couleur)
        for f in fonctions: pl += P.field_str(f)
        out.append(P.build_frame(86, pl))
    return out

def grade_frames(langue="fr"):
    """Trames op87 : definition des grades et de leurs permissions."""
    out=[]
    for gid, libelle, groupe, perms in GRADES:
        if langue == "en": libelle = GRADES_EN.get(gid, libelle)
        pl = bytes([1]) + P.field_int(gid) + P.field_str(libelle) + P.field_int(groupe)
        for p in perms: pl += P.field_str(p)
        out.append(P.build_frame(87, pl))
    return out

def notoriete_frames(langue="fr"):
    return [P.build_frame(88, bytes([1]) + P.field_int(i)
                          + P.field_str(NOTORIETES_EN.get(i, nom) if langue == "en" else nom) + P.field_int(seuil))
            for i, nom, seuil in NOTORIETES]

# Niveaux d'administration (le client ne les connait pas : c'est le serveur qui decide)
NIVEAUX_ADMIN = {0: "Joueur", 1: "Operateur niv. 1", 2: "Operateur niv. 2", 3: "Operateur niv. 3", 4: "Operateur niv. 4"}
# Les droits de chaque commande viennent des PERMISSIONS du grade (GRADES ci-dessus), les memes
# que celles envoyees au client dans op87 : voir ADMIN_CMDS / react_admin().

BASE_FERMEE = False   # True = seuls les comptes existants peuvent se connecter
ECHANGES = {}      # id joueur -> id du partenaire d'echange
_VERROU_ECHANGES = threading.Lock()   # la conclusion d'un echange n'a lieu qu'une fois, meme si les deux valident ensemble

# Regle du jeu d'origine, lue dans la table des erreurs du client (py ffwtt_binaire.py --erreurs) :
#   101 « Vous devez posseder plus de 10 cartes pour effectuer cette action »
#   105 « ... il doit vous en rester plus de 10 apres l'echange »      46 « pas assez de cartes disponibles
#   [...] depend de toutes vos actions en cours (encheres, echanges...) »      14 « pas assez de gils »
# Sans elle un joueur pouvait sacrifier (ou vendre, ou donner) toutes ses cartes et ne plus pouvoir jouer.
MIN_CARTES = 10
# Boutons de la fenetre « Mes cartes » (op66 + v(Tag du bouton), lu dans le DFM de TfrmMyCards).
JETER, POWERS, ACHETER, VENDRE = 0, 1, 2, 3
ACTIONS_CARTE = {JETER: "jeter", POWERS: "sacrifice", ACHETER: "achat", VENDRE: "vente"}
# Vente : 15 % du prix, arrondi. LU DANS LE CLIENT (2026-09-24) : la fenetre « Mes cartes » affiche « Vente : %d (%d%% achat) »
# avec Round(prix x 0,15) et « 15 » (0x655740-0x6557A2). L'ancien 10 % venait du changelog (« entre 10 et 25 % suivant
# Sentier », competence disparue en 3.3) : le joueur voyait un montant et en recevait un autre.
TAUX_VENTE = 0.15
MAX_EXEMPLAIRES = 255      # code 15 « Vous ne pouvez posseder plus de 255 exemplaires d'une meme carte ! »
# Regle d'origine (changelog, build 5448 : « 200 points d'experience sont maintenant necessaires pour vendre / jeter /
# transformer une carte en powers / faire un echange / creer une enchere » ; l'experience est multipliee par 10 en 3.3) :
# codes 99 « Vous devez posseder 2000 points d'experience au minimum pour effectuer cette action » et 100 (« %s doit... »).
EXP_MIN_ACTIONS = 2000

def experience(pseudo_db):
    return (db.get_stats(pseudo_db) or {}).get("noto", 0)

def cartes_aux_encheres(pseudo_db, card_id=None):
    """Nombre de cartes de ce pseudo en vente (toutes, ou d'un seul identifiant) : elles restent dans sa
    collection jusqu'a la conclusion de la vente, mais ne sont plus disponibles."""
    stock = db.stock_id(pseudo_db)             # toutes les ventes du COMPTE : ses pseudos partagent la meme collection
    return sum(1 for a in db.list_auctions()
               if db.stock_id(a["seller_pseudo"]) == stock and (card_id is None or a["card_id"] == card_id))

def cartes_en_partie(pseudo_db, card_id=None):
    """Cartes du compte engagees dans une partie A ENJEU en cours, ou dont le vainqueur n'a pas encore choisi ses gains.
    Le perdant les vendait, les sacrifiait ou les echangeait pendant la partie, et le transfert ne trouvait plus rien
    a prendre (audit du 2026-10-21) : elles ne sont plus disponibles jusqu'a la fin."""
    stock = db.stock_id(pseudo_db)
    parties = {id(g): g for g in list(GAMES.values()) if isinstance(g, G.PvpGame)}
    with _VERROU_CHOIX:
        parties.update((id(e["game"]), e["game"]) for e in CHOIX_EN_COURS.values())
    n = 0
    for g in parties.values():
        if getattr(g, "winner_rule", 0) not in REGLES_ENJEU: continue
        for cote in (0, 1):
            if db.stock_id(g.pids[cote] - 1000) == stock:
                n += sum(1 for c in g.main_de(cote) if card_id is None or c == card_id)
    return n

def cartes_disponibles(pseudo_db, card_id=None):
    """Cartes possedees, moins celles qui sont aux encheres ou engagees dans une partie a enjeu."""
    if card_id is None: return db.nb_cartes(pseudo_db) - cartes_aux_encheres(pseudo_db) - cartes_en_partie(pseudo_db)
    qte = next((c["qty"] for c in db.get_collection(pseudo_db) if c["card_id"] == card_id), 0)
    return qte - cartes_aux_encheres(pseudo_db, card_id) - cartes_en_partie(pseudo_db, card_id)

def collection_disponible(pseudo_db):
    """La collection sans les exemplaires mis aux encheres : seuls ceux-la peuvent entrer dans une main de duel (une
    carte vendue pendant la partie ne pouvait plus etre prise par le vainqueur)."""
    stock = db.stock_id(pseudo_db)
    ventes = {}
    for a in db.list_auctions():
        if db.stock_id(a["seller_pseudo"]) == stock: ventes[a["card_id"]] = ventes.get(a["card_id"], 0) + 1
    out = []
    for c in (db.get_collection(pseudo_db) or []):
        c = dict(c); q = (c.get("qty") or 1) - ventes.get(c["card_id"], 0)
        if q > 0: c["qty"] = q; out.append(c)
    return out

# ---------- anti-flood, joueurs muets (audit du 2026-10-21) ----------
# Envois au plus par connexion : (nombre, fenetre en secondes). Au-dela, l'envoi est ignore (journalise). La permission
# « canflood » de l'equipe en dispense : elle n'etait jusqu'ici qu'envoyee au client, jamais appliquee.
FLOOD = {"chat": (8, 10), "mp": (8, 10), "partie": (8, 10), "guilde": (8, 10), "defi": (8, 10), "echange": (8, 10)}
LONGUEUR_MAX_MESSAGE = 1000      # un message de 64 Ko etait relaye tel quel a chaque joueur

def trop_vite(sess, canal):
    if "canflood" in permissions_de(sess): return False
    n, duree = FLOOD[canal]
    maintenant = time.time()
    recents = [t for t in sess.setdefault("debit", {}).get(canal, []) if maintenant - t < duree]
    trop = len(recents) >= n
    if not trop: recents.append(maintenant)
    sess["debit"][canal] = recents
    return trop

def pids_du_compte(pid):
    """Les identifiants reseau de tous les pseudos du compte de `pid` (lui seul si le compte est introuvable)."""
    acc = db.account_of_pseudo(pid - 1000) if pid > 1000 else None
    return {1000 + p["id"] for p in db.get_pseudos(acc["id"])} if acc else {pid}

def filtrer_message(conn, sess, moi, msg, canal):
    """Le message a relayer (tronque a LONGUEUR_MAX_MESSAGE), ou None : joueur muet ou envois trop rapproches. Vaut pour
    le salon, les messages prives, le chat de partie et celui de guilde (rendre muet ne visait que le salon)."""
    if moi["id"] in MUTED:
        sys_notice(conn, "Vous etes actuellement rendu muet.", "You are currently muted."); return None
    if trop_vite(sess, canal):
        log(f"    ({canal} : message de {moi['name']} ignore, envois trop rapproches)"); return None
    return msg[:LONGUEUR_MAX_MESSAGE]

# ---------- identification : essais et creations limites (audit du 2026-10-21) ----------
ESSAIS_MAX, ESSAIS_IP_MAX, ESSAIS_FENETRE = 5, 30, 600    # mots de passe refuses : par compte et adresse, par adresse
CREATIONS_MAX = int(os.environ.get("FFWTT_CREATIONS_PAR_IP") or 5)   # comptes crees EN JEU par adresse et par heure
CREATIONS_FENETRE = 3600
ECHECS_CONNEXION = {}        # (ip, compte) et (ip, None) -> instants des refus de mot de passe
CREATIONS_COMPTES = {}       # ip -> instants des creations de compte en jeu
_VERROU_CONNEXION = threading.Lock()   # verification « compte deja connecte » et ouverture de session d'un seul tenant

def _recents(table, cle, fenetre):
    maintenant = time.time()
    if len(table) > 5000:                                   # menage : une adresse qui essaie mille noms n'occupe rien
        for k in [k for k, v in table.items() if not v or maintenant - v[-1] > fenetre]: table.pop(k, None)
    t = [x for x in table.get(cle, []) if maintenant - x < fenetre]
    if t: table[cle] = t
    else: table.pop(cle, None)
    return t
SPECTATEURS = {}   # game_id -> liste de connexions qui regardent
PENDING = {}   # room -> defi en attente d'acceptation
RULES = {"identique":False,"plus":False,"mur_meme":False,"mur_add":False,"combo":True}
# Index du menu « Temps par coup » -> secondes. C'est la table du CLIENT (binaire, 0x66729C :
# 15, 30, 45, 60, 90, 120, 180, 300) ; la capture confirme l'index 0 = 15 s (op139 ... 040f00).
TIMER_SECONDS = {0:15, 1:30, 2:45, 3:60, 4:90, 5:120, 6:180, 7:300}
# REGLES DU VAINQUEUR. L'ordre est celui du CLIENT (liste de TfrmRules.FormCreate et fonction 0x638BF8 qui
# transforme l'indice en libelle) : il etait faux ici (Entrainement et Totale inverses, entre autres), donc une
# partie « Entrainement » comptait dans les statistiques et une partie « Totale » n'y comptait pas.
WINNER_RULES = {0: "Entrainement", 1: "Aucune", 2: "One", 3: "Two", 4: "Three", 5: "Four",
                6: "Totale", 7: "Directe", 8: "Change", 9: "Aleatoire"}
ENTRAINEMENT, AUCUNE, TOTALE, DIRECTE, CHANGE, ALEATOIRE = 0, 1, 6, 7, 8, 9
# Combien de cartes le vainqueur choisit dans la main du perdant (One a Four) ; Totale les prend toutes.
CHOIX_CARTES = {2: 1, 3: 2, 4: 3, 5: 4}
REGLES_ENJEU = set(CHOIX_CARTES) | {TOTALE, DIRECTE, CHANGE, ALEATOIRE}
# « Un certain nombre d'experience est maintenant requis pour utiliser chaque regle du vainqueur » (journal des
# versions du jeu, build 5620) ; les seuils exacts sont perdus : le client ne les contient pas (sa fenetre des regles,
# TfrmRules.FormCreate 0x6226DC, propose les dix regles sans condition, et ses refus 107 / 108 ne portent aucun nombre,
# verifie le 2026-10-22). Seuils fixes par l'administrateur du serveur le 2026-10-22 : One 1000, Two 2000, Three 3000,
# Four 4000, Totale 5000, Directe, Change et Aleatoire 1000 (Entrainement et Aucune : aucun).
# Refus : op33 b0 v107 (moi) ou v108 (l'adversaire).
EXP_REGLE = {2: 1000, 3: 2000, 4: 3000, 5: 4000, TOTALE: 5000, DIRECTE: 1000, CHANGE: 1000, ALEATOIRE: 1000}
DELAI_CHOIX = 90          # secondes laissees au vainqueur pour choisir ses gains
CLIENTS = {}    # id(conn) -> {"conn":..., "pid":..., "name":...}  (joueurs en ligne)
ACCUEIL_URL = ""    # URL d'accueil (op81) ; VIDE par defaut : evite l'ecran de CGU du client
MOTD = []           # lignes de message d'accueil (op166) ; vide par defaut
MOTD_EN = []        # sa version anglaise (motd_en.txt), pour les comptes anglophones
FICHIER_MOTD = "motd.txt"
CLIENTS_LOCK = threading.Lock()

ICONE_TEST = None     # si defini, force le champ "statut"

def player_entry(pid, name, status=1, niveau=0, anim=False, langue="fr"):
    """Trame op59 : une entree dans la liste des joueurs.
    'status' et 'niveau' sont les deux champs candidats pour l'icone de grade."""
    if ICONE_TEST is not None: status = ICONE_TEST
    guilde = GUILDES.guilde_du_joueur(pid - 1000) if pid > 1000 else 0       # 5e champ : la guilde du joueur
    pl = (b"\x01" + P.field_int(pid) + P.field_str(name) + P.field_str("")
        + P.field_byte(status) + P.field_int(guilde) + P.field_int(0)
        + P.field_str("") + P.field_str("") + P.field_int(1700000000)
        + b"".join(_i16(n) for n in (db.get_notos(pid - 1000) if pid > 1000 else [50]*6)))
    for grade in grades_de(niveau, anim, langue):   # chaque grade place le joueur dans son groupe
        pl += P.field_v(grade)
    return P.build_frame(59, pl)

def fiche_robot(pid):
    """op59 d'un robot : meme disposition que la fiche du robot de la capture, plus son grade (section Robot)."""
    pl = (b"\x01" + P.field_int(pid) + P.field_str(G.ROBOTS[pid]["nom"]) + P.field_str("")
        + P.field_byte(1) + P.field_int(0) + P.field_int(0)
        + P.field_str("") + P.field_str("") + P.field_int(1700000000)
        + b"".join(_i16(50) for _ in range(6)) + P.field_v(GRADES_ROBOTS.get(pid, GRADE_ROBOT)))
    return P.build_frame(59, pl)

def fiches_robots():
    return [fiche_robot(pid) for pid in sorted(G.ROBOTS, reverse=True)]      # 999 Facile ... 996 Extreme

def grade_joueur_frame(pid, grade):
    """op61 : « le joueur <pid> recoit le grade <grade> ».  01 | int(pid) | v(grade).
    DEDUIT DU BINAIRE DU CLIENT, jamais capture : le gestionnaire (cas 0x13D du repartiteur,
    adresse 0x63D825) lit champ 1 -> Users.Find(pid), champ 2 -> Grades.Find(id), puis fait
    Joueur.Grades.Add(grade) et compare le joueur a « moi ». C'est le seul moyen de donner un
    grade au joueur LUI-MEME : op59 cree toujours une nouvelle fiche (doublon dans la liste),
    et « moi » n'est cree que par op45. Les champs sont lus comme des variants (v ou int)."""
    return P.build_frame(61, b"\x01" + P.field_int(pid) + P.field_v(grade))

def defi_ferme(pid, refuse=False, code=None):
    """op36 « defi refuse » : 03 | int(l'autre joueur) | b0 | b(message) [| v(code d'erreur)]. Lu dans le gestionnaire
    du client (cas 804, branche b0, 0x643557 ; jamais capture) : il referme la fenetre de defi ouverte avec ce joueur,
    puis rien (b0), « %s a refuse votre defi » (b1), ou le message de l'erreur (b1 + code)."""
    pl = b"\x03" + P.field_int(pid) + P.field_byte(0) + P.field_byte(1 if (refuse or code) else 0)
    if code: pl += P.field_v(code)
    return P.build_frame(36, pl)

def echange_annule_frame(pid_partenaire, parti=False):
    """op97 d'ECHEC d'echange.  Reussite = 02 | int(partenaire) | b1.
    Echec : 02 | int(partenaire) | b0  -> le client affiche « X a refuse ou annule l'echange ».
    S'il y a PLUS de 3 champs, il affiche en plus l'erreur du 4e (lu dans le binaire, cas 609 :
    « FieldCount > 3 »). Capture, partenaire deconnecte : b0 | b1 | v(24) -> parti=True.
    Ne PAS utiliser op60 ici : op60 = « X a quitte le FFWTT » (retire le joueur de la liste)."""
    fin = P.field_byte(1)+P.field_v(24) if parti else b""
    return P.build_frame(97, b"\x02"+P.field_int(pid_partenaire)+P.field_byte(0)+fin)

def couper(c):
    """Ferme une connexion qui ne lit plus ce qu'on lui envoie : son fil la retire ensuite du salon."""
    try: c.shutdown(socket.SHUT_RDWR)
    except OSError: pass

def broadcast(frame, exclude_conn=None):
    """Envoie une trame a tous les clients en ligne (sauf exclu). Un client qui ne lit plus (1 s d'attente : delai des
    sockets) est deconnecte : sans cela chacun retardait d'une seconde chaque diffusion, pour tous les joueurs."""
    with CLIENTS_LOCK:
        targets=[c["conn"] for c in CLIENTS.values() if c["conn"] is not exclude_conn]
    for c in targets:
        try: c.sendall(frame)
        except socket.timeout: couper(c)
        except OSError: pass

def find_client(pid):
    with CLIENTS_LOCK:
        for c in CLIENTS.values():
            if c["pid"]==pid: return c
    return None

def _clients():
    with CLIENTS_LOCK: return list(CLIENTS.values())

# Les guildes (ffwtt_guildes.py) : formats lus dans le binaire du client, voir la spec § Guildes.
GUILDES = GU.Guildes(clients=_clients, find_client=lambda pid: find_client(pid),
                     broadcast=lambda trame, exclude_conn=None: broadcast(trame, exclude_conn),
                     log=lambda texte: log(texte), sess=lambda conn: _sess(conn),
                     annoncer_gils=lambda conn, compte: annoncer_gils(conn, compte),
                     permissions=lambda sess: permissions_de(sess),
                     filtre_chat=lambda conn, sess, moi, msg: filtrer_message(conn, sess, moi, msg, "guilde"))

SESSIONS = {}   # id(conn) -> etat de session (par connexion)
def _sess(conn):
    return SESSIONS.setdefault(id(conn), {
        "pseudo": {"name": "Joueur", "id": 310, "db_id": None},
        "account_id": None, "admin": 0, "gils": 0, "power_mode": False, "conn": conn})

def session_du_compte(account_id, sauf=None):
    """La connexion deja ouverte sur ce compte (hors `sauf`), s'il y en a une qui repond encore. Une connexion morte
    (jeu plante, reseau coupe) est fermee au passage : son fil la nettoie, et le compte n'est pas bloque."""
    for k, s in list(SESSIONS.items()):
        c = s.get("conn")
        if k == id(sauf) or c is None or s.get("account_id") != account_id: continue
        try:
            c.sendall(P.build_frame(512, b"\x00"))                  # le ping habituel : le client y repond par op768
            return c
        except OSError:
            try: c.close()
            except OSError: pass
    return None
MUTED = set()  # joueurs rendus muets
BANNED = set() # pseudos bannis
ROOM_BURST = b""

# ENCHERES DES ROBOTS (demande de l'utilisateur, 2026-09-24). Chaque robot tient en permanence 3 cartes aux encheres,
# tirees dans les niveaux de sa main (Mog 1-3, Chocobo 3-6, Tonberry 5-8, Bahamut 8-10, hors deck Special), a -10 % du
# prix de la boutique, mise de depart comprise (75 % au depart : -25 % pour qui l'emportait seul, « trop » pour
# l'utilisateur, 2026-09-24). Quand une de ses encheres se termine (vendue, expiree
# sans preneur, retiree par un operateur), une autre carte la remplace. Le robot n'a ni compte ni collection : stock
# infini, il n'encaisse rien. Son enchere porte comme vendeur « pid - 1000 » (996..999 -> -4..-1) : sur le fil, op190
# donne l'identifiant du robot, qui est dans la liste des joueurs de chacun (fiches avant op62).
ENCHERES_PAR_ROBOT = 3
ROBOT_REMISE = 0.10           # achat immediat = prix boutique - 10 %
ROBOT_DEPART = 0.90           # mise de depart = le meme prix : la carte ne part jamais a moins de -10 %
ROBOT_DUREE = 30000           # secondes, comme les encheres des joueurs (db.create_auction)
ROBOTS_ENCHERES_VERROU = threading.Lock()

def prix_robot(cid):
    """(mise de depart, achat immediat) d'une carte vendue par un robot."""
    prix = db.ref_price(cid) or 100
    immediat = max(1, round(prix * (1 - ROBOT_REMISE)))
    return max(1, min(immediat, round(prix * ROBOT_DEPART))), immediat

def realigner_encheres_robots():
    """Au demarrage : les encheres de robot sans mise reprennent les prix des reglages actuels (meme carte)."""
    # prix calcules HORS du verrou de la base : prix_robot -> db.ref_price le reprend (verrou non reentrant : le serveur
    # restait bloque au demarrage des qu'une enchere de robot existait)
    with db._lock, db._conn() as c:
        a_revoir = [(r["id"], r["card_id"]) for r in
                    c.execute("SELECT id, card_id FROM auctions WHERE seller_pseudo<0 AND actif=1 AND meilleure_offre=0")]
    nouveaux = [prix_robot(cid) + (aid,) for aid, cid in a_revoir]
    with db._lock, db._conn() as c:
        c.executemany("UPDATE auctions SET prix_depart=?, achat_immediat=? WHERE id=?", nouveaux)

def encheres_des_robots(diffuser=True):
    """Complete les encheres des robots (3 chacun). diffuser : envoie les nouvelles fiches (op190) aux joueurs en ligne."""
    with ROBOTS_ENCHERES_VERROU:
        actives = db.list_auctions()
        for pid, r in G.ROBOTS.items():
            vendeur = pid - 1000
            deja = {a["card_id"] for a in actives if a["seller_pseudo"] == vendeur}
            for _ in range(ENCHERES_PAR_ROBOT - len(deja)):
                tirage = [c["card_id"] for c in db.sample_ref(8, *r["niveaux"]) if c["card_id"] not in deja]
                if not tirage: break
                cid = tirage[0]; deja.add(cid)
                depart, immediat = prix_robot(cid)
                aid = db.create_auction(vendeur, r["nom"], cid, depart, immediat, ROBOT_DUREE)
                if diffuser: broadcast(auction_frame(db.get_auction(aid)))
                log(f"    ENCHERE #{aid} du robot {r['nom']} : carte {cid} (depart {depart}, immediat {immediat}, "
                    f"boutique {db.ref_price(cid)})")

def surveiller_encheres():
    """Cloture les encheres expirees : la carte va au meilleur offrant, le vendeur encaisse."""
    import time as _t
    while True:
        _t.sleep(20)
        try:
            for a in db.list_auctions():
                if a["fin"] > _t.time(): continue
                aid = a["id"]
                if not db.close_auction(aid): continue        # deja close (achat immediat, annulation) : rien a livrer
                a = db.get_auction(aid) or a                  # la meilleure offre au moment de la cloture
                gagnant = a["meilleur_offrant"]; montant = a["meilleure_offre"]
                if gagnant and montant and a["seller_pseudo"] > 0 and not db.remove_card(a["seller_pseudo"], a["card_id"]):
                    # le vendeur n'a plus la carte (echangee, perdue...) : la mise est rendue, rien n'est livre (la carte
                    # etait donnee quand meme : un exemplaire de plus, audit du 2026-10-21)
                    _acc_g = _acc_of(gagnant)
                    if _acc_g: db.add_gils(_acc_g, montant)
                    log(f"    ENCHERE #{aid} annulee : le vendeur n'a plus la carte {a['card_id']}, mise rendue")
                elif gagnant and montant:
                    # commission selon le niveau de la competence "Vente aux encheres"
                    niv = db.get_skill_level(a["seller_pseudo"], 4)
                    taux = {0: 0.10, 1: 0.10, 2: 0.05, 3: 0.0}.get(niv, 0.10)
                    net = int(montant * (1 - taux))
                    db.add_card(gagnant, a["card_id"])
                    with db._conn() as c:
                        r=c.execute("SELECT account_id FROM pseudos WHERE id=?", (a["seller_pseudo"],)).fetchone()
                    if r: db.add_gils(r["account_id"], net)
                    log(f"    ENCHERE #{aid} adjugee : carte {a['card_id']} pour {montant} gils "
                        f"(vendeur net {net}, commission {int(taux*100)}%)")
                    acheteur = find_client(1000 + gagnant)
                    if acheteur:
                        acheteur["conn"].sendall(P.build_frame(63, b"\x01"+P.field_byte(1)
                            +_i16(a["card_id"])+P.field_v(1)+P.field_int(0)))
                        acheteur["conn"].sendall(build_collection_frame(db.get_collection(gagnant), acheteur["conn"]))
                        sys_notice(acheteur["conn"], f"Enchere remportee : carte {a['card_id']} pour {montant} gils.",
                                   f"Auction won: card {a['card_id']} for {montant} gils.")
                    vendeur = find_client(1000 + a["seller_pseudo"])
                    if vendeur:
                        vendeur["conn"].sendall(P.build_frame(63, b"\x01"+P.field_byte(0)
                            +_i16(a["card_id"])+P.field_v(1)+P.field_int(0)))
                        if r:
                            _sv = db.get_account(r["account_id"]) or {}
                            vendeur["conn"].sendall(P.build_frame(47, b"\x01"+P.field_int(_sv.get("gils",0))))
                        sys_notice(vendeur["conn"], f"Ta carte {a['card_id']} est vendue {montant} gils (net {net}).",
                                   f"Your card {a['card_id']} was sold for {montant} gils (net {net}).")
                else:
                    # personne n'a mise : rien a faire, la carte n'avait pas quitte la collection
                    log(f"    ENCHERE #{aid} expiree sans offre (carte {a['card_id']} conservee)")
                broadcast(P.build_frame(196, b"\x02"+_i32(aid)))
            encheres_des_robots()                 # une enchere de robot terminee (ou retiree) : une autre carte la remplace
        except Exception as e:
            log(f"    !! surveillance des encheres : {e}")

def motd_de(conn):
    """Le message d'accueil dans la langue du compte (l'anglais s'il existe, sinon le francais)."""
    return (MOTD_EN or MOTD) if langue_de(conn) == "en" else MOTD

def fichier_anglais(chemin):
    """La version anglaise d'un fichier de texte : motd.txt -> motd_en.txt (message d'accueil des anglophones)."""
    base, ext = os.path.splitext(chemin)
    return base + "_en" + ext

def charger_motd(chemin="motd.txt"):
    """Lit le message d'accueil (une ligne = une ligne affichee dans le chat), et sa version anglaise (motd_en.txt :
    comptes anglophones ; absente ou vide, ils recoivent la version francaise)."""
    global MOTD, MOTD_EN
    try:
        with open(fichier_anglais(chemin), encoding="utf-8") as f:
            MOTD_EN = [l.rstrip("\n") for l in f if l.strip()]
    except OSError: MOTD_EN = []
    try:
        with open(chemin, encoding="utf-8") as f:
            MOTD = [l.rstrip("\n") for l in f if l.strip()]
        log(f"    Message d'accueil : {len(MOTD)} ligne(s) depuis {chemin}")
    except OSError:
        # premier lancement : on cree un exemple
        exemple = ["Bienvenue sur ce serveur FFWTT prive !",
                   "Personne en ligne ? Quatre robots sont la pour jouer : Mog-Facile, Chocobo-Moyen, Tonberry-Dur et "
                   "Bahamut-Extrême, section Robot de la liste des joueurs. Defie-les avec les regles de ton choix : "
                   "plus le robot est fort, plus la victoire rapporte (tape !robots).",
                   "Tape !aide pour voir les commandes disponibles.",
                   "Bon jeu."]
        try:
            with open(chemin, "w", encoding="utf-8") as f:
                f.write("\n".join(exemple) + "\n")
            MOTD = exemple
            log(f"    Message d'accueil : {chemin} cree avec un exemple")
        except OSError:
            MOTD = []

# Rafale d'entree en salon GENEREE (2026-10-13). Elle etait rejouee depuis room_burst_neutral.bin, derivee d'une
# capture ; tout ce que le serveur n'y remplacait pas est ecrit ici, dans le meme ordre et a l'octet pres
# (verifie contre ce fichier). Le reste (nos groupes et grades, notoriete, guildes, compteurs, competences, fiches)
# est produit par le traitement d'op44, comme avant. Groupes 1 a 3 : les onglets de notes du profil (GROUPE_NOTES,
# cles « _notes_* ») ; 31 : un groupe de couleur. --rafale FICHIER rejoue encore une capture, pour comparer.
GROUPES_TECHNIQUES = [(1, "Publiques", "_notes_publiques", 10027263), (2, "de développement", "_notes_maj", 2475592),
                      (3, "Quicknews", "_notes_quicknews", 3650999), (31, "ColorGroup", "_colorgroup_31", 16777215)]
OPS_COMPETENCES = (53, 55, 89, 90, 56, 91)          # niveaux des competences, dans l'ordre de la capture

def rafale_generee():
    def f(op, pl=b""): return P.build_frame(op, bytes([1]) + pl)
    out = [f(86, P.field_int(g) + P.field_str(lib) + P.field_str(cle) + P.field_int(coul))
           for g, lib, cle, coul in GROUPES_TECHNIQUES]
    out.append(f(88))                                            # -> notoriete_frames()
    out.append(f(74))                                            # -> GUILDES.liste()
    out += [f(op, P.field_int(0)) for op in range(46, 52)]       # compteurs -> valeurs du joueur
    out += [f(op, P.field_v(0)) for op in OPS_COMPETENCES]       # niveau 0 tant que le joueur n'a pas la competence
    out.append(f(83, b"".join(_i16(0) for _ in range(6))))       # -> notorietes du joueur
    out.append(f(62))                                            # fin de liste : reecrite apres les fiches
    return b"".join(out)

def charger_rafale(chemin=""):
    global ROOM_BURST
    if not chemin:
        ROOM_BURST = rafale_generee()
        return
    try:
        ROOM_BURST = open(chemin,"rb").read()
        log(f"    Rafale d'entree rejouee : {chemin} ({len(ROOM_BURST)} octets)")
    except OSError:
        ROOM_BURST = rafale_generee()
        log(f"    !! rafale introuvable : {chemin} (rafale generee a la place)")

def keepalive(conn):
    try:
        while True:
            time.sleep(10)
            conn.sendall(P.build_frame(512, b"\x00"))   # ping serveur
    except OSError:
        pass


def build_profile(name, exp=0, gils=0, powers=0, wins=0, losses=0, draws=0, quits=0, elo=None,
                  pid=310, compte=0, cartes=0, note="", collection=None,
                  guilde=0, titre="", login=None, host="", email="", cree=1600000000, compte_cree=None):
    """Trame op65 (profil) — ordre des champs cale sur le client. Champs 4 a 11 lus dans son gestionnaire (0x63E3F9) :
    int(id de compte), int(guilde : cherchee dans la liste des guildes, nom et logo affiches), str(titre dans la guilde),
    str(nom de compte), str(host), str(e-mail), int(« Pseudo cree », date Unix), int(« Compte cree »). Un texte VIDE
    s'affiche « (cache) » ; le nom de compte vide masque aussi l'identifiant de compte. « Connecte(e) : Oui/Non » vient de
    la presence du pid dans la liste des joueurs du client, pas d'un champ."""
    import struct as _s
    F=P.field_int; S=P.field_str; B=P.field_byte
    def h(v): return b"\x04"+_s.pack("<H", v & 0xFFFF)
    elo = elo or [50]*6            # notorietes : memes valeurs que les 6 int16 de la fiche op59
    p  = (b"\x01" + B(1) + F(pid) + S(name) + F(compte) + F(guilde) + S(titre)
          + S(name if login is None else login) + S(host) + S(email))
    p += F(cree) + F(cree if compte_cree is None else compte_cree)   # pseudo cree / compte cree
    p += F(exp) + F(gils) + F(powers) + F(wins) + F(losses) + F(draws) + F(quits) + F(0)
    p += b"".join(h(e) for e in elo) + S(note) + B(0)
    # 33 entiers de fin = onglet des cartes du profil : 32 cases « nombre de cartes de power
    # 0, 1, ... 31 » puis le POWER TOTAL de la collection. Verifie sur deux profils captures :
    # 6 cartes de powers 0,23,28,30,30,30 -> cases 0,23,28 = 1, case 30 = 3, total 141.
    hist = [0]*32; total = 0
    for c in (collection or []):
        pw = max(0, (db.ref_price(c["card_id"]) or 0)//100); q = c.get("qty", 1) or 1
        hist[min(pw, 31)] += q; total += pw*q
    for v in hist + [total]:
        p += F(v)
    return P.build_frame(65, p)

def profil_joueur(pseudo_db, sess_lecteur):
    """op65 d'un pseudo, connecte ou non (menu « Infos », et « Infos offline » / /offinfos de l'equipe), d'apres la base.
    Compte, host et e-mail ne sont donnes qu'a leur proprietaire ou a qui a la permission (viewaccount, viewhost,
    viewemail) ; sinon vides, le client affiche « (cache) ». Host : celui de la connexion en cours, sinon l'adresse
    d'inscription (aucune autre n'est conservee). Retourne None si le pseudo n'existe pas."""
    ps = db.get_pseudo_par_id(pseudo_db)
    if not ps: return None
    acc = db.get_account(ps["account_id"]) or {}
    st = db.get_stats(pseudo_db) or {}
    pid = 1000 + pseudo_db
    perms = permissions_de(sess_lecteur)
    soi = bool(acc) and sess_lecteur.get("account_id") == acc.get("id")
    cl = find_client(pid)
    host = (cl.get("host") if cl else acc.get("reg_ip")) or ""
    g, m = db.membre_de(pseudo_db)
    guilde = g["id"] if g and g.get("finalisee") else 0
    titre = ((m or {}).get("titre") or "") if guilde else ""
    return build_profile(ps["name"], exp=st.get("noto", 0), gils=acc.get("gils", 0), powers=db.get_powers(pseudo_db),
                         wins=st.get("wins", 0), losses=st.get("losses", 0), draws=st.get("draws", 0), pid=pid,
                         compte=acc.get("id", 0), note=db.get_note(pseudo_db), elo=db.get_notos(pseudo_db),
                         collection=db.get_collection(pseudo_db), guilde=guilde, titre=titre,
                         login=acc.get("login", "") if (soi or "viewaccount" in perms) else "",
                         host=host if (soi or "viewhost" in perms) else "",
                         email=(acc.get("email") or "") if (soi or "viewemail" in perms) else "",
                         cree=acc.get("created") or 1600000000)

BOT_REPLIES = [
    "Bonjour. Je suis un robot capable de mener des parties.",
    "Defie-moi pour jouer une partie de Triple Triad, avec les regles de ton choix !",
    "Nous sommes quatre : Facile, Moyen, Dur et Extreme. Plus le robot est fort, plus la victoire rapporte.",
]
BOT_REPLIES_EN = [
    "Hello. I am a robot that can play games.",
    "Challenge me to a game of Triple Triad, with the rules of your choice!",
    "There are four of us: Facile (easy), Moyen (medium), Dur (hard) and Extreme. The stronger the robot, the bigger the reward.",
]

def champ_zlib(texte):
    """Champ « x » du protocole (encodeur du client 0x5E3480) : tag 08 + longueur sur 2 octets + flux zlib.
    Vide : exactement les octets de la capture (78da000000ffff)."""
    if not texte: return bytes.fromhex("0807" + "0078da000000ffff")
    co = zlib.compressobj(9)                 # niveau 9 : meme en-tete 78da que la capture
    blob = co.compress(texte.encode("latin1", "replace")) + co.flush(zlib.Z_SYNC_FLUSH)
    return b"\x08" + struct.pack("<H", len(blob)) + blob

GROUPE_NOTES = 1     # onglet « Publiques » : la rafale d'entree declare le groupe 1 « Publiques », cle « _notes_publiques »
                     # (les onglets de notes sont des pseudo-groupes « _notes_* » : 2 « de developpement », 3 « Quicknews »)

def notes_frame(pid, texte, groupe=GROUPE_NOTES):
    """op241 : la note publique d'un joueur, dans l'onglet du profil qui porte le NOM DU GROUPE `groupe`.
    04 | int(groupe) | int(pid) | x(texte). Lu dans le client (gestionnaire 0x64F1BE : le premier entier est cherche
    dans la liste des groupes, son libelle titre l'onglet ; un groupe inconnu = lecture d'un pointeur nul). L'ancien
    nom de ce champ, « morceau », etait une supposition."""
    return P.build_frame(241, b"\x04" + P.field_int(groupe) + P.field_int(pid) + champ_zlib(texte or ""))

def build_collection_frame(collection, conn=None, max_id=None):
    """op52 : collection complete = tableau[qte par id de carte] compresse zlib. Autant de cases que de cartes connues
    du client DESTINATAIRE `conn` (sa version, op5) : 4885 pour le client d'origine, qui en copie exactement autant ;
    les cases en trop valent 0."""
    max_id = max_id or max(db.max_carte(), cartes_connues(conn) if conn is not None else 0)
    # La case i du tableau est la carte d'identifiant i + 1. Verifie sur la capture : la
    # carte 4827 (0x12db) achetee par op66/op63 occupe la case 4826 a la connexion suivante, et les
    # mains op135 (963, 2337, 2630...) correspondent aux cases 962, 2336, 2629. Avec arr[id], toute
    # la collection s'affichait decalee d'une carte et le client renvoyait id + 1 (echanges, decks).
    arr=bytearray(max_id)
    for c in collection:
        cid=c["card_id"]
        if 1<=cid<=max_id: arr[cid-1]=min(c["qty"],255)
    co=zlib.compressobj()
    blob=co.compress(bytes(arr))+co.flush(zlib.Z_SYNC_FLUSH)
    payload=b"\x01\x08"+struct.pack("<H",len(blob))+blob+P.field_v(0)
    return P.build_frame(52, payload)

def _i32(v):
    return b"\x02"+struct.pack("<I", v & 0xFFFFFFFF)   # champ entier des encheres (type 0x02)

def _i16(v):
    return b"\x04"+struct.pack("<H", v & 0xFFFF)

def auction_frame(a, timer=None):
    """op190 : fiche d'une enchere (telle que l'envoie le serveur d'origine)."""
    import time as _t
    if timer is None:
        timer = max(0, int(a["fin"] - _t.time()))
    return P.build_frame(190, b"\x02" + _i32(a["id"]) + P.field_int(1000 + a["seller_pseudo"])
        + P.field_str(a["seller_name"]) + _i16(a["card_id"])
        + _i32(a["prix_depart"]) + _i32(a["achat_immediat"]) + _i32(a["meilleure_offre"])
        + P.field_str("") + _i16(min(timer, 65535)))

# Compteurs affiches par le client (ordre confirme par capture) :
# op46 = Exp, op47 = Gils, op48 = Powers, op49 = Victoires, op50 = Defaites, op51 = Matchs nuls
GAINS = {"win":  {"exp": 30, "gils": 100},
         "draw": {"exp": 15, "gils":  50},
         "loss": {"exp": 10, "gils":  37}}   # valeurs de defaite observees sur la capture

def enregistrer_resultat(conn, pseudo_db, mes_cartes, ses_cartes, nom="Duel", compte_id=None,
                         bet=0, winner_rule=0, coef=1.0):
    """Enregistre le resultat, verse les gains et met a jour les compteurs du client.
    'bet' = mise en gils (PvP) : le gagnant recupere 2x, le nul est rembourse.
    winner_rule 0 = Entrainement : aucune consequence (ni stat, ni gils, ni exp).
    'coef' = difficulte du robot affronte : multiplie l'experience et les gils d'une victoire ou d'un nul
    (jamais ceux d'une defaite : perdre expres contre le robot le plus fort ne doit pas rapporter)."""
    if pseudo_db is None: return
    if mes_cartes > ses_cartes:   res, mot = "win",  "Victoire"
    elif mes_cartes < ses_cartes: res, mot = "loss", "Defaite"
    else:                         res, mot = "draw", "Match nul"

    # --- Regle du vainqueur "Entrainement" : partie sans enjeu ---
    # (pas de ligne de resultat dans le chat : le client affiche deja la fin de partie, et ses compteurs suivent op46-51)
    if winner_rule == ENTRAINEMENT:
        log(f"    RESULTAT {nom} (Entrainement) : {mot} {mes_cartes}-{ses_cartes}")
        return

    g = GAINS[res]
    if coef != 1.0 and res != "loss":
        g = {k: int(round(val * coef)) for k, val in g.items()}
    # competences (valeurs affichees par le client, voir INITIE_BONUS) :
    #   Initie : bonus d'experience selon le resultat ; Profiteur : +5 % de gils par niveau ;
    #   Chanceux : 1 % par niveau de chance d'obtenir une carte en cas de victoire.
    niv_ini = db.get_skill_level(pseudo_db, 7); niv_pro = db.get_skill_level(pseudo_db, 3)
    niv_chc = db.get_skill_level(pseudo_db, 8)
    bonus_ini = INITIE_BONUS.get(min(niv_ini, 6), (0, 0, 0))[{"win": 0, "draw": 1, "loss": 2}[res]]
    exp_gain = int(round(g["exp"] * (1 + bonus_ini / 100)))
    db.add_result(pseudo_db, res, exp_gain)
    try: GUILDES.apres_partie(pseudo_db, exp_gain)            # experience de la guilde, fiche du membre
    except Exception as e: log(f"    (guilde : {e})")

    # verser les gils sur le compte correspondant (+ mise recuperee)
    if compte_id is None:
        compte_id = _acc_of(pseudo_db)
    prime = int(round(g["gils"] * (1 + 0.05 * niv_pro)))
    if bet:
        prime += (2 * bet if res == "win" else bet if res == "draw" else 0)
    if compte_id:
        db.add_gils(compte_id, prime)
        acc = db.get_account(compte_id) or {}
        conn.sendall(P.build_frame(47, b"\x01"+P.field_int(acc.get("gils", 0))))     # Gils

    st = db.get_stats(pseudo_db) or {}
    conn.sendall(P.build_frame(46, b"\x01"+P.field_int(st.get("noto", 0))))          # Exp
    conn.sendall(P.build_frame(49, b"\x01"+P.field_int(st.get("wins", 0))))          # Victoires
    conn.sendall(P.build_frame(50, b"\x01"+P.field_int(st.get("losses", 0))))        # Defaites
    conn.sendall(P.build_frame(51, b"\x01"+P.field_int(st.get("draws", 0))))         # Matchs nuls

    log(f"    RESULTAT {nom} : {mot} {mes_cartes}-{ses_cartes} "
        f"(+{prime} gils, +{exp_gain} exp, mise {bet})")
    # Chanceux : une carte aleatoire (reelle) en cas de victoire
    if res == "win" and niv_chc and random.random() < 0.01 * niv_chc:
        tirage = db.sample_ref(1)
        if tirage:
            cid = tirage[0]["card_id"]; info = db.ref_info(cid) or {}
            db.add_card(pseudo_db, cid)
            conn.sendall(P.build_frame(63, b"\x01"+P.field_byte(1)+_i16(cid)+P.field_v(1)+P.field_int(0)))
            sys_notice(conn, f"Chanceux : tu obtiens la carte {info.get('name', cid)} ({info.get('deck','')}) !",
                       f"Lucky (Chanceux): you get the card {info.get('name', cid)} ({info.get('deck','')})!")
            log(f"    CHANCEUX : carte {cid} offerte")

def commande_sondage(conn, msg, moi):
    """Commandes tapees dans le chat. Les joueurs n'ont que les leurs (!aide, !robots, !motd, !langue, !quiz) ;
    les commandes de sondage du protocole (!envoi, !grade, !badges...) envoient des trames brutes au client ou
    changent des grades : elles sont reservees aux operateurs de niveau 4 et n'apparaissent que dans LEUR !aide."""
    mots = msg[1:].split()
    if not mots: return
    cmd = mots[0].lower()
    niveau4 = _sess(conn).get("admin", 0) >= 4

    if cmd in ("aide","help"):
        lignes = (["!help    : this list",
                   "!robots  : the four robots to challenge and what they pay",
                   "!motd    : show the welcome message again",
                   "!language fr / en : language of the server's messages (French / English)",
                   "!quiz top / !quiz points : ranking and points of the current quiz"] if langue_de(conn) == "en" else
                  ["!aide    : cette liste",
                   "!robots  : les quatre robots a defier et ce qu'ils rapportent",
                   "!motd    : revoir le message d'accueil",
                   "!langue fr / en : langue des messages du serveur (francais / anglais)",
                   "!quiz top / !quiz points : classement et points du quizz en cours"])
        if niveau4:
            lignes += ["--- operateur de niveau 4 : sondage du protocole ---",
                       "!envoi <op> <hexa>  : envoie une trame brute (ex: !envoi 37 010301000000)",
                       "!parties            : teste les opcodes 37 a 43 (liste des parties)",
                       "!grade <n>          : change ton grade a chaud",
                       "!badges [debut] [nb] : joueurs fictifs, un par identifiant de grade",
                       "!champs             : teste tous les champs candidats de la fiche joueur",
                       "!motd               : recharge aussi motd.txt",
                       "!opcodes            : rappelle les opcodes encore inconnus"]
        for ligne in lignes: sys_notice(conn, ligne)
        return

    if cmd in ("robots", "robot", "bots", "bot"):
        sys_notice(conn, "Les robots sont dans la section Robot de la liste des joueurs : defie-les avec les regles de ton choix.",
                   "The robots are in the Robots section of the player list: challenge them with the rules of your choice.")
        for pid in sorted(G.ROBOTS, reverse=True):
            r = G.ROBOTS[pid]
            gils, exp = int(round(GAINS['win']['gils'] * r['gain'])), int(round(GAINS['win']['exp'] * r['gain']))
            sys_notice(conn, f"{r['nom']} : cartes de niveau {r['niveaux'][0]} a {r['niveaux'][1]}, "
                             f"victoire = {gils} gils et {exp} exp",
                             f"{r['nom']}: cards of level {r['niveaux'][0]} to {r['niveaux'][1]}, win = {gils} gils and {exp} exp")
        sys_notice(conn, "Contre un robot : jamais de mise en gils ni de cartes en jeu.",
                   "Against a robot: never any gils or cards at stake.")
        return


    if cmd in ("langue", "language", "lang"):
        # la langue du COMPTE : les messages du serveur changent tout de suite ; la section
        # « English speakers », les libelles et le message d'accueil partent a l'entree au salon, donc a la connexion
        # suivante (aucun moyen connu de retirer un grade en cours de session)
        choix = {"fr": "fr", "francais": "fr", "français": "fr", "french": "fr",
                 "en": "en", "anglais": "en", "english": "en"}.get(mots[1].lower() if len(mots) > 1 else "")
        sess = _sess(conn)
        if not choix:
            sys_notice(conn, "Langue : francais. Pour passer en anglais : !langue en",
                       "Language: English. To switch to French: !language fr"); return
        if sess.get("account_id"): db.changer_langue(sess["account_id"], choix)
        sess["langue"] = choix
        with CLIENTS_LOCK:
            if id(conn) in CLIENTS: CLIENTS[id(conn)]["langue"] = choix
        log(f"    LANGUE de {moi['name']} : {choix}")
        sys_notice(conn, "Langue : francais. Les messages du serveur sont maintenant en francais ; la liste des joueurs "
                         "et le message d'accueil suivront a ta prochaine connexion.",
                   "Language: English. The server's messages are now in English; the player list and the welcome "
                   "message will follow at your next connection.")
        return

    if cmd == "motd":
        if niveau4: charger_motd(FICHIER_MOTD)
        for ligne in motd_de(conn):
            sys_notice(conn, ligne)
        if niveau4: sys_notice(conn, f"({len(MOTD)} ligne(s) rechargees depuis motd.txt)")
        return

    if not niveau4:
        sys_notice(conn, "Commande inconnue. Tape !aide", "Unknown command. Type !help"); return

    if cmd == "envoi" and len(mots) >= 2:
        try:
            op = int(mots[1])
            charge = bytes.fromhex(mots[2]) if len(mots) > 2 else b"\x01"
        except ValueError:
            sys_notice(conn, "Usage : !envoi <opcode> <hexa>"); return
        conn.sendall(P.build_frame(op, charge))
        log(f"    SONDAGE : op{op} charge={charge.hex()}")
        sys_notice(conn, f"Trame op{op} envoyee ({len(charge)} octets).")
        return

    if cmd == "parties":
        # formats plausibles pour une entree "partie en cours" : id + 2 joueurs
        essais = []
        for op in (37, 38, 39, 40, 41, 42, 43):
            charge = (b"\x01" + P.field_int(1) + P.field_str(moi["name"])
                      + P.field_str(G.ROBOTS[999]["nom"]) + P.field_int(0) + P.field_byte(0))
            essais.append((op, charge))
        for op, ch in essais:
            try:
                conn.sendall(P.build_frame(op, ch))
                log(f"    SONDAGE parties : op{op} envoye")
            except OSError:
                break
        sys_notice(conn, "Opcodes 37 a 43 envoyes. Regarde l'onglet Parties et dis lequel a marche.")
        return

    if cmd == "grade" and len(mots) >= 2:
        # AFFICHAGE seulement : op61 AJOUTE un grade a l'operateur dans les listes (op59 creerait un doublon). Ce grade
        # ne donne aucune permission : il s'ajoutait autrefois aux grades de TOUS les comptes, et « !grade 14 » faisait
        # de chaque joueur un administrateur jusqu'au redemarrage (audit du 2026-10-21).
        try: grade = int(mots[1])
        except ValueError: sys_notice(conn, "Usage : !grade <numero>"); return
        broadcast(grade_joueur_frame(moi["id"], grade))
        sys_notice(conn, f"Grade {grade} affiche (les grades se cumulent : reconnecte-toi pour repartir de zero).")
        return

    if cmd == "badges":
        # Affiche des joueurs fictifs portant chacun un grade different :
        # une seule capture d'ecran montre alors quels identifiants ont une image.
        debut = int(mots[1]) if len(mots) > 1 else 1
        nb    = int(mots[2]) if len(mots) > 2 else 20
        for k in range(nb):
            gid = debut + k
            pid = 60000 + gid
            # definition du grade (op87) dans le groupe Administration
            pl = (b"\x01" + P.field_int(gid) + P.field_str(f"Grade {gid}")
                  + P.field_int(11) + P.field_str("warn"))
            conn.sendall(P.build_frame(87, pl))
            # fiche joueur portant ce grade
            fiche = (b"\x01" + P.field_int(pid) + P.field_str(f"Grade{gid:03d}") + P.field_str("")
                     + P.field_byte(1) + P.field_int(0) + P.field_int(0)
                     + P.field_str("") + P.field_str("") + P.field_int(1700000000)
                     + b"".join(_i16(50) for _ in range(6)) + P.field_v(gid))
            conn.sendall(P.build_frame(59, fiche))
        sys_notice(conn, f"{nb} joueurs fictifs ajoutes (grades {debut} a {debut+nb-1}). "
                         f"Regarde lesquels ont un badge, puis reconnecte-toi pour les enlever.")
        log(f"    SONDAGE badges : grades {debut} a {debut+nb-1}")
        return

    if cmd == "champs":
        # Teste TOUS les champs candidats de la fiche joueur (op59) d'un coup :
        # chaque joueur fictif ne fait varier qu'un seul champ, son nom indique lequel.
        def fiche(pid, nom, statut=1, e1=0, e2=0, s1="", s2="", grade=None):
            pl = (b"\x01" + P.field_int(pid) + P.field_str(nom) + P.field_str("")
                  + P.field_byte(statut) + P.field_int(e1) + P.field_int(e2)
                  + P.field_str(s1) + P.field_str(s2) + P.field_int(1700000000)
                  + b"".join(_i16(50) for _ in range(6)))
            if grade is not None: pl += P.field_v(grade)
            return P.build_frame(59, pl)

        envois = []
        for k in range(1, 6):                       # 1er entier (guilde ?)
            envois.append(fiche(61000+k, f"Ent1_{k}", e1=k))
        for k in range(1, 6):                       # 2e entier
            envois.append(fiche(62000+k, f"Ent2_{k}", e2=k))
        for k in range(1, 6):                       # statut
            envois.append(fiche(63000+k, f"Statut_{k}", statut=k))
        for k in range(1, 4):                       # chaines (nom de guilde ?)
            envois.append(fiche(64000+k, f"Texte_{k}", s1=f"Guilde{k}", s2=f"Guilde{k}"))
        for k in range(1, 6):                       # grade en fin de trame
            pl = (b"\x01" + P.field_int(k) + P.field_str(f"Grade {k}")
                  + P.field_int(11) + P.field_str("warn"))
            conn.sendall(P.build_frame(87, pl))
            envois.append(fiche(65000+k, f"Grade_{k}", grade=k))
        for fr in envois: conn.sendall(fr)
        sys_notice(conn, f"{len(envois)} joueurs fictifs envoyes. Celui qui porte une image "
                         f"designe le champ responsable (Ent1, Ent2, Statut, Texte ou Grade).")
        log(f"    SONDAGE champs : {len(envois)} fiches de test")
        return

    if cmd == "opcodes":
        sys_notice(conn, "Reste a observer : op119 (guildes), op53/89/90/91 (niveaux de competences),")
        sys_notice(conn, "op137/138 au demarrage, opcode C->S de /away, valeurs reelles des cartes.")
        return

    sys_notice(conn, "Commande inconnue. Tape !aide", "Unknown command. Type !help")

def _aux_autres(trame, joueurs=()):
    """Envoie une trame a tous les clients en ligne SAUF aux connexions `joueurs`."""
    with CLIENTS_LOCK:
        cibles = [c["conn"] for c in CLIENTS.values() if all(c["conn"] is not j for j in joueurs)]
    for c in cibles:
        try: c.sendall(trame)
        except OSError: pass

def annoncer_partie(game, joueurs=()):
    """op232 : la partie apparait dans l'onglet Parties des AUTRES joueurs (ils peuvent l'observer).
    Les deux adversaires la recoivent deja dans leurs trames de debut (start_frames, a la place qu'elle
    occupe dans la capture) : la leur envoyer aussi ici l'affichait EN DOUBLE chez eux."""
    _aux_autres(P.build_frame(232, game._gid() + game.annonce()), joueurs)
    log(f"    partie annoncee (id {game.game_id})")

def annoncer_fin_partie(game, joueurs=(), terminee=True):
    """op235 aux autres joueurs : dans leur onglet Parties la partie passe a « terminee » (heure de fin,
    score ; « - / - » si elle est interrompue) ou disparait, selon l'option du client (gestionnaire
    0x647437). Les adversaires, eux, la recoivent dans leurs trames de fin (end_frames)."""
    _aux_autres(P.build_frame(235, game._gid() + P.field_byte(1 if terminee else 0)), joueurs)

def parties_en_cours():
    vues = {}
    for g in list(GAMES.values()): vues[id(g)] = g
    return list(vues.values())

_OP141 = (141).to_bytes(2, "big")
def relayer_spectateurs(game, frames):
    """Retransmet des trames de partie aux spectateurs (sans op141, l'accuse de pose propre au joueur)."""
    for c in list(SPECTATEURS.get(game.game_id, [])):
        for fr in frames:
            if fr[2:4] == _OP141: continue
            try: c.sendall(fr)
            except OSError: pass

def joueurs_de(game):
    return list(getattr(game, "pids", None) or [game.my_pid, game.ai_pid])

def annoncer_spectateurs(game):
    """op234 a tout le monde : « 03 | int(partie) | int(nombre de spectateurs) » (capture :
    03031b0400000301000000 a l'arrivee d'un spectateur, ...0300000000 a son depart)."""
    broadcast(P.build_frame(234, game._gid() + P.field_int(len(SPECTATEURS.get(game.game_id, [])))))

def quitter_spectateur(conn, game=None, accuse=False):
    """Retire cette connexion des spectateurs (d'une partie, ou de toutes a la deconnexion). op159 previent les
    joueurs et les autres spectateurs ; op163 (« 03 | int(partie) | b1 ») ferme la fenetre du spectateur."""
    pid = _sess(conn)["pseudo"].get("id")
    for g in ([game] if game else parties_en_cours()):
        liste = SPECTATEURS.get(g.game_id, [])
        if conn not in liste: continue
        liste.remove(conn)
        if not liste: SPECTATEURS.pop(g.game_id, None)
        depart = P.build_frame(159, g._gid() + P.field_int(pid))
        for c in list(liste) + [cl["conn"] for cl in map(find_client, joueurs_de(g)) if cl]:
            try: c.sendall(depart)
            except OSError: pass
        if accuse:
            try: conn.sendall(P.build_frame(163, g._gid() + P.field_byte(1)))
            except OSError: pass
        annoncer_spectateurs(g)

def fin_pour_spectateurs(game, raison=0, pid=None):
    """op144 aux spectateurs : « Partie entre %s et %s terminee ». raison 1 = « %s a quitte le FFWTT : arret de la
    partie », 2 = arretee par un operateur (le pid suit). Puis on les oublie."""
    fin = P.build_frame(144, game._gid() + G._int16(game.score(0)) + P.field_v(raison)
                        + (P.field_int(pid) if raison and pid else b""))
    for c in SPECTATEURS.pop(game.game_id, []):
        try: c.sendall(fin)
        except OSError: pass

# ===========================================================================
# REGLE DU VAINQUEUR : l'enjeu en cartes (formats lus dans le binaire, spec § Duels)
#   op145 (S->C, au vainqueur) : 03 | int(partie) | v(nombre a choisir) | int16(carte)*   « Choisissez %d carte(s) »
#   op149 (C->S)               : 03 | int(partie) | v(indice)*          les cartes choisies, par leur RANG dans op145
#   op150 (S->C)               : 03 | int(partie) | b1   (ou b0 + v(code))
#   op146 / op147 (S->C)       : 03 | int(partie) | int16(carte)*       gains / pertes, puis op148 (fin definitive)
# ===========================================================================
CHOIX_EN_COURS = {}        # numero de partie -> choix des gains en attente
_VERROU_CHOIX = threading.RLock()

def cartes_en_jeu(game, cote_gagnant, regle, ecart):
    """(nombre a choisir, cartes proposees) pour les regles a choix, ou (0, cartes prises directement)."""
    perdant = 1 - cote_gagnant
    if regle == TOTALE:   return 0, game.main_de(perdant)
    if regle == DIRECTE:  return 0, game.cartes_du_plateau(perdant)
    if regle == ALEATOIRE:                                    # « Aleatoire » : comme One, mais le vainqueur ne choisit
        main = game.main_de(perdant)                          # pas : UNE carte du perdant tiree au sort (regle donnee
        return 0, [random.choice(main)] if main else []       # par l'administrateur du serveur, 2026-10-22)
    if regle in CHOIX_CARTES: n = CHOIX_CARTES[regle]
    else:                 n = max(1, min(5, ecart))          # « Change » : l'ecart de score (8-2 -> 6), au plus les 5
                                                              # cartes engagees (le panneau du client n'en montre que 5)
    return n, game.main_de(perdant)

def echanger_cartes(game, gains):
    """gains = {cote: [cartes que ce cote prend a l'autre]}. Deplace les cartes en base, puis envoie a chaque joueur
    ses gains (op146) et ses pertes (op147), meme vides comme dans la capture, op148 (fin definitive) et sa collection
    complete (op52 : le client s'y fie pour savoir ce qu'il possede)."""
    conns = getattr(game, "conns", [])
    reels = {0: [], 1: []}
    for cote in (0, 1):
        preneur, donneur = game.pids[cote] - 1000, game.pids[1 - cote] - 1000
        for cid in gains.get(cote, []):
            if db.remove_card(donneur, cid):
                db.add_card(preneur, cid); reels[cote].append(cid)
    for cote in (0, 1):
        _envoi(conns[cote], [P.build_frame(146, game._gid() + b"".join(_i16(c) for c in reels[cote])),
                             P.build_frame(147, game._gid() + b"".join(_i16(c) for c in reels[1 - cote])),
                             P.build_frame(148, game._gid())])
        try: conns[cote].sendall(build_collection_frame(db.get_collection(game.pids[cote] - 1000), conns[cote]))
        except (OSError, AttributeError, IndexError): pass
    log(f"    *** ENJEU : {game.pids[0]} prend {reels[0]}, {game.pids[1]} prend {reels[1]}")
    return reels

def transferer_cartes(game, cote_gagnant, cartes):
    """Le vainqueur prend ces cartes au perdant."""
    return echanger_cartes(game, {cote_gagnant: cartes, 1 - cote_gagnant: []})[cote_gagnant]

def regler_enjeu(game, cote_force=None):
    """Appelee a la fin d'une partie entre joueurs (ou quand l'un d'eux part : `cote_force` gagne d'office).
    Retourne True si le client attend un choix des gains."""
    regle = getattr(game, "winner_rule", 0)
    if regle not in REGLES_ENJEU: return False
    if regle == DIRECTE:
        # « les joueurs remportent les cartes qu'ils ont retournees au cours de la partie » : les DEUX joueurs, qu'il y
        # ait un vainqueur ou non, gardent les cartes adverses qu'ils detiennent a la fin.
        gains = {0: game.cartes_du_plateau(1), 1: game.cartes_du_plateau(0)}
        if not (gains[0] or gains[1]): return False
        echanger_cartes(game, gains)
        return False
    a, b_ = game.score(0), game.score(1)
    if cote_force is None and a == b_: return False           # match nul : personne ne prend rien
    cote = cote_force if cote_force is not None else (0 if a > b_ else 1)
    n, cartes = cartes_en_jeu(game, cote, regle, abs(a - b_))
    if not cartes: return False
    if not n:                                                 # Totale, Aleatoire : rien a choisir
        transferer_cartes(game, cote, cartes)
        return False
    n = min(n, len(cartes))
    with _VERROU_CHOIX:
        CHOIX_EN_COURS[game.made] = {"game": game, "cote": cote, "cartes": cartes, "n": n,
                                     "echeance": time.time() + DELAI_CHOIX}
    _envoi(getattr(game, "conns", [])[cote],
           [P.build_frame(145, game._gid() + P.field_v(n) + b"".join(_i16(c) for c in cartes))])
    log(f"    *** ENJEU : {WINNER_RULES.get(regle)} -> {game.pids[cote]} choisit {n} carte(s) parmi {cartes}")
    return True

def resoudre_choix(made, indices=None, auto=False):
    """Le vainqueur a choisi (op149), ou le delai est passe (tirage au sort)."""
    with _VERROU_CHOIX:
        etat = CHOIX_EN_COURS.pop(made, None)
    if not etat: return
    game, cote, cartes, n = etat["game"], etat["cote"], etat["cartes"], etat["n"]
    if auto or not indices:
        indices = random.sample(range(len(cartes)), n)
        log(f"    ENJEU : choix automatique (delai depasse) pour {game.pids[cote]}")
    choisies = [cartes[i] for i in indices if 0 <= i < len(cartes)][:n]
    conns = getattr(game, "conns", [])
    _envoi(conns[cote], [P.build_frame(150, game._gid() + P.field_byte(1))])
    transferer_cartes(game, cote, choisies)

def partie_abandonnee(game, conn_parti, parti):
    """Un joueur quitte en pleine partie. Journal des versions du jeu (3.2.3) : « Si un joueur gagnait une partie
    en mise parce que son adversaire avait ete deconnecte... » -> celui qui reste gagne l'enjeu. Le client de
    l'autre recoit op144 avec la raison 1 : « *** %s a quitte le FFWTT : arret de la partie »."""
    if not isinstance(game, G.PvpGame) or game.placed >= 9: return
    conns = getattr(game, "conns", [])
    cote = next((c for c in (0, 1) if len(conns) > c and conns[c] is not conn_parti), None)
    if cote is None: return
    GAMES.pop(id(conns[cote]), None); game.echeance = None
    _envoi(conns[cote], [P.build_frame(144, game._gid() + _i16(game.score(cote)) + P.field_v(1)
                                       + P.field_int(parti["pid"])),
                         P.build_frame(235, game._gid() + P.field_byte(1))])
    fin_pour_spectateurs(game, 1, parti["pid"])
    regle = getattr(game, "winner_rule", 0)
    if regle != ENTRAINEMENT:
        try:
            enregistrer_resultat(conns[cote], game.pids[cote] - 1000, 9, 0, "PvP (adversaire parti)",
                                 bet=getattr(game, "bet", 0), winner_rule=regle)
        except OSError: pass
    if not regler_enjeu(game, cote_force=cote):
        _envoi(conns[cote], [P.build_frame(146, game._gid()), P.build_frame(148, game._gid())])
    log(f"    *** PARTIE abandonnee par {parti['name']} : {game.pids[cote]} gagne l'enjeu")

def surveiller_choix():
    """Chien de garde : un vainqueur qui ne choisit pas (ou qui part) ne bloque pas la partie du perdant."""
    while True:
        time.sleep(1)
        try:
            with _VERROU_CHOIX:
                finis = [m for m, e in CHOIX_EN_COURS.items() if time.time() > e["echeance"]]
            for m in finis: resoudre_choix(m, auto=True)
        except Exception as e:
            log(f"    !! surveillance des gains : {e}")

def _acc_of(pseudo_db_id):
    """Retourne l'account_id proprietaire d'un pseudo (ou None)."""
    if pseudo_db_id is None: return None
    with db._conn() as _c:
        r=_c.execute("SELECT account_id FROM pseudos WHERE id=?", (pseudo_db_id,)).fetchone()
    return r["account_id"] if r else None

def annoncer_gils(conn, compte_id):
    """Envoie le solde de gils au client (op47) : il s'en sert pour autoriser les achats."""
    if not compte_id: return
    acc = db.get_account(compte_id) or {}
    try: conn.sendall(P.build_frame(47, b"\x01"+P.field_int(acc.get("gils", 0))))
    except OSError: pass

def langue_de(conn):
    """« fr » ou « en » : la langue du compte connecte sur cette connexion (« !langue en »)."""
    return _sess(conn).get("langue", "fr")

def sys_notice(conn, text, en=None):
    """Affiche un message systeme dans le chat (diffusion op145) ; `en` = le meme message pour un compte anglophone.
    Seuls les textes ECRITS PAR LE SERVEUR se traduisent ainsi : fenetres, menus et messages d'erreur (codes) sont dans
    le client, en francais."""
    if en is not None and langue_de(conn) == "en": text = en
    ps=_sess(conn)["pseudo"]
    conn.sendall(P.build_frame(145, b"\x01"+P.field_int(ps.get("id",310))
                 +P.field_str(text)+P.field_byte(0)+P.field_int(0)))

# ===========================================================================
# PARTIES : coups, temps par coup, fin de partie
# Capture (partie a 15 s par coup) : quand le temps d'un joueur est ecoule, le SERVEUR
# joue une carte a sa place (~2 s apres l'echeance), que ce joueur soit un robot ou un humain
# absent. Le client, lui, se contente d'afficher 0 et d'envoyer op154 chaque seconde pendant
# qu'il attend l'adversaire. D'ou un chien de garde cote serveur.
# ===========================================================================
def _envoi(c, trames):
    for fr in trames:
        try: c.sendall(fr)
        except (OSError, AttributeError): return

def armer_partie(game, conns=None):
    """(Re)lance le compte a rebours du joueur dont c'est le tour."""
    if conns is not None: game.conns = conns
    if not hasattr(game, "verrou"): game.verrou = threading.RLock()
    duree = int(os.environ.get("FFWTT_TIMER_TEST") or 0) or max(5, int(getattr(game, "timer", 60)))
    game.echeance = time.time() + duree + 2          # ~2 s de grace, comme dans la capture

def _terminer_partie(game):
    game.echeance = None
    conns = getattr(game, "conns", [])
    if isinstance(game, G.PvpGame):
        enjeu = getattr(game, "winner_rule", 0) in REGLES_ENJEU
        for cote in (0, 1): _envoi(conns[cote], game.end_frames(cote, gains=not enjeu))
        a, b_ = game.score(0), game.score(1)
        for cote, moi, lui in ((0, a, b_), (1, b_, a)):
            try:
                enregistrer_resultat(conns[cote], game.pids[cote]-1000, moi, lui, "PvP",
                                     bet=getattr(game, "bet", 0), winner_rule=getattr(game, "winner_rule", 0))
            except OSError: pass
        try:
            if enjeu and not regler_enjeu(game):              # Totale / Directe : deja transfere ; sinon on attend op149
                for cote in (0, 1):
                    _envoi(conns[cote], [P.build_frame(146, game._gid()), P.build_frame(147, game._gid()),
                                         P.build_frame(148, game._gid())])
        except Exception as e:
            log(f"    !! enjeu de fin de partie : {e}")
        log("  *** DUEL PvP termine")
    else:
        _envoi(conns[0], game.end_frames())
        try:
            enregistrer_resultat(conns[0], game.my_pid-1000, game.score(0), game.score(1),
                                 f"vs {game.robot['nom']}", winner_rule=getattr(game, "winner_rule", 0),
                                 coef=game.robot["gain"])
        except OSError: pass
        log("  *** PARTIE terminee")
    for c in conns:
        if GAMES.get(id(c)) is game: GAMES.pop(id(c), None)
    fin_pour_spectateurs(game)
    annoncer_fin_partie(game, conns)

def cote_de(game, conn):
    """Le cote (0 ou 1) d'une CONNEXION dans une partie entre joueurs. Il se deduisait du pseudo courant (side_of :
    1 pour tout pid autre que le joueur 0) : en changeant de pseudo en pleine partie (op207), le joueur 0 jouait les
    cartes de son adversaire (audit du 2026-10-21)."""
    conns = getattr(game, "conns", [])
    return conns.index(conn) if conn in conns else game.side_of(_sess(conn)["pseudo"]["id"])

def jouer_coup(game, cote, idx, x, y, auto=False):
    """Un coup du joueur `cote` (0 dans une partie contre l'IA). auto = joue par le serveur."""
    if not hasattr(game, "verrou"): armer_partie(game)
    with game.verrou:
        conns = getattr(game, "conns", [])
        if game.placed >= 9 or not conns: return
        qui = "serveur (temps ecoule)" if auto else "joueur"
        if isinstance(game, G.PvpGame):
            if game.turn != cote or not all(game.submitted):
                log("    pose ignoree (ce n'est pas ton tour)"); return
            mine, theirs = game.place(cote, idx, x, y)
            if not mine: log("    pose ignoree (coup impossible)"); return
            _envoi(conns[cote], mine); _envoi(conns[1-cote], theirs)
            relayer_spectateurs(game, game.trames_spectateur)     # proprietaire / score / tour vus du joueur 0
            log(f"    POSE PvP cote {cote} carte#{idx} en ({x},{y}) par le {qui}")
        else:
            if not game.pret: return
            coups = game.place(idx, x, y, 0)
            if not coups: log("    pose ignoree (coup impossible)"); return
            _envoi(conns[0], coups); relayer_spectateurs(game, coups)
            log(f"    POSE  carte#{idx} en ({x},{y}) par le {qui}")
            if game.placed < 9:
                time.sleep(0.4)
                ia = game.ai_play()
                if game.placed < 9: ia.append(game.next_turn_frame())
                _envoi(conns[0], ia); relayer_spectateurs(game, ia)
        if game.placed >= 9: _terminer_partie(game)
        else: armer_partie(game)

def surveiller_parties():
    """Chien de garde : joue a la place du joueur dont le temps est ecoule."""
    while True:
        time.sleep(0.5)
        try:
            for game in {id(g): g for g in list(GAMES.values())}.values():
                ech = getattr(game, "echeance", None)
                if not ech or time.time() < ech: continue
                pvp = isinstance(game, G.PvpGame)
                cote = game.turn if pvp else 0
                used = game.used[cote] if pvp else game.my_used
                mains = [i for i, u in enumerate(used) if not u]
                libres = [c for c, b in enumerate(game.board) if b is None]
                if not mains or not libres: game.echeance = None; continue
                c = random.choice(libres)
                jouer_coup(game, cote, random.choice(mains), c % 3, c // 3, auto=True)
        except Exception as e:
            log(f"    !! surveillance des parties : {e}")

# ===========================================================================
# ADMINISTRATION — categorie 4 (octet de contexte 04)
# Commandes C->S : observees en jeu le 2026-09-18 (menu du bouton droit d'un administrateur).
# Accuses et notifications S->C : lus dans le binaire du client (py ffwtt_binaire.py --ctx 4),
# jamais captures sur un serveur — c'est signale dans la specification.
#   accuse commun  : 04 | b1 [| b(actif)]            -> « Kick accepte par le serveur », etc.
#   op77 (ctx1)    : int(pid de l'auteur) + str(motif) -> « Vous avez ete kicke par %s ... »
#   op78 (ctx1)    : int(pid de l'auteur) + str(motif) -> « %s vous donne un avertissement ... »
#   op80 (ctx1)    : str(message)                      -> « Message global : ... »
#   op52 (ctx1)    : ... v(1)|v(2) + int(pid auteur)   -> « %s vous a donne un nouveau deck » /
#                                                         « %s vient de remettre votre compte a zero »
# ===========================================================================
ADMIN_CMDS = {   # opcode C->S : (permission du grade, opcode de l'accuse, libelle)
    181: ("kick",         182, "kick"),             # 182 -> « Kick accepte par le serveur »
    198: ("warn",         199, "avertissement"),    # 199 -> « Avertissement accepte par le serveur »
    206: ("newdeck",      207, "don d'un nouveau deck"),
    220: ("resetaccount", 221, "remise a zero du compte"),
    226: ("notoriety",    227, "edition de la notoriete"),
    245: ("mute",         246, "mute"),
    184: ("banhost",      186, "ban d'host"),
    185: ("banhost",      186, "ban d'host"),
    188: ("banhost",      189, "vidage des bans d'host"),
    191: ("bannick",      192, "ban de pseudo"),
    194: ("banaccount",   196, "ban de compte"),
    195: ("banaccount",   196, "ban de compte"),
    217: ("global",       218, "message global"),
}

def annoncer_notoriete(pseudo_db):
    """La notoriete d'un joueur a change. op84 (categorie 1) a TOUS : int(pid) + une valeur par categorie ; lu dans le
    gestionnaire du client (0x63DEBF) : il recalcule les etoiles du joueur et, si leur nombre change, le reclasse dans
    la liste (les joueurs sans grade y sont ranges par nombre d'etoiles, sous une ligne qui dessine ces etoiles).
    Et op83 au joueur lui-meme (« Notoriete : %d/%d »). Sans cela les autres ne voyaient rien avant de se reconnecter."""
    valeurs = db.get_notos(pseudo_db)
    broadcast(P.build_frame(84, bytes([1]) + P.field_int(1000 + pseudo_db) + b"".join(_i16(n) for n in valeurs)))
    cl = find_client(1000 + pseudo_db)
    if cl:
        try: cl["conn"].sendall(P.build_frame(83, bytes([1]) + b"".join(_i16(n) for n in valeurs)))
        except OSError: pass

def refus_regle_vainqueur(moi, adversaire, regle):
    """Code d'erreur si la regle du vainqueur est impossible entre ces deux joueurs, 0 sinon (table du client) :
    103/104 « plus de 10 cartes pour jouer en Totale », 107/108 « pas assez d'experience pour cette regle »."""
    if regle not in REGLES_ENJEU: return 0
    cible_db = adversaire["pid"] - 1000
    # moins de 5 cartes disponibles : la main etait tiree parmi TOUTES les cartes du jeu, que le joueur ne possede pas ;
    # il jouait l'enjeu sans rien risquer (101 / 102 « plus de 10 cartes pour effectuer cette action », le message le
    # plus proche de la table du client)
    if cartes_disponibles(moi.get("db_id")) < 5: return 101
    if cartes_disponibles(cible_db) < 5: return 102
    if regle == TOTALE:
        if cartes_disponibles(moi.get("db_id")) <= MIN_CARTES: return 103
        if cartes_disponibles(cible_db) <= MIN_CARTES: return 104
    besoin = EXP_REGLE.get(regle, 0)
    if (db.get_stats(moi.get("db_id")) or {}).get("noto", 0) < besoin: return 107
    if (db.get_stats(cible_db) or {}).get("noto", 0) < besoin: return 108
    return 0

def permissions_de(sess):
    """Permissions de tous les grades du compte (operateur, animateur...)."""
    miens = set(grades_de(sess.get("admin", 0), sess.get("anim", 0)))
    return {p_ for gid, _lib, _grp, perms in GRADES if gid in miens for p_ in perms}

def _expulser(cible, auteur_pid, motif):
    """op77 au joueur vise, puis fermeture : la deconnexion diffuse op60 aux autres."""
    try:
        cible["conn"].sendall(P.build_frame(77, b"\x01"+P.field_int(auteur_pid)+P.field_str(motif)))
        time.sleep(0.2)
        cible["conn"].shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try: cible["conn"].close()      # le fil du joueur sort de sa boucle au prochain recv (< 1 s)
    except OSError: pass

def react_admin(conn, op, payload, sess, moi):
    """Traite une commande d'administration. Retourne True si la trame a ete prise en charge."""
    if op not in ADMIN_CMDS: return False
    perm, op_ack, libelle = ADMIN_CMDS[op]
    f = parse_typed(payload)
    ints = [v for k, v in f if k == "int"]; strs = [v for k, v in f if k == "str"]
    drapeau = next((v for k, v in f if k == "b"), 1)
    if perm not in permissions_de(sess):
        # accuse negatif generique du protocole : b0 + v(code d'erreur) ;
        # 87 = « Vous n'avez pas les privileges necessaires pour executer cette action ! »
        conn.sendall(P.build_frame(op_ack, bytes([4])+P.field_byte(0)+P.field_v(87)))
        log(f"    refus ADMIN ({libelle}) : {moi['name']} n'a pas la permission '{perm}'")
        return True
    ack = lambda suite=b"": conn.sendall(P.build_frame(op_ack, b"\x04"+P.field_byte(1)+suite))
    cible = find_client(ints[0]) if ints else None
    nom_cible = cible["name"] if cible else (str(ints[0]) if ints else "")
    if cible and cible["conn"] is not conn and cible.get("niveau", 0) > sess.get("admin", 0):
        # un operateur n'agit pas sur un operateur de niveau superieur (un niveau 2 expulsait un niveau 4)
        conn.sendall(P.build_frame(op_ack, bytes([4])+P.field_byte(0)+P.field_v(87)))
        log(f"    refus ADMIN ({libelle}) : {nom_cible} est d'un niveau superieur a {moi['name']}")
        return True

    # 181 = KICK et 198 = AVERTISSEMENT : confirme en jeu (2026-09-19) ET par les cibles de sauts
    # de l'accuse commun (cas 1206/op182 -> « Kick accepte », cas 1223/op199 -> « Avertissement
    # accepte »). Une premiere lecture « dans l'ordre des opcodes » les avait inverses.
    if op == 198:                                           # AVERTISSEMENT : int(pid) + str(motif)
        motif = strs[0] if strs else ""
        if cible: cible["conn"].sendall(P.build_frame(78, b"\x01"+P.field_int(moi["id"])+P.field_str(motif)))
        ack(); log(f"    *** ADMIN {moi['name']} : avertissement a {nom_cible} ({motif!r})")
    elif op == 181:                                         # KICK : int(pid) + str(motif)
        motif = strs[0] if strs else ""
        ack(); log(f"    *** ADMIN {moi['name']} : kick de {nom_cible} ({motif!r})")
        if cible: _expulser(cible, moi["id"], motif)
    elif op in (206, 220):                                  # NOUVEAU DECK / REMISE A ZERO : int(pid)
        if ints and ints[0] > 1000:
            pdb = ints[0] - 1000
            (db.new_deck if op == 206 else db.reset_account)(pdb)
            if cible:
                trame = build_collection_frame(db.get_collection(pdb), cible["conn"])
                # op52 se termine par v(0) ; v(1)/v(2) + int(auteur) affichent le message au joueur
                corps = trame[4:-2] + P.field_v(1 if op == 206 else 2) + P.field_int(moi["id"])
                cible["conn"].sendall(P.build_frame(52, corps))
                if op == 220:
                    acc = db.account_of_pseudo(pdb)
                    if acc: annoncer_gils(cible["conn"], acc["id"])
                    cible["conn"].sendall(P.build_frame(48, b"\x01"+P.field_int(0)))
        ack(); log(f"    *** ADMIN {moi['name']} : {libelle} pour {nom_cible}")
    elif op == 226:                                         # NOTORIETE : int(pid) + 6 x int16
        vals = [v for k, v in f if k == "h16"][:6]
        if ints and ints[0] > 1000 and len(vals) == 6:
            db.set_notos(ints[0] - 1000, vals); annoncer_notoriete(ints[0] - 1000)
        ack(); log(f"    *** ADMIN {moi['name']} : notoriete de {nom_cible} = {vals}")
    elif op == 245:                                         # MUTE : b(actif) + int(pid)
        if ints:                                            # tous les pseudos du compte : en changer ne rend pas la parole
            for p_ in pids_du_compte(ints[0]): (MUTED.add if drapeau else MUTED.discard)(p_)
        ack(P.field_byte(1 if drapeau else 0))
        log(f"    *** ADMIN {moi['name']} : {'mute' if drapeau else 'unmute'} de {nom_cible}")
    elif op in (184, 185):                                  # BAN D'HOST : int(pid)  |  b(actif) + str(host)
        host = strs[0] if strs else (cible.get("host", "") if cible else "")
        actif = drapeau if op == 185 else 1
        if actif and host.startswith("127."):
            # en local tout le monde partage 127.0.0.1 : le bannir enfermerait l'administrateur dehors
            sys_notice(conn, "Ban d'host ignore : en local tous les joueurs ont l'adresse 127.0.0.1.",
                       "Host ban ignored: locally every player has the address 127.0.0.1.")
            log(f"    ban d'host {host!r} ignore (adresse locale)"); return True
        if host: (db.ban("host", host, moi["name"]) if actif else db.unban("host", host))
        ack(P.field_byte(1 if actif else 0))
        log(f"    *** ADMIN {moi['name']} : ban d'host {host!r} actif={actif}")
        if actif and cible: _expulser(cible, moi["id"], "Host banni")
    elif op == 188:
        db.clear_bans("host"); ack(); log(f"    *** ADMIN {moi['name']} : bans d'host vides")
    elif op == 191:                                         # BAN DE PSEUDO : b(actif) + str(pseudo) + str(motif)
        pseudo = strs[0] if strs else ""; motif = strs[1] if len(strs) > 1 else ""
        if pseudo: (db.ban("nick", pseudo, moi["name"], motif) if drapeau else db.unban("nick", pseudo))
        ack(P.field_byte(1 if drapeau else 0))
        log(f"    *** ADMIN {moi['name']} : ban du pseudo {pseudo!r} actif={drapeau} ({motif!r})")
        vise = next((c for c in list(CLIENTS.values()) if c["name"].lower() == pseudo.lower()), None)
        if drapeau and vise: _expulser(vise, moi["id"], f"Pseudo banni ({motif})" if motif else "Pseudo banni")
    elif op in (194, 195):                                  # BAN DE COMPTE : b + int(pid) + str  |  b + str(compte) + str
        motif = strs[-1] if strs else ""
        acc = (db.account_of_pseudo(ints[0] - 1000) if (op == 194 and ints and ints[0] > 1000)
               else db.account_by_login(strs[0]) if (op == 195 and strs) else None)
        if acc and acc["id"] == sess.get("account_id") and drapeau:
            sys_notice(conn, "Tu ne peux pas bannir ton propre compte.", "You cannot ban your own account."); return True
        if acc: db.set_banned(acc["id"], 1 if drapeau else 0)
        ack(P.field_byte(1 if drapeau else 0))
        log(f"    *** ADMIN {moi['name']} : ban du compte {acc['login'] if acc else '?'} actif={drapeau} ({motif!r})")
        if acc and drapeau:
            for c in list(CLIENTS.values()):
                if SESSIONS.get(id(c["conn"]), {}).get("account_id") == acc["id"]:
                    _expulser(c, moi["id"], f"Compte banni ({motif})" if motif else "Compte banni")
    elif op == 217:                                         # MESSAGE GLOBAL : str(message)
        msg = strs[0] if strs else ""
        broadcast(P.build_frame(80, b"\x01"+P.field_str(msg)))
        ack(); log(f"    *** ADMIN {moi['name']} : message global {msg!r}")
    return True

# ===========================================================================
# SALON DES OPERATEURS (panneau d'equipe du client) ET QUIZZ
#
# Panneau d'equipe. Lu dans le binaire (categorie 4) :
#   op177 S->C : b(1) + int(groupe)  « Vous faites maintenant partie de la categorie %s » : le
#                client ouvre le panneau du groupe (c'etait la reponse a la commande /ident).
#   op179 S->C : int(groupe) + int(pid) + str(texte) + b(action)  -> ligne « <pseudo> texte » du
#                salon. Le pid doit etre celui d'un joueur PRESENT, sinon la ligne est ignoree.
#                Aucun historique n'est conserve ni rejoue (retire le 2026-09-23 a la demande de l'utilisateur).
#   C->S       : jamais observe. On attend op178 (l'accuse/diffusion suit d'un numero, comme
#                partout) et, a defaut, toute trame inconnue de categorie 4 de la forme
#                int(groupe) + str ; le journal dira quel opcode le client utilise vraiment.
# Quizz. Diffusions S->C lues dans le binaire (categorie 5) :
#   220 int(pid) str(themes)   « [Quizz] %s a demarre le quizz (themes : %s) »
#   221 int(pid)               « [Quizz] %s a interrompu le quizz »
#   222 [int(pid) int(points)]*  « [Quizz] TOP 5 »
#   223 str(theme) str(question) « [Quizz] Question (%s) : %s »
#   224 int(pid) int(points) str(reponse)  « %s a trouve la reponse : "%s" et a maintenant %d point(s) »
#   225 str(reponse)           « Personne n'a trouve la reponse qui etait "%s" »
#   226 int(pid)               « %s a remis les points a zero »
#   228 int(points)            « Vous avez %d point(s) sur le quizz actuel »
# Le quizz se pilote par le panneau Quizz du client (lu dans le binaire le 2026-10-22 : react_quizz) ou par le chat
# (!quiz demarrer [theme] | arreter | top | zero | points), reserve aux animateurs et aux operateurs de niveau 3 et 4.
# ===========================================================================
def membres_du_groupe(groupe):
    """Connexions des joueurs en ligne qui ont un grade dans ce groupe."""
    ids = {gid for gid, _l, grp, _p in GRADES if grp == groupe}
    with CLIENTS_LOCK: clients = list(CLIENTS.values())
    return [c["conn"] for c in clients if ids & set(grades_de(c.get("niveau", 0), c.get("anim", 0), c.get("langue", "fr")))]

def ligne_salon(groupe, pid, texte, action=0):
    return P.build_frame(179, bytes([4]) + P.field_int(groupe) + P.field_int(pid)
                         + P.field_str(texte) + P.field_byte(1 if action else 0))

GRADE_SALON = 3          # le grade « membre du salon des operateurs » (groupe GROUPE_EQUIPE)

PANNEAUX = [(GROUPE_EQUIPE, GRADE_SALON), (GROUPE_QUIZZ, GRADE_QUIZZ)]     # (groupe, grade envoye par op177)

def trames_ouverture_salon(sess):
    """op177 = b(1) + int(GRADE) — et non le groupe : le client cherche le grade, affiche « Vous
    faites maintenant partie de la categorie <libelle du grade> » et cree le panneau de son
    groupe. Un identifiant qui n'est pas un grade = « Access violation at 00649EF3, read of 14 ».
    Un panneau par groupe : le salon des operateurs (grade 3) et le Quizz (grade 5)."""
    mes_grades = grades_de(sess.get("admin", 0), sess.get("anim", 0))
    out = []; sess["panneaux"] = set()
    for groupe, grade in PANNEAUX:
        if grade not in mes_grades: continue
        sess["panneaux"].add(groupe)                 # ce client a le panneau : il peut recevoir op211 / op231 / op20...
        out += [P.build_frame(177, bytes([4]) + P.field_byte(1) + P.field_int(grade))] + trames_etat_panneau(groupe)
    return out

# ---------------------------------------------------------------------------
# CAISSE DE GILS ET TOPIC DU PANNEAU D'EQUIPE (lus dans le client le 2026-10-12, jamais captures).
#   C->S cat4 209 « ux »  int(groupe) x(texte)   bouton « Changer le topic » (TfrmSpecialUser.btnChangeTopicClick)
#   S->C      210        int(groupe) b1 | int(groupe) b0 v(code)            (71 « Topic trop long »)
#   S->C      211        int(groupe) x(texte) str(auteur) int(date)         « Topic mis par %s le %s (%d caractere(s)
#                        restant(s)) » (0x8000 caracteres au plus), « Aucun topic » si le texte est vide
#   C->S cat4 232 / 234 « uu »  int(groupe) int(montant)   deposer / retirer (boutons de l'onglet, /putspegils, /takespegils)
#   S->C      233 / 235  int(groupe) b1 | int(groupe) b0 v(code)            (14 gils, 26 caisse, 116 montant 1 a 50 000)
#   C->S cat4 236 « u4 » int(groupe) i32(montant)  /gengils <groupe> <montant> (groupe = libelle ou cle, ex. « staff »)
#   S->C      237        int(groupe) b1 -> « Vous avez genere des gils dans la caisse du groupe %s avec succes »
#   S->C      231        int(groupe) int(total) [b(depot) int(pid) int(montant)] « Actuellement %d gils dans la caisse »,
#                        « %s a depose / retire %d gils », ligne Gils+ / Gils- des actions speciales
# 210, 211 et 231 lisent le PANNEAU du groupe sans verifier qu'il existe (gestionnaires 0x64DC8C, 0x64DDAD, 0x64EAC2) :
# ils ne partent qu'aux connexions qui ont recu op177 (sess["panneaux"]), sinon le client plante.
# ---------------------------------------------------------------------------
TOPIC_EQUIPE_MAX = 0x8000
CAISSE_MAX_OPERATION = 50000          # erreur 116 « Montant incorrect (doit etre compris entre 1 et 50000 gils) »
RETRAIT_CAISSE_NIVEAU = 3             # retirer de la caisse : operateurs de niveau 3 et 4 (deposer : tout membre du panneau)

def groupes_a_panneau(fonction):
    return {gid for gid, _l, _c, _co, fonctions in GROUPES if fonction in fonctions}

def membres_panneau(groupe):
    """Connexions qui ont le panneau de ce groupe (op177 recu)."""
    with CLIENTS_LOCK: conns = [c["conn"] for c in CLIENTS.values()]
    return [c for c in conns if groupe in SESSIONS.get(id(c), {}).get("panneaux", ())]

def trame_topic_groupe(groupe):
    g = db.groupe_equipe(groupe)
    return P.build_frame(211, bytes([4]) + P.field_int(groupe) + champ_zlib(g["topic"])
                         + P.field_str(g["topic_par"] or "") + P.field_int(g["topic_ts"] or 0))

def trame_caisse_groupe(groupe, total, depot=None, pid=0, montant=0):
    pl = bytes([4]) + P.field_int(groupe) + P.field_int(total)
    if depot is not None: pl += P.field_byte(1 if depot else 0) + P.field_int(pid) + P.field_int(montant)
    return P.build_frame(231, pl)

def trames_etat_panneau(groupe):
    """A l'ouverture du panneau (juste apres op177) : la caisse, et le topic s'il y en a un."""
    g = db.groupe_equipe(groupe); out = []
    if groupe in groupes_a_panneau("gilsbank"): out.append(trame_caisse_groupe(groupe, g["caisse"]))
    if groupe in groupes_a_panneau("topic") and g["topic"]: out.append(trame_topic_groupe(groupe))
    return out

def accuse_groupe(op, groupe, ok, code=None):
    """Accuse des requetes du panneau : 04 | int(groupe) | b(ok) [| v(code)] (code d'erreur au 3e champ)."""
    return P.build_frame(op, bytes([4]) + P.field_int(groupe) + P.field_byte(1 if ok else 0)
                         + (P.field_v(code) if not ok and code is not None else b""))

def aux_membres_panneau(groupe, trame):
    for c in membres_panneau(groupe):
        try: c.sendall(trame)
        except OSError: pass

def react_panneau(conn, op, payload, sess, moi):
    """Topic (209), depot (232), retrait (234) et generation (236) de la caisse d'un groupe d'equipe."""
    v = GU.champs(payload)
    groupe = v[0] if v and isinstance(v[0], int) and not isinstance(v[0], bool) else 0
    op_ack = {209: 210, 232: 233, 234: 235, 236: 237}[op]
    refus = lambda code: conn.sendall(accuse_groupe(op_ack, groupe, False, code))
    if op == 236:                                  # GENERER : cree des gils dans la caisse (permission generategilsbank)
        if "generategilsbank" not in permissions_de(sess) or groupe not in groupes_a_panneau("gilsbank"):
            return refus(87)
        montant = v[1] if len(v) > 1 and isinstance(v[1], int) else 0
        if not 1 <= montant <= CAISSE_MAX_OPERATION: return refus(116)
        total = db.ajouter_caisse_groupe(groupe, montant)
        conn.sendall(accuse_groupe(237, groupe, True))
        aux_membres_panneau(groupe, trame_caisse_groupe(groupe, total))
        log(f"{MARQUE_ADMIN}{moi['name']} : {montant} gils generes dans la caisse du groupe {groupe} (total {total})")
        return
    if groupe not in sess.get("panneaux", ()):     # le panneau de ce groupe n'est pas le sien
        # op210 lirait ce panneau sans verifier qu'il existe (plantage) : pas de reponse au topic ; op233 / op235, eux,
        # verifient, le refus 87 est sans danger
        if op != 209: refus(87)
        log(f"    {moi['name']} n'a pas le panneau du groupe {groupe} (op{op})"); return
    if op == 209:                                  # TOPIC : x(texte)
        if groupe not in groupes_a_panneau("topic"): return refus(87)
        blocs = [x for x in v[1:] if x is None or isinstance(x, bytes)]
        if not blocs or blocs[0] is None: return refus(69)
        texte = blocs[0].decode("latin1", "replace")
        if len(texte) > TOPIC_EQUIPE_MAX: return refus(71)
        db.topic_groupe(groupe, texte, moi["name"], int(time.time()))
        conn.sendall(accuse_groupe(210, groupe, True))
        aux_membres_panneau(groupe, trame_topic_groupe(groupe))
        log(f"{MARQUE_ADMIN}{moi['name']} : topic du groupe {groupe} = {texte[:80]!r}")
        return
    # DEPOSER (232) / RETIRER (234) : int(montant). Tout membre du panneau depose ; RETIRER est reserve aux operateurs de
    # niveau 3 et 4 (choix de l'administrateur du serveur, 2026-10-12 ; la regle de l'original n'est pas connue).
    if groupe not in groupes_a_panneau("gilsbank") or "viewgilsbank" not in permissions_de(sess): return refus(87)
    if op == 234 and sess.get("admin", 0) < RETRAIT_CAISSE_NIVEAU: return refus(87)
    montant = v[1] if len(v) > 1 and isinstance(v[1], int) else 0
    if not 1 <= montant <= CAISSE_MAX_OPERATION: return refus(116)
    compte = sess.get("account_id")
    if not compte: return refus(87)
    if op == 232:
        if (db.get_account(compte) or {}).get("gils", 0) < montant: return refus(14)
        db.add_gils(compte, -montant); total = db.ajouter_caisse_groupe(groupe, montant)
    else:
        total = db.ajouter_caisse_groupe(groupe, -montant)
        if total is None: return refus(26)
        db.add_gils(compte, montant)
    conn.sendall(accuse_groupe(op_ack, groupe, True))
    annoncer_gils(conn, compte)
    aux_membres_panneau(groupe, trame_caisse_groupe(groupe, total, op == 232, moi["id"], montant))
    mouvement = "depot" if op == 232 else "retrait"
    log(f"{MARQUE_ADMIN}{moi['name']} : {mouvement} de {montant} gils, caisse du groupe {groupe} = {total}")

def message_salon(conn, moi, groupe, texte, action=0):
    if conn not in membres_du_groupe(groupe):
        sys_notice(conn, "Ce salon est reserve a l'equipe.", "This lounge is reserved for the staff."); return
    trame = ligne_salon(groupe, moi["id"], texte, action)
    for c in membres_du_groupe(groupe):
        try: c.sendall(trame)
        except OSError: pass
    log(f"    SALON {groupe} <{moi['name']}> {texte!r}")

# ------------------------------- quizz -------------------------------------
# Questions en base (ffwtt_db : quiz_categories, quiz_questions), gerees depuis le panneau Quizz du client
# (react_quizz) ; quiz.json n'est lu qu'a la premiere mise en route (importer_quiz). Le quizz se lance du panneau
# (temps de reponse et pause choisis par l'animateur) ou par le chat (!quiz, temps QUIZ_DELAI / QUIZ_PAUSE).
QUIZ = {"actif": False, "points": {}, "question": None, "echeance": 0, "par": 0, "themes": [], "categories": [],
        "pioche": [], "delai": 30, "pause": 6}
QUIZ_VERROU = threading.Lock()
QUIZ_DELAI = 30           # secondes pour repondre (commande !quiz ; le panneau envoie les siennes, 45 par defaut)
QUIZ_PAUSE = 6            # secondes entre deux questions (!quiz ; 15 par defaut dans le panneau)
QUIZ_QUESTIONS = 15       # questions tirees par !quiz ; le panneau lance toutes celles des categories cochees
QUIZ_LONGUEURS = {"categorie": 40, "question": 250, "reponse": 100}
QUIZ_FICHES_MAX = 60000   # texte d'une trame op41, decompresse : le client range sa longueur sur 16 bits

def _sans_accents(s):
    import unicodedata
    s = unicodedata.normalize("NFD", s.lower())
    return "".join(ch for ch in s if ch.isalnum())

def charger_quiz(chemin="quiz.json"):
    """{theme: [{"q": question, "r": [reponses acceptees]}]}"""
    import json
    try: return json.load(open(chemin, encoding="utf-8"))
    except Exception as e:
        log(f"    !! quiz.json illisible : {e}"); return {}

def texte_quiz(s, longueur):
    """Nom de categorie, question ou reponse nettoye, ou "" s'il est refuse : vide, trop long, ou contenant « #10 ».
    « #10 » (les 3 caracteres) separe les champs des fiches d'op41 : le client y couperait le texte, decalerait les
    fiches suivantes et, selon le cas, planterait (identifiant ou date non numerique)."""
    s = " ".join(str(s).split()).encode("latin1", "replace").decode("latin1")
    return s if s and len(s) <= longueur and "#10" not in s else ""

def lire_reponses(texte):
    """Champ « Reponse » du panneau : les reponses acceptees separees par « | » (choix du serveur : le panneau n'a qu'un
    champ et quiz.json en donne plusieurs). La premiere est celle que le quizz annonce. [] si l'une est refusee."""
    morceaux = [m for m in (" ".join(x.split()) for x in str(texte).split("|")) if m]
    reponses = [texte_quiz(m, QUIZ_LONGUEURS["reponse"]) for m in morceaux]
    return reponses if reponses and all(reponses) else []

def affichage_reponses(reponses): return " | ".join(reponses)

def importer_quiz(chemin="quiz.json"):
    """Premiere mise en route : chaque theme de quiz.json devient une categorie du panneau Quizz. Une seule fois
    (reglage « quiz_importe ») : une categorie supprimee depuis le panneau ne revient pas au redemarrage."""
    if db.reglage("quiz_importe") or db.quiz_categories() or not os.path.exists(chemin): return
    n = 0
    for theme, questions in charger_quiz(chemin).items():
        nom = texte_quiz(theme, QUIZ_LONGUEURS["categorie"])
        cid = db.quiz_creer_categorie(nom) if nom else None
        if not cid: continue
        for q in questions:
            question = texte_quiz(q.get("q", ""), QUIZ_LONGUEURS["question"])
            reponses = lire_reponses("|".join(q.get("r", [])))
            if question and reponses:
                db.quiz_ajouter_question(cid, question, reponses, "quiz.json", int(time.time())); n += 1
    db.definir_reglage("quiz_importe", "1")
    log(f"    quizz : {n} question(s) importee(s) de {chemin}")

def _diffuser5(op, corps): broadcast(P.build_frame(op, bytes([5]) + corps))

def _quiz5(op, corps=b""): return P.build_frame(op, bytes([5]) + corps)

def pilote_quiz(sess):
    """Animateurs et operateurs de niveau 3 et 4 : ceux qui ont le grade 5 (et donc le panneau Quizz)."""
    return GRADE_QUIZZ in grades_de(sess.get("admin", 0), sess.get("anim", 0))

def quiz_aux_responsables(trame):
    """Les trames d'etat du panneau Quizz (op20, 23, 24, 27, 30, 33, 39) n'identifient pas le groupe : le client les
    applique au panneau de chacun de ses grades du groupe Quizz, sans verifier qu'il existe. Elles ne partent donc
    qu'aux connexions qui ont recu op177 (sess["panneaux"]), jamais par broadcast."""
    aux_membres_panneau(GROUPE_QUIZZ, trame)

def trame_quiz_points():
    """op39 [int(pid) int(points)]* : remplace la liste de l'onglet « Quizz en cours ». Le client numerote dans l'ordre
    recu (ex aequo au meme rang) : du plus au moins de points. Les joueurs partis ne sont pas envoyes."""
    corps = b""
    for pid, pts in sorted(QUIZ["points"].items(), key=lambda kv: -kv[1]):
        if find_client(pid): corps += P.field_int(pid) + P.field_int(pts)
    return _quiz5(39, corps)

def trame_quiz_etat():
    """op30 int(temps de reponse) int(temps entre les questions) int(categorie)* : quizz en cours (bouton « Arreter »
    actif, categories cochees, temps affiches) ; op33 : quizz arrete (seule trame qui rend le bouton « Demarrer »)."""
    if not QUIZ["actif"]: return _quiz5(33)
    return _quiz5(30, P.field_int(QUIZ["delai"]) + P.field_int(QUIZ["pause"])
                  + b"".join(P.field_int(c) for c in QUIZ["categories"]))

def trame_quiz_categorie(k):
    return _quiz5(20, P.field_int(k["id"]) + P.field_str(k["nom"]) + P.field_int(k["nombre"]))

def trames_quiz_panneau():
    """A l'entree au salon, pour qui a le panneau : les categories (op20 x N, puis op28 « Liste des quizz recue »,
    qui ecrit « Nom [n question(s)] » dans la liste), l'etat (op30 si un quizz tourne) et les points (op39). Le client
    ne demande rien a l'ouverture du panneau : il faut les pousser, APRES les op61 (avant, il ne connait pas encore son
    grade du groupe Quizz et ignore ces trames). Une seule fois par entree : op20 ajoute sans dedoublonner."""
    out = [trame_quiz_categorie(k) for k in db.quiz_categories()] + [_quiz5(28)]
    with QUIZ_VERROU:
        if QUIZ["actif"]: out.append(trame_quiz_etat())
        out.append(trame_quiz_points())
    return out

def fiches_quiz(cid):
    """Textes des trames op41 d'une categorie : fiches « id#10question#10reponse#10auteur#10date » collees par « #10 »
    (la chaine litterale de 3 caracteres, pas un saut de ligne ; date Unix), en morceaux de fiches entieres."""
    morceaux = []; courant = ""
    for q in db.quiz_questions(cid):
        fiche = "#10".join([str(q["id"]), q["question"], affichage_reponses(q["reponses"]),
                            q["auteur"] or "?", str(q["ts"])])
        if courant and len(courant) + 3 + len(fiche) > QUIZ_FICHES_MAX:
            morceaux.append(courant); courant = ""
        courant = courant + "#10" + fiche if courant else fiche
    return morceaux + ([courant] if courant else [])

def categorie_en_cours(cid): return QUIZ["actif"] and cid in QUIZ["categories"]

def _question_suivante():
    if not QUIZ["pioche"]:
        QUIZ["actif"] = False; QUIZ["question"] = None
        quiz_aux_responsables(trame_quiz_etat())          # fin du quizz : op33 rend le bouton « Demarrer »
        quiz_top(); return
    theme, q = QUIZ["pioche"].pop()
    QUIZ["question"] = (theme, q); QUIZ["echeance"] = time.time() + QUIZ["delai"]
    _diffuser5(223, P.field_str(theme) + P.field_str(q["q"]))

def quiz_top():
    corps = b""
    for pid, pts in sorted(QUIZ["points"].items(), key=lambda kv: -kv[1])[:5]:
        if find_client(pid): corps += P.field_int(pid) + P.field_int(pts)
    _diffuser5(222, corps)

def demarrer_quiz(moi, categories, delai, pause, nombre=None):
    """Lance le quizz sur ces categories ({id, nom}) ; sous QUIZ_VERROU. Faux (et rien d'envoye) sans question."""
    pioche = []; utilisees = []
    for k in categories:
        qs = [(k["nom"], {"q": q["question"], "r": q["reponses"]}) for q in db.quiz_questions(k["id"]) if q["reponses"]]
        if qs: pioche += qs; utilisees.append(k)
    if not pioche: return False
    random.shuffle(pioche)
    QUIZ.update(actif=True, par=moi["id"], themes=[k["nom"] for k in utilisees], categories=[k["id"] for k in utilisees],
                pioche=pioche[:nombre] if nombre else pioche, question=None, delai=delai, pause=pause,
                echeance=time.time() + 3)
    _diffuser5(220, P.field_int(moi["id"]) + P.field_str(", ".join(QUIZ["themes"])))
    quiz_aux_responsables(trame_quiz_etat())
    log(f"    *** QUIZZ demarre par {moi['name']} ({len(QUIZ['pioche'])} questions : {QUIZ['themes']}, "
        f"{delai} s pour repondre, {pause} s entre les questions)")
    return True

def arreter_quiz(moi):
    """Sous QUIZ_VERROU."""
    QUIZ["actif"] = False; QUIZ["question"] = None; QUIZ["pioche"] = []
    _diffuser5(221, P.field_int(moi["id"]))
    quiz_aux_responsables(trame_quiz_etat())

def remettre_points_a_zero(moi):
    """Sous QUIZ_VERROU."""
    QUIZ["points"].clear(); _diffuser5(226, P.field_int(moi["id"]))
    quiz_aux_responsables(trame_quiz_points())

def quiz_commande(conn, sess, moi, mots):
    """!quiz demarrer [theme...] | arreter | top | zero | points"""
    action = (mots[0].lower() if mots else "aide")
    with QUIZ_VERROU:
        if action in ("points", "score"):
            conn.sendall(P.build_frame(228, bytes([5]) + P.field_int(QUIZ["points"].get(moi["id"], 0)))); return
        if action == "top": quiz_top(); return
        if not pilote_quiz(sess):
            sys_notice(conn, "Le quizz est pilote par les animateurs.", "The quiz is run by the event hosts."); return
        if action in ("demarrer", "start", "go"):
            if QUIZ["actif"]:
                sys_notice(conn, "Un quizz est deja en cours.", "A quiz is already running."); return       # erreur 114 du client
            categories = db.quiz_categories()
            voulu = [m.lower() for m in mots[1:]]
            choisies = [k for k in categories if not voulu or any(v in k["nom"].lower() for v in voulu)]
            if not demarrer_quiz(moi, choisies, QUIZ_DELAI, QUIZ_PAUSE, QUIZ_QUESTIONS):
                noms = ", ".join(k["nom"] for k in categories if k["nombre"])
                sys_notice(conn, f"Themes disponibles : {noms or 'aucun'}", f"Available themes: {noms or 'none'}")
        elif action in ("arreter", "stop"):
            if QUIZ["actif"]: arreter_quiz(moi)
        elif action in ("zero", "reset", "raz"):
            remettre_points_a_zero(moi)
        else:
            sys_notice(conn, "!quiz demarrer [theme] | arreter | top | zero | points")

def quiz_reponse(moi, texte):
    """Appele pour chaque message du chat global : bonne reponse = 1 point (+ notoriete Quizz)."""
    with QUIZ_VERROU:
        if not QUIZ["actif"] or not QUIZ["question"]: return
        theme, q = QUIZ["question"]
        dit = _sans_accents(texte)
        if not dit or not any(_sans_accents(r) == dit for r in q["r"]): return
        pts = QUIZ["points"][moi["id"]] = QUIZ["points"].get(moi["id"], 0) + 1
        QUIZ["question"] = None; QUIZ["echeance"] = time.time() + QUIZ["pause"]
        _diffuser5(224, P.field_int(moi["id"]) + P.field_int(pts) + P.field_str(q["r"][0]))
        quiz_aux_responsables(trame_quiz_points())
        if moi.get("db_id"):
            notos = db.get_notos(moi["db_id"])
            notos[NOTO_QUIZZ] = min(NOTORIETES[NOTO_QUIZZ][2], notos[NOTO_QUIZZ] + 5)
            db.set_notos(moi["db_id"], notos); annoncer_notoriete(moi["db_id"])

def surveiller_quiz():
    while True:
        time.sleep(1)
        try:
            with QUIZ_VERROU:
                if not QUIZ["actif"] or time.time() < QUIZ["echeance"]: continue
                if QUIZ["question"]:                                # temps ecoule
                    _diffuser5(225, P.field_str(QUIZ["question"][1]["r"][0]))
                    QUIZ["question"] = None; QUIZ["echeance"] = time.time() + QUIZ["pause"]
                else:
                    _question_suivante()
        except Exception as e:
            log(f"    !! quizz : {e}")

# ===========================================================================
# REQUETES DU CLIENT RESTEES SANS REPONSE JUSQU'AU 2026-10-12. Inventaire : py ffwtt_envois.py (82 requetes, 18 sans
# reponse). Formats lus dans le binaire du client (envois par 0x6367C4, gestionnaires par ffwtt_binaire.py), jamais
# captures : c'est signale dans la specification.
#   cat4 op202 u    « Arreter la partie » (onglet Parties)   stopgame      -> op203 04 b1 | 04 b0 v12 int(numero)
#   cat4 op223 -    /moderate                                 moderatemode  -> op224 04 b1 b(actif) ; op82 01 b(actif) a tous
#   cat4 op176 ss   /ident <groupe> <mot de passe>                          -> op177 04 b0 v(86 | 83)
#   cat5 op227 -    /points                                                 -> op228 05 int(points)
#   cat6 op64  x    notes personnelles (onglet « Personnelles »)            -> op65  06 b1 | 06 b0 v(code)
#   cat6 op164 s    /quicknews [texte]                        quicknews     -> op165 06 b1 ; op166 06 str a tous
#   cat4 op209, 232, 234, 236 : topic et caisse de gils du panneau d'equipe (react_panneau, plus haut)
#   cat4 op242 u / op215 s : infos offline -> profil op65 + op241 (infos_offline) ; erreur op216 04 v(code)
#   cat5 op21 a op40 : le panneau Quizz du client (react_quizz, depuis le 2026-10-22)
# Reste sans reponse : le menu Twitter (cat5 op120).
# ===========================================================================
MODERE = {"actif": False}      # mode modere : seuls les grades qui ont « talkwhilemoderate » parlent au salon

def refus_permission(conn, op_ack, categorie, perm, moi):
    """Accuse negatif : <categorie> | b0 | v(87) « Vous n'avez pas les privileges necessaires... »."""
    conn.sendall(P.build_frame(op_ack, bytes([categorie]) + P.field_byte(0) + P.field_v(87)))
    log(f"    refus : {moi['name']} n'a pas la permission '{perm}' (op{op_ack - 1})")

def arreter_partie(game, auteur_pid):
    """Un operateur arrete une partie. op144 se termine par v(raison) + int(pid) : raison 2 = « *** L'operateur %s a
    arrete la partie » (gestionnaire 0x645189, commun aux joueurs et aux spectateurs ; le pid doit figurer dans leur
    liste des joueurs). Puis gains et pertes vides et op148 (« definitivement terminee »), op235 b0 (« - / - ») partout.
    Ni statistique, ni gain, ni enjeu ; les mises en gils, prelevees a l'acceptation du defi, sont rendues."""
    verrou = getattr(game, "verrou", None)
    if verrou is None: verrou = game.verrou = threading.RLock()
    with verrou:                                   # attend la fin d'un coup en cours (celui d'un robot compris)
        game.echeance = None
        conns = list(getattr(game, "conns", []))
        for c in conns:
            if GAMES.get(id(c)) is game: GAMES.pop(id(c), None)
        game.conns = []                            # jouer_coup s'arrete sur une liste vide : plus aucun coup
        for cote, c in enumerate(conns):
            _envoi(c, [P.build_frame(144, game._gid() + _i16(game.score(cote)) + P.field_v(2) + P.field_int(auteur_pid)),
                       P.build_frame(235, game._gid() + P.field_byte(0)),
                       P.build_frame(146, game._gid()), P.build_frame(147, game._gid()),
                       P.build_frame(148, game._gid())])
        mise = getattr(game, "bet", 0)
        if isinstance(game, G.PvpGame) and mise:
            for cote, c in enumerate(conns):
                compte = _acc_of(game.pids[cote] - 1000)
                if compte:
                    db.add_gils(compte, mise); annoncer_gils(c, compte)
    fin_pour_spectateurs(game, 2, auteur_pid)
    annoncer_fin_partie(game, conns, terminee=False)

def infos_offline(conn, op, payload, sess, moi):
    """« Infos offline » (menu du bouton droit sur un joueur, cat4 op242 int(pid)) et « /offinfos <pseudo> » (cat4 op215
    str) : la fiche d'un joueur, connecte ou non, d'apres la base (permission viewoffinfos). Reponse : le profil op65
    (profil_joueur) et sa note publique op241 ; erreur : op216 04 v(code), dont le gestionnaire (0x64E235) n'affiche
    qu'un message d'erreur. Lu dans le client (op65 accepte un pid absent de la liste : « Connecte(e) : Non ») et non
    capture : la reponse positive de l'original n'est pas connue autrement."""
    v = GU.champs(payload)
    if "viewoffinfos" not in permissions_de(sess):
        conn.sendall(P.build_frame(216, bytes([4]) + P.field_v(87))); return
    if op == 242:
        pid = next((x for x in v if isinstance(x, int)), 0)
        cible = pid - 1000 if pid > 1000 else None
    else:
        nom = next((x for x in v if isinstance(x, str)), "").strip()
        ps = db.chercher_pseudo(nom) if nom else None
        cible = ps["id"] if ps else None
    fr = profil_joueur(cible, sess) if cible else None
    if fr is None:
        conn.sendall(P.build_frame(216, bytes([4]) + P.field_v(9))); return     # « Pseudo inexistant »
    conn.sendall(fr)
    conn.sendall(notes_frame(1000 + cible, db.get_note(cible)))
    log(f"    INFOS OFFLINE : {moi['name']} consulte la fiche du pseudo {cible}")

def react_equipe(conn, op, payload, sess, moi):
    """Requetes d'equipe de categorie 4 qui ne sont ni des guildes ni des commandes de react_admin."""
    if op in (209, 232, 234, 236):
        react_panneau(conn, op, payload, sess, moi); return True
    if op in (215, 242):
        infos_offline(conn, op, payload, sess, moi); return True
    if op not in (176, 202, 223): return False
    v = GU.champs(payload)
    perms = permissions_de(sess)
    if op == 202:                                  # ARRETER UNE PARTIE : int(numero de partie, celui d'op232)
        if "stopgame" not in perms:
            refus_permission(conn, 203, 4, "stopgame", moi); return True
        made = next((x for x in v if isinstance(x, int)), -1)
        partie = next((g for g in parties_en_cours() if g.made == made), None)
        if not partie:
            conn.sendall(GU.f_ack(203, False, 12, made)); return True       # « *** ID %d inexistant »
        noms = []
        for pid_j in joueurs_de(partie):
            cl = find_client(pid_j)
            noms.append(cl["name"] if cl else (G.ROBOTS[pid_j]["nom"] if pid_j in G.ROBOTS else str(pid_j)))
        arreter_partie(partie, moi["id"])
        conn.sendall(GU.f_ack(203, True))                                   # « Arret de la partie accepte par le serveur »
        log(f"{MARQUE_ADMIN}{moi['name']} : arret de la partie {made} ({' contre '.join(noms)})")
        return True
    if op == 223:                                  # MODE MODERE : bascule
        if "moderatemode" not in perms:
            refus_permission(conn, 224, 4, "moderatemode", moi); return True
        MODERE["actif"] = not MODERE["actif"]
        drapeau = P.field_byte(1 if MODERE["actif"] else 0)
        conn.sendall(P.build_frame(224, bytes([4]) + P.field_byte(1) + drapeau))   # « (Des)activation ... acceptee »
        broadcast(P.build_frame(82, bytes([1]) + drapeau))                        # « *** Le mode modere a ete (des)active »
        etat = "active" if MODERE["actif"] else "desactive"
        log(f"{MARQUE_ADMIN}{moi['name']} : mode modere {etat}")
        return True
    # op176, /ident <groupe> <mot de passe> : « S'identifier en tant qu'utilisateur special ». Ici l'equipe vient du
    # niveau du compte (ffwtt_admin.py, --admin), pas d'un mot de passe de groupe : 86 « Vous etes deja membre de ce groupe
    # d'utilisateurs speciaux » pour l'equipe, 83 « Groupe ou mot de passe incorrect » pour les autres.
    code = 86 if GRADE_SALON in grades_de(sess.get("admin", 0), sess.get("anim", 0)) else 83
    conn.sendall(GU.f_ack(177, False, code))
    log(f"    /ident de {moi['name']} : code {code}")
    return True

# ---------------------------------------------------------------------------
# PANNEAU QUIZZ DU CLIENT (TfrmSpecialUser, onglets « Questions des quizz » et « Quizz en cours »), lu dans le binaire
# le 2026-10-22, jamais capture. Requetes (categorie 5) et reponses :
#   21 b1 s(nom) | b0 u(categorie)        ajouter / supprimer une categorie  -> 22 b(ajout) b1 | b(ajout) b0 v(code) [int]
#   25 b1 u(cat) s(question) s(reponse) | b0 u(cat) u(question)              -> 26 (meme forme) ; « Editer » = 25 b0 puis 25 b1
#   40 u(groupe) u(cat)                   questions d'une categorie          -> 41 int(groupe) int(cat) x(fiches)* puis 42 b1 int(groupe) int(cat)
#   29 u(temps de reponse) u(temps entre les questions) u(cat)*   demarrer   -> 31 b1 | b0 v(code)
#   32 arreter -> 34 ; 35 remettre les points a zero -> 36 ; 37 « Afficher le top5 actuel » -> 38   (b1 | b0 v(code))
# Etat des panneaux : 20 int(cat) str(nom) int(nombre) ajoute une categorie, 23 int(cat) la retire, 24 int(question)
# int(cat) str(question) str(reponse) str(auteur) int(date) ajoute une question, 27 int(cat) int(question) la retire,
# 30 / 33 quizz en cours / arrete, 39 les points. Les accuses (22, 26, 31...) ne touchent pas aux listes : le serveur
# envoie lui-meme les trames d'etat. Codes : 109 categorie existante, 110 categorie %d inexistante (+ int, seulement
# dans 22 et 26), 111 question %d inexistante (+ int, 26), 112 categorie en cours d'utilisation, 113 pas de quizz en
# cours, 114 quizz deja en cours, 115 aucune categorie avec des questions, 87 droits, 0 texte refuse. Un code dont le
# message attend un nombre, envoye sans lui, fait planter le client (« Erreur fatale ») : ne pas en ajouter d'autres.
# ---------------------------------------------------------------------------
QUIZ_ACCUSES = {21: 22, 25: 26, 29: 31, 32: 34, 35: 36, 37: 38, 40: 42}

def react_quizz(conn, op, payload, sess, moi):
    """Categorie 5 : le panneau Quizz du client et /points (op227). Le client ne verifie aucun droit avant d'envoyer :
    tout se reverifie ici (avoir recu le panneau Quizz, c'est-a-dire le grade 5). Reste sans reponse : le menu
    Twitter (op120, une recompense en gils op121 sur l'original)."""
    if op == 227:
        with QUIZ_VERROU: points = QUIZ["points"].get(moi["id"], 0)
        conn.sendall(P.build_frame(228, bytes([5]) + P.field_int(points)))    # « Vous avez %d point(s) ... »
        return
    if op not in QUIZ_ACCUSES:
        log(f"    >>> categorie 5 op{op} non geree (menu Twitter) : args={payload.hex()}"); return
    v = GU.champs(payload)
    nombre = lambda i: v[i] if len(v) > i and isinstance(v[i], int) else 0
    ajout = op in (21, 25) and nombre(0) == 1
    accuse = QUIZ_ACCUSES[op]
    def ok(): conn.sendall(_quiz5(accuse, (P.field_byte(1 if ajout else 0) if op in (21, 25) else b"") + P.field_byte(1)))
    def refus(code, ident=None):
        pl = (P.field_byte(1 if ajout else 0) if op in (21, 25) else b"") + P.field_byte(0) + P.field_v(code)
        conn.sendall(_quiz5(accuse, pl + (P.field_int(ident) if ident is not None else b"")))
        log(f"    quizz : op{op} de {moi['name']} refuse (code {code})")
    # op42 lit le panneau du groupe qu'il nomme sans verifier qu'il existe : sans panneau, seul un refus (b0) part
    if GROUPE_QUIZZ not in sess.get("panneaux", ()): return refus(87)
    if op == 40:                                   # QUESTIONS D'UNE CATEGORIE (la liste se debloque a op42 b1)
        groupe, cid = nombre(0), nombre(1)
        if groupe != GROUPE_QUIZZ: return refus(87)
        if db.quiz_categorie(cid):                 # categorie supprimee entre-temps : op42 seul (op23 est deja parti)
            for texte in fiches_quiz(cid):
                conn.sendall(_quiz5(41, P.field_int(groupe) + P.field_int(cid) + champ_zlib(texte)))
        conn.sendall(_quiz5(42, P.field_byte(1) + P.field_int(groupe) + P.field_int(cid)))
        return
    auteur = texte_quiz(moi["name"], 40) or "?"
    with QUIZ_VERROU:
        if op == 21 and ajout:                     # NOUVELLE CATEGORIE
            nom = texte_quiz(next((x for x in v[1:] if isinstance(x, str)), ""), QUIZ_LONGUEURS["categorie"])
            if not nom: return refus(0)
            cid = db.quiz_creer_categorie(nom)
            if not cid: return refus(109)          # « La categorie existe deja ! »
            ok(); quiz_aux_responsables(trame_quiz_categorie({"id": cid, "nom": nom, "nombre": 0}))
            log(f"{MARQUE_ADMIN}{moi['name']} : categorie de quizz {nom!r} creee ({cid})")
            return
        if op in (21, 25):
            cid = nombre(1)
            k = db.quiz_categorie(cid)
            if not k: return refus(110, cid)       # « Categorie %d inexistante »
            # 112 « en cours d'utilisation » : ni suppression, ni ajout (« Editer » envoie suppression PUIS ajout : un
            # ajout accepte apres une suppression refusee doublerait la question)
            if categorie_en_cours(cid): return refus(112)
            if op == 21:                           # SUPPRIMER UNE CATEGORIE (et ses questions)
                db.quiz_supprimer_categorie(cid)
                ok(); quiz_aux_responsables(_quiz5(23, P.field_int(cid)))
                log(f"{MARQUE_ADMIN}{moi['name']} : categorie de quizz {k['nom']!r} supprimee ({cid})")
                return
            if ajout:                              # NOUVELLE QUESTION : s(question) s(reponse)
                textes = [x for x in v[2:] if isinstance(x, str)] + ["", ""]
                question = texte_quiz(textes[0], QUIZ_LONGUEURS["question"])
                reponses = lire_reponses(textes[1])
                if not question or not reponses: return refus(0)
                ts = int(time.time())
                qid = db.quiz_ajouter_question(cid, question, reponses, auteur, ts)
                ok(); quiz_aux_responsables(_quiz5(24, P.field_int(qid) + P.field_int(cid) + P.field_str(question)
                                                   + P.field_str(affichage_reponses(reponses)) + P.field_str(auteur)
                                                   + P.field_int(ts)))
                log(f"{MARQUE_ADMIN}{moi['name']} : question {qid} ajoutee au quizz {k['nom']!r}")
                return
            qid = nombre(2)                        # SUPPRIMER UNE QUESTION
            q = db.quiz_question(qid)
            if not q or q["categorie"] != cid: return refus(111, qid)    # « Question %d inexistante »
            db.quiz_supprimer_question(qid)
            ok(); quiz_aux_responsables(_quiz5(27, P.field_int(cid) + P.field_int(qid)))
            log(f"{MARQUE_ADMIN}{moi['name']} : question {qid} retiree du quizz {k['nom']!r}")
            return
        if op == 29:                               # DEMARRER : temps bornes a 5..300 s, comme le fait le client
            if QUIZ["actif"]: return refus(114)
            delai = min(300, max(5, nombre(0))); pause = min(300, max(5, nombre(1)))
            voulues = {x for x in v[2:] if isinstance(x, int)}
            choisies = [k for k in db.quiz_categories() if k["id"] in voulues and k["nombre"]]
            if not choisies: return refus(115)     # « Aucune categorie avec des questions selectionnee »
            ok(); demarrer_quiz(moi, choisies, delai, pause)
            return
        if op == 32:                               # ARRETER
            if not QUIZ["actif"]: return refus(113)
            ok(); arreter_quiz(moi)
            return
        ok()
        if op == 35: remettre_points_a_zero(moi)   # REMETTRE LES POINTS A ZERO
        else: quiz_top()                           # op37 : le top 5 a tout le salon (op222), comme « !quiz top »

def nouvelle_rapide():
    """La news rapide (/quicknews), affichee « *** Infos : <texte> » a l'entree au salon apres le message d'accueil."""
    return db.reglage("quicknews", "").encode("latin1", "replace").decode("latin1")

def react_cat6(conn, op, payload, sess, moi):
    """Categorie 6 : notes personnelles (op64) et news rapides (op164)."""
    if op == 64:                                   # x(texte) : l'onglet « Personnelles » de son propre profil
        blocs = [x for x in GU.champs(payload) if x is None or isinstance(x, bytes)]
        if not blocs or blocs[0] is None:
            conn.sendall(P.build_frame(65, bytes([6]) + P.field_byte(0) + P.field_v(69))); return  # « donnees compressees »
        texte = blocs[0].decode("latin1", "replace")[:30000]
        db.set_note_perso(moi.get("db_id"), texte)
        conn.sendall(P.build_frame(65, bytes([6]) + P.field_byte(1)))
        log(f"    NOTES PERSONNELLES de {moi['name']} : {texte[:60]!r}")
        return
    if op == 164:                                  # str(texte) : « /quicknews [texte] Change les news rapides »
        if "quicknews" not in permissions_de(sess):
            refus_permission(conn, 165, 6, "quicknews", moi); return
        texte = next((x for x in GU.champs(payload) if isinstance(x, str)), "").strip()[:250]
        db.definir_reglage("quicknews", texte)
        conn.sendall(P.build_frame(165, bytes([6]) + P.field_byte(1)))
        if texte: broadcast(P.build_frame(166, bytes([6]) + P.field_str(texte)))   # « *** Infos : %s »
        log(f"{MARQUE_ADMIN}{moi['name']} : news rapide {texte!r}")
        return
    log(f"    >>> categorie 6 op{op} non geree : args={payload.hex()}")

OPCODES_CONNUS = {3,5,32,35,44,64,66,68,71,88,91,93,96,97,100,119,133,140,144,146,149,151,154,156,162,188,191,203,239,
                  194,200,207,244,768}

def react(conn, op, payload, server_name):
    """Reponses minimales. A completer au fur et a mesure des tests."""
    sess = _sess(conn)              # etat propre a CETTE connexion
    SESSION = sess                  # alias (retro-compatibilite du code)
    current_pseudo = sess["pseudo"]
    # L'octet de contexte est l'octet de poids fort du vrai opcode (le client envoie opcode + 256 x categorie) : le
    # meme numero existe dans plusieurs categories. Les categories 4, 5 et 6 sont donc aiguillees AVANT tout le reste,
    # et une trame de ces categories ne descend jamais dans les branches des categories 0 a 3. Sans cela (corrige le
    # 2026-10-12, inventaire ffwtt_envois.py) : « Arreter le quizz » (cat5 op32) lancait un duel contre un robot,
    # « Remise a zero des points » (cat5 op35) passait pour une reponse a un defi, et l'enregistrement des notes
    # personnelles (cat6 op64) pour une ouverture de profil.
    categorie = payload[0] if payload else 0
    # Avant l'identification (op100), seuls la version (op5), la connexion et les pongs passent. Sans compte, une
    # connexion entrait dans la liste des joueurs, ecrivait au salon et envoyait des messages prives sous le nom
    # « Joueur » (audit du 2026-10-21) ; un compte ou un pseudo banni passait ainsi quand meme.
    if not sess.get("account_id") and not (op in (3, 768) or (categorie == 0 and op in (5, 100))):
        log(f"    (op{op} ignore : connexion pas encore identifiee)"); return
    if categorie == 4:
        if GUILDES.react(conn, op, payload, sess, current_pseudo): return
        if react_admin(conn, op, payload, sess, current_pseudo): return
        if react_equipe(conn, op, payload, sess, current_pseudo): return
        _f = parse_typed(payload)
        _ints = [v for k, v in _f if k == "int"]; _strs = [v for k, v in _f if k == "str"]
        if op not in OPCODES_CONNUS and _ints and _strs and _ints[0] in {g[0] for g in GROUPES}:
            if op != 178: log(f"    (op{op} categorie 4 pris pour un message de salon : a confirmer)")
            message_salon(conn, current_pseudo, _ints[0], _strs[0], next((v for k, v in _f if k == "b"), 0))
            return
        if op != 239:                    # la seule requete de categorie 4 traitee plus bas (note publique d'un profil)
            log(f"    >>> categorie 4 op{op} non geree : args={payload.hex()}"); return
    elif categorie == 5:
        react_quizz(conn, op, payload, sess, current_pseudo); return
    elif categorie == 6:
        react_cat6(conn, op, payload, sess, current_pseudo); return
    if op not in OPCODES_CONNUS:
        log(f"    >>> OPCODE NON GERE {op} : args={payload.hex()}")
    if op == 3 or op == 768:
        # pong du client -> rien a faire
        return
    if op == 68:
        # MODE POWER (sacrifice) : ctx + byte(actif) + [texte] -> ack op69 + diffusion op70
        on = payload[2] if len(payload)>2 else 0
        SESSION["power_mode"] = bool(on)
        rest = payload[3:]
        conn.sendall(P.build_frame(69, b"\x01"+P.field_byte(on)))
        conn.sendall(P.build_frame(70, b"\x01"+P.field_int(current_pseudo["id"])+P.field_byte(on)+rest))
        log(f"    MODE POWER actif={on}")
        return
    if op == 35:
        # REPONSE AU DEFI : ctx3 + int(defiant) + b(1 = accepte / 0 = refuse)
        fld = parse_typed(payload)
        ints = [v for k, v in fld if k == "int"]
        challenger = ints[0] if ints else 0
        accepte = next((v for k, v in fld if k == "b"), 0)
        key = (challenger, current_pseudo["id"])
        p = PENDING.get(key)
        # Le bouton « Annuler le defi » du DEFIANT envoie la meme trame (int = le joueur defie, b0) : le client ne
        # referme sa fenetre qu'a la reponse du serveur (op36 b0). Sans elle, la fenetre restait bloquee.
        if not p and not accepte and PENDING.get((current_pseudo["id"], challenger)):
            annule = PENDING.pop((current_pseudo["id"], challenger))
            conn.sendall(defi_ferme(challenger))
            try: annule["to_conn"].sendall(defi_ferme(current_pseudo["id"]))
            except OSError: pass
            log(f"    DEFI annule par {current_pseudo['name']}"); return
        if not p:
            conn.sendall(defi_ferme(challenger))          # defi disparu (defiant parti...) : refermer la fenetre
            log(f"    reponse a un defi inconnu (defiant {challenger})"); return
        if not accepte:
            PENDING.pop(key, None)
            conn.sendall(defi_ferme(challenger))                              # ma fenetre se referme
            try: p["from_conn"].sendall(defi_ferme(current_pseudo["id"], refuse=True))  # « %s a refuse votre defi »
            except OSError: pass
            log(f"    DEFI refuse par {current_pseudo['name']}")
            return
        # === mise en gils : chaque joueur paie sa mise a l'acceptation, s'il l'a ===
        # Le solde n'etait jamais verifie et pouvait devenir negatif : un second compte misait 4 milliards puis se
        # deconnectait, et le premier empochait le double (audit du 2026-10-21). Le debit est conditionnel
        # (db.retirer_gils) ; si l'un des deux ne peut pas payer, l'autre est rembourse et le defi se referme
        # (14 « pas assez de gils disponibles » pour celui qui ne peut pas, 40 « %s ne possede pas assez... » pour l'autre).
        bet = p.get("bet", 0)
        if bet:
            acc_a, acc_b = _acc_of(p["from_db"]), _acc_of(current_pseudo.get("db_id"))
            paye_a = db.retirer_gils(acc_a, bet)
            paye_b = paye_a and db.retirer_gils(acc_b, bet)
            if not paye_b:
                if paye_a: db.add_gils(acc_a, bet)
                PENDING.pop(key, None)
                conn.sendall(defi_ferme(challenger, code=40 if not paye_a else 14))
                try: p["from_conn"].sendall(defi_ferme(current_pseudo["id"], code=14 if not paye_a else 40))
                except OSError: pass
                log(f"    DEFI annule : mise de {bet} gils impossible ({'defiant' if not paye_a else current_pseudo['name']} "
                    f"n'a pas assez de gils)")
                return
            annoncer_gils(p["from_conn"], acc_a)
            annoncer_gils(conn, acc_b)
        # accepte : on cree la partie et on previent les deux joueurs (mains tirees parmi les cartes qui ne sont pas
        # aux encheres : une carte vendue pendant la partie ne pouvait plus etre prise par le vainqueur)
        pvp = G.PvpGame(0, p["from_pid"], collection_disponible(p["from_db"]),
                        current_pseudo["id"], collection_disponible(current_pseudo.get("db_id")),
                        rules=p.get("rules") or RULES, made=next_made(),
                        timer=p.get("timer", 60), winner_rule=p.get("winner_rule", 0),
                        bet=bet, spectators=p.get("spec", 1))
        GAMES[id(p["from_conn"])] = pvp; GAMES[id(conn)] = pvp
        PENDING.pop(key, None)
        # op36 : partie creee. Chaque joueur recoit l'identifiant de SON adversaire. Avec la regle
        # Aleatoire la partie demarre tout de suite ; sinon le client ouvre « Choix des cartes »
        # et la partie commencera quand les deux joueurs auront envoye leur main (op133).
        for cote, c_, other in ((0, p["from_conn"], current_pseudo["id"]),
                                (1, conn, p["from_pid"])):
            c_.sendall(pvp.trame_creation(other))
            if all(pvp.submitted):
                for fr in pvp.start_frames(cote): c_.sendall(fr)
        pvp.conns = [p["from_conn"], conn]; pvp.verrou = threading.RLock(); pvp.echeance = None
        if all(pvp.submitted): armer_partie(pvp)
        annoncer_partie(pvp, pvp.conns)
        log(f"    *** DUEL accepte : {p['from_name']} vs {current_pseudo['name']} (partie {pvp.made}, "
            f"mise {bet}, {'mains aleatoires' if all(pvp.submitted) else 'choix des cartes'})")
        return
    if op == 133:
        # LE JOUEUR ENVOIE SES 5 CARTES (parties sans la regle Aleatoire) :
        #   int(partie) + 5 x int16(carte)  ->  op134 int(partie) + b1 (« Cartes acceptees par le serveur »)
        game = GAMES.get(id(conn))
        if not game:
            log("    op133 sans partie en cours"); return
        cartes = [v for k, v in parse_typed(payload) if k == "h16"][:5]
        coll = collection_disponible(current_pseudo.get("db_id"))       # pas les cartes mises aux encheres
        conn.sendall(P.build_frame(134, game._gid()+P.field_byte(1)))
        if isinstance(game, G.PvpGame):
            side = cote_de(game, conn)
            if game.submitted[side]: return                      # deja envoye
            ok = game.set_hand(side, cartes, coll)
            log(f"    MAIN choisie par {current_pseudo['name']} : {cartes}" + ("" if ok else "  (refusee : main tiree au hasard)"))
            if all(game.submitted):
                for s_i in (0, 1):
                    c_i = find_client(game.pids[s_i])
                    if c_i:
                        for fr in game.start_frames(s_i): c_i["conn"].sendall(fr)
                armer_partie(game)
                log("    *** LES DEUX MAINS SONT PRETES : la partie commence")
        else:
            if game.pret: return
            ok = game.set_hand(cartes, coll)
            log(f"    MAIN choisie par {current_pseudo['name']} : {cartes}" + ("" if ok else "  (refusee : main tiree au hasard)"))
            for fr in game.start_frames(): conn.sendall(fr)
            armer_partie(game)
        return
    if op == 203:
        # CREER UN PSEUDO : ctx0 + str(nom) -> op204. Lu dans le binaire (cas 204) : champ 1 =
        # booleen de reussite, champ 2 = identifiant (reussite) ou code d'erreur (echec).
        # Le client AJOUTE lui-meme le pseudo a sa liste : ne pas lui renvoyer les op201, sinon
        # chaque pseudo apparait en double (constate en jeu).
        echec = lambda code: conn.sendall(P.build_frame(204, bytes([0])+P.field_byte(0)+P.field_v(code)))
        try: nom,_ = P.decode_string(payload, 1)
        except Exception:
            log("    !! op203 mal forme"); echec(5); return
        nom = nom.strip()
        acc_id = SESSION.get("account_id")
        # memes caracteres qu'un nom de compte (3 a 20 lettres, chiffres, _ - [ ] .) : les caracteres de controle, les
        # traits d'union conditionnels et les espaces permettaient d'imiter un autre joueur ou un robot
        if not db.NOM_COMPTE_RE.match(nom) or not acc_id or db.nom_interdit(nom):
            echec(5); return                                    # 5 = « Pseudo invalide » (ou interdit par l'administration)
        if len(db.get_pseudos(acc_id)) >= 5:
            echec(7); return                                    # 7 = « maximum de pseudos »
        nouveau, err = db.create_pseudo(acc_id, nom)
        if err:
            echec(6)                                            # 6 = « Ce pseudo existe deja »
            log(f"    creation de pseudo refusee ({nom}) : {err}")
            return
        conn.sendall(P.build_frame(204, bytes([0])+P.field_byte(1)
                     +P.field_int(nouveau["id"])+P.field_str(nom)))
        log(f"    *** PSEUDO CREE : {nom} (id {nouveau['id']})")
        return
    if op == 239:
        # NOTE PUBLIQUE D'UN PROFIL : 04 | int(groupe de l'onglet) | int(pid du PROFIL affiche) | x(texte).
        # Lu dans le client (TfrmInfos.btnChangeNotesClick, 0x62CD44) : l'onglet « Personnelles » part en cat6 op64,
        # tout autre onglet ici avec le pid du profil ouvert (champ 0x33C de la fenetre). Jusqu'au 2026-10-12 le serveur
        # prenait le 1er entier pour un numero de « morceau » et ignorait le pid : un operateur qui corrigeait la note
        # d'un joueur ecrasait la sienne. Ecrire sur le profil d'un autre demande la permission « editnotes ».
        # Accuse op240 : 04 | b1, ou 04 | b0 | v(code) (69 « Le serveur attendait des donnees compressees »,
        # 87 « pas les privileges »).
        v = GU.champs(payload)
        ints = [x for x in v if isinstance(x, int)]; blocs = [x for x in v if isinstance(x, (bytes, type(None)))]
        cible = ints[1] if len(ints) > 1 else current_pseudo["id"]
        if not blocs or blocs[0] is None:
            log(f"    !! op239 illisible : {payload[:24].hex()}")
            conn.sendall(GU.f_ack(240, False, 69)); return
        texte = blocs[0].decode("latin1", "replace")[:30000]
        if cible != current_pseudo["id"] and "editnotes" not in permissions_de(SESSION):
            conn.sendall(GU.f_ack(240, False, 87))
            log(f"    note de {cible} refusee a {current_pseudo['name']} (permission editnotes)"); return
        if cible <= 1000:                                   # robot ou identifiant invalide : 9 « Pseudo inexistant »
            conn.sendall(GU.f_ack(240, False, 9)); return
        db.set_note(cible - 1000, texte)
        conn.sendall(GU.f_ack(240, True))
        qui = "sa note" if cible == current_pseudo["id"] else f"la note de {cible}"
        log(f"    NOTE : {current_pseudo['name']} ecrit {qui} : {texte[:60]!r}")
        if cible != current_pseudo["id"]: log(f"{MARQUE_ADMIN}{current_pseudo['name']} : note publique de {cible} modifiee")
        return
    # ======================= ECHANGE DE CARTES (categorie 2) =======================
    # Capture :         C 88 int(cible)            -> S 89 int(cible) b1 ; la cible recoit S 90 int(moi)
    #                   C 91 int(initiateur) b     -> S 92 int(autre) b aux DEUX (b0 = refus)
    #                   C 93 int(part) int(gils) [int16(carte) v(qte)]*   -> S 94 int(part) b1
    #                        et le partenaire recoit S 95 int(moi) int(gils) [int16 v]*
    #                   C 96 int(part) b  (b1 = je valide, b0 = j'annule)
    #                   S 97 int(part) b1 = conclu ; b0 = « X a refuse ou annule l'echange »
    if op == 88:
        f = parse_typed(payload); ints = [v for k, v in f if k == "int"]
        if not ints: log("    !! op88 mal forme"); return
        cible = ints[0]; moi = current_pseudo["id"]
        autre = find_client(cible)
        if trop_vite(SESSION, "echange"):
            log(f"    (demande d'echange de {current_pseudo['name']} ignoree : envois trop rapproches)"); return
        # 2000 points d'experience des deux cotes. Refus = op89 « 02 int(cible) b0 v(code) » (gestionnaire 0x640788) : le
        # client affiche le message du code avec le pseudo de la cible (99 pour moi, 100 « %s doit posseder... »).
        # 19 « Vous etes deja en train de faire un echange avec %s » : une nouvelle demande ecrasait l'echange en cours
        # de la cible (audit du 2026-10-21).
        refus = (99 if experience(current_pseudo.get("db_id")) < EXP_MIN_ACTIONS else
                 100 if autre and cible > 1000 and experience(cible - 1000) < EXP_MIN_ACTIONS else
                 19 if autre and cible != moi and (moi in ECHANGES or cible in ECHANGES) else 0)
        if refus:
            conn.sendall(P.build_frame(89, b"\x02"+P.field_int(cible)+P.field_byte(0)+P.field_v(refus)))
            log(f"    echange refuse ({current_pseudo['name']} -> {cible}) : code {refus}"); return
        conn.sendall(P.build_frame(89, b"\x02"+P.field_int(cible)+P.field_byte(1)))
        if not autre or cible == moi:
            # robot ou joueur parti : on referme la demande (op97 d'echec), sinon le client
            # reste bloque sur « En attente de la validation de ton partenaire ».
            conn.sendall(echange_annule_frame(cible))
            if cible not in G.ROBOTS: sys_notice(conn, "Ce joueur n'est pas en ligne.", "This player is not online.")
            return
        ECHANGES[moi]   = {"partenaire": cible, "cartes": [], "gils": 0, "offre": False, "valide": False, "initiateur": moi}
        ECHANGES[cible] = {"partenaire": moi,   "cartes": [], "gils": 0, "offre": False, "valide": False, "initiateur": moi}
        autre["conn"].sendall(P.build_frame(90, b"\x02"+P.field_int(moi)))   # invitation
        log(f"    ECHANGE propose : {current_pseudo['name']} -> {autre['name']}")
        return

    if op == 91:
        f = parse_typed(payload); ints = [v for k, v in f if k == "int"]
        if not ints: return
        part = ints[0]; moi = current_pseudo["id"]
        ok = next((v for k, v in f if k == "b"), 1)
        cl = find_client(part)
        if not ok:
            # « Refuser » (l'invite) ou « Annuler » (celui qui propose) : op92 02 | int(l'autre) | b0 | b(message), lu dans
            # le gestionnaire du client : il ferme la fenetre, puis rien (b0) ou « %s a refuse votre echange » (b1).
            # Celui qui clique attend CETTE reponse pour fermer sa fenetre (bouton grise sinon : 2026-09-23).
            etat = ECHANGES.pop(moi, None); ECHANGES.pop(part, None)
            conn.sendall(P.build_frame(92, b"\x02"+P.field_int(part)+P.field_byte(0)+P.field_byte(0)))
            propose = bool(etat and etat.get("initiateur") == moi)          # il annule sa propre proposition
            if cl: cl["conn"].sendall(P.build_frame(92, b"\x02"+P.field_int(moi)+P.field_byte(0)
                                                    + P.field_byte(0 if propose else 1)))
            log(f"    ECHANGE {'annule' if propose else 'refuse'} par {current_pseudo['name']}")
            return
        etat, autre_etat = ECHANGES.get(moi), ECHANGES.get(part)
        if (not etat or not autre_etat or etat["partenaire"] != part or autre_etat["partenaire"] != moi
                or etat.get("initiateur") == moi):
            # pas d'echange propose par ce joueur : on n'accepte rien (l'accord d'un echange inexistant etait annonce)
            log(f"    ECHANGE : acceptation sans proposition de {part} ignoree ({current_pseudo['name']})"); return
        etat["accepte"] = autre_etat["accepte"] = True
        conn.sendall(P.build_frame(92, b"\x02"+P.field_int(part)+P.field_byte(1)))
        if cl: cl["conn"].sendall(P.build_frame(92, b"\x02"+P.field_int(moi)+P.field_byte(1)))
        log(f"    ECHANGE accepte entre {moi} et {part}")
        return

    if op == 93:
        # MON OFFRE : int(partenaire) + int(gils) + [int16(carte) + v(quantite)]*
        # (Ancien bug : la carte etait lue un octet trop tot -> identifiant inexistant renvoye
        #  au partenaire, dont le client plantait en 0040505A en cherchant la carte.)
        f = parse_typed(payload); ints = [v for k, v in f if k == "int"]
        if not ints: log("    !! op93 mal forme"); return
        part = ints[0]; gils = ints[1] if len(ints) > 1 else 0
        moi = current_pseudo["id"]; pdb = current_pseudo.get("db_id")
        offre = {}; champs = [(k, v) for k, v in f if k in ("h16", "v")]
        for (k1, c_id), (k2, qte) in zip(champs[0::2], champs[1::2]):
            if k1 == "h16" and k2 == "v" and qte > 0: offre[c_id] = offre.get(c_id, 0) + qte   # une carte citee 2 fois
        cartes = list(offre.items())
        etat = ECHANGES.get(moi)
        if not etat or etat["partenaire"] != part:
            sys_notice(conn, "Aucun echange en cours avec ce joueur.", "No trade in progress with this player."); return
        if not etat.get("accepte"):                       # 22 « L'echange avec %s n'a pas encore ete accepte »
            conn.sendall(P.build_frame(94, bytes([2]) + P.field_int(part) + P.field_byte(0) + P.field_v(22))); return
        # on ne peut offrir que ce que l'on possede et qui n'est ni aux encheres ni engage dans une partie a enjeu
        # (et il faut garder plus de 10 cartes)
        acc = db.get_account(SESSION.get("account_id")) or {}
        if any(cartes_disponibles(pdb, c_id) < qte for c_id, qte in cartes) or gils > acc.get("gils", 0):
            sys_notice(conn, "Offre refusee : tu ne possedes pas ces cartes ou ces gils.",
                       "Offer refused: you do not own these cards or these gils.")
            log(f"    ECHANGE : offre invalide de {current_pseudo['name']} ({cartes}, {gils} gils)")
            return
        if cartes and cartes_disponibles(pdb) - sum(q for _c, q in cartes) <= MIN_CARTES:
            conn.sendall(P.build_frame(94, bytes([2]) + P.field_int(part) + P.field_byte(0) + P.field_v(105)))
            log(f"    ECHANGE : offre refusee a {current_pseudo['name']} (il doit lui rester plus de {MIN_CARTES} cartes)")
            return
        etat.update(cartes=cartes, gils=gils, offre=True, valide=False)
        # une offre modifiee annule AUSSI la validation du partenaire : il validait l'ancienne, et l'on pouvait la
        # remplacer par une offre vide juste avant de valider soi-meme (audit du 2026-10-21)
        if ECHANGES.get(part): ECHANGES[part]["valide"] = False
        conn.sendall(P.build_frame(94, b"\x02"+P.field_int(part)+P.field_byte(1)))   # accuse
        cl = find_client(part)
        if cl:   # op95 : le partenaire voit mon offre (meme disposition que op93)
            corps = b"".join(_i16(c_id)+P.field_v(qte) for c_id, qte in cartes)
            cl["conn"].sendall(P.build_frame(95, b"\x02"+P.field_int(moi)+P.field_int(gils)+corps))
        log(f"    ECHANGE : {current_pseudo['name']} offre {cartes or 'aucune carte'} + {gils} gils")
        return

    if op == 96:
        # b1 = je valide l'echange ; b0 = je l'annule
        f = parse_typed(payload); ints = [v for k, v in f if k == "int"]
        if not ints: return
        part = ints[0]; moi = current_pseudo["id"]
        valide = next((v for k, v in f if k == "b"), 1)
        etat = ECHANGES.get(moi); cl = find_client(part)
        if not etat or etat["partenaire"] != part:
            conn.sendall(echange_annule_frame(part)); return
        autre_etat = ECHANGES.get(part)
        if not valide or not cl or not autre_etat or autre_etat["partenaire"] != moi or not etat.get("accepte"):
            ECHANGES.pop(moi, None); ECHANGES.pop(part, None)
            conn.sendall(echange_annule_frame(part))
            if cl: cl["conn"].sendall(echange_annule_frame(moi))
            log(f"    ECHANGE annule par {current_pseudo['name']}")
            return
        with _VERROU_ECHANGES:
            etat["valide"] = True
            if not autre_etat.get("valide"):
                return                               # on attend l'autre joueur
            # les deux ont valide : l'echange quitte la table ICI, sous le verrou. Deux validations simultanees
            # faisaient le transfert deux fois (audit du 2026-10-21).
            if ECHANGES.get(moi) is not etat or ECHANGES.get(part) is not autre_etat: return
            ECHANGES.pop(moi, None); ECHANGES.pop(part, None)
        # --- transfert reel, apres une derniere verification : depuis les offres, des gils ont pu etre depenses et des
        # cartes vendues, mises aux encheres ou engagees dans une partie ---
        db_moi, db_lui = moi - 1000, part - 1000
        acc_moi, acc_lui = db.account_of_pseudo(db_moi), db.account_of_pseudo(db_lui)
        meme_compte = not acc_moi or not acc_lui or acc_moi["id"] == acc_lui["id"]
        possible = not meme_compte and all(cartes_disponibles(pdb_, c_id) >= qte
                                           for pdb_, e in ((db_moi, etat), (db_lui, autre_etat)) for c_id, qte in e["cartes"])
        paye_moi = possible and db.retirer_gils(acc_moi["id"], etat["gils"])
        paye_lui = paye_moi and db.retirer_gils(acc_lui["id"], autre_etat["gils"])
        if not paye_lui:
            if paye_moi: db.add_gils(acc_moi["id"], etat["gils"])
            for c_conn, autre_pid in ((conn, part), (cl["conn"], moi)):
                try: c_conn.sendall(echange_annule_frame(autre_pid))
                except OSError: pass
            sys_notice(conn, "Echange annule : des cartes ou des gils offerts ne sont plus disponibles.",
                       "Trade cancelled: some of the cards or gils offered are no longer available.")
            sys_notice(cl["conn"], "Echange annule : des cartes ou des gils offerts ne sont plus disponibles.",
                       "Trade cancelled: some of the cards or gils offered are no longer available.")
            log(f"    ECHANGE {current_pseudo['name']} / {part} annule a la conclusion : offres plus disponibles")
            return
        for donneur, receveur, e in ((db_moi, db_lui, etat), (db_lui, db_moi, autre_etat)):
            for c_id, qte in e["cartes"]:
                for _ in range(qte):
                    if db.remove_card(donneur, c_id): db.add_card(receveur, c_id)
        db.add_gils(acc_lui["id"], etat["gils"]); db.add_gils(acc_moi["id"], autre_etat["gils"])
        for c_conn, pdb_, acc_, autre_pid in ((conn, db_moi, acc_moi, part), (cl["conn"], db_lui, acc_lui, moi)):
            c_conn.sendall(build_collection_frame(db.get_collection(pdb_), c_conn))
            if acc_: annoncer_gils(c_conn, acc_["id"])
            c_conn.sendall(P.build_frame(97, b"\x02"+P.field_int(autre_pid)+P.field_byte(1)))
        ECHANGES.pop(moi, None); ECHANGES.pop(part, None)
        log(f"    *** ECHANGE CONCLU : {current_pseudo['name']} donne {etat['cartes']} + {etat['gils']} gils, "
            f"recoit {autre_etat['cartes']} + {autre_etat['gils']} gils")
        return

    if op == 97:
        # le client referme l'echange de son cote
        moi = current_pseudo["id"]
        etat = ECHANGES.pop(moi, None)
        if etat:
            part = etat["partenaire"]; ECHANGES.pop(part, None)
            cl = find_client(part)
            if cl: cl["conn"].sendall(echange_annule_frame(moi))
        log("    ECHANGE annule")
        return

    if op == 156:
        # DEMANDE DE VISIONNAGE : 03 | int(numero de partie) | b   (le client envoie le format « ub »).
        # Rien de tout cela n'a ete capture : chaque trame ci-dessous est lue dans son gestionnaire du client.
        #   op157  03 | b1 | int(partie)     le client cherche la partie dans SA liste (onglet Parties, remplie par
        #                                    op232) avec ce numero : c'est le PETIT numero, pas « numero << 8 | 3 ».
        #                                    Avec l'ancien identifiant il ne trouvait rien et ne faisait rien, sans
        #                                    message (signale le 2026-09-20). Refus : 03 | b0 | v(code 56 a 60).
        #   op161  l'etat complet : score, regles, regle du vainqueur, mise, les 9 cases (G.trame_etat_spectateur)
        #   op135 / op136  les deux mains (dos de cartes, 0 = deja jouee), op137/138 le plateau, op139 le tour
        #   op160  03 | int(partie) | int(pid)*   les spectateurs presents ; op158 les annonce aux autres
        ints = [val for k, val in parse_typed(payload) if k == "int"]
        made = ints[0] if ints else -1
        partie = next((g for g in parties_en_cours() if g.made == made), None)
        def refus(code):
            conn.sendall(P.build_frame(157, bytes([3]) + P.field_byte(0) + P.field_v(code)))
            log(f"    SPECTATEUR refuse (partie {made}) : code {code}")
        if not partie: return refus(58)                       # « n'existe pas ou plus »
        if GAMES.get(id(conn)) is partie: return refus(56)    # « spectateur de sa propre partie »
        if conn in SPECTATEURS.get(partie.game_id, []): return refus(60)
        if not partie.pret: return refus(57)                  # « n'a pas encore commence »
        if not partie.spectators and "spygame" not in permissions_de(SESSION): return refus(59)
        SPECTATEURS.setdefault(partie.game_id, []).append(conn)
        conn.sendall(P.build_frame(157, bytes([3]) + P.field_byte(1) + P.field_int(partie.made)))     # accord
        for fr in partie.trames_plateau(): conn.sendall(fr)      # elements / restrictions de la partie
        for fr in partie.trames_mains_spectateur(): conn.sendall(fr)
        conn.sendall(partie.trame_etat_spectateur())
        reste = max(0, int((getattr(partie, "echeance", None) or time.time()) - time.time() - 2))
        conn.sendall(P.build_frame(139, partie._gid() + P.field_v(partie.tour_spectateur) + G._int16(reste)))
        presents = [_sess(c)["pseudo"].get("id") for c in SPECTATEURS[partie.game_id]]
        conn.sendall(P.build_frame(160, partie._gid() + b"".join(P.field_int(p_) for p_ in presents if p_)))
        arrivee = P.build_frame(158, partie._gid() + P.field_int(current_pseudo["id"]))
        for c in SPECTATEURS[partie.game_id] + [cl["conn"] for cl in map(find_client, joueurs_de(partie)) if cl]:
            try: c.sendall(arrivee)
            except OSError: pass
        annoncer_spectateurs(partie)
        log(f"    SPECTATEUR {current_pseudo['name']} regarde la partie {partie.made}")
        return
    if op == 162:
        # « Arreter de regarder la partie » : 03 | int(numero de partie)  (format « u », lu dans le client)
        ints = [val for k, val in parse_typed(payload) if k == "int"]
        partie = next((g for g in parties_en_cours() if ints and g.made == ints[0]), None)
        if partie: quitter_spectateur(conn, partie, accuse=True)
        else: conn.sendall(P.build_frame(163, bytes([3]) + P.field_int(ints[0] if ints else 0) + P.field_byte(1)))
        log(f"    SPECTATEUR {current_pseudo['name']} ne regarde plus la partie {ints[0] if ints else '?'}")
        return
    if op == 149:
        # CHOIX DES GAINS : 03 | int(numero de partie) | v(indice dans la liste d'op145)*
        f = parse_typed(payload)
        made = next((val for k, val in f if k == "int"), None)
        indices = [val for k, val in f if k == "v"]
        with _VERROU_CHOIX: etat = CHOIX_EN_COURS.get(made)
        if not etat or etat["game"].pids[etat["cote"]] != current_pseudo["id"]:
            conn.sendall(P.build_frame(150, b"\x03" + P.field_int(made or 0) + P.field_byte(0) + P.field_v(53)))
            return                                            # 53 = « Vous n'avez pas gagne la partie avec %s »
        if len(set(indices)) != etat["n"]:
            conn.sendall(P.build_frame(150, etat["game"]._gid() + P.field_byte(0) + P.field_v(84)))
            return
        resoudre_choix(made, sorted(set(indices)))
        return
    if op == 154:
        # « le temps de mon adversaire est ecoule » (envoye chaque seconde par le client qui
        # attend). Le chien de garde du serveur fait deja jouer le retardataire ; on en profite
        # seulement pour ne pas attendre son prochain passage.
        game = GAMES.get(id(conn))
        if game and getattr(game, "echeance", None) and time.time() >= game.echeance - 1.5:
            game.echeance = time.time()
        return
    if op == 151:
        # CHAT DANS LA PARTIE : int(game_id) + ctx + str(message)
        try:
            gid = struct.unpack("<I", payload[1:5])[0]
            msg,_ = P.decode_string(payload, 6)
        except Exception: return
        partie = next((g for g in list(GAMES.values()) if getattr(g,"game_id",None)==gid), None)
        # seuls les joueurs et les spectateurs de la partie y ecrivent (n'importe qui ecrivait dans n'importe quelle
        # partie par son numero, sequentiel)
        if not partie or (GAMES.get(id(conn)) is not partie and conn not in SPECTATEURS.get(gid, [])):
            log(f"    (chat de partie de {current_pseudo['name']} ignore : ni joueur ni spectateur de {gid})"); return
        msg = filtrer_message(conn, SESSION, current_pseudo, msg, "partie")      # muet, anti-flood, longueur
        if msg is None: return
        fr = P.build_frame(153, P.field_int(gid)+b"\x00"+P.field_int(current_pseudo["id"])
                           +P.field_str(msg)+P.field_byte(0))
        conn.sendall(fr)
        if partie:
            for c in SPECTATEURS.get(gid, []):
                if c is not conn:
                    try: c.sendall(fr)
                    except OSError: pass
            for pid in (getattr(partie,"pids",None) or [getattr(partie,"my_pid",0)]):
                cl = find_client(pid)
                if cl and cl["conn"] is not conn:
                    try: cl["conn"].sendall(fr)
                    except OSError: pass
        log(f"    CHAT PARTIE {current_pseudo['name']}: {msg!r}")
        return
    if op == 188:
        # METTRE UNE CARTE AUX ENCHERES : ctx2 + int16(carte) + int32(prix depart) + int32(achat immediat)
        try:
            card_id = struct.unpack("<H", payload[2:4])[0]
            prix    = struct.unpack("<I", payload[5:9])[0]
            immediat= struct.unpack("<I", payload[10:14])[0]
        except Exception:
            log("    !! op188 mal forme"); return
        pdb = current_pseudo.get("db_id")
        # Capacite « Vente aux encheres » : sans elle le client grise deja le bouton (32 si une trame arrive quand
        # meme) ; son niveau fixe le nombre de ventes simultanees du COMPTE (ENCHERES_MAX, lu dans le client).
        niv_ve = db.get_skill_level(pdb, 4)
        stock = db.stock_id(pdb)
        en_vente = sum(1 for a in db.list_auctions() if db.stock_id(a["seller_pseudo"]) == stock)
        refus = (99 if experience(pdb) < EXP_MIN_ACTIONS else
                 46 if cartes_disponibles(pdb, card_id) < 1 else
                 101 if cartes_disponibles(pdb) <= MIN_CARTES else
                 32 if niv_ve < 1 else
                 31 if en_vente >= ENCHERES_MAX.get(niv_ve, ENCHERES_MAX[3]) else 0)
        if refus:                                     # op189 « 02 b0 v(code) »
            conn.sendall(P.build_frame(189, bytes([2]) + P.field_byte(0) + P.field_v(refus)))
            log(f"    enchere refusee (carte {card_id}) : code {refus}"); return
        # la carte reste dans la collection tant que la vente n'est pas conclue
        aid = db.create_auction(pdb, current_pseudo["name"], card_id, prix, immediat)
        conn.sendall(P.build_frame(189, b"\x02"+P.field_byte(1)+_i16(card_id)))     # accuse
        a = db.get_auction(aid)
        broadcast(auction_frame(a))                 # fiche a tous, vendeur compris (une seule fois !)
        log(f"    *** ENCHERE #{aid} : carte {card_id} (depart {prix}, immediat {immediat})")
        return
    if op == 191:
        # MISER : ctx2 + int32(id enchere) + int32(montant)
        try:
            aid     = struct.unpack("<I", payload[2:6])[0]
            montant = struct.unpack("<I", payload[7:11])[0]
        except Exception:
            log("    !! op191 mal forme"); return
        pdb = current_pseudo.get("db_id")
        a = db.get_auction(aid)
        # Une enchere CLOSE (achat immediat deja conclu) acceptait encore des mises : chacune remboursait la precedente
        # et livrait un nouvel exemplaire de la carte, pour 1 gil (audit du 2026-10-21). Desormais : enchere active et
        # pas encore expiree, pas la sienne, au moins le prix de depart ; la mise est debitee AVANT d'etre enregistree
        # (debit conditionnel), et bid_auction l'enregistre d'un seul tenant en rendant l'ancien meilleur offrant.
        if not a or not a["actif"] or a["fin"] <= time.time():
            sys_notice(conn, "Cette enchere n'existe plus.", "This auction no longer exists."); return
        if db.stock_id(a["seller_pseudo"]) == db.stock_id(pdb):
            sys_notice(conn, "Tu ne peux pas miser sur ta propre enchere.", "You cannot bid on your own auction."); return
        if montant <= a["meilleure_offre"] or montant < (a["prix_depart"] or 0):
            sys_notice(conn, "Mise trop basse.", "Bid too low."); return
        if not db.retirer_gils(SESSION.get("account_id"), montant):
            sys_notice(conn, "Gils insuffisants pour cette mise.", "Not enough gils for this bid."); return
        ok, ancien, ancienne_offre = db.bid_auction(aid, pdb, montant)
        if not ok:                                   # depassee ou close entre-temps : la mise est rendue
            db.add_gils(SESSION["account_id"], montant)
            sys_notice(conn, "Mise trop basse.", "Bid too low."); return
        if ancien and ancienne_offre:                # rembourser l'ancien meilleur offrant (une seule fois)
            _acc_ancien = _acc_of(ancien)
            if _acc_ancien:
                db.add_gils(_acc_ancien, ancienne_offre)
                _cl = find_client(1000 + ancien)
                if _cl and _cl["conn"] is not conn: annoncer_gils(_cl["conn"], _acc_ancien)
        a = db.get_auction(aid)
        reste = (db.get_account(SESSION["account_id"]) or {}).get("gils", 0)
        import time as _t
        timer = max(0, int(a["fin"] - _t.time()))

        conn.sendall(P.build_frame(192, b"\x02"+P.field_byte(1)+_i32(aid)+_i32(montant)))   # accuse
        maj = P.build_frame(193, b"\x02"+_i32(aid)+_i32(montant)
                            +P.field_str(current_pseudo["name"])+_i16(min(timer,65535)))
        conn.sendall(maj); broadcast(maj, exclude_conn=conn)                                 # nouvelle meilleure offre
        conn.sendall(P.build_frame(47, b"\x01"+P.field_int(reste)))                          # ton solde de gils
        log(f"    MISE {montant} gils sur l'enchere #{aid} par {current_pseudo['name']} (reste {reste})")

        # achat immediat atteint -> on conclut la vente (une seule fois : close_auction ne rend True qu'au premier appel)
        if a["achat_immediat"] and montant >= a["achat_immediat"] and db.close_auction(aid):
            # un robot n'a pas de collection ; un joueur doit encore avoir la carte (sinon personne ne l'aurait payee :
            # elle n'est plus livree « en plus », la mise est rendue)
            if a["seller_pseudo"] > 0 and not db.remove_card(a["seller_pseudo"], a["card_id"]):
                db.add_gils(SESSION["account_id"], montant)
                annoncer_gils(conn, SESSION["account_id"])
                broadcast(P.build_frame(196, b"\x02"+_i32(aid)))
                sys_notice(conn, "Vente annulee : le vendeur n'a plus cette carte. Ta mise t'est rendue.",
                           "Sale cancelled: the seller no longer has this card. Your bid is refunded.")
                log(f"    ENCHERE #{aid} annulee : le vendeur n'a plus la carte {a['card_id']}"); return
            db.add_card(pdb, a["card_id"])                                   # elle te revient
            with db._conn() as _c:
                _r=_c.execute("SELECT account_id FROM pseudos WHERE id=?", (a["seller_pseudo"],)).fetchone()
            if _r: db.add_gils(_r["account_id"], montant)                    # le vendeur encaisse
            conn.sendall(P.build_frame(63, b"\x01"+P.field_byte(1)+_i16(a["card_id"])+P.field_v(1)+P.field_int(0)))
            conn.sendall(build_collection_frame(db.get_collection(pdb), conn))   # rafraichit toutes les listes
            fin = P.build_frame(196, b"\x02"+_i32(aid))
            conn.sendall(fin); broadcast(fin, exclude_conn=conn)
            sys_notice(conn, f"Carte {a['card_id']} achetee pour {montant} gils !", f"Card {a['card_id']} bought for {montant} gils!")
            vendeur = find_client(1000 + a["seller_pseudo"])
            if vendeur:
                vendeur["conn"].sendall(P.build_frame(63, b"\x01"+P.field_byte(0)
                    +_i16(a["card_id"])+P.field_v(1)+P.field_int(0)))     # carte retiree au vendeur
                if _r:
                    _sv = db.get_account(_r["account_id"]) or {}
                    vendeur["conn"].sendall(P.build_frame(47, b"\x01"+P.field_int(_sv.get("gils",0))))
                sys_notice(vendeur["conn"], f"Ta carte {a['card_id']} a ete vendue {montant} gils.",
                           f"Your card {a['card_id']} was sold for {montant} gils.")
            log(f"    *** VENTE CONCLUE : enchere #{aid} carte {a['card_id']} pour {montant} gils")
            if a["seller_pseudo"] < 0: encheres_des_robots()            # le robot remet aussitot une carte en vente
        return
    if op == 194:
        # ANNULER UNE ENCHERE : ctx2 + int32(id) + byte
        try: aid = struct.unpack("<I", payload[2:6])[0]
        except Exception: log("    !! op194 mal forme"); return
        a = db.get_auction(aid)
        if not a: return
        if db.stock_id(a["seller_pseudo"]) != db.stock_id(current_pseudo.get("db_id")) and not SESSION.get("admin"):
            sys_notice(conn, "Ce n'est pas ton enchere.", "This is not your auction."); return
        if not db.close_auction(aid): return                         # deja close : rien a annuler ni a rendre
        a = db.get_auction(aid) or a                                 # la meilleure offre au moment de la cloture
        if a["meilleur_offrant"] and a["meilleure_offre"]:          # la mise en cours est rendue (elle etait perdue)
            _acc_o = _acc_of(a["meilleur_offrant"])
            if _acc_o:
                db.add_gils(_acc_o, a["meilleure_offre"])
                _cl = find_client(1000 + a["meilleur_offrant"])
                if _cl: annoncer_gils(_cl["conn"], _acc_o)
        conn.sendall(P.build_frame(195, b"\x02"+P.field_byte(1)+_i32(aid)))   # accuse
        broadcast(P.build_frame(196, b"\x02"+_i32(aid)))                       # retrait de la liste (tous, moi compris)
        conn.sendall(build_collection_frame(db.get_collection(current_pseudo.get("db_id")), conn))
        log(f"    ENCHERE #{aid} annulee, carte {a['card_id']} rendue")
        if a["seller_pseudo"] < 0: encheres_des_robots()                # retiree par un operateur : une autre carte
        return
    if op == 244:
        # ACHAT / AMELIORATION D'UNE COMPETENCE : ctx + v(id competence)
        skill = payload[2] if len(payload) > 2 else 0
        pdb = current_pseudo.get("db_id")
        niveau = db.get_skill_level(pdb, skill)
        cout, nom = cout_competence(skill, niveau)
        libelle = SKILL_TABLE.get(nom, {}).get("libelle", f"Competence {skill}")
        # Accuse = op245 (gestionnaire 0x640580 du client) : « 01 b1 v(id) v(niveau) » affiche « Le niveau
        # de la capacite %s est maintenant de %d ! » ; « 01 b0 v(code) » affiche l'erreur du code :
        # 16 deja au plus haut niveau, 17 pas assez de powers, 18 capacite inconnue.
        dispo = db.get_powers(pdb)
        echec = 18 if nom is None else 16 if cout is None else 17 if dispo < cout else 0
        if echec:
            conn.sendall(P.build_frame(245, bytes([1]) + P.field_byte(0) + P.field_v(echec)))
            log(f"    competence {skill} refusee : code {echec}"); return
        db.add_powers(pdb, -cout)
        db.set_skill_level(pdb, skill, niveau+1)
        reste = db.get_powers(pdb)
        conn.sendall(P.build_frame(48, b"\x01"+P.field_int(reste)))
        lvl_op = SKILL_LEVEL_OP.get(skill)
        if lvl_op:
            conn.sendall(P.build_frame(lvl_op, b"\x01"+P.field_v(niveau+1)))
        conn.sendall(P.build_frame(245, bytes([1]) + P.field_byte(1) + P.field_v(skill) + P.field_v(niveau+1)))
        log(f"    COMPETENCE {skill} ({libelle}) niveau {niveau+1} (-{cout} powers) -> reste {reste}")
        # (pas d'annonce dans le chat : a la reception de l'opcode de niveau le client ecrit lui-meme
        #  « Capacite %s niveau %d »)
        return
    if op == 66:
        # Fenetre « Mes cartes » (TfrmMyCards) : ctx + int16(id carte) + v(action). L'action est le Tag du bouton
        # dans le DFM : 0 = JETER (btnDel, apres confirmation), 1 = POWERS (btnPower), 2 = ACHETER (btnBuy, mode
        # boutique), 3 = VENDRE (btnSell). Une action inconnue ne doit JAMAIS finir en achat : « Vendre » et « Jeter »
        # achetaient la carte (2026-09-23).
        f = parse_typed(payload)
        card_id = next((v for k, v in f if k == "h16"), None)
        action = next((v for k, v in f if k == "v"), None)
        if card_id is None or action not in ACTIONS_CARTE:
            log(f"    !! op66 inattendu : {f}"); return
        pdb = current_pseudo.get("db_id")
        if action != ACHETER:
            # JETER / POWERS / VENDRE : la carte quitte la collection (sequence capturee du sacrifice : op48 + op63 b0
            # + op67 b1). Refus = op67 « 01 b0 v(code) » : le client affiche le message du code (gestionnaire
            # 0x640259) ; 2000 points d'experience et « plus de 10 cartes » valent pour les trois (changelog, build 5448).
            refus = (99 if experience(pdb) < EXP_MIN_ACTIONS else
                     101 if cartes_disponibles(pdb) <= MIN_CARTES else
                     46 if cartes_disponibles(pdb, card_id) < 1 else 0)
            if refus:
                conn.sendall(P.build_frame(67, bytes([1]) + P.field_byte(0) + P.field_v(refus)))
                log(f"    {ACTIONS_CARTE[action]} refuse (carte {card_id}) : code {refus}"
                    + (f", il ne reste que {cartes_disponibles(pdb)} carte(s) disponibles" if refus == 101 else ""))
                return
            if not db.remove_card(pdb, card_id):
                # carte non possedee en base (desync d'affichage) : on ignore proprement
                log(f"    {ACTIONS_CARTE[action]} ignore : carte {card_id} absente de la base")
                sys_notice(conn, "Carte non disponible (redemarre le client pour resynchroniser).",
                           "Card not available (restart the game to resynchronise).")
                return
            detail = ""
            if action == POWERS:
                # powers d'une carte = prix / 100 (changelog 3.3) ; Connaisseur : +20% par niveau
                niv_con = db.get_skill_level(pdb, 2)
                base_pw = max(1, (db.ref_price(card_id) or 1000) // 100)
                gain = int(round(base_pw * (1 + 0.20*niv_con)))
                db.add_powers(pdb, gain)
                total = db.get_powers(pdb)
                conn.sendall(P.build_frame(48, b"\x01"+P.field_int(total)))
                detail = f" -> power total={total} (+{gain})"
            elif action == VENDRE:
                gain = max(1, round((db.ref_price(card_id) or 100) * TAUX_VENTE))   # comme l'affiche le client
                db.add_gils(SESSION["account_id"], gain)
                solde = (db.get_account(SESSION["account_id"]) or {}).get("gils", 0)
                conn.sendall(P.build_frame(47, b"\x01"+P.field_int(solde)))
                detail = f" -> +{gain} gils, gils={solde}"
            conn.sendall(P.build_frame(63, b"\x01"+P.field_byte(0)+_i16(card_id)+P.field_v(1)+P.field_int(0)))
            conn.sendall(P.build_frame(67, b"\x01"+P.field_byte(1)))
            log(f"    {ACTIONS_CARTE[action].upper()} carte {card_id}{detail}")
            return
        # ACHAT — prix reel de la carte (cartes.json : power x 100) ; Souk : -5% par niveau
        if next((c["qty"] for c in db.get_collection(pdb) if c["card_id"] == card_id), 0) >= MAX_EXEMPLAIRES:
            conn.sendall(P.build_frame(67, bytes([1]) + P.field_byte(0) + P.field_v(15)))   # 15 = 255 exemplaires
            log(f"    achat refuse (carte {card_id}) : deja {MAX_EXEMPLAIRES} exemplaires"); return
        # seulement une carte de la table, que le client connait : un identifiant inexistant s'achetait 100 gils (valeurs
        # tirees au hasard, et le client des autres joueurs plante sur une carte qu'il ne connait pas)
        PRICE = db.ref_price(card_id)
        if PRICE is None or not 0 < card_id <= cartes_connues(conn):
            conn.sendall(P.build_frame(67, bytes([1]) + P.field_byte(0) + P.field_v(46)))   # 46 : carte indisponible
            log(f"    achat refuse : carte {card_id} inconnue"); return
        niv_souk = next((db.get_skill_level(pdb, sid) for sid,n in SKILL_BY_ID.items() if n=="souk"), 0)
        if niv_souk: PRICE = max(1, int(PRICE * (1 - 0.05*niv_souk)))
        if db.retirer_gils(SESSION.get("account_id"), PRICE):            # debit conditionnel : jamais de solde negatif
            db.add_card(pdb, card_id)
            solde = (db.get_account(SESSION["account_id"]) or {}).get("gils", 0)
            conn.sendall(P.build_frame(63, b"\x01"+P.field_byte(1)+_i16(card_id)+P.field_v(1)+P.field_int(0)))
            conn.sendall(P.build_frame(67, b"\x01"+P.field_byte(1)))
            conn.sendall(P.build_frame(47, b"\x01"+P.field_int(solde)))   # solde de gils
            log(f"    ACHAT carte {card_id} (-{PRICE} gils) -> gils={solde}")
        else:
            conn.sendall(P.build_frame(67, bytes([1]) + P.field_byte(0) + P.field_v(14)))   # 14 = pas assez de gils
        return
    if op == 64:
        # ouvrir un profil : payload = ctx + int(pid)
        pid = struct.unpack("<I", payload[2:6])[0] if len(payload)>=6 else 0
        if pid in G.ROBOTS:
            fr = build_profile(G.ROBOTS[pid]["nom"], pid=pid)
        else:
            # soi-meme ou un joueur connecte : profil d'apres la base (profil_joueur, comme « Infos offline ») ; compte,
            # host et e-mail masques selon les permissions de celui qui regarde (avant le 2026-10-12, le pseudo etait
            # affiche comme nom de compte a tout le monde, et les dates de creation etaient fixes)
            cible_db = current_pseudo.get("db_id") if pid == current_pseudo["id"] else (pid - 1000 if find_client(pid) else None)
            fr = profil_joueur(cible_db, SESSION) if cible_db else None
            if fr is None: fr = build_profile(f"Joueur{pid}", pid=pid)
        log(f"    PROFIL demande pid={pid}")
        conn.sendall(fr)
        # Dans la capture, CHAQUE op65 est suivi des notes : op66 (categorie 6 : notes PERSONNELLES, seulement pour son
        # propre profil ; vides = trame identique a la capture) puis op241 (notes publiques, onglet du groupe 1),
        # meme quand le joueur n'a rien ecrit.
        if pid == current_pseudo["id"]:
            conn.sendall(P.build_frame(66, bytes([6]) + champ_zlib(db.get_note_perso(current_pseudo.get("db_id")))))
        note_db = current_pseudo.get("db_id") if pid==current_pseudo["id"] else (pid-1000 if pid>1000 else None)
        note_txt = (db.get_note(note_db) if note_db is not None else "") or ""
        conn.sendall(notes_frame(pid, note_txt))
        return
    if op == 146:
        # message prive : ctx + int(cible) + str(message) + b0
        try:
            target = struct.unpack("<I", payload[2:6])[0]
            msg,_ = P.decode_string(payload, 6)
        except Exception:
            log("    !! op146 mal forme"); return
        msg = filtrer_message(conn, SESSION, current_pseudo, msg, "mp")          # muet, anti-flood, longueur
        if msg is None: return
        log(f"    MP de {current_pseudo['name']} a {target}")    # le contenu d'un message prive n'est pas journalise
        # echo dans ta fenetre
        conn.sendall(P.build_frame(147, b"\x01"+P.field_byte(0)+P.field_int(target)+P.field_str(msg)+P.field_byte(0)))
        dest=find_client(target)
        if dest:
            # vrai joueur en ligne -> on lui transmet (b1 = message recu, de ta part)
            dest["conn"].sendall(P.build_frame(147, b"\x01"+P.field_byte(1)
                                 +P.field_int(current_pseudo["id"])+P.field_str(msg)+P.field_byte(0)))
        else:
            for rep in (BOT_REPLIES_EN if langue_de(conn) == "en" else BOT_REPLIES):
                conn.sendall(P.build_frame(147, b"\x01"+P.field_byte(1)+P.field_int(target)+P.field_str(rep)+P.field_byte(0)))
        return
    if op == 5:
        # VERSION du client -> op6 b(1) « Session initialisee » ou b(0) « Vous ne possedez pas la bonne version de
        # FFWTT » (capture : op6 part APRES op5).
        version = next((v for k, v in parse_typed(payload) if k == "int"), 0)
        connues = P.CARTES_CLIENT
        send(conn, P.build_frame(6, b"\x00" + P.field_byte(1)),
             f"op6 b1 : version {version}" + (f" ({connues} cartes)" if connues != P.CARTES_CLIENT else ""))
        return
    if op == 32:
        # DEFI : ctx3 + int(cible) + int16(regles) + v(regle vainqueur) + int(mise gils)
        #        + v(index du temps) + b(spectateurs autorises).  La cible = pid BRUT.
        f = parse_typed(payload)
        ints = [v for k, v in f if k == "int"]
        vlist = [v for k, v in f if k == "v"]
        target_pid  = ints[0] if ints else 0
        bet         = ints[1] if len(ints) > 1 else 0
        rules_mask  = next((v for k, v in f if k == "h16"), 0)
        winner_rule = vlist[0] if vlist else 0
        timer_idx   = vlist[1] if len(vlist) > 1 else 0
        spec        = next((v for k, v in f if k == "b"), 1)
        gr = G.rules_from_mask(rules_mask) if rules_mask else dict(RULES)
        timer = TIMER_SECONDS.get(timer_idx, 300)
        me_coll = db.get_collection(current_pseudo.get("db_id"))
        opp = find_client(target_pid)
        if trop_vite(SESSION, "defi"):
            log(f"    (defi de {current_pseudo['name']} ignore : envois trop rapproches)"); return
        if opp and opp["conn"] is not conn and target_pid not in G.ROBOTS:
            if winner_rule == ENTRAINEMENT: bet = 0          # partie sans enjeu : la mise n'etait jamais rendue
            refus = refus_regle_vainqueur(current_pseudo, opp, winner_rule)
            if not refus and bet:                            # 14 « pas assez de gils », 40 « %s ne possede pas assez... »
                refus = (14 if (db.get_account(SESSION.get("account_id")) or {}).get("gils", 0) < bet else
                         40 if (db.get_account(_acc_of(target_pid - 1000)) or {}).get("gils", 0) < bet else 0)
            if refus:
                conn.sendall(P.build_frame(33, b"\x03" + P.field_int(target_pid) + P.field_byte(0) + P.field_v(refus)))
                log(f"    defi refuse (regle '{WINNER_RULES.get(winner_rule,'?')}') : code {refus}")
                return
            # === DEFI D'UN JOUEUR : on demande son accord (op34) ===
            echo = (P.field_int16(rules_mask) + P.field_v(winner_rule) + P.field_int(bet)
                    + P.field_v(timer_idx) + P.field_byte(spec))
            conn.sendall(P.build_frame(33, b"\x03" + P.field_int(target_pid)
                         + P.field_byte(1) + echo))                              # accuse au defiant
            opp["conn"].sendall(P.build_frame(34, b"\x03" + P.field_int(current_pseudo["id"])
                         + echo))                                               # invitation a la cible
            PENDING[(current_pseudo["id"], target_pid)] = {
                "from_conn": conn, "from_pid": current_pseudo["id"],
                "from_name": current_pseudo["name"], "from_db": current_pseudo.get("db_id"),
                "to_pid": target_pid, "to_conn": opp["conn"],
                "rules_mask": rules_mask, "rules": gr, "winner_rule": winner_rule,
                "bet": bet, "timer": timer, "timer_idx": timer_idx, "spec": spec}
            r = ", ".join(k for k, v in gr.items() if v and k != "combo") or "de base"
            log(f"    *** DEFI : {current_pseudo['name']} -> {opp['name']} "
                f"(regles {r}, mise {bet}, {timer}s, vainqueur '{WINNER_RULES.get(winner_rule,'?')}')")
            return
        # === DUEL CONTRE UN ROBOT (ou cible absente : le robot par defaut) ===
        # Les robots acceptent toutes les regles du joueur, mais JAMAIS d'enjeu : ni mise en gils, ni regle du
        # vainqueur qui ferait changer des cartes de main (« Entrainement » reste possible : partie sans
        # consequence). L'accuse op33 renvoie donc les parametres du defi CORRIGES (mise 0, vainqueur « Aucune ») :
        # meme format que la capture, et le client affiche ce qui sera reellement joue.
        if winner_rule != ENTRAINEMENT: winner_rule = AUCUNE
        bet = 0
        ancienne = GAMES.get(id(conn))               # une partie contre un robot encore ouverte : on la referme
        if ancienne is not None and not isinstance(ancienne, G.PvpGame):
            fin_pour_spectateurs(ancienne, 1, current_pseudo["id"])
            annoncer_fin_partie(ancienne, [], terminee=False)
        echo = (P.field_int16(rules_mask) + P.field_v(winner_rule) + P.field_int(bet)
                + P.field_v(timer_idx) + P.field_byte(spec))
        game = G.Game(current_pseudo["id"], target_pid, echo, ai_pid=target_pid, collection=me_coll, rules=gr,
                      made=next_made(), timer=timer, winner_rule=winner_rule,
                      bet=bet, spectators=spec)
        GAMES[id(conn)] = game
        annoncer_partie(game, [conn])
        log(f"    *** PARTIE vs {game.robot['nom']} (cible {target_pid}, gains x{game.robot['gain']}) ; ta main = {game.my_hand}")
        game.conns = [conn]; game.verrou = threading.RLock(); game.echeance = None
        for fr in game.deal_frames():
            conn.sendall(fr)
        if game.pret: armer_partie(game)
        return
    if op == 140 and id(conn) in GAMES:
        # pose d'une carte : 03 | int(partie) | v(index en main) v(x) v(y)
        game = GAMES[id(conn)]
        vs = [v for k, v in parse_typed(payload) if k == "v"]
        if len(vs) < 3: log("    !! op140 mal forme"); return
        cote = cote_de(game, conn) if isinstance(game, G.PvpGame) else 0
        jouer_coup(game, cote, vs[0], vs[1], vs[2])
        return
    if op == 144:
        # message de chat : ctx(1) + str(message) + b(mode action) -> diffusion op145
        try:
            msg, j = P.decode_string(payload, 1)   # l'octet 0 est le contexte
        except Exception:
            msg = ""; j = len(payload)
        # drapeau "mode action" (/me) : octet type-6 juste apres la chaine, echo dans op145
        action = payload[j+1] if (j < len(payload) and payload[j] == 0x06) else 0
        if action == 0 and msg.lower().startswith(("!quiz", "!quizz")):
            quiz_commande(conn, SESSION, current_pseudo, msg.split()[1:]); return
        if action == 0 and msg.startswith("!"):
            commande_sondage(conn, msg, current_pseudo)
            return
        msg = filtrer_message(conn, SESSION, current_pseudo, msg, "chat")        # muet, anti-flood, longueur
        if msg is None: return
        if MODERE["actif"] and "talkwhilemoderate" not in permissions_de(SESSION):
            # mode modere : le client a affiche « *** Le mode modere a ete active » (op82) ; la table d'erreurs du
            # client n'a pas de message pour ce refus, le message n'est donc simplement pas diffuse
            log(f"    CHAT ignore (mode modere) {current_pseudo['name']}: {msg!r}"); return
        log(f"    CHAT {current_pseudo['name']}: {msg!r}" + (" (action)" if action else ""))
        out = (b"\x01" + P.field_int(current_pseudo["id"]) + P.field_str(msg)
               + P.field_byte(action) + P.field_int(0))
        frame = P.build_frame(145, out)
        conn.sendall(frame)                      # a toi
        broadcast(frame, exclude_conn=conn)      # et a tous les autres
        quiz_reponse(current_pseudo, msg)
        return
    if op in (44, 71) and db.is_banned("nick", current_pseudo["name"]):
        # pseudo banni : le client ne le laisse pas choisir (op207 refuse), mais op100 selectionne d'office le pseudo
        # principal, et un script qui sautait op207 entrait au salon avec (audit du 2026-10-21)
        log(f"    *** ENTREE AU SALON REFUSEE : le pseudo {current_pseudo['name']} est banni"); return
    if op == 71:
        # le client a recu le salon -> on finalise l'entree
        # ton identite (op45) : le client cree lui-meme ta fiche
        me_pid = current_pseudo["id"]; me_name = current_pseudo["name"]
        # op45 (identite) et la liste des joueurs sont partis AVANT op62, dans la rafale (op44),
        # comme sur le serveur d'origine. Le client n'a PAS de fiche op59 pour lui-meme : lui en
        # envoyer une cree un doublon dans la liste et l'annonce « X vient d'entrer ».
        if not SESSION.get("identite_envoyee"):          # filet : op71 sans op44 prealable
            conn.sendall(P.build_frame(45, b"\x01"+P.field_int(me_pid)+P.field_str(me_name)))
        # enregistrer ce client comme joueur en ligne
        with CLIENTS_LOCK:
            CLIENTS[id(conn)] = {"conn": conn, "pid": me_pid, "name": me_name,
                                 "niveau": SESSION.get("admin", 0), "anim": SESSION.get("anim", 0),
                                 "langue": SESSION.get("langue", "fr"), "host": (conn.getpeername()[0] if conn else "")}
        # joueurs arrives entre la rafale et maintenant (ecran de CGU...) : vraies arrivees
        deja = SESSION.get("liste_vue", set())
        with CLIENTS_LOCK:
            others=[(c["pid"],c["name"],c.get("niveau",0),c.get("anim",0),c.get("langue","fr")) for c in CLIENTS.values() if c["conn"] is not conn]
        for pid_o,name_o,niv_o,anim_o,lang_o in others:
            if pid_o not in deja:
                conn.sendall(player_entry(pid_o, name_o, niveau=niv_o, anim=anim_o, langue=lang_o))
        # t'annoncer aux autres
        broadcast(player_entry(me_pid, me_name, niveau=SESSION.get("admin",0), anim=SESSION.get("anim",0),
                               langue=SESSION.get("langue", "fr")), exclude_conn=conn)
        log(f"    JOUEUR EN LIGNE {me_name} (id {me_pid}) ; {len(others)} autre(s) present(s)")
        GUILDES.connexion(current_pseudo.get("db_id"))
        send(conn, P.build_frame(72, b"\x01"+P.field_byte(1)), "op72 (ack)")
        send(conn, P.build_frame(73, b"\x01"+P.field_int(current_pseudo["id"])+P.field_byte(1)),
             "op73 (entree salon OK)")
        # les parties deja en cours : sans cela un joueur arrive apres leur debut ne peut pas les observer
        for _g in parties_en_cours():
            try: conn.sendall(P.build_frame(232, _g._gid() + _g.annonce()))
            except Exception as e: log(f"    (partie en cours non annoncee : {e})")
        # envoyer ta collection complete (base) via op52 (remplace le cache client)
        pdb = current_pseudo.get("db_id")
        coll = db.get_collection(pdb) or []
        conn.sendall(build_collection_frame(coll, conn))
        # ecraser le compteur de power de la rafale par ta vraie valeur (pour l'ecran competences)
        conn.sendall(P.build_frame(48, b"\x01"+P.field_int(db.get_powers(pdb))))
        # ton solde de gils (op47)
        _acc = db.get_account(SESSION.get("account_id")) or {}
        conn.sendall(P.build_frame(47, b"\x01"+P.field_int(_acc.get("gils",0))))
        # (les encheres en cours sont parties dans la rafale, avant op62, comme dans la capture)
        log(f"    collection ({len(coll)} cartes) + power {db.get_powers(pdb)} + {len(db.get_skills(pdb))} competences")
        # keepalive : ping op512 toutes les 10 s (le client repond op768)
        if not conn_state.get(id(conn)):
            conn_state[id(conn)]=True
            threading.Thread(target=keepalive, args=(conn,), daemon=True).start()
        return
    if op == 44:
        # DIAGNOSTIC : rejouer la rafale "informations du serveur" capturee,
        # pour confirmer que le client entre bien dans le chat.
        if ROOM_BURST:
            # ORDRE CALE SUR LA CAPTURE :
            #   86/87 (groupes, grades) 88 74 | 45 (ton identite) | 46..83 (compteurs) |
            #   59 x N (joueurs presents) | 190 x N (encheres) | 62 (fin de liste) | 166 (accueil)
            # Tout ce que le client ajoute a sa liste APRES op62 (op59, mais aussi op45) est
            # annonce comme une arrivee : « X vient d'entrer sur le FFWTT ». La capture ne contient
            # jamais de fiche op59 du joueur pour lui-meme (op45 suffit) : en envoyer une le
            # fait apparaitre deux fois dans la liste.
            me_pid = current_pseudo["id"]; me_name = current_pseudo["name"]
            ident = P.build_frame(45, b"\x01"+P.field_int(me_pid)+P.field_str(me_name))
            trames = P.parse_frames(bytearray(ROOM_BURST))
            dernier86 = max((i for i, (o, _) in enumerate(trames) if o == 86), default=-1)
            out = []; ident_ok = False; fiches = []
            # op81 (URL d'accueil / CGU) part EN PREMIER, comme dans la capture. Le client affiche la
            # page dans sa fenetre de chargement, qu'il DETRUIT en recevant op62 : une URL envoyee
            # apres op62 navigue dans une fenetre liberee -> « Access violation at 0061125E ».
            if ACCUEIL_URL:
                url = ACCUEIL_URL
                out.append(P.build_frame(81, b"\x01"+P.field_str(url)))
            # Ton identite (op45) puis ton grade (op61). « moi » doit exister AVANT toute fiche
            # op59 : le gestionnaire d'op59 parcourt les grades de « moi », et plante s'il n'existe
            # pas encore (« Access violation at 0063CED2, read of address 0000003C »).
            mes_grades = grades_de(SESSION.get("admin", 0), SESSION.get("anim", 0), SESSION.get("langue", "fr"))
            # identite, PUIS le panneau du salon (op177), PUIS les grades (op61) : le panneau doit
            # exister avant que « moi » ait un grade du groupe, donc avant toute fiche op59.
            moi = [ident] + trames_ouverture_salon(SESSION) + [grade_joueur_frame(me_pid, g) for g in mes_grades]
            # compteurs du panneau de gauche (op46..51) : les VRAIES valeurs, a la place de celles
            # de la capture (le client affichait « 23 victoires » jusqu'a la premiere partie)
            _st = db.get_stats(current_pseudo.get("db_id")) or {}
            _ac = db.get_account(SESSION.get("account_id")) or {}
            compteurs = {46: _st.get("noto", 0), 47: _ac.get("gils", 0),
                         48: db.get_powers(current_pseudo.get("db_id")) if current_pseudo.get("db_id") else 0,
                         49: _st.get("wins", 0), 50: _st.get("losses", 0), 51: _st.get("draws", 0)}
            # niveaux reels des competences, a la place de ceux de la rafale
            niveaux = {}
            if current_pseudo.get("db_id"):
                _sk = db.get_skills(current_pseudo["db_id"])
                if not isinstance(_sk, dict): _sk = {int(x): 1 for x in _sk}
                for sid, niv in _sk.items():
                    if SKILL_LEVEL_OP.get(int(sid)): niveaux[SKILL_LEVEL_OP[int(sid)]] = niv
            nos_groupes = {g[0] for g in GROUPES} | {20}          # 20 = groupe d'essai de la capture
            noto_ok = False; guildes_ok = False
            for i, (o, pl) in enumerate(trames):
                if o == 59: continue            # la fiche du robot de la capture : remplacee par nos robots
                if o in (45, 62, 81): continue                                # reconstruits ici
                if o == 74:                     # la liste des guildes : les NOTRES (la capture portait les siennes)
                    if not guildes_ok: out.extend(GUILDES.liste()); guildes_ok = True
                    continue
                if o == 86 and (parse_typed(pl)[1:2] or [("", 0)])[0][1] in nos_groupes:
                    pl = None                                                 # nos groupes remplacent ceux-la
                if o == 88:                                                   # nos categories de notoriete
                    if not noto_ok: out.extend(notoriete_frames(langue_de(conn))); noto_ok = True
                    continue
                if o == 83:                                                   # MES notorietes (6 x int16)
                    pl = bytes([1]) + b"".join(_i16(n) for n in db.get_notos(current_pseudo.get("db_id")))
                if o == 46 and not ident_ok:
                    out.extend(moi); ident_ok = True
                if o in niveaux: pl = bytes([1]) + P.field_v(niveaux[o])
                if o in compteurs: pl = bytes([1]) + P.field_int(compteurs[o])
                if pl is not None: out.append(P.build_frame(o, pl))
                if i == dernier86:
                    out.extend(groupe_frames(langue_de(conn)))       # op86 : nos groupes
                    out.extend(grade_frames(langue_de(conn)))        # op87 : grades, juste apres leurs groupes
            if not ident_ok: out.extend(moi)
            # --- liste des joueurs presents (sans toi) ---
            vus = set(G.ROBOTS) | {me_pid}
            out.extend(fiches_robots())       # avant op62 (apres, chaque robot serait annonce comme une arrivee)
            with CLIENTS_LOCK:
                others=[(c["pid"],c["name"],c.get("niveau",0),c.get("anim",0),c.get("langue","fr")) for c in CLIENTS.values() if c["conn"] is not conn]
            for pid_o, name_o, niv_o, anim_o, lang_o in others:
                if pid_o in vus: continue
                out.append(player_entry(pid_o, name_o, niveau=niv_o, anim=anim_o, langue=lang_o)); vus.add(pid_o)
            # --- ma guilde (op57 : il faut « moi » (op45) et la liste des guildes (op74) ; les fiches des membres (op78)
            #     veulent la liste des joueurs pour savoir qui est en ligne), ou mon tableau en cours (op92) ---
            try: out.extend(GUILDES.trames_entree(current_pseudo.get("db_id")))
            except Exception as e: log(f"    !! guilde non envoyee : {e}")
            # --- encheres en cours (et fiche du vendeur s'il est hors ligne) ---
            try:
                encheres = db.list_auctions()
            except AttributeError:
                encheres = []
                log("    !! ffwtt_db.py obsolete : pas de gestion des encheres")
            for a in encheres:
                spid = 1000 + (a["seller_pseudo"] or 0)
                if spid not in vus:
                    out.append(player_entry(spid, a["seller_name"] or "Marche", status=0)); vus.add(spid)
            for a in encheres: out.append(auction_frame(a))
            out.append(P.build_frame(62, b"\x01"))                            # fin de la liste
            conn.sendall(b"".join(out))
            SESSION["identite_envoyee"] = True; SESSION["liste_vue"] = vus
            log(f"  S->C  rafale salon ({len(out)} trames) : identite, {len(others)} joueur(s), "
                f"{len(encheres)} enchere(s), fin de liste")
            if ACCUEIL_URL: log(f"  S->C  page d'accueil (en tete de rafale) : {ACCUEIL_URL}")
            if mes_grades: log(f"  S->C  grades {mes_grades} attribues a {me_name} (op61)")
            for ligne in motd_de(conn):              # message d'accueil : apres op62, comme la capture
                conn.sendall(P.build_frame(166, b"\x06"+P.field_str(ligne)))
            if nouvelle_rapide():                    # la news rapide (/quicknews) : meme trame, « *** Infos : %s »
                conn.sendall(P.build_frame(166, b"\x06"+P.field_str(nouvelle_rapide())))
            if MODERE["actif"]:                      # op82 : le client note l'etat et l'annonce (« mode modere active »)
                conn.sendall(P.build_frame(82, bytes([1]) + P.field_byte(1)))
            if GROUPE_QUIZZ in SESSION.get("panneaux", ()):   # panneau Quizz : categories, etat, points (apres les op61)
                conn.sendall(b"".join(trames_quiz_panneau()))
        else:
            log("  !! room_burst_neutral.bin introuvable")
        return
    if op == 205:
        # SUPPRIMER UN PSEUDO (fenetre des pseudos, TfrmNick.btnDelClick) : ctx0 + int(id du pseudo) + str(e-mail),
        # le client ayant demande « Entrez votre e-mail pour la verification : ». Reponse lue dans le binaire (cas 206,
        # 0x63A7AF) : op206 b1 = le client retire lui-meme le pseudo de sa liste ; b0 v(code) = message du code.
        f = parse_typed(payload)
        pid_del = next((v for k, v in f if k == "int"), None)
        email = next((v for k, v in f if k == "str"), "").strip().lower()
        acc = db.get_account(SESSION.get("account_id")) or {}
        ps = db.get_pseudo_par_id(pid_del) if pid_del is not None else None
        code = (9 if not ps else                                          # « Pseudo inexistant »
                10 if ps["account_id"] != acc.get("id") else              # « Ce pseudo n'est pas le votre »
                8 if not email or email != (acc.get("email") or "").strip().lower() else   # « E-mail incorrect »
                30 if ps["is_main"] else                                  # « Impossible de supprimer le pseudo principal »
                80 if db.membre_de(pid_del)[0] else 0)                    # membre d'une guilde (ou d'un tableau)
        if code:
            conn.sendall(P.build_frame(206, b"\x00" + P.field_byte(0) + P.field_v(code)))
            log(f"    suppression du pseudo {pid_del} refusee : code {code}"); return
        for aid in db.supprimer_pseudo(pid_del):
            broadcast(P.build_frame(196, b"\x02" + _i32(aid)))           # ses encheres quittent la liste
        conn.sendall(P.build_frame(206, b"\x00" + P.field_byte(1)))
        log(f"    *** PSEUDO SUPPRIME : {ps['name']} (id {pid_del}, compte {acc.get('login')})")
        return
    if op == 207:
        # selection d'un pseudo (payload = int id) -> confirmation op208 (OK)
        ids=[v for k,v in P.decode_fields(payload) if k=="int"]
        pid_sel = ids[0] if ids else None
        moi_pid = current_pseudo["id"]
        occupe = (id(conn) in GAMES or moi_pid in ECHANGES or any(moi_pid in k for k in list(PENDING))
                  or any(conn in v for v in list(SPECTATEURS.values())))
        if occupe:
            # changer de pseudo pendant une partie, un defi, un echange ou un visionnage : refuse (87 « pas les
            # privileges »). En pleine partie, il donnait la main sur les cartes de l'adversaire (audit du 2026-10-21).
            conn.sendall(P.build_frame(208, b"\x00"+P.field_byte(0)+P.field_v(87)))
            log(f"    *** CHOIX DE PSEUDO REFUSE (id {pid_sel}) : partie, defi ou echange en cours"); return
        with db._conn() as _c:       # le pseudo doit appartenir au compte connecte
            _r=_c.execute("SELECT name FROM pseudos WHERE id=? AND account_id=?",
                          (pid_sel, SESSION.get("account_id"))).fetchone()
        if not _r or db.is_banned("nick", _r["name"]):
            # accuse negatif : b0 + v(code). 11 = « Ce pseudo est banni », 10 = « Ce pseudo n'est
            # pas le votre » (table des erreurs du client : py ffwtt_binaire.py --erreurs)
            code = 11 if _r else 10
            log(f"    *** CHOIX DE PSEUDO REFUSE (id {pid_sel}) : code {code}")
            conn.sendall(P.build_frame(208, b"\x00"+P.field_byte(0)+P.field_v(code)))
            return
        if _r:
            current_pseudo["id"]=1000+pid_sel; current_pseudo["name"]=_r["name"]; current_pseudo["db_id"]=pid_sel
        log(f"    pseudo choisi id={pid_sel} ({current_pseudo['name']})")
        send(conn, P.build_frame(208, b"\x00"+P.field_byte(1)), "op208 (pseudo OK)")
        return
    if op == 200:
        # liste des pseudos du compte (depuis la base)
        acc_id = SESSION.get("account_id")
        for p in db.get_pseudos(acc_id):
            # champs lus par le client : 5 = principal, 6 = BANNI (« %s (principal, banni) »)
            entry = (b"\x00" + P.field_int(p["id"]) + P.field_str(p["name"])
                     + P.field_str("") + P.field_int16(0)
                     + P.field_byte(p["is_main"])
                     + P.field_byte(1 if db.is_banned("nick", p["name"]) else 0))
            send(conn, P.build_frame(201, entry), f"op201 pseudo='{p['name']}'")
        send(conn, P.build_frame(202, b"\x00"), "op202 (fin de liste)")
        return
    if op == 100:
        # LOGIN via base : payload = ctx + [login] + [mot de passe]
        fields=[v for k,v in P.decode_fields(payload) if k=="str"]
        if len(fields) < 2 or SESSION.get("account_id"):
            log("    (op100 sans identifiant ni mot de passe, ou connexion deja identifiee : ignore)"); return
        login, pw = fields[0][:40], fields[1][:40]
        ip = SESSION.get("ip", "")
        refuser = lambda code: conn.sendall(P.build_frame(101, b"\x00"+P.field_byte(0)+P.field_v(code)))
        # Essais limites : 5 mots de passe refuses en 10 minutes pour un compte depuis une adresse, 30 pour une adresse
        # (rien ne freinait l'essai de mots de passe a la chaine). Pendant ce temps : « Mot de passe incorrect ».
        if (len(_recents(ECHECS_CONNEXION, (ip, login.lower()), ESSAIS_FENETRE)) >= ESSAIS_MAX
                or len(_recents(ECHECS_CONNEXION, (ip, None), ESSAIS_FENETRE)) >= ESSAIS_IP_MAX):
            refuser(3); log(f"    *** CONNEXION REFUSEE ({login}) : trop d'essais depuis {ip}"); return
        # creation a la premiere connexion, sauf si l'administration l'a fermee (reglages)
        souple = ((not BASE_FERMEE) and db.inscriptions_ouvertes() and not db.nom_interdit(login)
                  and not db.email_obligatoire())
        nouveau = souple and not db.account_by_login(login)
        if nouveau:
            # creation en jeu : CREATIONS_MAX comptes par adresse et par heure (chacun recevait gils et cartes de depart,
            # et la creation occupait le verrou de la base : une boucle d'op100 bloquait le serveur)
            if len(_recents(CREATIONS_COMPTES, ip, CREATIONS_FENETRE)) >= CREATIONS_MAX:
                refuser(91); log(f"    *** CREATION REFUSEE ({login}) : {CREATIONS_MAX} comptes deja crees depuis {ip} "
                                 f"dans l'heure"); return
            CREATIONS_COMPTES.setdefault(ip, []).append(time.time())
        acc, code = db.verifier_connexion(login, pw, base_souple=souple)
        if code:
            # 2 = banni, 3 = mot de passe incorrect, 91 = compte inexistant
            if code == 3:
                for cle in ((ip, login.lower()), (ip, None)): ECHECS_CONNEXION.setdefault(cle, []).append(time.time())
            refuser(code)
            raisons={2:"compte banni", 3:"mot de passe incorrect", 91:"compte inexistant", 96:"e-mail non confirme"}
            log(f"    *** CONNEXION REFUSEE ({login}) : {raisons.get(code, code)}")
            return
        with _VERROU_CONNEXION:          # deux connexions simultanees sur le meme compte passaient toutes les deux
            if session_du_compte(acc["id"], sauf=conn):
                # comme le serveur d'origine : code 4 « Ce compte est deja connecte sur le serveur » (table des erreurs du
                # client). Sans ce refus, le meme compte apparaissait deux fois dans la liste des joueurs.
                refuser(4)
                log(f"    *** CONNEXION REFUSEE ({login}) : compte deja connecte")
                return
            SESSION["account_id"]=acc["id"]
        ECHECS_CONNEXION.pop((ip, login.lower()), None)
        if nouveau and acc.get("admin"):              # un compte cree n'a un niveau que s'il est le premier du serveur
            log(f"{MARQUE_ADMIN}{login} : premier compte du serveur, administrateur (niveau 4)")
        created = False
        SESSION["admin"]=acc["admin"]; SESSION["gils"]=acc["gils"]
        SESSION["anim"]=acc.get("anim") or 0
        SESSION["langue"]=acc.get("langue") or "fr"
        main = next((p for p in db.get_pseudos(acc["id"]) if p["is_main"]), None) or db.get_pseudos(acc["id"])[0]
        pid = 1000 + main["id"]          # identifiant reseau unique (evite 996..999 = robots)
        current_pseudo["id"]=pid; current_pseudo["name"]=main["name"]; current_pseudo["db_id"]=main["id"]
        log(f"    *** LOGIN {login} ("
            f"niveau={acc['admin']} {NIVEAUX_ADMIN.get(acc['admin'],'?')}) gils={acc['gils']}")
        payload_out = b"\x00" + P.field_byte(1) + P.field_int(pid) + P.field_str(main["name"])
        send(conn, P.build_frame(101, payload_out), f"op101 login OK pseudo='{main['name']}'")
        return

def main():
    global MAX_CONNEXIONS, MAX_PAR_IP
    ap=argparse.ArgumentParser()
    ap.add_argument("--host",default="127.0.0.1",
        help="adresse d'ecoute ; mettre 0.0.0.0 pour accepter une machine virtuelle ou le reseau local")
    ap.add_argument("--port",type=int,default=27888)
    ap.add_argument("--name",default="Balamb")
    ap.add_argument("--grade",type=int,default=None,metavar="N",
        help="force l'identifiant de grade : 201..205 (Administration), 2/3/4 (Staff), 209 (Animation)")
    ap.add_argument("--icone",type=int,default=None,metavar="N",
        help="force le champ statut des fiches joueurs (essayer 0..9 pour trouver l'icone de grade)")
    ap.add_argument("--motd",default="motd.txt",metavar="FICHIER",
        help="fichier du message d'accueil affiche dans le chat (une ligne par message)")
    ap.add_argument("--admin",action="append",default=[],metavar="COMPTE",
        help="compte EXISTANT passe au niveau 4 (administrateur) au demarrage ; repetable (aussi : "
             "FFWTT_ADMINS=compte1,compte2). Creer d'abord le compte (premiere connexion), puis relancer. "
             "Autre moyen, serveur arrete : py ffwtt_admin.py niveau COMPTE 4")
    ap.add_argument("--accueil",default="",
        help="URL d'accueil (op81). VIDE par defaut : une URL declenche l'ecran de CGU du client.")
    ap.add_argument("--encheres-test",type=int,default=0,
        help="cree N encheres de test (cartes aleatoires, 100 gils, achat immediat)")
    ap.add_argument("--rafale",default="",metavar="FICHIER",
        help="rejouer une rafale d'entree capturee au lieu de la generer (diagnostic : comparer avec une capture)")
    ap.add_argument("--regles",default="",
        help="regles actives, separees par des virgules : identique,plus,mm,ma  (ex: --regles identique,plus,mm)")
    ap.add_argument("--sans-premier-admin",action="store_true",
        help="ne pas faire administrateur le premier compte cree sur une base vide (par defaut, il l'est)")
    ap.add_argument("--max-connexions",type=int,default=MAX_CONNEXIONS,metavar="N",
        help=f"connexions simultanees au plus (defaut {MAX_CONNEXIONS})")
    ap.add_argument("--max-par-ip",type=int,default=MAX_PAR_IP,metavar="N",
        help=f"connexions simultanees au plus depuis une meme adresse IP (defaut {MAX_PAR_IP})")
    a=ap.parse_args()
    MAX_CONNEXIONS, MAX_PAR_IP = max(1, a.max_connexions), max(1, a.max_par_ip)
    db.PREMIER_ADMIN = not a.sans_premier_admin
    db.ADMIN_LOGINS.update(n.strip().lower() for n in a.admin if n.strip())
    db.init()
    if not db.nombre_cartes():
        # cartes.json n'est pas distribue (donnees du client) : chacun le reconstruit depuis SON jeu installe
        print(f"\n*** Table des cartes introuvable : {db.CARTES_JSON}\n"
              "*** Elle se construit depuis le jeu installe (FFWTT.exe et son dossier Cartes) :\n"
              "***   py ffwtt_cards_build.py --exe \"<dossier du jeu>/FFWTT.exe\" --cartes \"<dossier du jeu>/Cartes\"\n")
        raise SystemExit(1)
    global ACCUEIL_URL, ACCUEIL_LANGUE, ICONE_TEST, BASE_FERMEE, FICHIER_MOTD
    ICONE_TEST = a.icone
    FICHIER_MOTD = a.motd
    hote_public = a.host
    if hote_public in ("0.0.0.0", ""):
        try:
            _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _s.connect(("8.8.8.8", 80)); hote_public = _s.getsockname()[0]; _s.close()
        except OSError:
            hote_public = "127.0.0.1"
    ACCUEIL_URL = a.accueil
    # Le port de jeu est reserve EN PREMIER et en exclusivite. Sous Windows, SO_REUSEADDR
    # laisse deux serveurs ecouter le meme port : le client tombe alors sur l'ANCIEN, avec
    # l'ancien code, sans aucun message (piege rencontre le 2026-09-18).
    srv = socket.socket()
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((a.host, a.port)); srv.listen(8)
    except OSError:
        print(f"\n*** Le port {a.port} est deja utilise : un autre serveur FFWTT tourne encore.\n"
              f"*** Ferme-le d'abord (Ctrl+C dans sa fenetre), puis relance celui-ci.\n")
        raise SystemExit(1)
    # logos des grades et des notorietes : le client les lit dans SON dossier Images, sous le nom
    # du serveur. S'il est installe sur cette machine, on les y depose (voir ffwtt_images.py).
    perso = None                                  # dossier de logos personnalises (<type>_<id>.png)
    try:
        import ffwtt_images
        _n = 0 if os.environ.get("FFWTT_DB") else ffwtt_images.installer(a.name, dossier_perso=perso)   # pas en test
        if _n: log(f"    {_n} logo(s) de grades/notorietes installes pour le client (relance-le pour les voir)")
    except Exception as e:
        log(f"    (logos non installes : {e})")
    charger_motd(a.motd)
    charger_rafale(a.rafale)
    threading.Thread(target=surveiller_encheres, daemon=True).start()
    threading.Thread(target=surveiller_parties, daemon=True).start()
    threading.Thread(target=surveiller_choix, daemon=True).start()
    threading.Thread(target=surveiller_quiz, daemon=True).start()
    if a.encheres_test:
        import random as _r
        db.init()
        for _ in range(a.encheres_test):
            carte=_r.randint(1,3400)
            db.create_auction(0, "Marche", carte, 100, 100)
        log(f"    {a.encheres_test} enchere(s) de test creees (100 gils, achat immediat)")
    alias={"identique":"identique","=":"identique","plus":"plus","+":"plus",
           "mm":"mur_meme","memе_mur":"mur_meme","mur_meme":"mur_meme",
           "ma":"mur_add","mur_add":"mur_add"}
    for r in [x.strip().lower() for x in a.regles.split(",") if x.strip()]:
        if r in alias: RULES[alias[r]]=True
    actives=[k for k,v in RULES.items() if v]
    log(f"    Regles actives : {', '.join(actives) if actives else 'aucune (regle de base seule)'}")
    db.init()
    for nom in db.appliquer_admins():
        log(f"    *** --admin {nom} : aucun compte de ce nom. Creer le compte (premiere connexion), puis relancer "
            f"le serveur : un niveau n'est jamais reserve a un nom libre (le premier venu le prendrait)")
    importer_quiz(os.path.join(os.path.dirname(os.path.abspath(__file__)), "quiz.json"))   # base neuve : questions de depart
    realigner_encheres_robots()               # prix des reglages actuels pour celles qui n'ont pas de mise
    encheres_des_robots(diffuser=False)       # les 3 cartes de chaque robot, avant la premiere connexion
    log(f"=== Serveur FFWTT v0 sur {a.host}:{a.port}  (nom='{a.name}') ===")
    if a.host in ("0.0.0.0", ""):
        log(f"    Client (meme machine)   : ffwtt://127.0.0.1:{a.port}")
        log(f"    Client (autre machine)  : ffwtt://{hote_public}:{a.port}")
    else:
        log(f"    Client : ffwtt://{a.host}:{a.port}")
    if db.PREMIER_ADMIN and db.base_vide():
        log("    *** Serveur neuf : le PREMIER compte cree sera administrateur (niveau 4). Creez le votre avant d'ouvrir "
            "le serveur a d'autres joueurs (--sans-premier-admin pour l'eviter).")
    try:
        while True:
            try:
                c,ad=srv.accept()
                accepter(c, ad, a.name)
            except OSError as e:
                # plus de descripteur de fichier (EMFILE), connexion avortee... : JAMAIS une raison d'arreter le serveur
                log(f"    !! acceptation : {e}"); time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        srv.close(); log("=== arrete ===")

if __name__=="__main__":
    main()
