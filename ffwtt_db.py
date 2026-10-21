#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffwtt_db.py — Persistance SQLite pour le serveur FFWTT.

Fichier unique 'ffwtt.db' cree automatiquement. Aucune installation requise.

Modele :
  accounts   : compte de connexion (login/mot de passe hache, admin, gils)
  pseudos    : pseudos rattaches a un compte (principal ou secondaire)
  collection : cartes possedees par un pseudo (id carte + quantite + 4 valeurs)
  powers     : points de power + competences debloquees (par pseudo)
  decks      : decks sauvegardes (par pseudo)
  stats      : victoires/defaites/notoriete/elo (par pseudo)

Choix : "base souple" -> un login inconnu cree automatiquement le compte,
un pseudo principal, une collection de depart aleatoire et des gils.
Administrateur : aucun compte n'est code en dur. Le premier compte cree sur une base vide est administrateur ; ensuite
--admin COMPTE (ffwtt_server.py) ou FFWTT_ADMINS=compte1,compte2 (compte existant, au demarrage), ou serveur arrete :
py ffwtt_admin.py niveau COMPTE 4.
"""
import sqlite3, hashlib, hmac, secrets, re, os, random, time, threading, functools

# FFWTT_DB permet a test_serveur.py d'utiliser une base jetable au lieu de la vraie.
DB_PATH = os.environ.get("FFWTT_DB") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffwtt.db")
_lock = threading.Lock()

START_GILS   = 5000
START_CARDS  = 20          # cartes de depart (aleatoires)
CARD_MIN, CARD_MAX = 1, 3400
# comptes crees d'office au niveau 4 (Administrateur) : --admin du serveur ou variable FFWTT_ADMINS (separateur virgule)
ADMIN_LOGINS = {n.strip().lower() for n in os.environ.get("FFWTT_ADMINS", "").split(",") if n.strip()}
NIVEAU_ADMIN = 4

def _hash(pw): return hashlib.sha256(pw.encode("utf-8")).hexdigest()   # ancien format (sans sel)

# Mots de passe : PBKDF2-SHA256 avec sel (« pbkdf2$<sel>$<hache> »). Les anciens comptes (SHA-256
# nu) restent acceptes et sont convertis a la premiere connexion reussie. _hash("") marque un
# compte SANS mot de passe (cree par ffwtt_admin.py ou par un login sans mot de passe).
_ITERATIONS = 120000
def hash_mdp(pw, sel=None):
    if not pw: return _hash("")
    sel = sel or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(sel), _ITERATIONS).hex()
    return f"pbkdf2${sel}${h}"

def sans_mdp(stocke): return (not stocke) or stocke == _hash("")

def mdp_correct(stocke, pw):
    """True si `pw` correspond au hache stocke (nouveau ou ancien format)."""
    if sans_mdp(stocke): return False
    if stocke.startswith("pbkdf2$"):
        try: _, sel, _h = stocke.split("$")
        except ValueError: return False
        return hmac.compare_digest(hash_mdp(pw, sel), stocke)
    return hmac.compare_digest(stocke, _hash(pw))
def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init():
    with _lock, _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS accounts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE, pw TEXT, admin INTEGER DEFAULT 0, banned INTEGER DEFAULT 0,
            gils INTEGER DEFAULT 0, spegils INTEGER DEFAULT 0,
            created INTEGER);
        CREATE TABLE IF NOT EXISTS pseudos(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER, name TEXT UNIQUE, is_main INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS collection(
            pseudo_id INTEGER, card_id INTEGER, qty INTEGER DEFAULT 1,
            h INTEGER, d INTEGER, b INTEGER, g INTEGER,
            PRIMARY KEY(pseudo_id, card_id));
        CREATE TABLE IF NOT EXISTS powers(
            pseudo_id INTEGER PRIMARY KEY, points INTEGER DEFAULT 0, skills TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS decks(
            id INTEGER PRIMARY KEY AUTOINCREMENT, pseudo_id INTEGER, name TEXT, cards TEXT);
        CREATE TABLE IF NOT EXISTS auctions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_pseudo INTEGER, seller_name TEXT, card_id INTEGER,
            prix_depart INTEGER DEFAULT 0, achat_immediat INTEGER DEFAULT 0,
            meilleure_offre INTEGER DEFAULT 0, meilleur_offrant INTEGER DEFAULT 0,
            fin INTEGER, actif INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS stats(
            pseudo_id INTEGER PRIMARY KEY, wins INTEGER DEFAULT 0, losses INTEGER DEFAULT 0,
            draws INTEGER DEFAULT 0, noto INTEGER DEFAULT 0, elo INTEGER DEFAULT 1000);
        CREATE TABLE IF NOT EXISTS refcards(
            card_id INTEGER PRIMARY KEY, name TEXT, deck TEXT,
            h INTEGER, d INTEGER, b INTEGER, g INTEGER, element INTEGER, power INTEGER);
        """)
        try: c.execute("ALTER TABLE accounts ADD COLUMN banned INTEGER DEFAULT 0")
        except Exception: pass
        try: c.execute("ALTER TABLE pseudos ADD COLUMN note TEXT DEFAULT ''")
        except Exception: pass
        # notes PERSONNELLES (onglet « Personnelles » de son propre profil, visibles de soi seul : cat6 op64 / op66)
        try: c.execute("ALTER TABLE pseudos ADD COLUMN note_perso TEXT DEFAULT ''")
        except Exception: pass
        for col, typ in (("level","INTEGER DEFAULT 0"),("src","TEXT DEFAULT ''"),
                         ("conf","REAL DEFAULT 0"),("price","INTEGER DEFAULT 0")):
            try: c.execute(f"ALTER TABLE refcards ADD COLUMN {col} {typ}")
            except Exception: pass
        # notorietes editees par un administrateur (6 valeurs, une par classement) ; bans
        try: c.execute("ALTER TABLE accounts ADD COLUMN anim INTEGER DEFAULT 0")      # animateur
        except Exception: pass
        try: c.execute("ALTER TABLE pseudos ADD COLUMN notos TEXT DEFAULT ''")
        except Exception: pass
        try: c.execute("ALTER TABLE accounts ADD COLUMN email TEXT DEFAULT ''")      # (suppression d'un pseudo)
        except Exception: pass
        try: c.execute("ALTER TABLE accounts ADD COLUMN reg_ip TEXT DEFAULT ''")     # adresse a l'inscription
        except Exception: pass
        # confirmation de l'adresse e-mail (reglage « email_obligatoire ») : les comptes existants comptent comme confirmes
        for col, typ in (("email_ok", "INTEGER DEFAULT 1"), ("jeton", "TEXT DEFAULT ''"), ("jeton_ts", "INTEGER DEFAULT 0")):
            try: c.execute(f"ALTER TABLE accounts ADD COLUMN {col} {typ}")
            except Exception: pass
        # langue du joueur (« fr » ou « en », « !langue en ») : les anglophones ont leur section dans la liste des joueurs
        try: c.execute("ALTER TABLE accounts ADD COLUMN langue TEXT DEFAULT 'fr'")
        except Exception: pass
        # journal de moderation et reglages de l'administration
        c.execute("""CREATE TABLE IF NOT EXISTS journal_moderation(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, auteur TEXT, action TEXT,
            cible TEXT DEFAULT '', detail TEXT DEFAULT '', ip TEXT DEFAULT '')""")
        c.execute("CREATE TABLE IF NOT EXISTS reglages(cle TEXT PRIMARY KEY, valeur TEXT)")
        # guildes : un « tableau » (finalisee = 0) que les joueurs rejoignent, puis la guilde finalisee
        # panneau d'equipe du client (TfrmSpecialUser) : caisse de gils et topic de chaque groupe d'utilisateurs speciaux
        c.execute("""CREATE TABLE IF NOT EXISTS groupes_equipe(
            groupe INTEGER PRIMARY KEY, caisse INTEGER DEFAULT 0,
            topic TEXT DEFAULT '', topic_par TEXT DEFAULT '', topic_ts INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS guildes(
            id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE COLLATE NOCASE, maitre INTEGER, cree INTEGER,
            finalisee INTEGER DEFAULT 0, mdp TEXT DEFAULT '', exp INTEGER DEFAULT 0, gils INTEGER DEFAULT 0,
            topic TEXT DEFAULT '', topic_par TEXT DEFAULT '', topic_ts INTEGER DEFAULT 0,
            logo BLOB, logo_ts INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS guilde_membres(
            pseudo_id INTEGER PRIMARY KEY, guilde_id INTEGER, titre TEXT DEFAULT '', pouvoirs INTEGER DEFAULT 0,
            entree INTEGER DEFAULT 0, invite_par INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS guilde_journal(
            id INTEGER PRIMARY KEY AUTOINCREMENT, guilde_id INTEGER, ts INTEGER, auteur TEXT DEFAULT '',
            action TEXT DEFAULT '', detail TEXT DEFAULT '')""")
        try: c.execute("ALTER TABLE pseudos ADD COLUMN vu INTEGER DEFAULT 0")          # derniere connexion
        except Exception: pass
        c.execute("""CREATE TABLE IF NOT EXISTS bans(
            kind TEXT, value TEXT, par TEXT DEFAULT '', motif TEXT DEFAULT '', ts INTEGER DEFAULT 0,
            PRIMARY KEY(kind, value))""")
        # Le salon des operateurs ne garde plus d'historique (2026-09-23) : l'ancienne table disparait avec son contenu.
        c.execute("DROP TABLE IF EXISTS salon")
        _load_refcards(c)
        # Les cartes deja possedees gardent une copie de leurs valeurs : on les aligne sur la table des cartes (exacte
        # depuis le 2026-09-23 : valeurs lues dans le client ; quelques lectures OCR anciennes etaient fausses).
        c.execute("""UPDATE collection SET
                        h=(SELECT h FROM refcards r WHERE r.card_id=collection.card_id),
                        d=(SELECT d FROM refcards r WHERE r.card_id=collection.card_id),
                        b=(SELECT b FROM refcards r WHERE r.card_id=collection.card_id),
                        g=(SELECT g FROM refcards r WHERE r.card_id=collection.card_id)
                     WHERE EXISTS (SELECT 1 FROM refcards r WHERE r.card_id=collection.card_id
                                   AND (r.h IS NOT collection.h OR r.d IS NOT collection.d OR r.b IS NOT collection.b
                                        OR r.g IS NOT collection.g))""")
        # Un ancien bug de l'echange (identifiant lu un octet trop tot) a range dans des
        # collections des cartes qui n'existent pas ; le client plante en les recevant.
        if c.execute("SELECT COUNT(*) FROM refcards").fetchone()[0] > 4000:
            c.execute("DELETE FROM collection WHERE card_id NOT IN (SELECT card_id FROM refcards)")
    purger_anciens()

# ---------- cartes reelles ----------
# cartes.json (produit par ffwtt_cards_build.py) : { "id": {deck, name, level, digits:[H,D,B,G], element,
#   src: "client", conf}, ... }  -- tout vient de la table du client (id canonique, donc bonne image) ;
#   prix et power : calcules comme le client (prix_client), jamais lus dans le fichier.
# digits = [Haut, Droite, Bas, Gauche] = h,d,b,g.
ICI = os.path.dirname(os.path.abspath(__file__))
CARTES_JSON = os.path.join(ICI, "cartes.json")
_REF_CACHE = None

def prix_client(nom, deck, niveau, dg):
    """(prix, power) d'une carte, EXACTEMENT comme le client les calcule et les affiche (« Power : %d », « Prix : %d »).
    Lu dans le binaire le 2026-09-24 : la boucle d'initialisation de la table des cartes (0x5CC71E-0x5CCC45) range le
    prix a l'octet 0x209 de chaque fiche et le power a 0x20F (les « 8 octets nuls » du demarrage). Verifie sur les
    prix affiches par le client ; carte FFWorld (4 x A) : 113503, le maximum.
    Il remplace l'ancienne estimation par la seule somme des chiffres, qui sous-evaluait les cartes a deux A.
    Le serveur ne transmet aucun prix : ce calcul est la seule facon d'etre d'accord avec ce que le joueur voit."""
    h, d, b, g = (int(x) for x in dg)                 # digits = [Haut, Droite, Bas, Gauche]
    s = h + d + b + g; A = 10
    p = s * 1100.0 if nom == "FFWorld" else s * 900.0 if deck == "Special" else 0.0
    for i in range(1, s + 1): p += (i * 0.1 + niveau / 10.0) * i
    p += 500 * ((h == A and g == A) + (h == A and d == A) + (b == A and g == A) + (b == A and d == A))   # deux A voisins
    p += 300 * ((h == A and b == A) + (g == A and d == A))                                              # deux A opposes
    if h == d == b == g: p += 100 + 50 * h
    if min(h, d, b, g) > 5 and A in (h, d, b, g): p += (s - 25) * 75
    if deck == "Special": p *= 1.3
    prix = round(p * 2.0 * 0.85)                      # Round de Delphi = arrondi au pair, comme round() en Python
    return prix, int(prix / 100)

def power_depuis_chiffres(dg, niveau, nom="", deck=""):
    return prix_client(nom, deck, niveau, dg)[1]

def _prix(nom, deck, level, dg):
    """Prix boutique de base (sans la competence Souk) : celui du client."""
    return prix_client(nom, deck, level, dg)[0]

def _load_refcards(c):
    """Importe/actualise la table des cartes reelles (cartes.json)."""
    import json, statistics
    global _REF_CACHE
    try:
        data = json.load(open(CARTES_JSON, encoding="utf-8"))
    except Exception:
        data = None
    if not data: return 0
    n = 0
    for sid, v in data.items():
        dg = v.get("digits")
        if not dg or len(dg) != 4: continue          # sans valeurs : pas dans le pool de jeu
        try:
            cid = int(sid); level = int(v.get("level") or 0)
            c.execute("INSERT INTO refcards(card_id,name,deck,h,d,b,g,element,power,level,src,conf,price) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(card_id) DO UPDATE SET "
                      "name=excluded.name,deck=excluded.deck,h=excluded.h,d=excluded.d,b=excluded.b,"
                      "g=excluded.g,element=excluded.element,power=excluded.power,level=excluded.level,"
                      "src=excluded.src,conf=excluded.conf,price=excluded.price",
                      (cid, v.get("name",""), v.get("deck",""), dg[0], dg[1], dg[2], dg[3],
                       int(v.get("element") or 0), prix_client(v.get("name", ""), v.get("deck", ""), level, dg)[1], level,
                       v.get("src",""), float(v.get("conf") or 0), _prix(v.get("name", ""), v.get("deck", ""), level, dg)))
            n += 1
        except Exception:
            continue
    global _MAX_CARTE
    _REF_CACHE = None; _MAX_CARTE = None
    return n

def nombre_cartes():
    """Nombre de cartes de la table de reference (0 : ni cartes.json ni table deja en base -> serveur inutilisable)."""
    with _lock, _conn() as c:
        return c.execute("SELECT COUNT(*) FROM refcards").fetchone()[0]

_MAX_CARTE = None
def max_carte():
    """Le plus grand identifiant de carte connu (4885 pour le client d'origine) : taille de la collection op52."""
    global _MAX_CARTE
    if _MAX_CARTE is None:
        try:
            with _lock, _conn() as c: _MAX_CARTE = c.execute("SELECT MAX(card_id) FROM refcards").fetchone()[0] or 4885
        except sqlite3.OperationalError: _MAX_CARTE = 4885
    return max(4885, _MAX_CARTE)

def ref_price(card_id):
    """Prix boutique d'une carte reelle (gils), ou None si inconnue."""
    with _lock, _conn() as c:
        r = c.execute("SELECT price FROM refcards WHERE card_id=?", (card_id,)).fetchone()
    return r["price"] if r else None

def ref_info(card_id):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM refcards WHERE card_id=?", (card_id,)).fetchone()
    return dict(r) if r else None

def ref_ids():
    """Liste des id de cartes reelles connues (avec vraies valeurs)."""
    global _REF_CACHE
    if _REF_CACHE is None:
        with _lock, _conn() as c:
            _REF_CACHE = [r["card_id"] for r in c.execute("SELECT card_id FROM refcards")]
    return _REF_CACHE

def ref_vals(card_id):
    """Vraies valeurs (h,d,b,g) d'une carte reelle, ou None si inconnue."""
    with _lock, _conn() as c:
        r = c.execute("SELECT h,d,b,g FROM refcards WHERE card_id=?", (card_id,)).fetchone()
    return (r["h"], r["d"], r["b"], r["g"]) if r else None

def sample_ref(n, niveau_min=None, niveau_max=None):
    """Tire n cartes reelles distinctes : liste de dict {card_id,h,d,b,g}. Avec une fourchette de niveaux
    (1 a 10), le tirage se fait parmi les cartes de ces niveaux, hors deck « Special » (mains des robots)."""
    if niveau_min is not None or niveau_max is not None:
        with _lock, _conn() as c:
            rows = c.execute("SELECT card_id,h,d,b,g FROM refcards WHERE level BETWEEN ? AND ? AND deck<>'Special' "
                             "ORDER BY RANDOM() LIMIT ?", (niveau_min or 1, niveau_max or 10, n)).fetchall()
        if len(rows) >= n: return [dict(r) for r in rows]
    ids = ref_ids()
    if not ids: return []
    pick = random.sample(ids, min(n, len(ids)))
    out = []
    with _lock, _conn() as c:
        for cid in pick:
            r = c.execute("SELECT h,d,b,g FROM refcards WHERE card_id=?", (cid,)).fetchone()
            out.append({"card_id": cid, "h": r["h"], "d": r["d"], "b": r["b"], "g": r["g"]})
    return out

# ---------- connexion / creation ----------
def verifier_connexion(login, password, base_souple=True):
    """Retourne (compte, code). code : 0 = OK, 2 = banni, 3 = mot de passe, 91 = inconnu, 96 = e-mail non confirme."""
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM accounts WHERE login=?", (login.lower(),)).fetchone()
    if not row:
        if not base_souple: return None, 91
        # creation a la premiere connexion : regles d'un nouveau compte (nom, mot de passe)
        erreur = valider_nouveau_compte(login, password)
        if erreur: return None, (3 if erreur == ERREUR_MDP else 91)
        acc, _ = login_or_create(login, password)
        return acc, 0
    acc = dict(row)
    if acc.get("banned"): return acc, 2
    attendu = acc.get("pw") or ""
    # Un compte SANS mot de passe n'accepte plus aucune connexion (il acceptait n'importe quel mot de passe : un compte
    # cree d'avance par ffwtt_admin.py revenait au premier venu). L'administrateur lui en donne un : ffwtt_admin.py mdp.
    if sans_mdp(attendu) or not mdp_correct(attendu, password): return acc, 3
    if not attendu.startswith("pbkdf2$"):                     # ancien hache : on le renforce
        with _lock, _conn() as c:
            c.execute("UPDATE accounts SET pw=? WHERE id=?", (hash_mdp(password), acc["id"]))
    # 96 = « Ce compte n'a pas ete confirme. [...] verifiez votre boite e-mail » (table des erreurs du client)
    if email_obligatoire() and not acc.get("email_ok", 1): return acc, 96
    return acc, 0

def set_banned(account_id, valeur=1):
    with _lock, _conn() as c:
        c.execute("UPDATE accounts SET banned=? WHERE id=?", (1 if valeur else 0, account_id))

PREMIER_ADMIN = True     # le premier compte cree sur une base VIDE est administrateur (option --sans-premier-admin)

def base_vide():
    """Aucun compte en base : le prochain compte cree sera le premier (administrateur si PREMIER_ADMIN)."""
    with _lock, _conn() as c:
        return c.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0

def login_or_create(login, password):
    """Retourne (account_row, created_bool) : le compte existant (SANS verifier le mot de passe : reserve aux appelants
    qui l'ont deja fait), ou un compte cree. Jamais de compte sans mot de passe. Un seul niveau d'administration a la
    creation : celui du PREMIER compte d'une base vide (le proprietaire qui installe son serveur ; decision de
    l'utilisateur du 2026-10-21), compte dans la meme transaction que l'insertion. Aucun niveau n'est reserve a un NOM :
    --admin ne s'applique qu'a un compte qui existe deja (appliquer_admins)."""
    if not password: raise ValueError("compte sans mot de passe refuse")
    pw = hash_mdp(password)                       # PBKDF2 (~50 ms) HORS du verrou global de la base
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM accounts WHERE login=?", (login.lower(),)).fetchone()
        if row:
            return dict(row), False
        premier = PREMIER_ADMIN and c.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        cur = c.execute("INSERT INTO accounts(login,pw,admin,gils,created) VALUES(?,?,?,?,?)",
                        (login.lower(), pw, NIVEAU_ADMIN if premier else 0, START_GILS, int(time.time())))
        acc_id = cur.lastrowid
        # pseudo principal = le login
        pc = c.execute("INSERT INTO pseudos(account_id,name,is_main) VALUES(?,?,1)", (acc_id, login))
        ps_id = pc.lastrowid
        _give_starter_cards(c, ps_id)
        c.execute("INSERT INTO powers(pseudo_id,points) VALUES(?,0)", (ps_id,))
        c.execute("INSERT INTO stats(pseudo_id) VALUES(?)", (ps_id,))
        return dict(c.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()), True

def _give_starter_cards(c, pseudo_id):
    # De préférence : cartes RÉELLES (vraies valeurs, id canonique = bonne image chez le client).
    # Le premier deck vaut au moins 210 powers (changelog 3.3.2) : on retire jusqu'a l'obtenir.
    meilleur = None
    for _ in range(25):
        rows = c.execute("SELECT card_id,h,d,b,g,price FROM refcards WHERE deck<>'Special' "
                         "ORDER BY RANDOM() LIMIT ?", (START_CARDS,)).fetchall()
        if not rows: break
        pw = sum(max(1, (r["price"] or 0)//100) for r in rows)
        if meilleur is None or pw > meilleur[0]: meilleur = (pw, rows)
        if pw >= 210: break
    if meilleur:
        for r in meilleur[1]:
            c.execute("INSERT OR IGNORE INTO collection(pseudo_id,card_id,qty,h,d,b,g) "
                      "VALUES(?,?,1,?,?,?,?)", (pseudo_id, r["card_id"], r["h"], r["d"], r["b"], r["g"]))
        return
    # Repli : cartes aléatoires si aucune carte réelle n'est chargée.
    seen=set()
    while len(seen) < START_CARDS:
        cid = random.randint(CARD_MIN, CARD_MAX)
        if cid in seen: continue
        seen.add(cid)
        vals = [random.randint(1,10) for _ in range(4)]
        c.execute("INSERT OR IGNORE INTO collection(pseudo_id,card_id,qty,h,d,b,g) VALUES(?,?,1,?,?,?,?)",
                  (pseudo_id, cid, *vals))

# ---------- un seul deck par COMPTE ----------
# Comme sur le serveur officiel, les cartes (donc aussi les powers tires de leur sacrifice et les competences achetees
# avec) appartiennent au compte : tous ses pseudos jouent avec la meme collection. Elles sont rangees sous l'identifiant
# du pseudo PRINCIPAL (qui ne peut pas etre supprime) ; les statistiques et la notoriete, elles, restent par pseudo.
_STOCK = {}
def stock_id(pseudo_id):
    """Identifiant sous lequel sont rangees les cartes de ce pseudo : le pseudo principal de son compte."""
    if pseudo_id is None or pseudo_id in _STOCK: return _STOCK.get(pseudo_id, pseudo_id)
    with _lock, _conn() as c:
        r = c.execute("""SELECT m.id FROM pseudos p JOIN pseudos m ON m.account_id=p.account_id AND m.is_main=1
                         WHERE p.id=?""", (pseudo_id,)).fetchone()
    if r: _STOCK[pseudo_id] = r["id"]
    return r["id"] if r else pseudo_id

def _du_compte(f):
    """Decorateur : le 1er argument (un id de pseudo) est remplace par l'id de rangement du compte."""
    @functools.wraps(f)
    def g(pseudo_id, *a, **k): return f(stock_id(pseudo_id), *a, **k)
    return g

# ---------- lectures ----------
def create_pseudo(account_id, name):
    """Cree un pseudo supplementaire sur un compte. Retourne (pseudo, erreur)."""
    if pseudo_pris(name): return None, "nom deja pris"          # sans tenir compte des majuscules
    with _lock, _conn() as c:
        cur = c.execute("INSERT INTO pseudos(account_id,name,is_main) VALUES(?,?,0)",
                        (account_id, name))
        ps_id = cur.lastrowid
        # PAS de nouveau deck : un pseudo supplementaire joue avec les cartes du compte (voir stock_id)
        c.execute("INSERT INTO stats(pseudo_id) VALUES(?)", (ps_id,))
        r = c.execute("SELECT * FROM pseudos WHERE id=?", (ps_id,)).fetchone()
        return dict(r), None

def supprimer_pseudo(pseudo_id):
    """Supprime un pseudo SECONDAIRE et ce qui lui est propre (statistiques, decks, encheres en cours). Les cartes,
    powers et competences sont rangees sous le pseudo principal (stock_id) : elles restent au compte.
    Retourne les identifiants des encheres fermees (a retirer de la liste des clients)."""
    with _lock, _conn() as c:
        fermees = _retirer_des_encheres(c, pseudo_id)
        for table in ("stats", "decks", "collection", "powers"):
            c.execute(f"DELETE FROM {table} WHERE pseudo_id=?", (pseudo_id,))
        c.execute("DELETE FROM pseudos WHERE id=? AND is_main=0", (pseudo_id,))
    _STOCK.pop(pseudo_id, None)
    return fermees

def _retirer_des_encheres(c, pseudo_id):
    """Un pseudo qui disparait : ses encheres en cours sont fermees et le meilleur offrant rembourse (ses gils etaient
    retenus) ; ses propres offres sur les encheres des autres sont annulees et lui sont rendues. -> encheres fermees."""
    def rendre(pseudo, montant):
        c.execute("UPDATE accounts SET gils=gils+? WHERE id=(SELECT account_id FROM pseudos WHERE id=?)", (montant, pseudo))
    fermees = []
    for r in c.execute("SELECT * FROM auctions WHERE seller_pseudo=? AND actif=1", (pseudo_id,)).fetchall():
        if r["meilleur_offrant"] and r["meilleure_offre"]: rendre(r["meilleur_offrant"], r["meilleure_offre"])
        fermees.append(r["id"])
    c.execute("UPDATE auctions SET actif=0 WHERE seller_pseudo=? AND actif=1", (pseudo_id,))
    for r in c.execute("SELECT * FROM auctions WHERE meilleur_offrant=? AND actif=1", (pseudo_id,)).fetchall():
        rendre(pseudo_id, r["meilleure_offre"])
    c.execute("UPDATE auctions SET meilleure_offre=0, meilleur_offrant=0 WHERE meilleur_offrant=? AND actif=1", (pseudo_id,))
    return fermees


def get_pseudos(account_id):
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM pseudos WHERE account_id=?", (account_id,))]

def get_pseudo(name):
    with _lock, _conn() as c:
        r=c.execute("SELECT * FROM pseudos WHERE name=?", (name,)).fetchone()
        return dict(r) if r else None

def chercher_pseudo(name):
    """Un pseudo par son nom, sans tenir compte des majuscules (commandes tapees dans le chat : /offinfos...)."""
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM pseudos WHERE name=? COLLATE NOCASE", (name,)).fetchone()
        return dict(r) if r else None

def get_pseudo_par_id(pseudo_id):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM pseudos WHERE id=?", (pseudo_id,)).fetchone()
        return dict(r) if r else None

def set_note(pseudo_id, texte):
    with _lock, _conn() as c:
        c.execute("UPDATE pseudos SET note=? WHERE id=?", (texte, pseudo_id))

def get_note(pseudo_id):
    with _lock, _conn() as c:
        r=c.execute("SELECT note FROM pseudos WHERE id=?", (pseudo_id,)).fetchone()
        return (r["note"] if r and r["note"] else "")

def set_note_perso(pseudo_id, texte):
    with _lock, _conn() as c:
        c.execute("UPDATE pseudos SET note_perso=? WHERE id=?", (texte, pseudo_id))

def get_note_perso(pseudo_id):
    with _lock, _conn() as c:
        r = c.execute("SELECT note_perso FROM pseudos WHERE id=?", (pseudo_id,)).fetchone()
        return (r["note_perso"] if r and r["note_perso"] else "")

@_du_compte
def get_collection(pseudo_id):
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM collection WHERE pseudo_id=?", (pseudo_id,))]

def get_account(account_id):
    with _lock, _conn() as c:
        r=c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return dict(r) if r else None

def get_stats(pseudo_id):
    with _lock, _conn() as c:
        r=c.execute("SELECT * FROM stats WHERE pseudo_id=?", (pseudo_id,)).fetchone()
        return dict(r) if r else {}

def is_admin(account_id):
    a=get_account(account_id)
    return bool(a and a["admin"])

@_du_compte
def get_powers(pseudo_id):
    with _lock, _conn() as c:
        r=c.execute("SELECT points FROM powers WHERE pseudo_id=?", (pseudo_id,)).fetchone()
        return r["points"] if r else 0

# ---------- encheres ----------
def create_auction(pseudo_id, name, card_id, prix_depart, achat_immediat, duree=30000):
    with _lock, _conn() as c:
        cur=c.execute("INSERT INTO auctions(seller_pseudo,seller_name,card_id,prix_depart,"
                      "achat_immediat,meilleure_offre,meilleur_offrant,fin,actif) "
                      "VALUES(?,?,?,?,?,0,0,?,1)",
                      (pseudo_id,name,card_id,prix_depart,achat_immediat,int(time.time())+duree))
        return cur.lastrowid

def list_auctions():
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM auctions WHERE actif=1")]

def get_auction(aid):
    with _lock, _conn() as c:
        r=c.execute("SELECT * FROM auctions WHERE id=?", (aid,)).fetchone()
        return dict(r) if r else None

def bid_auction(aid, pseudo_id, montant):
    """Mise atomique sur une enchere ACTIVE : au-dessus de la meilleure offre et au moins le prix de depart.
    Rend (True, ancien meilleur offrant, ancienne offre) : l'appelant rembourse cet ancien offrant, une seule fois
    meme si deux mises arrivent ensemble. (False, 0, 0) si la mise est refusee."""
    with _lock, _conn() as c:
        r=c.execute("SELECT meilleure_offre, meilleur_offrant, prix_depart FROM auctions WHERE id=? AND actif=1",
                    (aid,)).fetchone()
        if not r or montant <= r["meilleure_offre"] or montant < (r["prix_depart"] or 0): return False, 0, 0
        c.execute("UPDATE auctions SET meilleure_offre=?, meilleur_offrant=? WHERE id=?",
                  (montant, pseudo_id, aid))
        return True, r["meilleur_offrant"], r["meilleure_offre"]

def close_auction(aid):
    """Cloture une enchere encore active. True si c'est CET appel qui l'a cloturee : achat immediat, fin du delai et
    annulation ne peuvent donc livrer ou rembourser qu'une seule fois."""
    with _lock, _conn() as c:
        return c.execute("UPDATE auctions SET actif=0 WHERE id=? AND actif=1", (aid,)).rowcount == 1

# ---------- ecritures (economie) ----------
@_du_compte
def get_skills(pseudo_id):
    """Retourne {id_competence: niveau}. Compatible avec l'ancien format (simple liste d'ids)."""
    with _lock, _conn() as c:
        r=c.execute("SELECT skills FROM powers WHERE pseudo_id=?", (pseudo_id,)).fetchone()
    brut = r["skills"] if r and r["skills"] else ""
    out={}
    for item in brut.split(","):
        item=item.strip()
        if not item: continue
        if ":" in item:
            sid,niv=item.split(":",1)
            try: out[int(sid)]=int(niv)
            except ValueError: pass
        else:
            try: out[int(item)]=1        # ancien format : niveau 1
            except ValueError: pass
    return out

def get_skill_level(pseudo_id, skill_id):
    return get_skills(pseudo_id).get(int(skill_id), 0)

@_du_compte
def set_skill_level(pseudo_id, skill_id, niveau):
    sk=get_skills(pseudo_id); sk[int(skill_id)]=int(niveau)
    txt=",".join(f"{k}:{v}" for k,v in sorted(sk.items()))
    with _lock, _conn() as c:
        c.execute("INSERT INTO powers(pseudo_id,points,skills) VALUES(?,0,?) "
                  "ON CONFLICT(pseudo_id) DO UPDATE SET skills=?", (pseudo_id, txt, txt))

def has_skill(pseudo_id, skill_id):
    return get_skill_level(pseudo_id, skill_id) > 0

@_du_compte
def add_powers(pseudo_id, delta):
    with _lock, _conn() as c:
        c.execute("INSERT INTO powers(pseudo_id,points) VALUES(?,0) ON CONFLICT(pseudo_id) DO NOTHING", (pseudo_id,))
        c.execute("UPDATE powers SET points=MAX(0,points+?) WHERE pseudo_id=?", (delta, pseudo_id))

def add_result(pseudo_id, resultat, noto=0):
    """resultat : 'win', 'loss' ou 'draw'. Met a jour les statistiques du pseudo."""
    colonne = {"win":"wins", "loss":"losses", "draw":"draws"}.get(resultat)
    if not colonne: return
    with _lock, _conn() as c:
        c.execute("INSERT INTO stats(pseudo_id) VALUES(?) ON CONFLICT(pseudo_id) DO NOTHING", (pseudo_id,))
        c.execute(f"UPDATE stats SET {colonne}={colonne}+1, noto=noto+? WHERE pseudo_id=?", (noto, pseudo_id))

def add_gils(account_id, delta):
    with _lock, _conn() as c:
        c.execute("UPDATE accounts SET gils=gils+? WHERE id=?", (delta, account_id))

def retirer_gils(account_id, montant):
    """Debite `montant` gils SEULEMENT si le solde suffit, en une seule requete (verifier puis debiter en deux temps
    laissait deux actions simultanees passer, et un solde devenir negatif). True si le debit a eu lieu."""
    if montant < 0 or account_id is None: return False
    with _lock, _conn() as c:
        return c.execute("UPDATE accounts SET gils=gils-? WHERE id=? AND gils>=?",
                         (montant, account_id, montant)).rowcount == 1

def appliquer_admins():
    """--admin / FFWTT_ADMINS : niveau 4 pour les comptes qui EXISTENT deja. Rend les noms sans compte (aucun
    niveau n'est reserve a un nom libre : le premier venu qui le prenait devenait administrateur)."""
    absents = []
    for login in sorted(ADMIN_LOGINS):
        with _lock, _conn() as c:
            if not c.execute("UPDATE accounts SET admin=? WHERE login=?", (NIVEAU_ADMIN, login)).rowcount:
                absents.append(login)
    return absents

@_du_compte
def add_card(pseudo_id, card_id, vals=None):
    with _lock, _conn() as c:
        if vals is None:
            rr=c.execute("SELECT h,d,b,g FROM refcards WHERE card_id=?", (card_id,)).fetchone()
            vals=[rr["h"],rr["d"],rr["b"],rr["g"]] if rr else [random.randint(1,10) for _ in range(4)]
        r=c.execute("SELECT qty FROM collection WHERE pseudo_id=? AND card_id=?", (pseudo_id,card_id)).fetchone()
        if r: c.execute("UPDATE collection SET qty=qty+1 WHERE pseudo_id=? AND card_id=?", (pseudo_id,card_id))
        else: c.execute("INSERT INTO collection(pseudo_id,card_id,qty,h,d,b,g) VALUES(?,?,1,?,?,?,?)",
                        (pseudo_id,card_id,*vals))

@_du_compte
def remove_card(pseudo_id, card_id):
    with _lock, _conn() as c:
        r=c.execute("SELECT qty FROM collection WHERE pseudo_id=? AND card_id=?", (pseudo_id,card_id)).fetchone()
        if not r: return False
        if r["qty"]>1: c.execute("UPDATE collection SET qty=qty-1 WHERE pseudo_id=? AND card_id=?", (pseudo_id,card_id))
        else: c.execute("DELETE FROM collection WHERE pseudo_id=? AND card_id=?", (pseudo_id,card_id))
        return True

# ---------- administration ----------
@_du_compte
def new_deck(pseudo_id):
    """« Don de nouveau deck » : la collection est remplacee par un deck de depart."""
    with _lock, _conn() as c:
        c.execute("DELETE FROM collection WHERE pseudo_id=?", (pseudo_id,))
        _give_starter_cards(c, pseudo_id)

def reset_account(pseudo_id):
    """« Remise a zero du compte » : deck de depart, gils de depart, powers, competences et
    statistiques a zero."""
    stock = stock_id(pseudo_id)                 # cartes, powers, competences : ceux du compte
    with _lock, _conn() as c:
        c.execute("DELETE FROM collection WHERE pseudo_id=?", (stock,))
        _give_starter_cards(c, stock)
        c.execute("UPDATE powers SET points=0, skills='' WHERE pseudo_id=?", (stock,))
        c.execute("UPDATE stats SET wins=0, losses=0, draws=0, noto=0, elo=1000 WHERE pseudo_id=?", (pseudo_id,))
        c.execute("UPDATE pseudos SET notos='' WHERE id=?", (pseudo_id,))
        r = c.execute("SELECT account_id FROM pseudos WHERE id=?", (pseudo_id,)).fetchone()
        if r: c.execute("UPDATE accounts SET gils=? WHERE id=?", (START_GILS, r["account_id"]))

def get_notos(pseudo_id):
    """Les 6 notorietes (une par classement) ; 50 par defaut, comme la fiche d'origine."""
    with _lock, _conn() as c:
        r = c.execute("SELECT notos FROM pseudos WHERE id=?", (pseudo_id,)).fetchone()
    try: vals = [int(x) for x in (r["notos"] or "").split(",") if x != ""]
    except (ValueError, TypeError, IndexError): vals = []
    return (vals + [50]*6)[:6]

def set_notos(pseudo_id, vals):
    with _lock, _conn() as c:
        c.execute("UPDATE pseudos SET notos=? WHERE id=?", (",".join(str(int(v)) for v in vals[:6]), pseudo_id))

def ban(kind, value, par="", motif=""):
    """kind = 'nick' | 'host' | 'account' (ce dernier passe aussi par accounts.banned)."""
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO bans(kind,value,par,motif,ts) VALUES(?,?,?,?,?)",
                  (kind, str(value).lower(), par, motif, int(time.time())))

def unban(kind, value):
    with _lock, _conn() as c:
        c.execute("DELETE FROM bans WHERE kind=? AND value=?", (kind, str(value).lower()))

def is_banned(kind, value):
    with _lock, _conn() as c:
        return c.execute("SELECT 1 FROM bans WHERE kind=? AND value=?",
                         (kind, str(value).lower())).fetchone() is not None

def clear_bans(kind):
    with _lock, _conn() as c:
        c.execute("DELETE FROM bans WHERE kind=?", (kind,))

def account_of_pseudo(pseudo_id):
    with _lock, _conn() as c:
        r = c.execute("SELECT a.* FROM accounts a JOIN pseudos p ON p.account_id=a.id WHERE p.id=?",
                      (pseudo_id,)).fetchone()
        return dict(r) if r else None

def account_by_login(login):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM accounts WHERE login=?", (str(login).lower(),)).fetchone()
        return dict(r) if r else None

# ---------- comptes : noms, langue, mot de passe ----------
NOM_COMPTE_RE = re.compile(r"^[A-Za-z0-9_\-\[\]\.]{3,20}$")

LANGUES = ("fr", "en")

def changer_langue(account_id, langue):
    with _lock, _conn() as c:
        c.execute("UPDATE accounts SET langue=? WHERE id=?", (langue if langue in LANGUES else "fr", account_id))

ERREUR_MDP = "Le mot de passe doit faire de 4 à 20 caractères."

def valider_nouveau_compte(login, password):
    """Regles d'un NOUVEAU compte : None, ou le message d'erreur."""
    if nom_interdit(login): return "Ce nom n'est pas autorisé sur ce serveur."
    if not NOM_COMPTE_RE.match(login or ""):
        return "Le nom de compte doit faire de 3 à 20 caractères (lettres, chiffres, _ - [ ] .)."
    if len(password or "") < 4 or len(password) > 20: return ERREUR_MDP
    if pseudo_pris(login): return "Ce nom de compte (ou ce pseudo) est déjà pris."
    if is_banned("nick", login): return "Ce nom est banni."
    return None

def pseudo_pris(nom):
    """Nom deja utilise par un compte ou un pseudo, SANS tenir compte des majuscules (« ADMIN » imitait « Admin »)."""
    with _lock, _conn() as c:
        return bool(c.execute("SELECT 1 FROM accounts WHERE login=?", ((nom or "").lower(),)).fetchone() or
                    c.execute("SELECT 1 FROM pseudos WHERE lower(name)=?", ((nom or "").lower(),)).fetchone())


def changer_mdp(account_id, nouveau):
    with _lock, _conn() as c:
        c.execute("UPDATE accounts SET pw=? WHERE id=?", (hash_mdp(nouveau), account_id))


@_du_compte
def nb_cartes(pseudo_id):
    with _lock, _conn() as c:
        return c.execute("SELECT COALESCE(SUM(qty),0) FROM collection WHERE pseudo_id=?", (pseudo_id,)).fetchone()[0]

# ---------- reglages de l'administration, journal de moderation ----------
def reglage(cle, defaut=""):
    try:
        with _lock, _conn() as c:
            r = c.execute("SELECT valeur FROM reglages WHERE cle=?", (cle,)).fetchone()
        return r["valeur"] if r else defaut
    except sqlite3.OperationalError:            # base d'avant cette table (init() pas encore passe)
        return defaut

def definir_reglage(cle, valeur):
    with _lock, _conn() as c:
        c.execute("INSERT INTO reglages(cle,valeur) VALUES(?,?) "
                  "ON CONFLICT(cle) DO UPDATE SET valeur=?", (cle, str(valeur), str(valeur)))

def inscriptions_ouvertes(): return reglage("inscriptions", "1") == "1"



def email_obligatoire(): return reglage("email_obligatoire", "0") == "1"   # compte non confirme : refus (code 96)


def purger_anciens(jours=365):
    """Le journal de moderation est conserve un an."""
    limite = int(time.time()) - jours * 86400
    with _lock, _conn() as c:
        c.execute("DELETE FROM journal_moderation WHERE ts < ?", (limite,))

NOMS_RESERVES = set()      # noms pris par le serveur lui-meme (les robots, renseignes au demarrage)

def nom_interdit(nom):
    """True si le nom contient un des mots interdits par l'administrateur (reglage « noms_interdits »), ou si c'est
    celui d'un robot."""
    n = (nom or "").lower()
    if n.strip() in NOMS_RESERVES: return True
    return any(m and m in n for m in (x.strip().lower() for x in reglage("noms_interdits", "").replace(",", "\n").split("\n")))

def journal_ajouter(auteur, action, cible="", detail="", ip=""):
    """Une ligne du journal de moderation : qui, quoi, sur qui, pourquoi. Ne doit jamais faire echouer l'action."""
    try:
        with _lock, _conn() as c:
            c.execute("INSERT INTO journal_moderation(ts,auteur,action,cible,detail,ip) VALUES(?,?,?,?,?,?)",
                      (int(time.time()), str(auteur)[:40], str(action)[:40], str(cible)[:60], str(detail)[:400], str(ip)[:64]))
    except sqlite3.Error:
        pass


# ---------- guildes ----------
# Une guilde commence par un TABLEAU (finalisee = 0) : son maitre le cree en jeu (capacite « Guilde », 2500 powers),
# les autres joueurs le rejoignent (page web que le client ouvre), puis le maitre la finalise en jeu.
# L'appartenance est par PSEUDO (identifiant du pseudo, comme le reste du protocole).
GUILDE_COUT = 2500                 # powers : le client n'active le bouton « Utiliser » qu'a partir de 2500 (0x9C4)
_NOM_GUILDE = re.compile(r"^[A-Za-z0-9ÀÂÄÇÉÈÊËÎÏÔÖÙÛÜŸàâäçéèêëîïôöùûüÿ' _\-\.!&]{3,30}$")

def nom_guilde_valide(nom):
    return bool(nom) and nom == nom.strip() and "  " not in nom and bool(_NOM_GUILDE.match(nom)) and not nom_interdit(nom)

def guilde(gid):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM guildes WHERE id=?", (gid,)).fetchone()
    return dict(r) if r else None

def guilde_par_nom(nom):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM guildes WHERE nom=? COLLATE NOCASE", (nom.strip(),)).fetchone()
    return dict(r) if r else None

def liste_guildes(finalisees=True):
    """Les guildes (ou les tableaux) avec leur nombre de membres et le nom du maitre."""
    with _lock, _conn() as c:
        rows = c.execute("""SELECT g.*, p.name AS nom_maitre,
                                   (SELECT COUNT(*) FROM guilde_membres m WHERE m.guilde_id=g.id) AS nb_membres
                            FROM guildes g LEFT JOIN pseudos p ON p.id=g.maitre
                            WHERE g.finalisee=? ORDER BY g.nom COLLATE NOCASE""", (1 if finalisees else 0,)).fetchall()
    return [dict(r) for r in rows]

def membre_de(pseudo_id):
    """(guilde, membre) du pseudo -- tableau compris -- ou (None, None)."""
    with _lock, _conn() as c:
        m = c.execute("SELECT * FROM guilde_membres WHERE pseudo_id=?", (pseudo_id,)).fetchone()
        g = c.execute("SELECT * FROM guildes WHERE id=?", (m["guilde_id"],)).fetchone() if m else None
    return (dict(g), dict(m)) if (g and m) else (None, None)

def guilde_membres(gid):
    with _lock, _conn() as c:
        rows = c.execute("""SELECT m.*, p.name, p.account_id, p.vu FROM guilde_membres m JOIN pseudos p ON p.id=m.pseudo_id
                            WHERE m.guilde_id=? ORDER BY m.entree, p.name COLLATE NOCASE""", (gid,)).fetchall()
    return [dict(r) for r in rows]

def pseudos_en_guilde(account_id):
    """Nombre de pseudos de ce compte deja dans une guilde ou un tableau."""
    with _lock, _conn() as c:
        return c.execute("""SELECT COUNT(*) FROM guilde_membres m JOIN pseudos p ON p.id=m.pseudo_id
                            WHERE p.account_id=?""", (account_id,)).fetchone()[0]

def creer_tableau(nom, maitre, mdp=""):
    t = int(time.time())
    with _lock, _conn() as c:
        cur = c.execute("INSERT INTO guildes(nom, maitre, cree, mdp) VALUES(?,?,?,?)", (nom.strip(), maitre, t, mdp or ""))
        gid = cur.lastrowid
        c.execute("INSERT OR REPLACE INTO guilde_membres(pseudo_id, guilde_id, entree) VALUES(?,?,?)", (maitre, gid, t))
    return gid

def ajouter_membre(gid, pseudo_id, invite_par=0, pouvoirs=0):
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO guilde_membres(pseudo_id, guilde_id, pouvoirs, entree, invite_par) VALUES(?,?,?,?,?)",
                  (pseudo_id, gid, pouvoirs, int(time.time()), invite_par))

def retirer_membre(pseudo_id):
    with _lock, _conn() as c:
        c.execute("DELETE FROM guilde_membres WHERE pseudo_id=?", (pseudo_id,))

def finaliser_guilde(gid):
    with _lock, _conn() as c:
        c.execute("UPDATE guildes SET finalisee=1 WHERE id=?", (gid,))

def supprimer_guilde(gid):
    """Dissolution ou annulation : la guilde et ses membres (son journal reste, pour l'equipe)."""
    with _lock, _conn() as c:
        c.execute("DELETE FROM guilde_membres WHERE guilde_id=?", (gid,))
        c.execute("DELETE FROM guildes WHERE id=?", (gid,))

_CHAMPS_GUILDE = {"exp", "gils", "topic", "topic_par", "topic_ts", "logo", "logo_ts"}
def maj_guilde(gid, **champs):
    champs = {k: v for k, v in champs.items() if k in _CHAMPS_GUILDE}
    if not champs: return
    with _lock, _conn() as c:
        c.execute(f"UPDATE guildes SET {', '.join(k + '=?' for k in champs)} WHERE id=?", (*champs.values(), gid))

def ajouter_gils_guilde(gid, delta):
    """Ajoute (ou retire) des gils a la caisse ; refuse de passer sous zero. Retourne le nouveau total ou None."""
    with _lock, _conn() as c:
        r = c.execute("SELECT gils FROM guildes WHERE id=?", (gid,)).fetchone()
        if not r or r["gils"] + delta < 0: return None
        c.execute("UPDATE guildes SET gils=gils+? WHERE id=?", (delta, gid))
        return r["gils"] + delta

# ---------- panneau d'equipe : caisse et topic par groupe ----------
def groupe_equipe(groupe):
    """{caisse, topic, topic_par, topic_ts} d'un groupe d'utilisateurs speciaux (valeurs nulles s'il n'a rien)."""
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM groupes_equipe WHERE groupe=?", (groupe,)).fetchone()
    return dict(r) if r else {"groupe": groupe, "caisse": 0, "topic": "", "topic_par": "", "topic_ts": 0}

def topic_groupe(groupe, texte, par, ts):
    with _lock, _conn() as c:
        c.execute("INSERT INTO groupes_equipe(groupe, topic, topic_par, topic_ts) VALUES(?,?,?,?) "
                  "ON CONFLICT(groupe) DO UPDATE SET topic=?, topic_par=?, topic_ts=?", (groupe, texte, par, ts, texte, par, ts))

def ajouter_caisse_groupe(groupe, delta):
    """Ajoute (ou retire) des gils a la caisse du groupe ; refuse de passer sous zero. Nouveau total, ou None."""
    with _lock, _conn() as c:
        r = c.execute("SELECT caisse FROM groupes_equipe WHERE groupe=?", (groupe,)).fetchone()
        total = (r["caisse"] if r else 0) + delta
        if total < 0: return None
        c.execute("INSERT INTO groupes_equipe(groupe, caisse) VALUES(?,?) ON CONFLICT(groupe) DO UPDATE SET caisse=?",
                  (groupe, total, total))
        return total

def ajouter_exp_guilde(gid, delta):
    with _lock, _conn() as c:
        c.execute("UPDATE guildes SET exp=exp+? WHERE id=?", (delta, gid))
        r = c.execute("SELECT exp FROM guildes WHERE id=?", (gid,)).fetchone()
    return r["exp"] if r else 0

_CHAMPS_MEMBRE = {"titre", "pouvoirs"}
def maj_membre(pseudo_id, **champs):
    champs = {k: v for k, v in champs.items() if k in _CHAMPS_MEMBRE}
    if not champs: return
    with _lock, _conn() as c:
        c.execute(f"UPDATE guilde_membres SET {', '.join(k + '=?' for k in champs)} WHERE pseudo_id=?", (*champs.values(), pseudo_id))

def journal_guilde(gid, auteur, action, detail=""):
    try:
        with _lock, _conn() as c:
            c.execute("INSERT INTO guilde_journal(guilde_id, ts, auteur, action, detail) VALUES(?,?,?,?,?)",
                      (gid, int(time.time()), str(auteur)[:40], str(action)[:60], str(detail)[:300]))
    except sqlite3.Error: pass


def noter_connexion(pseudo_id):
    """Date de derniere connexion d'un pseudo (fiche des membres de guilde)."""
    if not pseudo_id: return
    with _lock, _conn() as c:
        c.execute("UPDATE pseudos SET vu=? WHERE id=?", (int(time.time()), pseudo_id))


if __name__=="__main__":
    # Controle de la base, sans rien y creer (l'ancien essai creait un compte administrateur au mot de passe connu).
    init()
    with _lock, _conn() as c:
        for table in ("accounts", "pseudos", "refcards", "auctions"):
            print(f"{table:10s}", c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    print("base :", DB_PATH)
