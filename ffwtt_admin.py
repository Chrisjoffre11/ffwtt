#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffwtt_admin.py — petits outils d'administration de la base ffwtt.db.

Usage (SERVEUR ARRETE pour eviter le verrou de la base) :
  py ffwtt_admin.py power  MonCompte 99999      # fixe les points de power
  py ffwtt_admin.py gils   MonCompte 99999      # fixe les gils
  py ffwtt_admin.py show   MonCompte            # affiche l'etat du compte
  py ffwtt_admin.py bannir MonCompte 1          # 1 = bannir, 0 = debannir
  py ffwtt_admin.py niveau MonCompte 4          # 0 joueur, 1 a 4 = operateur de niveau 1 a 4 (pastille
                                                #   « 1 » a « 4 » dans la liste ; 4 a tous les droits)
  py ffwtt_admin.py anim   Nini 1               # 1 = animateur (quizz, notoriete, annonces), 0 = non
  py ffwtt_admin.py resetcards MonCompte [N]    # vide la collection et redonne N cartes (defaut 20)
  py ffwtt_admin.py mdp    MonCompte secret     # attribue un nouveau mot de passe (« mot de passe perdu »)
Le premier compte cree sur un serveur neuf est deja administrateur (niveau 4).
"""
import sys
import ffwtt_db as db

def main():
    db.init()
    if len(sys.argv) < 3:
        print(__doc__); return
    cmd, name = sys.argv[1], sys.argv[2]
    ps = db.get_pseudo(name)
    if not ps:
        # Plus de creation d'office : un compte cree ici n'avait pas de mot de passe, et le premier venu qui se
        # connectait sous ce nom recevait le niveau ou les gils donnes d'avance.
        print(f"Pseudo inconnu : {name}. Le joueur doit d'abord creer son compte (premiere connexion).")
        raise SystemExit(1)
    acc = db.get_account(ps["account_id"])
    stock = db.stock_id(ps["id"])          # cartes et powers sont ceux du COMPTE (ranges sous le pseudo principal)
    if cmd == "power":
        val = int(sys.argv[3])
        with db._lock, db._conn() as c:
            c.execute("INSERT INTO powers(pseudo_id,points) VALUES(?,?) "
                      "ON CONFLICT(pseudo_id) DO UPDATE SET points=?", (stock, val, val))
        print(f"{name}: power = {val}")
    elif cmd == "gils":
        val = int(sys.argv[3])
        with db._lock, db._conn() as c:
            c.execute("UPDATE accounts SET gils=? WHERE id=?", (val, acc["id"]))
        print(f"{name}: gils = {val}")
    elif cmd == "resetcards":
        import random
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        with db._lock, db._conn() as c:
            c.execute("DELETE FROM collection WHERE pseudo_id=?", (stock,))
            seen=set()
            while len(seen) < n:
                cid=random.randint(1,3400)
                if cid in seen: continue
                seen.add(cid)
                vals=[random.randint(1,10) for _ in range(4)]
                c.execute("INSERT INTO collection(pseudo_id,card_id,qty,h,d,b,g) VALUES(?,?,1,?,?,?,?)",
                          (stock, cid, *vals))
        print(f"{name}: collection reinitialisee ({n} cartes)")
    elif cmd == "niveau":
        val = int(sys.argv[3])
        with db._lock, db._conn() as c:
            c.execute("UPDATE accounts SET admin=? WHERE id=?", (val, acc["id"]))
        noms={0:"Joueur",1:"Operateur niv. 1",2:"Operateur niv. 2",3:"Operateur niv. 3",4:"Operateur niv. 4"}
        print(f"{name}: niveau {val} ({noms.get(val,'?')})")
    elif cmd == "anim":
        val = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        with db._lock, db._conn() as c:
            c.execute("UPDATE accounts SET anim=? WHERE id=?", (val, acc["id"]))
        print(f"{name}: {'animateur' if val else 'plus animateur'}")
    elif cmd == "mdp":
        if len(sys.argv) < 4 or not 4 <= len(sys.argv[3]) <= 20:
            print("mot de passe : 4 a 20 caracteres"); return
        db.changer_mdp(acc["id"], sys.argv[3])
        print(f"{name}: nouveau mot de passe enregistre (compte '{acc['login']}')")
    elif cmd == "bannir":
        val = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        db.set_banned(acc["id"], val)
        print(f"{name}: {'banni' if val else 'debanni'}")
    elif cmd == "show":
        noms={0:"Joueur",1:"Operateur niv. 1",2:"Operateur niv. 2",3:"Operateur niv. 3",4:"Operateur niv. 4"}
        etat = " [BANNI]" if acc.get("banned") else ""
        print(f"{name}: compte#{acc['id']}{etat} niveau={acc['admin']} ({noms.get(acc['admin'],'?')}) gils={acc['gils']} "
              f"power={db.get_powers(ps['id'])} cartes={len(db.get_collection(ps['id']))}")
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
