# FFWorld Triple Triad — Protocole reconstruit et serveur

Client : **FFWTT.exe v3.3.3.6065** (© MrJul / FFWorld). Delphi natif, Winsock brut.
Lancement : `ffwtt://HOTE:PORT`.

Tout ce document a été établi par **observation du trafic réseau** (proxy) et vérifié
en jeu : chaque trame décrite est reproduite à l'octet près par le serveur.

---

## 1. Cadrage des trames

```
[ longueur : uint16 LITTLE-ENDIAN ][ opcode : uint16 BIG-ENDIAN ][ champs ]
```
La longueur couvre `opcode + champs`. **Piège** : longueur en LE, opcode en BE (htons).

### Ce qu'est vraiment « l'octet de contexte » (établi dans le binaire, 2026-09-18)

Le répartiteur de trames du client (grande fonction vers `0x639500`, tables de sauts) ne
teste pas l'opcode seul : il teste le mot **little-endian formé par l'octet d'opcode et
l'octet de contexte**, soit `code = opcode + 256 × contexte`. Exemples vérifiés par le
comportement du gestionnaire : op59/ctx1 → cas **315** (`0x63C9FE`, crée une fiche joueur),
op81/ctx1 → 337 (`0x63DE80`, passe la chaîne au navigateur), op65/ctx1 → 321 (`0x63E3F9`, lit
pid/nom/compte), op62/ctx1 → 318 (`0x63DB03`) ; les tables couvrent aussi 900–1001 (parties,
ctx3) et 1234–1302 (ctx4). Le « contexte » est donc l'octet de poids fort de l'opcode réel (la **catégorie** :
0 connexion, 1 salon, 2 enchères/échanges, 3 parties, 4 notes, 6 messages serveur), et
l'octet nul devant n'est pas un poids fort d'opcode. Conséquence : un contexte faux, c'est
**un autre opcode** — d'où la règle d'or n° 2. Cette correspondance permet aussi de retrouver
le gestionnaire de n'importe quelle trame dans le binaire (adresse du cas `opcode + 256×ctx`).

## 2. Champs

Un octet de **contexte** ouvre la charge utile (0x00 à 0x06 selon la catégorie),
puis des champs typés. Le client range tous les champs dans un tableau de variants
(16 octets par champ) et les relit par **position** : le type exact d'un champ numérique
(`v`, int16, int) importe peu, c'est son rang qui compte.

| Tag  | Type    | Encodage |
|------|---------|----------|
| 0x01 | chaîne  | `01` + [uint16 LE longueur XOR **0x55DE**] + caractères chiffrés |
| 0x02 | int32   | `02` + uint32 LE (utilisé par les enchères) |
| 0x03 | int32   | `03` + uint32 LE |
| 0x04 | int16   | `04` + uint16 LE |
| 0x05 | valeur  | `05` + 1 octet (index, coordonnée, score, grade…) |
| 0x06 | octet   | `06` + 1 octet (drapeau) |
| 0x08 | bloc    | `08` + [uint16 LE taille] + données **zlib** |

### Chiffrement des chaînes (clé fixe, aucun secret)
```
caractère_chiffré[i] = caractère_clair[i] XOR (0x4F + i)
```
La clé repart à 0x4F pour chaque chaîne. La longueur est XORée avec 0x55DE.

---

## 3. Table des opcodes

### Connexion et salon
| Sens | op | Rôle |
|------|----|------|
| S→C | 1, 4 | accueil (`00`), nom du serveur (`00 str(nom)`) |
| C→S | 5 | **version du client** : `00 u(version)`, envoyée dès réception d'`op4` (immédiat en `0x63A00B`). FFWTT.exe v3.3.3.6065 : **23082001** (capture : `00 03 11346001`). |
| S→C | 6 | **réponse à la version**, APRÈS `op5` (capture : `op5` puis `op6 00 06 01`). `b(1)` : « Session initialisée », le client passe à l'identification ; `b(0)` : « Vous ne possédez pas la bonne version de FFWTT » (cas 6, `0x63A162` ; même drapeau `0x8E80B4` qu'une adresse bannie), puis le serveur ferme. La collection `op52` a la taille du client **destinataire** (4885) |
| C→S | 100 | login (str login + str mot de passe) |
| S→C | 101 | réponse : `byte(1)+int(pid)+str(pseudo)` = OK ; `byte(0)+v(code)` = refus.<br>**Codes** : 2 = banni, 3 = mot de passe, 4 = « Ce compte est déjà connecté sur le serveur » (le serveur d'origine refusait une seconde connexion au même compte ; la nôtre aussi depuis le 2026-09-23, après avoir vérifié par un ping que l'ancienne répond encore), 91 = compte inexistant ; 97 existe aussi (même nom d'hôte déjà connecté : interdiction de jouer à plusieurs depuis un même réseau), non appliqué |
| C→S | 200 / S→C 201, 202 | liste des pseudos : op201 = `int(id) + str(nom) + str + int16 + b(principal) + b(banni)` (le 6ᵉ champ affiche « (banni) ») ; le client **ajoute** chaque op201 sans vider sa liste |
| C→S | 203 / S→C 204 | **créer un pseudo** (str nom) / `b(1)+int(id)+str(nom)` ou `b(0)+v(code)` (5 invalide, 6 existe déjà, 7 maximum atteint). Le client ajoute lui-même le pseudo à sa liste : ne pas renvoyer les op201 (doublons) |
| C→S | 205 / S→C 206 | **supprimer un pseudo** : `00 int(id du pseudo) str(e-mail)` — le client demande d'abord « Entrez votre e-mail pour la vérification : » (`TfrmNick.btnDelClick`) / `00 b1` = le client retire lui-même le pseudo de sa liste, `00 b0 v(code)` = message du code (gestionnaire `0x63A7AF`, lu dans le binaire, jamais capturé). Codes : 8 « E-mail incorrect » (e-mail du compte, casse ignorée ; un compte sans e-mail ne peut donc rien supprimer), 9 pseudo inexistant, 10 pas le vôtre, 30 « Impossible de supprimer le pseudo principal », 80 membre d'une guilde. Les cartes restent au compte (pseudo principal) ; ses enchères en cours sont retirées |
| C→S | 207 / S→C 208 | choix du pseudo / `b(1)`, ou `b(0)+v(code)` : 11 « Ce pseudo est banni », 10 « Ce pseudo n'est pas le vôtre » |
| S→C | 10 | **adresse bannie** (ctx 0, aucun champ). **Capturé** : le serveur envoie `op1 00`, `op4 00 str(nom du serveur)`, puis `op10 00` **à la place d'`op6`**, et ferme la connexion. Le client affiche : « Votre nom d'hôte est banni de ce serveur. Acceptez votre sanction : le ban n'en sera levé que plus vite (quelques heures généralement). Si vous pensez ne pas être concerné par ce ban, veuillez nous en excuser et réessayer de vous connecter au serveur un peu plus tard. » |
| C→S | 44 | prêt : le serveur envoie la rafale du salon |
| C→S | 71 / S→C 72, 73 | fin de réception, entrée validée |
| S↔C | 2/3, 512/768 | pings |

### Contenu du salon (rafale envoyée après op44)
Ordre observé (capture) : `op81` (page d'accueil) ; `op86` groupes (dont les pseudo-groupes des onglets de notes,
1 « Publiques » `_notes_publiques`, 2 « de développement » `_notes_maj`, 3 « Quicknews » `_notes_quicknews`, et 31
« ColorGroup » `_colorgroup_31`), `op87` grades, `op88` notoriétés, `op74` guildes ; `op45` identité, panneau d'équipe
(`op177`) et grades du joueur (`op61`) ; `op46`–`op51` compteurs, niveaux des compétences (53, 55, 89, 90, 56, 91),
`op83` notoriétés du joueur ; fiches `op59`, guilde, enchères `op190` ; `op62`. Le serveur génère toute la rafale
(`rafale_generee()`, 2026-10-13), identique à l'octet près à l'ancienne rafale rejouée hors enchères.

| op | Rôle |
|----|------|
| 45 | ton identité : `int(pid) + str(pseudo)` |
| 46–51 | **compteurs** : 46 Exp, 47 Gils, 48 Powers, 49 Victoires, 50 Défaites, 51 Nuls |
| 52 | **collection** : bloc zlib = tableau de 4885 octets de quantités ; **la case `i` est la carte d'identifiant `i + 1`** (capture : carte 4827 achetée → case 4826 ; mains op135 963/2337/2630 ↔ cases 962/2336/2629). Se termine par `v(0)` ; `v(1)`/`v(2)` + `int(pid)` = nouveau deck / remise à zéro par un administrateur |
| 53, 55, 56, 89, 90, 91 | niveau de chaque compétence (55 = Connaisseur, 56 = Vente aux enchères) |
| 59 | fiche joueur : id, nom, statut, horodatage, 6 Elo, **+ v(grade)** en fin |
| 62 | **fin de la liste des joueurs** (voir « Ordre d'entrée » ci-dessous) |
| 88 | **catégorie de notoriété** : `int(id) + str(libellé) + int(seuil)` ; logo `Images/<Serveur>_Notoriety_<id>.png`. Un joueur a **une étoile par catégorie dont il atteint le seuil** (le gestionnaire d'op59 compte les `valeur ≥ seuil`) : ce sont les lignes ★★★★ de la liste. Le nombre de catégories fixe le nombre d'int16 des fiches op59 |
| 83 | **mes** notoriétés : autant d'int16 que de catégories (« Notoriété : %d/%d ») |
| 74 | liste des **guildes** |
| 81 | **URL** affichée dans la fenêtre de CGU / panneau d'accueil (`--accueil URL`), sans lien (la fenêtre `TfrmAgreement` n'a qu'« J'accepte » / « Je refuse », navigateur de 667 × 419) |
| 86 | **groupe** : `int(id) + str(libellé) + str(clé) + int(couleur) + [str(fonction)]*`. Clés `$op`, `$anim`, `$prof` = lignes d'en-tête de la liste des joueurs ; un groupe qui a des fonctions (`chat`, `topic`, `joins`, `specialactions`, `currentactions`, `banlist`, `activity`, `gilsbank`, `quizz`) possède un **panneau d'équipe** |
| 87 | **grade** : `int(id) + str(libellé) + int(groupe) + [str(permission)]*`. À sa réception le client charge le logo `%APPDATA%/FFWorld Triple Triad/Images/<Serveur>_SpecCateg_<id>.png` s'il existe (binaire, cas 343) : ce sont les pastilles « 4 3 2 1 » des opérateurs. Le protocole ne les transmet pas ; `ffwtt_images.py` les crée |
| 166 | lignes du message d'accueil |
| 190 | fiche d'enchère |
| 232 | **annonce de partie** : `int(joueur1) + int(joueur2) + v(5) + int(0) + b(1) + i32(masque des règles) + v(1)` (alimente l'onglet Parties ; le i32 est le **masque de règles** du défi : capture 0x3ee, 0x12, 0x62…) |

**Ordre d'entrée (capture, établi le 2026-09-18).**
**`81`** → `86/87…` `88` `74` → **`45`** (→ `61` si le joueur a un grade) → `46…51` `53 55 89 90 56 91` `83` `52` → **`59` × N** → `190` × N → **`62`** → `166`,
puis le client envoie `71` et reçoit `72` et `73(int pid, b1)`.
- Tout ce qui s'ajoute à la liste du client **après `62`** est annoncé dans le chat :
  « X vient d'entrer sur le FFWTT ». Un `45` ou un `59` tardif produit donc une fausse arrivée
  (c'était le cas d'un robot, du joueur lui-même et du vendeur « Marche »).
- La capture ne contient **jamais de `59` du joueur pour lui-même** : `45` suffit. Lui en envoyer un
  le fait apparaître **deux fois**. Confirmé dans le binaire : le gestionnaire d'`op59`
  (`0x63C9FE`) **crée toujours** une nouvelle fiche, sans chercher si le pid existe déjà.
- **`81` doit partir en tête** (c'est la première trame de la capture). Le client affiche l'URL dans
  le navigateur de sa fenêtre de chargement, et le gestionnaire d'`op62` **détruit** cette
  fenêtre : un `81` reçu après `62` navigue dans un objet libéré →
  « Access violation at address 0061125E … read of address 00000378 ».
- **`45` doit précéder tout `59`.** L'objet « moi » du client (global `0x8E80C8`) n'est créé
  que par le gestionnaire d'`op45` ; celui d'`op59` parcourt les grades de « moi » à chaque
  fiche reçue → « Access violation at address 0063CED2 … read of address 0000003C » si une
  fiche (un robot…) arrive avant `45`.
- **`61` = « le joueur reçoit un grade »** : `01 + int(pid) + v(id_grade)`. **Déduit du binaire,
  jamais capturé** (cas 317, `0x63D825` : `Users.Find(pid)`, `Grades.Find(id)`,
  `joueur.Grades.Add(grade)`, puis comparaison du joueur à « moi »). C'est le seul moyen de
  donner son grade — donc ses permissions (`kick`, `mute`, `bannick`, `banaccount`, `banhost`,
  `warn`, `global`…) — au joueur lui-même. Il doit suivre les `87` (définition des grades) et
  le `45`. Les grades se cumulent (aucun opcode de retrait identifié).
- Arrivée d'un autre joueur en cours de session : `59` (sa fiche) puis `73(int pid, b1)`. Départ : `60(int pid, v0, v0)`.

**Notoriété et liste des joueurs.** Le client compte les **étoiles** d'un joueur (catégories dont la valeur atteint le seuil
d'`op88`) et range les joueurs **sans grade** par nombre d'étoiles : la ligne de séparation dessine ces étoiles (gestionnaire
de dessin `TfrmMDI.lstNicksDrawItem`, `0x629084` : grade → nom du groupe, sinon `[joueur+0x28]` étoiles). Mise à jour d'un
joueur déjà listé : **`op84` (catégorie 1) = `int(pid)` + une valeur par catégorie** (`0x63DEBF` : recalcule les étoiles et
reclasse le joueur si leur nombre change) ; pour soi-même, `op83`. Le serveur diffuse les deux à chaque changement
(édition par un opérateur, points du quizz).

**Joueurs anglophones (choix de ce serveur, 2026-09-24).** La langue du compte (`accounts.langue`, « !langue en »)
donne aux anglophones le grade **41 « English speaker »** du groupe **40 « English speakers »** (sans fonction, donc sans
panneau), défini juste après le grade des robots : ils forment une section entre « Robot » et les joueurs sans grade. Même
mécanique que les robots et les opérateurs, aucune trame nouvelle : `op61 int(pid) v41` pour soi (le client écrit alors
« *** X est maintenant un(e) English speaker » à chaque connexion, comme pour les autres grades), `v41` en fin de fiche
`op59` pour les autres. Logo : un drapeau britannique (`SpecCateg_41.png`). Les francophones restent **sans** grade : un
grade « français » remplacerait les rangs d'étoiles de notoriété par une section unique. Un changement de langue compte à
la connexion suivante (aucun retrait de grade connu).

### Salon d'équipe et quizz (lus dans le binaire, catégories 4 et 5)
| Sens | op | Rôle |
|------|----|------|
| S→C | 177 (ctx4) | `b(1) + int(GRADE)` — **un identifiant de grade, pas de groupe** : le client cherche le grade (`Grades.Find`), affiche « Vous faites maintenant partie de la catégorie <libellé> » et crée le panneau du groupe de ce grade (réponse d'origine à `/ident`). Un identifiant inconnu = « Access violation at 00649EF3, read of 00000014 ». **Doit précéder tout `op61` d'un grade de ce groupe et toute fiche `op59`** : dès que « moi » a un grade dont le groupe a la fonction `joins` (resp. `chat`), les gestionnaires d'`op59` (resp. `op60`, `op70`) écrivent dans le panneau sans vérifier qu'il existe → « Access violation at 0063CF31, read of 00000374 », après quoi plus rien ne marche. Fonctions testées par gestionnaire : 59 `joins` · 60, 70 `chat` · 187, 190 `banlist` · 201 `activity` · 243 `currentactions` · ctx5 20–39 `quizz` |
| S→C | 179 (ctx4) | ligne du salon : `int(groupe) + int(pid) + str(texte) + b(action)`. Le pid doit être celui d'un joueur **présent**, sinon la ligne est ignorée : aucun historique n'est conservé (retiré le 2026-09-23 à la demande de l'utilisateur) |
| C→S | 178 ? (ctx4) | message du salon : **jamais observé** ; on accepte 178 et, à défaut, toute trame inconnue de forme `int(groupe) + str` (le journal signale l'opcode réel) |
| S→C | 220–228 (ctx5) | quizz : 220 `int(pid) str(thèmes)` démarré · 221 `int(pid)` interrompu · 222 `[int(pid) int(points)]*` TOP 5 · 223 `str(thème) str(question)` · 224 `int(pid) int(points) str(réponse)` trouvé · 225 `str(réponse)` personne · 226 `int(pid)` remise à zéro · 228 `int(points)` mes points |
| C→S | 227 (ctx5) / S→C 228 | `/points` : aucun champ / `05 int(points)` (« Vous avez %d point(s) sur le quizz actuel ») |
| C→S | 21, 25, 29, 32, 35, 37, 40 (ctx5) | panneau Quizz du client (formats connus par `ffwtt_envois.py` : 21 `bs`/`bu` catégorie, 25 `buss`/`buu` question, 29 démarrer, 32 arrêter, 35 remise à zéro, 37 top 10, 40 `uu` questions d'une catégorie ; accusés 22, 26, 28, 30, 31/34/36/38, 39, 41, 42) : **pas branché**, le quizz se pilote par `!quiz demarrer [thème] · arreter · top · zero · points` |
| C→S | 120 (ctx5) / S→C 121 | menu « Twitter » : sur l'original, une récompense (« Merci, votre compte a été crédité de %d gils ! ») ; pas branché |

### Profil
| Sens | op | Rôle |
|------|----|------|
| C→S | 64 | ouvrir un profil (int pid) |
| S→C | 65 | profil complet (voir §4) |
| S→C | 66 (ctx6) | **notes personnelles** (`06` + bloc zlib, onglet « Personnelles »), envoyé après op65 **uniquement pour son propre profil** (vide : `0608070078da000000ffff`). Enregistrées en base depuis le 2026-10-12 (`pseudos.note_perso`) |
| C→S | 64 (ctx6) / S→C 65 (ctx6) | enregistrer ses notes personnelles : `06 + x(texte)` (30 000 caractères au plus) / accusé `06 b1`, ou `06 b0 v(code)` (69 « Le serveur attendait des données compressées »). **Même numéro que l'ouverture d'un profil (catégorie 1)** : voir § Aiguillage |
| S→C | 241 | **note publique** : `04 + int(groupe) + int(pid) + x(texte)`. Le premier entier est un **identifiant de groupe** (lu dans le gestionnaire `0x64F1BE` : cherché dans la liste des groupes, son libellé titre l'onglet ; un groupe inconnu = pointeur nul). Ce n'est pas un « numéro de morceau » (ancienne supposition). Les onglets de notes sont des **pseudo-groupes** déclarés par `op86` avec une clé `_notes_*` : la rafale d'entrée déclare 1 « Publiques » (`_notes_publiques`), 2 « de développement » (`_notes_maj`), 3 « Quicknews » (`_notes_quicknews`). Le serveur envoie l'onglet du groupe 1 après **chaque** op65, même sans note |
| C→S | 239 / S→C 240 | **écrire une note publique** : `04 + int(groupe de l'onglet) + int(pid du profil affiché) + x(texte)` (`TfrmInfos.btnChangeNotesClick`, `0x62CD44` : l'onglet « Personnelles » part en ctx6 op64, tout autre onglet ici) / accusé `04 b1` ou `04 b0 v(code)`. Le profil d'un autre demande la permission `editnotes` (87 sinon). Jusqu'au 2026-10-12 le serveur ignorait le pid : un opérateur qui corrigeait la note d'un joueur écrasait la sienne |

### Chat
| Sens | op | Rôle |
|------|----|------|
| C→S | 144 / S→C 145 | message public ; l'octet final `b` = **mode action** (`/me`), rediffusé tel quel dans op145 |
| C→S | 146 / S→C 147 | message privé |
| C→S | 151 / S→C 153 | message dans une partie |

### Boutique, powers, compétences
| Sens | op | Rôle |
|------|----|------|
| C→S | 66 | fenêtre « Mes cartes » : `01 int16(carte) v(action)`, l'action étant le **Tag du bouton** (DFM de `TfrmMyCards`) : **0 = jeter** (`btnDel`, le client demande confirmation), **1 = powers** (`btnPower`), **2 = acheter** (`btnBuy`, « Mode boutique »), **3 = vendre** (`btnSell`). Jeter, powers et vendre répondent `op63 b0` + `op67 b1` (plus `op48` ou `op47`) ; la vente rapporte **10 % du prix** (changelog 3.2 : « entre 10% et 25% du prix suivant votre compétence Sentier », compétence supprimée en 3.3 : déduit, jamais observé). Jusqu'au 2026-09-23 le serveur prenait toute action ≠ 1 pour un achat : « Vendre » et « Jeter » achetaient la carte |
| S→C | 63 | collection : `byte(1)` ajoute, `byte(0)` retire + int16(carte) |
| S→C | 67 | accusé d'`op66` : `01 b1` = réussi (le client joue le son « tradeok ») ; **`01 b0 v(code)`** = refus, le client affiche le message du code (gestionnaire `0x640259`) : 14 pas assez de gils, 15 déjà 255 exemplaires (achat), 46 pas assez de cartes disponibles (enchères en cours…), **101 « Vous devez posséder plus de 10 cartes pour effectuer cette action »** ; codes particuliers 13 (`+ carte` : carte non possédée) et 106 (`+ int` : expérience minimale pour acheter). **99 « Vous devez posséder 2000 points d'expérience au minimum pour effectuer cette action »** : règle d'origine (changelog, build 5448 : 200 points, expérience ×10 en 3.3) pour vendre, jeter, sacrifier, échanger (`op89`) et mettre aux enchères (`op189`), appliquée depuis le 2026-09-23. |
| C→S | 68 / S→C 69, 70 | mode power |
| C→S | 244 | acheter/améliorer une compétence (`v = id`). **id = Tag du bouton « + » de TfrmSkills** (tous branchés sur `btnUpDCClick`) : **0 Souk** (`btnUpDC` n'a pas de Tag dans le DFM, donc 0 — et non 1), 2 Connaisseur, 3 Profiteur, 4 Vente aux enchères, 7 Initié, 8 Chanceux. |
| S→C | 245 | **accusé d'op244** (gestionnaire `0x640580`) : `01 b1 v(id) v(niveau)` → « Le niveau de la capacité %s est maintenant de %d ! » ; `01 b0 v(code)` → erreur 16 (déjà au plus haut niveau), 17 (pas assez de powers), 18 (capacité inconnue). |
| S→C | 53, 55, 56, 89, 90, 91 | **niveau d'une compétence**, `01 05 <niveau>`, un opcode par compétence : **53 Souk, 55 Connaisseur, 56 Vente aux enchères, 89 Profiteur, 90 Initié, 91 Chanceux** (55 et 56 observés ; les quatre autres lus dans le binaire : chaque gestionnaire charge le nom de sa compétence). Le client écrit lui-même « Capacité %s niveau %d » dans le chat : le serveur n'a rien à annoncer. Envoyés aussi dans la rafale d'entrée. |

**Effets des compétences**, tels que le client les affiche (bulle « Plus d'infos » de `TfrmSkills`, fonction `0x61C3F0` ;
coûts et niveaux maximum : `TfrmSkills.UpdateLevelButtons`, `0x61D008`, qui grise le bouton « + » si le niveau suivant est
hors de portée) : Souk −5 % du prix d'achat par niveau (6 niveaux), Connaisseur +20 % de powers au sacrifice (3), Profiteur
+5 % de gils par partie (6), Chanceux 1 % de chance de gagner une carte (5), Vente aux enchères (3, voir § Enchères) et
**Initié** (6), dont le bonus d'expérience **dépend du résultat** (table `0x6671A4`, victoire / nul / défaite) :
1 = +10/0/0 %, 2 = +10/+10/0, 3 = +10/+10/+10, 4 = +20/+10/+10, 5 = +20/+20/+10, 6 = +20/+20/+20 (appliqué depuis le
2026-10-12 ; le serveur donnait +3,3 % par niveau quel que soit le résultat).

**Règle des « plus de 10 cartes »** (table des erreurs du client, codes 101, 103, 105) : on ne peut ni sacrifier, ni mettre aux
enchères (`op189` : `02 b0 v101`), ni offrir en échange (`op94` : `02 int(partenaire) b0 v105`) si cela fait tomber à 10 cartes
disponibles ou moins ; les cartes en vente restent dans la collection mais ne sont plus « disponibles » (code 46).

### Enchères
| Sens | op | Rôle |
|------|----|------|
| C→S | 188 / S→C 189 | mettre en vente (int16 carte + prix + achat immédiat) |
| S→C | 190 | fiche d'enchère diffusée |
| C→S | 191 / S→C 192, 193 | miser / accusé / nouvelle meilleure offre |
| C→S | 194 / S→C 195 | annuler |
| S→C | 196 | enchère retirée (aussi à l'expiration sans offre) |
| S→C | 197 | minuteur d'une enchère |

**Cycle** : la carte **reste** chez le vendeur pendant la vente ; elle ne change de mains
qu'à la conclusion (op63 retrait chez le vendeur, ajout chez l'acheteur).

**Capacité « Vente aux enchères »** (tables du client lues dans la bulle « Plus d'infos », `0x667194` / `0x667198`) :
niveau 1 = 1 vente à la fois et 10 % de perte, niveau 2 = 3 ventes et 5 %, niveau 3 = 5 ventes et 0 %. Refus d'`op188`
par `op189 02 b0 v(code)` : 32 « Vous ne possédez pas cette capacité » (le client grise déjà le bouton), 31 « Vous avez
déjà le maximum d'enchères en cours » (compté sur le compte, appliqué depuis le 2026-10-12).

### Échange de cartes
| Sens | op | Rôle |
|------|----|------|
| C→S | 88 / S→C 89 | je demande un échange / accusé `02 int(cible) b1` ; refus `02 int(cible) b0 v(code)` (gestionnaire `0x640788`, le message reçoit le pseudo de la cible) : 99 (moi) ou 100 « %s doit posséder 2000 points d'expérience… » (la cible) |
| S→C | 90 | **invitation** envoyée à la cible |
| C→S | 91 / S→C 92 | réponse à la proposition : `int(l'autre) + b` (« Accepter » b1 ; « Refuser » de l'invité ou « Annuler » du proposant b0) / `02 int(l'autre) b1` aux deux ouvre la fenêtre d'échange ; **`02 int(l'autre) b0 b(message) [v(code)]`** la ferme (gestionnaire `0x640B5D`, jamais capturé) : rien (`b0`), « %s a refusé votre échange » (`b1`), ou l'erreur. Celui qui clique **attend** cette réponse (bouton grisé sinon) |
| C→S | 93 / S→C 94 | mon offre : `int(partenaire) + int(gils) + [int16(carte) + v(quantité)]*` / accusé `int(partenaire) + b1` |
| S→C | 95 | offre du partenaire : `int(partenaire) + int(gils) + [int16(carte) + v(quantité)]*` (capture d'une offre vide : `int + int(0)`). **L'identifiant doit être exact** : une carte hors table fait planter le client (`0040505A`) |
| C→S | 96 | `int(partenaire) + b` : **b1 = je valide** (les deux → transfert), **b0 = j'annule** |
| S→C | 97 | fin d'échange : `int(partenaire) + b(1)` = conclu ; `int(partenaire) + b(0)` = « %s a refusé ou annulé l'échange ». Au-delà de 3 champs le client affiche en plus l'erreur du 4e (binaire, cas 609) : capture d'un partenaire déconnecté = `b(0) + b(1) + v(24)` |
| S→C | 60 | **« X a quitté le FFWTT »** : `01 + int(pid) + v(0) + v(0)`, diffusé à la déconnexion (retire le joueur de la liste). Ce n'est PAS une annulation d'échange (ancienne erreur de lecture : le partenaire avait quitté pendant l'échange). |

### Duels
| Sens | op | Rôle |
|------|----|------|
| C→S | 32 | défi : `03` + `int(pid_cible)` **brut** (999 pour le bot) + `int16(règles)` + `v(règle vainqueur)` + `int(mise gils)` + `v(index temps)` + `b(spectateurs)` |
| S→C | 33 | accusé du défi : `03` + `int(pid_cible)` + `b(1)` + **écho exact** des paramètres d'op32. Capture : `03 0316040000 0601 04ee03 0501 0300000000 0500 0601` |
| S→C | 34 / C→S 35 | **invitation** (`int(pid_défiant)` + mêmes champs) / réponse (`int(pid_défiant)` + `b(accepte)`) |
| S→C | 36 | partie créée : `03` + `int(pid_adversaire)` + `b(1)` + `b(0)` + `int(id_partie)`. Capture : `03 0316040000 0601 0600 03 1a040000` |
| S→C | 36 | **défi refusé ou annulé** : `03` + `int(l'autre joueur)` + `b0` + `b(message)` [+ `v(code)`]. Lu dans le gestionnaire (branche `b0`, `0x643557`), jamais capturé : le client **referme la fenêtre de défi** ouverte avec ce joueur, puis rien (`b0`), « %s a refusé votre défi » (`b1`) ou le message de l'erreur (`b1` + code). Le bouton « Refuser » (et « Annuler le défi » du défiant, même trame `op35` avec `b0`) **attend cette réponse** pour fermer la fenêtre : sans elle, elle restait bloquée (2026-09-23) |

**Correction (2026-09-08).** La cible d'un défi est le **pid brut** de l'adversaire, pas
`pid << 8 | 3`. L'identifiant de partie est attribué à part par le serveur.

**Piège (2026-09-18).** Le journal du serveur affiche `op32 int=255747` pour un défi au bot :
c'est `describe()` qui lit l'octet de contexte `03` comme une étiquette d'entier
(`03 | 03 e7 03 00` = 255747 = 999<<8|3). Le client envoie bien `int(999)`. L'ancien code
produisait les bons octets d'op33/op36 *par accident* grâce à ce décalage ; en passant au
décodage correct sans réécrire ces deux trames, le duel contre le bot est devenu muet.
`test_serveur.py` compare désormais op33/op36 octet par octet au format de la capture.

**Masque de règles (int16, cases à cocher du client, champ Tag) :**

| bit | règle | appliquée ? |
|----:|-------|-------------|
| 1   | Open : la main adverse est visible (op136 porte les vraies cartes) | oui |
| 2   | Aléatoire : 5 cartes tirées dans la collection de chacun, la partie démarre aussitôt ; **sans** elle, op36 demande le choix des cartes | oui |
| 4   | Élémentaire (plateau op137) | oui (élément de chaque carte lu dans la table du client, § 6) |
| 8   | Bataille | oui |
| 16  | Mur cassé | oui |
| 32  | Identique | oui |
| 64  | Plus | oui |
| 128 | Même mur | oui |
| 256 | Mur additionnel | oui |
| 512 | Mur puissant (plateau op138, déplacements dans op143) | oui |

**Règle du vainqueur** (`v`) — **ordre corrigé le 2026-09-22** d'après le client (liste de `TfrmRules.FormCreate`
et fonction `0x638BF8` qui convertit l'indice en libellé) ; l'ancienne table était fausse (Entraînement et Totale
inversés, notamment) :

| valeur | règle | enjeu appliqué par ce serveur |
|---:|---|---|
| 0 | Entraînement | rien du tout : ni statistiques, ni expérience, ni gils, ni cartes (journal des versions 3.2 : « vous permettant de jouer sans modifier votre expérience, victoires, défaites ou matchs nuls ») |
| 1 | Aucune | statistiques et gils, aucune carte |
| 2 à 5 | One, Two, Three, Four | le vainqueur **choisit** 1 à 4 cartes dans la main du perdant |
| 6 | Totale | les 5 cartes de la main du perdant (le client exige « plus de 10 cartes », erreurs 103 / 104) |
| 7 | Directe | « les joueurs remportent les cartes qu'ils ont retournées au cours de la partie » (définition donnée par l'utilisateur, joueur de l'époque) : **les deux joueurs**, vainqueur ou non, match nul compris, gardent les cartes adverses qu'ils détiennent à la fin. L'origine de chaque carte est le 4ᵉ élément de la case du plateau (`ffwtt_regles`), conservé par les retournements et les déplacements |
| 8 | Change | « le vainqueur remporte le nombre de cartes équivalant à la différence de points » (même source ; 8 à 2 → 6), au plus les 5 cartes engagées : le panneau « Choisissez vos gains » du client est dessiné pour 5 cartes |
| 9 | Aléatoire | le serveur tire le nombre de cartes (1 à 5), le vainqueur choisit (**déduit**) |

Les seuils d'expérience par règle (« Un certain nombre d'expérience est maintenant requis pour utiliser chaque règle
du vainqueur », journal des versions, build 5620) sont perdus : ce serveur en fixe (`EXP_REGLE`), refus par
`op33 b0 v107` (moi) / `v108` (l'adversaire). La **mise en gils** est prélevée à l'acceptation (op35) et le gagnant
récupère le double (nul = remboursé). Contre un robot, aucun enjeu : la règle est ramenée à « Aucune ».

**Le choix des gains** (formats lus dans les gestionnaires du client, jamais capturés) :

| Sens | op | Format |
|------|----|--------|
| S→C | 145 | `03` + `int(numéro de partie)` + `v(nombre à choisir)` + `int16(carte)`×5 → panneau « Choisissez %d carte(s) : » |
| C→S | 149 | `03` + `int(numéro de partie)` + `v(rang)`× : les cartes choisies, **par leur rang dans op145** (format d'envoi « u111… ») |
| S→C | 150 | `03` + `int(partie)` + `b1`, ou `b0` + `v(code)` (53 = « Vous n'avez pas gagné la partie avec %s ») |
| S→C | 146 / 147 | `03` + `int(partie)` + `int16(carte)`× : **gains** (au vainqueur) et **pertes** (au perdant) ; vides s'il n'y a pas d'enjeu |
| S→C | 148 | `03` + `int(partie)` : partie définitivement terminée (« (terminé) », bouton Fermer) |

Après le transfert, le serveur renvoie la **collection complète** (`op52`) aux deux joueurs : le client s'y fie pour
savoir ce qu'il possède. Si le vainqueur ne choisit pas dans les 90 s, le serveur tire ses cartes au sort. Un joueur
qui **quitte en pleine partie** fait gagner l'enjeu à l'autre (op144 avec la raison 1), comme sur le serveur d'origine
(« Si un joueur gagnait une partie en mise parce que son adversaire avait été déconnecté… », journal des versions 3.2.3).
| S→C | 135 / 136 | ta main (5 int16) / main adverse masquée (0x1316) |
| C→S | 133 / S→C 134 | deck choisi / accusé (facultatif : le serveur peut distribuer) |
| S→C | 232 | initialisation |
| S→C | 139 | tour : `v(joueur) + int16(chrono)` |
| C→S | 140 / S→C 141 | poser une carte `v(index) v(x) v(y)` / accusé |
| S→C | 142 | carte posée : `int16(carte) v(x) v(y) v(propriétaire) v(index)` |
| S→C | 143 | retournements : `byte(0)` + `[v(x) v(y) int(pid) v(1)]…` + `v(score)` |
| S→C | 233 | score |
| S→C | 144, 235, 146, 147, 148 | fin de partie |

**Identifiant de partie** = `numéro_partie << 8 \| 3` en interne ; **sur le fil, c'est toujours `03` + `int(numéro de partie)`**
(l'octet `03` est la catégorie). Tout champ qui désigne une partie ailleurs que derrière l'octet de catégorie (`op157`) porte
donc le petit numéro.

**Robots.** Quatre adversaires permanents (pid 999 Mog-Facile, 998 Chocobo-Moyen, 997 Tonberry-Dur, 996 Bahamut-Extrême ; grade 102,
section « Robot »). Ils acceptent toutes les règles, **jamais d'enjeu** : l'écho d'`op33` revient avec la règle du vainqueur à 0
(sauf 6, Entraînement) et la mise à 0. Main tirée dans une fourchette de niveaux, IA à profondeur croissante, gains d'une
victoire ou d'un nul multipliés (×1, ×1,5, ×2,5, ×4).

**Onglet Parties.** `op232` (`gid` + annonce) ajoute la partie à la liste : les deux adversaires le reçoivent dans
leurs trames de début, **les autres joueurs par diffusion** (jamais les deux, sinon la ligne est en double), et un joueur
qui entre au salon reçoit les parties en cours après `op73`. `op235` (`gid` + `b`) la termine (gestionnaire `0x647437` :
heure de fin et score, « - / - » si `b0` ; la ligne est supprimée si l'option « supprimer les parties finies » du client
est cochée) : envoyé aux adversaires dans leurs trames de fin et diffusé aux autres ; `b0` quand la partie est abandonnée.

### Spectateur

**Source : le binaire du client** (gestionnaires des cas 925 à 931 et 1002, et les deux envois `0x39C` / `0x3A2`), plus une
capture d'`op234`. Aucun visionnage n'a été capturé. Refait le 2026-09-20 : l'ancien code envoyait dans
`op157` l'identifiant interne `numéro << 8 | 3` ; le client cherche la partie dans **sa** liste (onglet Parties, remplie par
`op232`) avec le **petit numéro**, ne la trouvait pas, et ne faisait rien, sans message.

| Sens | op | Rôle |
|------|----|------|
| C→S | 156 | demander à regarder : `03` + `int(numéro de partie)` + `b` (format d'envoi « ub ») |
| S→C | 157 | accord : `03` + `b1` + `int(numéro de partie)` → « Entrée comme spectateur acceptée dans la partie entre %s et %s », ouvre la fenêtre « Jeu entre %s et %s ». Refus : `03` + `b0` + `v(code)` : 56 sa propre partie, 57 pas commencée, 58 inexistante, 59 spectateurs interdits (sauf permission `spygame`), 60 déjà spectateur |
| S→C | 161 | **état complet** (réservé aux spectateurs) : `03` + `int(partie)` + `v(score du joueur 0)` + `int16(masque des règles)` + `v(règle du vainqueur)` + `int(mise)` + 9 × [`int16(carte, 0 = case vide)` + `v(propriétaire)`], cases dans l'ordre du fil `x*3 + y` |
| S→C | 135 / 136 | les deux mains : dos de cartes `0x1316` (vraies cartes en Open), **`0` = carte déjà jouée** (le client saute l'identifiant 0). Chez un spectateur, le joueur « 0 » est celui d'`op135` : propriétaire d'`op142`, tour d'`op139` et score d'`op143`/`op233` sont exprimés par rapport au **premier joueur de la partie**, pas au destinataire ; l'accusé `op141` ne lui est pas envoyé |
| S→C | 160 | spectateurs présents (réservé aux spectateurs) : `03` + `int(partie)` + `int(pid)`… |
| S→C | 158 / 159 | `03` + `int(partie)` + `int(pid)` : « *** %s observe maintenant la partie » / « a arrêté d'observer » ; aux deux joueurs et aux autres spectateurs |
| S→C | 234 | **nombre de spectateurs** d'une partie, diffusé à tous (onglet Parties) : `03` + `int(partie)` + `int(nombre)`. Capture : `03031b0400000301000000` puis `…0300000000`. Ce n'est PAS un « début de visionnage » (ancienne lecture, avec un octet en trop) |
| C→S | 162 / S→C 163 | « Arrêter de regarder la partie » : `03` + `int(partie)` (format « u ») / accusé `03` + `int(partie)` + `b1` (ferme la fenêtre) |
| S→C | 144 | fin pour les spectateurs : « Partie entre %s et %s terminée » ; 3e champ `v(raison)` : 0 normale, 1 « %s a quitté le FFWTT : arrêt de la partie », 2 « L'opérateur %s a arrêté la partie », suivies d'`int(pid)` |
| C→S | 154 | « le temps de mon adversaire est écoulé » (chaque seconde, par le joueur qui attend) |

**Trouver le format d'un envoi du client** : tous passent par la fonction `0x6367C4(ax = opcode + 256 × catégorie, edx = format,
ecx = arguments)`. Le format est une petite chaîne. Chercher `66 B8 <opcode LE>` suivi de l'appel donne donc le format de
n'importe quelle trame C→S sans capture (c'est ainsi qu'`op162` a été trouvé) ; `py ffwtt_envois.py` les liste toutes.
L'encodeur (`0x5E35C4`, décompilé avec REA/Ghidra le 2026-10-12) écrit un champ par lettre :

| Lettre | Champ | Lettre | Champ |
|---|---|---|---|
| `s` | chaîne brouillée (tag 01) | `1` | octet « valeur » (tag 05) |
| `u` | entier 32 bits (tag 03) | `b` | booléen (tag 06) |
| `4` | entier 32 bits (tag 02, celui des enchères) | `x` | **bloc zlib** : tag 08 + longueur sur 2 octets + flux zlib (`0x5E3480`) |
| `2` | entier 16 bits (tag 04) | `r` | écrivain `0x5E3548`, non décompilé : aucune requête inventoriée ne l'utilise |

### Guildes (lues dans le binaire le 2026-09-22, implémentées dans `ffwtt_guildes.py` ; rien de capturé)

**Sources.** Requêtes du client : `py ffwtt_envois.py --cat 4` (toutes passent par `0x6367C4` avec une chaîne de format) et
`--commandes`. Réponses : chaque gestionnaire relu instruction par instruction (champs lus, offsets de l'enregistrement
rempli, messages). Formulaires : `TfrmGuild`, `TfrmChangePowers`, `TfrmChangeLogo`, `TfrmInvite`. **Aucune trame n'a été
observée sur un serveur** ; `test_serveur.py` vérifie chaque format champ par champ, mais ne voit pas un plantage du client.

**Formats d'envoi** (constructeur `0x5E35C4`) : `s` chaîne (01), `4` entier 32 bits (02), `u` entier (03), `2` int16 (04),
`1` octet « v » (05), `b` booléen (06), `x` bloc **zlib** (08 + uint16 longueur + données). À la réception, un bloc est
décompressé dans un tampon global et le champ vaut `"$COMPDATA$"` (le gestionnaire compare avec cette chaîne).

**Déroulement.** Un joueur ayant 2500 powers (le client n'active « Utiliser » qu'à partir de `0x9C4`) crée un **tableau** :
nom définitif + mot de passe facultatif. Le client ouvre `guildroster.php?id=N` : « Transmettez ensuite cette page à vos
amis pour qu'ils rejoignent votre future guilde » — **on rejoint un tableau par cette page web**. Le maître finalise (bouton
« Finaliser », affiché quand `op92` catégorie 1 vaut `b1`) ou annule (powers rendus).

**Catégorie 1** (liste et appartenance, pour tous les joueurs) :

| op | Champs | Rôle (gestionnaire) |
|---|---|---|
| 74 | `int(id) str(nom)` | ajoute / met à jour une guilde dans la liste ; le client charge `Images\<Serveur>_Logo_<id>.png` s'il existe |
| 57 | `int(id)` | **ma** guilde : rattache la fenêtre Guilde, « *** Votre guilde est %s ». Il faut « moi » (op45) et la guilde (op74) avant |
| 75 | `int(pid) int(id)` | le joueur change de guilde (0 = aucune) |
| 76 | `int(id)` | guilde supprimée : retirée de la liste, plus personne n'y appartient |
| 92 | `b` | j'ai un tableau en cours (bouton « Finaliser ») |
| 59 | 5ᵉ champ | la fiche d'un joueur porte l'identifiant de sa guilde |

**Catégorie 4** — requêtes et réponses. Accusé commun : `b1`, ou `b0 v(code)` (+ `int(pid)` pour les messages « %s … »).

| Requête (C→S) | Réponses (S→C) |
|---|---|
| 119 `s(nom) s(mdp)` créer le tableau | 120 `b1 int(id)` (le client ouvre `guildroster.php?id=`) ; refus 17 powers, 63 nom pris, 64 déjà en guilde, 66 nom invalide, 117 trop de pseudos |
| 121 finaliser | 122 `b1` (refus 119 pas maître d'un tableau, 120 pas assez d'inscrits) |
| 123 annuler le tableau | 124 `b1` |
| 104 `u(pid)` inviter | 105 `b1 int(pid)` à l'inviteur (fenêtre « Invitation », bouton Annuler) ; 107 `int(inviteur) int(guilde)` à l'invité |
| 108 `b` réponse (b0 aussi quand l'inviteur annule, ou automatiquement si l'option « Refuser automatiquement les invitations de guilde » est cochée) | 106 à l'inviteur : `b1 b1` accepté, `b0 b1` refusé, `b0 b1 v(code)` erreur ; aux membres, 78 **avec** le 15ᵉ champ (« Nouveau membre %s dans la guilde, invité par %s ») |
| 109 `u(pid) s(raison)` expulser | 110 `b1` ; 111 `int(expulsé) int(auteur) str(raison)` à tous les membres, l'expulsé compris (son client referme la guilde) |
| 112 `s(raison)` quitter | 113 `b1` (refus 79 : le maître dissout) ; 114 `int(pid) str(raison)` aux autres |
| 86 `s(raison)` dissoudre (maître) | 87 `b1` ; 88 `int(auteur) str(raison)` aux membres (la fenêtre Guilde est recréée vide), puis 76 à tous |
| 212 `s(guilde) s(raison)` dissoudre (opérateur, permission `dissolveguild`) | 213 `b1` (94 guilde inexistante) ; puis comme ci-dessus |
| 100 `u(pid) s(titre)` titre | 101 `b1` ; 89 `int(pid) str(titre) int(auteur)` |
| 102 `u(pid) 2(masque)` pouvoirs | 103 `b1` ; 93 `int(pid) int16(masque) int(auteur)` |
| 94 `x(PNG 64×64)` logo (maître) | 96 `b1` (70 : une fois par 24 h) ; 95 `x(PNG)` aux membres |
| 97 `x(texte)` topic | 99 `b1` (71 trop long, 32 768 caractères) ; 98 `x(texte) str(auteur) int(date)` |
| 115 `u(montant)` déposer | 116 `b1` ; 85 `int(total) b(1 = dépôt) int(pid) int(montant)` ; le 1er champ seul met la caisse à jour |
| 117 `u(montant)` retirer | 118 `b1` ; 85 avec `b0` |
| 81 `s(message) b(action)` chat de guilde | 82 `int(pid) str(message) b(action) b(opérateur)` aux membres ; 83 `v(code)` en cas d'erreur |

**Fenêtre Guilde** (envoyée à un membre en entrant au salon, après les fiches op59, et quand il rejoint la guilde) :
`op57 (cat. 1)`, `84 int(exp)`, `85 int(gils)`, une **fiche 78 par membre**, `98` topic, `95` logo, puis **`80`** (fin : les
fiches 78 suivantes sont annoncées comme de nouveaux membres). Fiche 78 (enregistrement de 0x3B octets) : `int(pid)
str(nom) str(titre) int(cartes) int(exp) int(gils) int(powers) int(victoires) int(défaites) int(nuls) int16(pouvoirs)
int(entrée) int(dernière connexion) b(maître) [int(inviteur)]` — dates Unix. Mises à jour : 90 `int(pid) int(cartes)`,
91 `int(pid) int(exp) int(gils) int(powers)`, 92 `int(pid) int(v) int(d) int(n)`, 125 `int(pid) int(dernière connexion)`.

**Pouvoirs** (cases de `TfrmChangePowers`) : 1 inviter, 2 expulser, 4 topic, 8 retirer des gils, 16 protégé contre
l'expulsion, 32 maître secondaire. Le maître a tout (`HasAccess`, `0x61B498`).

**Capacité.** `TfrmGuild` affiche une table de 10 à 50 membres (exp et gils nécessaires, bonus de compétences), mais ce
client ne la remplit jamais (tableau en mémoire non initialisée : tout à 0), donc 50 membres au plus et aucun bonus.

**Choix du serveur** (non observés) : 5 inscrits pour finaliser (réglage `guilde_membres_min`), un pseudo par compte en
guilde, expérience de guilde = expérience gagnée par ses membres depuis leur entrée, notoriété de guilde
= somme des notoriétés des membres.

### Administration — catégorie 4 (octet de contexte `04`)

**Sources.** Les commandes C→S ont été **observées** le 2026-09-18 (menu du bouton droit d'un
administrateur, journal du serveur). Les accusés et notifications S→C n'ont **jamais été
capturés** : ils sont **lus dans le binaire du client** (`py ffwtt_binaire.py --ctx 4 --champs`,
qui donne pour chaque cas les messages chargés et les champs lus). Attention : la catégorie 4
réutilise des numéros de la catégorie 2 (191/194 = enchères) — le serveur aiguille donc sur le
contexte avant l'opcode.

| C→S (observé) | Charge utile | Permission | Accusé S→C (binaire) | Effet |
|---|---|---|---|---|
| 198 | `int(pid) + str(motif)` | `warn` | 199 | la cible reçoit **op78** (ctx1) `int(pid auteur) + str(motif)` : « %s vous donne un avertissement » |
| 181 | `int(pid) + str(motif)` | `kick` | 182 | la cible reçoit **op77** (ctx1) `int(pid auteur) + str(motif)` puis est déconnectée (les autres reçoivent op60) |
| 206 | `int(pid)` | `newdeck` | 207 | nouvelle collection ; **op52** se termine par `v(1) + int(pid auteur)` : « %s vous a donné un nouveau deck » |
| 220 | `int(pid)` | `resetaccount` | 221 | remise à zéro ; op52 avec `v(2) + int(pid auteur)` : « %s vient de remettre votre compte à zéro » |
| 226 | `int(pid) + 6 × int16` | `notoriety` | 227 | les 6 notoriétés (celles des 6 int16 de la fiche op59 et du profil op65) |
| 245 | `b(actif) + int(pid)` | `mute` | 246 `+ b(actif)` | « Mute / Unmute accepté par le serveur » |
| 184 | `int(pid)` | `banhost` | 186 `+ b(ajout)` | ban de l'adresse du joueur (ignoré en local : tout le monde est 127.0.0.1) |
| 185 | `b(ajout) + str(host)` | `banhost` | 186 `+ b(ajout)` | (non observé, déduit du couple 184/186) |
| 188 | — | `banhost` | 189 | vider les bans d'host (non observé) |
| 191 | `b(ajout) + str(pseudo) + str(motif)` | `bannick` | 192 `+ b(ajout)` | « Ajout / Suppression d'un ban de pseudo » |
| 194 | `b(ajout) + int(pid) + str(motif)` | `banaccount` | 196 `+ b(ajout)` | ban du compte du joueur |
| 195 | `b(ajout) + str(compte) + str(motif)` | `banaccount` | 196 `+ b(ajout)` | idem par nom de compte (`/banaccount`) |
| 217 | `str(message)` | `global` | 218 | tous reçoivent **op80** (ctx1) `str` : « Message global : … » |

**181 = kick, 198 = avertissement** : confirmé en jeu, et par les cibles de sauts de l'accusé
commun (cas 1206/op182 → « Kick accepté », cas 1223/op199 → « Avertissement accepté »). Une
première lecture « dans l'ordre des opcodes » les avait inversés : **décoder les sauts, ne pas
supposer l'ordre**.

**Accusé commun** (gestionnaire partagé `0x64A4CD` pour 182/199/203/207/221/227/246) :
`04 + b(1)` = « … accepté par le serveur » (le message dépend du **numéro** de l'accusé) ; le 2e champ booléen choisit
Mute/Unmute ou Ajout/Suppression. En cas d'échec : `04 + b(0) + v(code)`, avec la table d'erreurs commune à tout le
protocole (`py ffwtt_binaire.py --erreurs`, 121 codes : 2 compte banni, 3 mot de passe, 11 pseudo banni,
24 partenaire d'échange parti, 87 « privilèges insuffisants », 91 compte inexistant…). Deux variantes lues dans le
gestionnaire : `04 b0 v(12) int(n)` affiche « *** ID %d inexistant » avec `n`, et `04 b0 v(code) int(pid)` remplace le
`%s` du message par le nom du joueur `pid` (92 « … a une ou plusieurs parties en cours », 98, 102…).

| C→S (lu dans le binaire) | Charge utile | Permission | Réponse |
|---|---|---|---|
| 202 « Arrêter la partie » (onglet Parties, `TfrmListGames.mnuEndGameClick`) | `int(numéro de partie)` (celui d'`op232`) | `stopgame` | `op203 04 b1` ; joueurs : `op144 … v(2) int(pid de l'opérateur)` (« *** L'opérateur %s a arrêté la partie », gestionnaire `0x645189`, commun aux joueurs et aux spectateurs), `op235 b0`, `op146`/`op147` vides, `op148` ; spectateurs : `op144` motif 2 ; autres : `op235 b0`. Ni statistique ni enjeu, mises rendues. Partie inconnue : `op203 04 b0 v(12) int(numéro)` |
| 223 `/moderate` | — | `moderatemode` | `op224 04 b1 b(actif)` (« Activation / Désactivation du mode modéré acceptée par le serveur ») ; **`op82` catégorie 1 `01 b(actif)` à tous** (« *** Le mode modéré a été activé / désactivé », gestionnaire `0x640479` ; le client mémorise l'état et ne montre plus les absences / retours). Chat public refusé sans `talkwhilemoderate` (aucun code d'erreur prévu : message non diffusé). `op225 int(pid) b` = ligne du journal des actions spéciales du panneau d'équipe (fonction `specialactions`, non envoyée) |
| 176 `/ident <groupe> <mot de passe>` | `str str` | — | `op177 04 b0 v(code)` : 83 « Groupe ou mot de passe incorrect », 86 « Vous êtes déjà membre de ce groupe d'utilisateurs spéciaux » (l'équipe vient ici du niveau du compte) |

**Panneau d'équipe : topic et caisse de gils** (lus dans le client le 2026-10-12, jamais capturés). Les onglets du panneau
(`TfrmSpecialUser`) s'affichent selon les **fonctions du groupe** (`op86`) : le gestionnaire d'`op177` compare chaque
fonction au nom du composant de la page sans son préfixe « tab », en minuscules. Pages : `chat`, `specialactions`, `banlist`,
`joins`, `topic`, `activity` (2, 3), `currentactions`, `quizz`, `quizzcurrent`, `gilsbank`. L'onglet `gilsbank` exige en plus la
permission `viewgilsbank` **du grade envoyé par `op177`**. Avec `topic`, le panneau s'ouvre sur cet onglet plutôt que sur le chat.

| Sens | op (ctx4) | Charge utile | Rôle |
|---|---|---|---|
| C→S | 209 | `int(groupe) + x(texte)` | « Changer le topic » (`btnChangeTopicClick` grise le bouton jusqu'à la réponse) |
| S→C | 210 | `int(groupe) + b1`, ou `+ b0 + v(code)` | accusé (71 « Topic trop long ») |
| S→C | 211 | `int(groupe) + x(texte) + str(auteur) + int(date Unix)` | « Topic mis par %s le %s (%d caractère(s) restant(s)) », 32 768 caractères au plus ; texte vide = « Aucun topic » |
| C→S | 232 / 234 | `int(groupe) + int(montant)` | déposer / retirer (boutons de l'onglet, `/putspegils` / `/takespegils <groupe> <montant>`) |
| S→C | 233 / 235 | `int(groupe) + b1`, ou `+ b0 + v(code)` | accusés (14 pas assez de gils, 26 caisse insuffisante, 116 montant hors de 1 à 50 000) |
| C→S | 236 | `int(groupe) + i32(montant)` | `/gengils <groupe> <montant>` (groupe désigné par son libellé ou sa clé, ex. `staff`) |
| S→C | 237 | `int(groupe) + b1`, ou `+ b0 + v(code)` | « Vous avez généré des gils dans la caisse du groupe %s avec succès » |
| S→C | 231 | `int(groupe) + int(total)` [`+ b(dépôt) + int(pid) + int(montant)`] | « Actuellement %d gils dans la caisse », « %s a déposé / retiré %d gils », ligne Gils+ / Gils- des actions spéciales |

**Piège** : `op210`, `op211` et `op231` lisent le panneau du groupe **sans vérifier qu'il existe** (gestionnaires `0x64DC8C`,
`0x64DDAD`, `0x64EAC2`) : ils ne partent qu'aux connexions qui ont reçu `op177` (`sess["panneaux"]`), sinon le client
plante. `op233`/`op235` vérifient, `op237` n'y touche pas. Une demande de topic venant d'une connexion sans ce panneau ne
reçoit donc aucune réponse. À l'ouverture du panneau, le serveur envoie la caisse puis le
topic juste après `op177`. Règles du serveur (choix de l'administrateur, l'original n'est pas connu) : tout membre du panneau dépose, **retirer est
réservé aux opérateurs de niveau 3 et 4** (`RETRAIT_CAISSE_NIVEAU`, refus 87), générer demande `generategilsbank`
(opérateurs de niveau 4) ; chaque mouvement s'affiche chez tous les membres et va au journal de modération.

Infos offline (242 / 215) : voir § 4 (profil). Restent sans réponse dans cette catégorie : 183/200/208/222/247 journal des
actions spéciales, et `op243` (« actions en cours » du panneau d'équipe, fonction `currentactions`).

### Aiguillage par catégorie (corrigé le 2026-10-12)

Le client envoie `opcode + 256 × catégorie` et **le même numéro existe dans plusieurs catégories**. Le serveur aiguille
donc sur l'octet de catégorie avant l'opcode pour les catégories 4, 5 et 6, et une trame de ces catégories ne descend
jamais dans les branches des catégories 0 à 3. Avant, seule la catégorie 4 l'était : « Arrêter le quizz » (ctx5 op32)
lançait un duel contre un robot, « Remise à zéro des points » (ctx5 op35) passait pour une réponse à un défi, et
l'enregistrement des notes personnelles (ctx6 op64) pour une ouverture de profil. Inventaire des 82 requêtes du client :
`py ffwtt_envois.py`. Avant le 2026-10-12, 61 avaient une vraie réponse (un croisement par numéro d'opcode en comptait
64 : ces trois-là y passaient à tort pour traitées) ; 73 depuis. Les 9 restantes : ctx4 178 (salon, traité par
approximation) ; ctx5 21, 25, 29, 32, 35, 37, 40, 120.

### News rapides (catégorie 6)
| Sens | op | Rôle |
|------|----|------|
| C→S | 164 (ctx6) | `/quicknews [texte]` « Change les news rapides » : `06 str(texte)` (permission `quicknews`) |
| S→C | 165 (ctx6) | accusé `06 b1` (silencieux), ou `06 b0 v(code)` |
| S→C | 166 (ctx6) | `06 str(texte)` → « *** Infos : %s » dans le salon. **C'est aussi la trame du message d'accueil** (observé après `op62`). La news rapide est diffusée quand elle change et rappelée à l'entrée, après le message d'accueil |

**Permissions** nommées, transmises par les grades (op87) : `viewaccount`, `viewhost`,
`viewemail`, `viewoffinfos`, `global`, `stopgame`, `spygame`, `moderatemode`,
`notoriety`, `newdeck`, `resetaccount`, `warn`, `kick`, `mute`, `banhost`, `bannick`,
`banaccount`, `dissolveguild`, `viewgilsbank`, `generategilsbank`, `talkwhilemoderate`,
`editnotes`, `anytrade`, `quicknews`, `canflood`, `mechanic`.

### Vérifications du serveur (audit de sécurité du 2026-10-21)
Le client vérifie beaucoup de choses lui-même (solde, cartes, tour de jeu…), mais n'importe qui peut envoyer ses propres
trames : le serveur revérifie tout. Les refus passent par les codes d'erreur du client (`py ffwtt_binaire.py --erreurs`),
choisis au plus près ; **ce sont des choix de ce serveur, pas des réponses observées**.

| Situation | Réponse |
|-----------|---------|
| Toute trame autre que `op5`, `op100` ou un pong avant l'identification | ignorée |
| `op100` : 5 mots de passe refusés en 10 min (compte + adresse), ou 30 pour l'adresse | `op101 b0 v3` |
| `op100` : compte créé en jeu au-delà de 5 par heure et par adresse, ou nom invalide | `op101 b0 v91` |
| `op100` : compte sans mot de passe (n'accepte plus aucune connexion) | `op101 b0 v3` |
| `op203` : pseudo hors `[A-Za-z0-9_-[].]{3,20}` | `op204 b0 v5` |
| `op207` pendant une partie, un défi, un échange ou un visionnage | `op208 b0 v87` |
| `op44` / `op71` avec un pseudo banni (`op207` sauté) | ignorés |
| `op32` : mise au-delà du solde du défiant / de la cible | `op33 b0 v14` / `v40` ; règle « Entraînement » : mise ramenée à 0 dans l'écho |
| `op35` : la mise n'est plus payable à l'acceptation | `op36 b0 b1 v14` à celui qui ne peut pas, `v40` à l'autre |
| règle du vainqueur à enjeu avec moins de 5 cartes disponibles | `op33 b0 v101` (moi) / `v102` (la cible) |
| `op88` : l'un des deux est déjà dans un échange | `op89 b0 v19` |
| `op93` avant l'acceptation (`op91 b1` de l'invité) | `op94 b0 v22` |
| `op93` : offre modifiée | la validation du partenaire est annulée |
| `op191` : enchère close ou expirée, la sienne, sous le prix de départ | refus (message du serveur), rien n'est débité |
| `op66` : achat d'une carte absente de la table ou inconnue du client | `op67 b0 v46` |
| chat, message privé, chat de partie et de guilde au-delà de 8 en 10 s (sans `canflood`) | ignorés ; texte coupé à 1000 caractères |
| `op151` d'un joueur qui n'est ni joueur ni spectateur de la partie | ignoré |
| bloc `x` qui dépasse 100 000 octets une fois décompressé | refusé comme illisible (code 69 selon la requête) |

Cartes **disponibles** (vente, sacrifice, échange, mise aux enchères) = possédées − aux enchères − engagées dans une
partie à enjeu en cours ou dont le gain n'est pas encore choisi. Une main de duel ne peut contenir que des cartes qui ne
sont pas aux enchères.

---

## 4. Structure du profil (op65)

```
ctx1 + byte(1) + int(pid) + str(pseudo) + int(id de compte) + int(guilde)
     + str(titre dans la guilde) + str(nom de compte) + str(host) + str(e-mail)
     + int(pseudo créé) + int(compte créé)
     + int(Exp) + int(Gils) + int(Powers) + int(Victoires)
     + int(Défaites) + int(Nuls) + int(Quits illégaux) + int(0)
     + 6 × int16(notoriété Elo, sur 2000)
     + str(NOTE PUBLIQUE) + byte(0)
     + 33 × int (statistiques de collection ; le dernier = total de cartes)
```

Champs 4 à 11 relus dans le gestionnaire (`0x63E3F9`) le 2026-10-12 (l'ancienne lecture « int(0) + str(host) + … » était
fausse) : la **guilde** est cherchée dans la liste des guildes (nom et logo affichés, puis le titre) ; **nom de compte,
host et e-mail vides s'affichent « (caché) »**, et le nom de compte vide masque aussi l'identifiant de compte ; les deux
dates sont des dates Unix (« Pseudo créé », « Compte créé »). « Connecté(e) : Oui / Non » n'est pas un champ : le client
regarde si le pid est dans sa liste des joueurs, et ouvre la fenêtre même pour un pid absent. Le serveur ne donne compte,
host et e-mail qu'au propriétaire ou à qui a `viewaccount`, `viewhost`, `viewemail` (`profil_joueur`).

**Infos offline** (permission `viewoffinfos`) : menu « Infos offline » du bouton droit (`TfrmMDI.mnuOffInfosClick`, ctx4
op242 `int(pid)`) et `/offinfos <pseudo>` (ctx4 op215 `str`). Réponse : le profil `op65` du joueur, connecté ou non, d'après
la base, puis sa note (`op241`). Erreur : `op216 04 v(code)` (le gestionnaire `0x64E235` n'affiche qu'une erreur : 87
privilèges, 9 pseudo inexistant). La réponse positive est déduite du client (rien de capturé) : `op216` n'a pas de branche
de réussite, et `op243` (242 + 1) est en réalité la liste « actions en cours » du panneau d'équipe.

---

## 5. Règles du jeu

**Sources.** Le texte officiel : page « Règle du jeu » du wiki officiel du jeu (version archivée de 2013). Les trames :
une partie complète capturée (masque 0x3ee). `test_regles.py` rejoue
ses 9 coups dans `ffwtt_regles.py` et retrouve **exactement** les déplacements, les
retournements (case, propriétaire, type) et les scores de la capture.

Plateau 3×3. Côtés d'une carte : Haut, Droite, Bas, Gauche (A = 10).

- **Normal** : « celle ayant la plus grande valeur retourne l'autre carte ».
- **Open** : les cartes de l'adversaire sont visibles.
- **Aléatoire** : cartes tirées au hasard, la partie démarre directement ; sans elle « le jeu
  demande à choisir 5 cartes » (op36 3ᵉ champ = 1, puis op133/op134).
- **Élémentaire** : 0 à 6 éléments posés au hasard sur les cases ; carte du même élément +1,
  toute autre carte −1. Les bonus/malus ne comptent **pas** pour Bataille, Identique, Plus et les murs.
  Éléments : 1 Eau, 2 Feu, 3 Glace, 4 Poison, 5 Terre, 6 Sacré, 7 Ténèbres, 8 Tonnerre, 9 Vent
  (numéros de la table des cartes du client, noms d'après les icônes des images ; l'ordre du wiki
  n'est pas celui-là).
- **Bataille** : si deux chiffres qui se touchent sont égaux, la carte de plus faible **somme**
  est retournée — y compris celle que l'on vient de poser (capture, coup 8). Chaque paire se règle sur le plateau
  d'avant les batailles, du côté du joueur qui pose ; la carte posée est reprise (en dernier) si elle en perd au moins
  une. (Jusqu'au 2026-10-21, une carte reprise « combattait » ensuite les cartes de son propre joueur et le résultat
  dépendait du sens du plateau : trouvé par comparaison avec une implémentation indépendante des règles.)
  **Combo** : la règle de base, bonus Élémentaire compris, à partir des cartes prises par Identique / Plus.
- **Mur cassé** : le plateau est une sphère, haut/bas et gauche/droite sont reliés ; pas de murs.
- **Identique** / **Même mur**, **Plus** / **Mur additionnel** : au moins 2 côtés (ou sommes)
  égaux, dont une carte adverse ; les murs valent A. **Combo** : réaction en chaîne ensuite.
- **Mur puissant** (propre au FFWTT) : chaque case sauf le centre peut porter une restriction
  `+n`, `-n` ou `=n` (n de 2 à 30, ou 100) portant sur le **power** de la carte posée. Si elle
  est remplie, la ligne ou la colonne glisse d'une case depuis la case posée vers le côté opposé,
  en tapis roulant ; les captures se font **après** le déplacement.

**Trames des règles** (ordre des tableaux 3×3 du client : `x*3 + y`, lu dans le binaire) :

| op | Contenu |
|----|---------|
| 36 | `int(adversaire) + b(1) + b(choix) + int(n° de partie)` : `b(choix)=1` ouvre « Jeu avec %s – Choix des cartes » (binaire, cas 804), 0 ouvre le plateau |
| 133 / 134 | C→S `int(partie) + 5 × int16(carte)` / S→C `int(partie) + b(1)` « Cartes acceptées par le serveur » |
| 137 | Élémentaire : 9 × `v(élément)` (0 = aucun) |
| 138 | Mur puissant : 9 × `int16(nombre) + v(type) + v(orientation)` ; type 1 = `+`, 2 = `-` (3 = `=` par élimination) ; orientation 1 = la ligne glisse, 0 = la colonne |
| 136 | main adverse : 5 × `int16` ; `0x1316` = dos de carte, ou les vraies cartes en Open (déduit : même gestionnaire que op135) |
| 142 | carte posée : coordonnées **de pose** (avant déplacement) |
| 143 | `b(déplacement)` ; si 1 : `b(axe : 1 colonne, 0 ligne) + v(indice) + v(sens : 0 observé = vers l'indice 0) + int16(1)` ; puis les retournements `v(x) v(y) int(pid du nouveau propriétaire) v(type)` en coordonnées **après** déplacement ; puis `v(score du destinataire)`. Types : **1 normal (et Bataille), 2 Identique, 3 Plus** |
| 233 | score **du destinataire** (pas celui du joueur qui vient de poser) |
| 154 | C→S : « le temps de mon adversaire est écoulé » (chaque seconde). C'est le **serveur** qui tient le chronomètre : ~2 s après l'échéance il joue une carte à la place du retardataire (capture d'une partie à 15 s par coup : chaque coup du retardataire tombe à 15 s + 2). Durées du menu (table du client `0x66729C`) : index 0…7 = **15, 30, 45, 60, 90, 120, 180, 300 s** |

**Score final** = cartes possédées sur le plateau **+ carte restée en main**
(le second joueur en garde une : 5-4 sur le plateau = 5-5 = match nul).

---

## 6. La table des cartes du client

Les valeurs ne transitent jamais sur le réseau, mais le client **embarque la table des
cartes**, remplie au démarrage par du code d'initialisation dans un tableau en BSS (base
0x66EE90 dans cette build, `id = index + 2`, 4884 cartes). Enregistrement de **529 octets**,
compté depuis le nom :

| offset | taille | contenu |
|-------:|-------:|---------|
| 0   | 256 | **nom** (ShortString) |
| 256 | 256 | **deck** (ShortString) |
| 512 | 4   | niveau (1..10, colonne « Nv » du client) |
| 516 | 1   | **Haut** (1..10, A = 10) |
| 517 | 1   | **Gauche** |
| 518 | 1   | **Droite** |
| 519 | 1   | **Bas** |
| 520 | 1   | **élément** : 0 aucun, 1 Eau, 2 Feu, 3 Glace, 4 Poison, 5 Terre, 6 Sacré, 7 Ténèbres, 8 Tonnerre, 9 Vent |
| 521 | 8   | nuls au départ : le client y calcule le **prix** (dword à l'octet 0x209 de la fiche) et le **power** (int16 à 0x20F, = prix / 100) |

Vérifié le 2026-09-23 : identique à 4879 des 4883 lectures OCR des images (les 4 autres étaient des erreurs de l'OCR) ; noms
des éléments contrôlés sur les icônes des images. Jusque-là, ces champs étaient lus **avant**
le nom, donc ceux de la carte précédente : ce qui passait pour « quatre octets qui ne sont pas
les valeurs » et un « octet partiellement corrélé à l'élément ».

Les noms sont copiés depuis un tableau de chaînes dédupliqué (une entrée par nom distinct,
sans les noms de 3 lettres, stockés inline dans un `mov dword`). Voir `ffwtt_cards_build.py`
et `cartes.json` (`digits = [Haut, Droite, Bas, Gauche]`, ordre du serveur).

Identifiant spécial : `0x1316` = 4886 = dos de carte (main adverse masquée).

