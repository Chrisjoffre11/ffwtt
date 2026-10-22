# Journal des modifications

Les changements du serveur, du plus récent au plus ancien. Avant de mettre à jour un serveur en service, lisez la
rubrique « À savoir pour mettre à jour ».

## 2026-10-22

### Nouveautés

- **Le panneau Quizz du jeu fonctionne.** Les animateurs et les opérateurs de niveau 3 et 4 reçoivent à la connexion
  un panneau « Quizz » (onglets « Questions des quizz » et « Quizz en cours ») :
  - créer et supprimer des catégories ; ajouter, éditer et supprimer des questions ;
  - lancer un quizz sur les catégories cochées, avec le temps de réponse et la pause entre les questions choisis
    (de 5 à 300 secondes) ;
  - arrêter le quizz, remettre les points à zéro, afficher le top 5 ;
  - suivre les points des joueurs en direct.

  Le panneau a aussi son salon et son topic, comme le groupe « Quizz » observé dans une capture. Le protocole a été lu
  dans le binaire du client : rien n'a été capturé, signalez tout plantage du jeu.
- **Les questions du quizz sont en base.** Au premier démarrage, `quiz.json` y est importé une seule fois : une
  catégorie par thème. Ensuite, tout se gère depuis le panneau. Dans le champ « Réponse », plusieurs réponses acceptées
  se séparent par `|` (par exemple `Cloud | Cloud Strife`) ; le quizz annonce la première. La commande `!quiz` du chat
  marche toujours et utilise ces mêmes catégories.

### Règles

- **Règle du vainqueur « Aléatoire »** : comme One, mais le vainqueur ne choisit pas. **Une seule carte** de la main du
  perdant est tirée au sort et lui est prise directement. Avant, le serveur tirait un nombre de cartes de 1 à 5 et le
  vainqueur choisissait.
- **Expérience exigée pour chaque règle du vainqueur**, aux deux joueurs. Le jeu d'origine avait des seuils, mais ils
  sont perdus : ni le client ni le journal des versions du jeu ne les contiennent. Seuils de ce serveur :

  | Règle | Expérience |
  |---|---|
  | One, Directe, Change, Aléatoire | 1000 |
  | Two | 2000 |
  | Three | 3000 |
  | Four | 4000 |
  | Totale | 5000 |

  Entraînement et Aucune n'en demandent pas. Les seuils sont dans `EXP_REGLE`, au début de `ffwtt_server.py`.

### Précisions

- **`/moderate` se tape seul.** Avec un paramètre (`/moderate on`), c'est le jeu lui-même qui répond « Nombre de
  paramètres incorrects », et il n'envoie rien au serveur. Chaque `/moderate` active ou désactive le mode modéré.
- **Mur puissant** : le client dessine bien la restriction de type 3 avec le signe « = ».
- **Vu dans le vrai client** : `/offinfos`, `/quicknews` et l'arrêt d'une partie par un opérateur. Après un arrêt,
  l'écran de jeu des joueurs affiche « Égalité ».
- **Menu Twitter du client** : laissé de côté. La requête est seulement notée dans le journal.

### À savoir pour mettre à jour

- Arrêtez le serveur, remplacez les fichiers, relancez-le. La base existante est complétée toute seule : nouvelles
  tables du quizz, puis import de `quiz.json` si aucune catégorie n'existe encore.
- Les seuils d'expérience sont plus élevés qu'avant (Totale demandait 2000, il faut maintenant 5000) : certains
  joueurs ne pourront plus proposer les mêmes règles.
- Un opérateur de niveau 4 voit deux lignes de plus à la connexion : l'ouverture du panneau Quizz et « est maintenant
  un(e) Responsable des quizz ». C'est le jeu qui les écrit, on ne peut pas les supprimer.

### Tests

`test_serveur.py` passe de 181 à 205 vérifications : le panneau Quizz (21), les seuils d'expérience, et une vraie
partie « Aléatoire » jouée du défi jusqu'au transfert de la carte.

## 2026-10-21 : première version publique

Le serveur de jeu complet : comptes, salon, chat, profils, collection, boutique, enchères, échanges, duels contre
quatre robots et entre joueurs avec toutes les règles du client, mode spectateur, administration à niveaux,
protections contre les abus. Voir le [README](README.md).
