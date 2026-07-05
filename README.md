# Step — Authentication as a Service

Backend FastAPI multi-tenant qui fournit une authentification à deux facteurs (MFA par OTP
email) en tant que service : les développeurs qui l'utilisent délèguent à Step tout le flow
d'authentification de leurs propres utilisateurs finaux, sans avoir à réimplémenter
hashing de mot de passe, OTP, JWT, rate limiting ou audit trail.

## Sommaire

- [Concept](#concept)
- [Flow d'authentification](#flow-dauthentification)
- [Modèle de permissions](#modèle-de-permissions)
- [Architecture](#architecture)
- [Aperçu des routes](#aperçu-des-routes)
- [Sécurité](#sécurité)
- [Installation](#installation)
- [Variables d'environnement](#variables-denvironnement)
- [Lancer le serveur](#lancer-le-serveur)
- [Documentation Swagger](#documentation-swagger)
- [Tests](#tests)
- [Pistes d'évolution](#pistes-dévolution)

## Concept

Trois types d'acteurs :

- **User** — un développeur (ou un admin, `is_admin` les différencie) qui s'inscrit sur la
  plateforme Step et crée des **Apps**. C'est son propre compte, protégé par le flow MFA
  standard (mot de passe + OTP email).
- **App** — représente une application tierce créée par un User. Chaque App possède un
  **token secret** unique (`secrets.token_urlsafe`), affiché en clair une seule fois à la
  création (ou à la rotation). Ce token sert de credential serveur-à-serveur : c'est le
  backend du développeur intégrateur qui l'utilise (header `X-App-Token`), jamais l'utilisateur
  final directement.
- **EndUser** — l'utilisateur final de l'App du développeur. Scopé par `app_id` : l'unicité
  de l'email est vérifiée par App, pas globalement (le même email peut exister sur deux Apps
  différentes sans collision). Toutes les routes `/v1/end-users/*` exigent le header
  `X-App-Token` correspondant à l'App concernée.

Chaque action significative (inscription, connexion, échec de connexion, lecture, modification,
activation, suppression, dépassement de rate limit, refus de permission...) est tracée dans un
**AuditLog**, consultable en lecture seule par les admins (historique complet) et par les
développeurs pour leurs propres Apps.

## Flow d'authentification

Identique pour User et EndUser (seul le header `X-App-Token` change la donne côté EndUser) :

```
POST .../auth/login        → email + password → 200 + envoi d'un OTP par email (SMTP)
POST .../auth/verify-otp   → email + code      → JWT
POST .../auth/logout       → Authorization: Bearer <JWT> → révoque le token
```

Pas de refresh token : à l'expiration du JWT (30 minutes par défaut), on refait le flow complet.

Gestion du mot de passe oublié, même principe pour les deux populations :

```
POST .../auth/forgot-password  → email → envoi d'un token de reset par email (usage unique, 15 min)
POST .../auth/reset-password   → email + token + nouveau mot de passe
```

Le message de `forgot-password` est volontairement neutre ("si cet email existe...") pour ne pas
révéler l'existence d'un compte. Le lien de reset est construit avec `FRONTEND_URL` (pour les
Users) ou `App.frontend_url` (optionnel, par App, pour les EndUsers) ; si l'URL n'est pas
configurée, l'email contient le token brut à la place d'un lien cliquable — au développeur
intégrateur de choisir l'option qui lui convient.

## Modèle de permissions

| Ressource | Route | Qui peut y accéder |
|---|---|---|
| User | `POST /v1/users` (inscription) | Public |
| User | `GET /v1/users/me` | L'utilisateur connecté (lui-même) |
| User | `GET`/`PATCH`/`DELETE /v1/users/{id}` | Lui-même ou un admin |
| User | `GET /v1/users` (liste), `activate`/`deactivate`/`promote-admin`/`demote-admin` | Admin uniquement |
| App | Toutes les routes `/v1/apps/*` | Le créateur de l'App ou un admin |
| App | `GET /v1/apps` | Ses propres Apps (un admin voit tout par défaut, `?mine=true` restreint aux siennes) |
| EndUser | `POST /v1/end-users` (inscription) | X-App-Token seul (pas de JWT requis) |
| EndUser | `GET /v1/end-users/me` | L'EndUser connecté (lui-même) |
| EndUser | `GET`/`PATCH`/`DELETE /v1/end-users/{id}` | L'EndUser concerné, le créateur de l'App, ou un admin |
| EndUser | `GET /v1/end-users` (liste), `activate`/`deactivate` | Créateur de l'App ou admin |
| AuditLog | `GET /v1/audit-logs` (historique complet) | Admin uniquement |
| AuditLog | `GET /v1/audit-logs/apps/{app_id}` | Créateur de l'App concernée ou un admin |

Un compte désactivé (`is_active=False`) reçoit systématiquement un `401 Unauthorized` sur toute
route protégée, y compris avec un JWT encore valide.

## Architecture

```
app/
├── core/         # config (pydantic-settings), sécurité (JWT/hash/tokens), rate limiter,
│                 # redis, email, dépendances FastAPI (auth + permissions croisées)
├── db/           # engine SQLAlchemy async (asyncpg) + session
├── models/       # User, App, EndUser, AuditLog (SQLAlchemy 2.0 Mapped/mapped_column)
│                 # + enums.py (ActorType, AuditEventType)
├── schemas/      # Pydantic request/response (dont Page[T] générique pour la pagination)
├── api/v1/       # routers : users, users_auth, apps, end_users, end_users_auth, audit_logs
│                 # — montés dans router.py
└── services/     # otp_service, password_reset_service, audit_service (Redis + AuditLog)
alembic/          # migrations
test_app.py       # script de test end-to-end (voir "Tests")
```

Points clés :

- **Isolation JWT** : deux secrets distincts (`JWT_SECRET_USERS` / `JWT_SECRET_END_USERS`) — un
  JWT User ne peut jamais être accepté sur une route EndUser et inversement.
- **Logout par blacklist** : chaque JWT a un `jti` ; le logout le blackliste dans Redis jusqu'à
  expiration naturelle du token.
- **Permissions centralisées** dans `app/core/dependencies.py` : `require_admin`,
  `require_app_owner_or_admin` (X-App-Token + JWT User), `get_owned_app` (dépendance réutilisable
  pour scoper une App à son créateur), `authorize_end_user_access` (autorise soit l'EndUser
  concerné via son propre JWT, soit le créateur de l'App/un admin via JWT User).
- **Audit systématique** : `log_event()` trace lectures, écritures, échecs d'auth, rate limits
  déclenchés et permissions refusées — voir `app/models/enums.py` pour le catalogue complet des
  événements.

## Aperçu des routes

Toutes préfixées par `/v1`.

| Router | Préfixe | Contenu |
|---|---|---|
| `users` | `/users` | Inscription, `/me`, CRUD, activation/désactivation, promotion/démotion admin, liste (admin) |
| `users_auth` | `/users/auth` | `login`, `verify-otp`, `logout`, `forgot-password`, `reset-password` |
| `apps` | `/apps` | Création, liste (paginée, filtrable `?mine=`), CRUD, rotation de token, activation/désactivation |
| `end_users` | `/end-users` | Inscription (X-App-Token), `/me`, CRUD, liste, activation/désactivation |
| `end_users_auth` | `/end-users/auth` | `login`, `verify-otp`, `logout`, `forgot-password`, `reset-password` (tout X-App-Token) |
| `audit_logs` | `/audit-logs` | Lecture seule : historique complet (admin) et par App (créateur/admin) |

Toutes les routes de liste (`GET /v1/users`, `GET /v1/apps`, `GET /v1/end-users`,
`GET /v1/audit-logs*`) sont paginées via un modèle générique `Page[T]`
(`items`, `total`, `limit`, `offset`) — query params `limit` (défaut 20, max 100) et `offset`.

## Sécurité

- **Mots de passe** hashés avec bcrypt (passlib).
- **Tokens d'App** jamais stockés en clair : seul le hash SHA-256 est en base. Rotation possible
  via `POST /v1/apps/{id}/rotate-token` (invalide l'ancien immédiatement).
- **OTP** stockés dans Redis (hashés SHA-256, TTL 5 min par défaut), avec limite de tentatives
  (`OTP_MAX_ATTEMPTS`) qui verrouille le code après dépassement.
- **Rate limiting anti-bruteforce** sur les routes de login (User et EndUser), deux fenêtres
  Redis indépendantes : 5 échecs / 15 min par email ciblé, 20 échecs / 15 min par IP source.
  Réponse `429` avec header `Retry-After`.
- **JWT isolés** par population (secrets distincts) + blacklist Redis au logout via le `jti`.
- **AuditLog** exhaustif : succès et échecs d'authentification, lectures, modifications,
  activations/désactivations, rate limits déclenchés, accès refusés — consultable en lecture
  seule par les admins et par les développeurs pour leurs propres Apps.

## Installation

```bash
python -m venv venv
source venv/bin/activate          # Windows : venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # puis renseigner DATABASE_URL, REDIS_URL, secrets JWT, SMTP
```

Prérequis : PostgreSQL et Redis démarrés (locaux ou via Docker).

```bash
alembic upgrade head
```

## Variables d'environnement

Voir `.env.example` pour le fichier complet — à ne jamais committer un `.env` réel.

| Variable | Rôle |
|---|---|
| `PROJECT_NAME` | Nom affiché dans le titre de l'app FastAPI |
| `ENVIRONMENT` | `development` / `production` (informatif) |
| `FRONTEND_URL` | Optionnel — base du lien de reset password pour les Users. Vide = token brut envoyé par email |
| `DATABASE_URL` | DSN PostgreSQL, dialecte `asyncpg` (`postgresql+asyncpg://...`) |
| `REDIS_URL` | DSN Redis (OTP, blacklist JWT, rate limiting, tokens de reset) |
| `JWT_SECRET_USERS` / `JWT_SECRET_END_USERS` | Secrets distincts par population — ne jamais les partager |
| `JWT_ALGORITHM` | Algorithme de signature JWT (`HS256` par défaut) |
| `ACCESS_TOKEN_TTL_MINUTES` | Durée de vie des JWT (30 min par défaut) |
| `OTP_TTL_SECONDS` / `OTP_LENGTH` / `OTP_MAX_ATTEMPTS` | Config de l'OTP (durée de vie, nombre de chiffres, tentatives avant verrouillage) |
| `APP_TOKEN_BYTES` / `APP_TOKEN_PREFIX` | Config du secret aléatoire généré pour chaque App |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_USE_TLS` | Envoi des emails (OTP, reset password). `SMTP_USER` vide = mode dev, les codes/tokens sont juste affichés dans les logs au lieu d'être envoyés |

## Lancer le serveur

```bash
uvicorn app.main:app --reload
```

`GET /health` répond `{"status": "ok"}` une fois le serveur démarré.

## Documentation Swagger

- **`/docs`** — doc publique, routes taguées `end-user-auth`/`end-users` uniquement (inscription,
  login/OTP, CRUD des utilisateurs finaux) : à donner aux développeurs qui intègrent l'API.
- **`/docs/admin`** — doc complète (users, apps, end-users, audit-logs...) — usage interne
  uniquement. ⚠️ À restreindre en prod (IP allowlist / basic auth via Nginx ou Dokku), le "cacher"
  via l'URL ne suffit pas comme unique protection.

## Tests

`test_app.py` est un script de test end-to-end autonome (aucune dépendance de test à installer :
stdlib uniquement). Il lance sa propre instance uvicorn sur un port dédié (SMTP désactivé pour
que les OTP/tokens de reset s'affichent dans les logs au lieu de partir par email réel), exécute
une centaine de vérifications couvrant toutes les routes, les permissions, le brute-force et la
gestion d'erreurs, puis nettoie les données qu'il a créées.

```bash
python test_app.py
```

Affichage en temps réel dans le terminal + récap complet dans `test_report.md`. Nécessite
PostgreSQL/Redis démarrés et les migrations appliquées.

## Pistes d'évolution

- Déploiement Dokku/Coolify avec HTTPS.
- Rate limiting additionnel sur `forgot-password`/`reset-password` (actuellement seules les
  routes de login sont protégées contre le brute-force).
- Export/rétention configurable de l'AuditLog (purge automatique au-delà d'une certaine durée).
