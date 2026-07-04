# Keystone — Authentication as a Service

Backend FastAPI multi-tenant pour l'authentification à deux facteurs (MFA par OTP email),
destiné aux développeurs qui veulent déléguer l'auth de leurs propres utilisateurs finaux.

## Concept

- **User** (dev ou admin, `is_admin` différencie) : s'inscrit sur la plateforme, crée des **Apps**.
- **App** : possède un token secret unique généré aléatoirement (`secrets.token_urlsafe`),
  affiché en clair une seule fois à la création.
- **EndUser** : utilisateur final d'une App, scopé par `app_id` (unicité email par app, pas globale).

Toutes les routes `/v1/end-users/*` exigent le header `X-App-Token` avec le token de l'App.

## Flow d'authentification (identique pour User et EndUser)

```
POST /auth/login        → email + password → 200 + envoi d'un OTP par email (SMTP)
POST /auth/verify-otp   → email + code      → JWT (+ email pour EndUser)
```

Pas de refresh token : à expiration du JWT (30 min par défaut), on refait le flow complet.

## Structure du projet

```
app/
├── core/         # config, sécurité (JWT/hash/tokens), redis, email, dépendances FastAPI
├── db/           # engine SQLAlchemy async + session
├── models/       # User, App, EndUser, AuditLog
├── schemas/      # Pydantic (request/response)
├── api/v1/       # routers : users_auth, end_users_auth, apps, admin
└── services/     # otp_service (Redis), audit_service
alembic/          # migrations (schéma initial inclus)
```

## Installation

```bash
python -m venv venv
source venv/bin/activate          # Windows : venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # puis renseigner DATABASE_URL, REDIS_URL, secrets JWT, SMTP
```

Prérequis : PostgreSQL et Redis démarrés (locaux ou via Docker).

## Migrations

```bash
alembic upgrade head
```

## Lancer le serveur

```bash
uvicorn app.main:app --reload
```

## Documentation Swagger

- **`/docs`** → doc publique, uniquement les routes `end-user-auth` — à donner aux développeurs
  qui intègrent l'API pour authentifier leurs utilisateurs.
- **`/docs/admin`** → doc complète (users, apps, admin, end-users) — usage interne uniquement.
  ⚠️ À restreindre en prod (IP allowlist / basic auth via Nginx ou Dokku), le "cacher" via l'URL
  ne suffit pas comme unique protection.

## Sécurité — points clés

- Mots de passe hashés avec bcrypt (passlib).
- Tokens d'App : jamais stockés en clair, seul le hash SHA-256 est en base. Rotation possible
  via `POST /v1/apps/{id}/rotate-token` (invalide l'ancien immédiatement).
- OTP stockés dans Redis (hashés, TTL de 5 min par défaut), avec limite de tentatives
  (`OTP_MAX_ATTEMPTS`) pour bloquer le bruteforce.
- JWT : deux secrets distincts (`JWT_SECRET_USERS` / `JWT_SECRET_END_USERS`) pour isoler
  complètement les deux populations. Chaque JWT a un `jti` ; le logout blackliste ce `jti`
  dans Redis jusqu'à expiration naturelle du token.
- `AuditLog` trace les événements clés (register, login, OTP, création/rotation d'App).

## Variables d'environnement principales

Voir `.env.example`. À ne jamais committer un `.env` réel.

## Prochaines étapes suggérées

- Rate limiting sur `/auth/login` (par IP et par email) pour limiter le bruteforce mot de passe.
- Endpoint `forgot-password` / `reset-password` (réutilise `otp_service` avec `purpose="password_reset"`).
- Déploiement Dokku/Coolify avec HTTPS (cf. ton setup existant DuckDNS + Let's Encrypt).
