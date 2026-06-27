# 🧠 NL2EL — Guide de Setup Complet (Partie IA)

> **Objectif** : Reproduire le pipeline NL2EL sur une nouvelle machine Windows.
> Ce guide couvre **uniquement la partie IA** (modèle Mistral + proxy + LibreChat).
> La partie MCP/Elasticsearch n'est **pas** incluse.

---

## 📋 Table des Matières

1. [Architecture](#-architecture)
2. [Prérequis](#-prérequis)
3. [Étape 1 — Installer Ollama](#étape-1--installer-ollama)
4. [Étape 2 — Préparer le Modèle NL2EL](#étape-2--préparer-le-modèle-nl2el)
5. [Étape 3 — Créer le Proxy Stateless](#étape-3--créer-le-proxy-stateless-openai-compatible)
6. [Étape 4 — Installer et Configurer LibreChat](#étape-4--installer-et-configurer-librechat)
7. [Étape 5 — Lancer le Tout](#étape-5--lancer-le-tout)
8. [Étape 6 — Créer un Preset dans LibreChat](#étape-6--créer-un-preset-dans-librechat)
9. [Vérification](#-vérification)
10. [Résumé des Ports](#-résumé-des-ports)
11. [Erreurs Connues et Solutions](#-erreurs-connues-et-comment-les-éviter)
12. [Fichiers de Référence](#-fichiers-de-référence)

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│   Navigateur (User)                                              │
│       │                                                          │
│       ▼                                                          │
│   LibreChat (:3080)          ← Docker (MongoDB, MeiliSearch…)    │
│       │                                                          │
│       │  POST /v1/chat/completions                               │
│       ▼                                                          │
│   Proxy Stateless (:8082)    ← Docker (python:3.11-slim)         │
│       │  ↳ Supprime l'historique de conversation                 │
│       │  ↳ Envoie SEULEMENT le dernier message user              │
│       │                                                          │
│       │  POST /api/generate (context=[])                         │
│       ▼                                                          │
│   Ollama (:11434)            ← Installé nativement sur Windows   │
│       │                                                          │
│       ▼                                                          │
│   kql-copilot-stateless      ← Mistral 7B Q4_K_M (4.4 Go)       │
│       │  ↳ System: "SOC analyst, KQL expert, return only query"  │
│       │  ↳ temperature=0.1, num_ctx=1000                         │
│       ▼                                                          │
│   Requête KQL/ES|QL                                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **Pourquoi un proxy ?** LibreChat envoie tout l'historique de conversation au modèle.
> Le modèle KQL doit être **stateless** (chaque requête est indépendante).
> Le proxy intercepte la requête, extrait uniquement le dernier message utilisateur,
> et appelle Ollama avec `context: []` — exactement comme le script CLI.

---

## 📦 Prérequis

| Outil | Version Minimale | Lien |
|-------|-----------------|------|
| **Windows** | 10/11 (64-bit) | — |
| **Docker Desktop** | 4.x+ | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| **Ollama** | 0.5+ | [ollama.com/download](https://ollama.com/download) |
| **Git** | 2.x+ | [git-scm.com](https://git-scm.com/) |
| **RAM** | 16 Go minimum (8 Go pour le modèle + 4 Go pour Docker) | — |
| **Disque** | ~15 Go libres (4.4 Go modèle + images Docker) | — |

> [!TIP]
> Le modèle tourne sur **CPU uniquement**. Un GPU n'est pas requis mais accélère l'inférence.
> Sur CPU, l'inférence prend entre 10-60 secondes par requête.

---

## Étape 1 — Installer Ollama

### 1.1 Télécharger et installer

Télécharger Ollama depuis [ollama.com/download](https://ollama.com/download) et l'installer.

Vérifier l'installation :
```powershell
ollama --version
```

### 1.2 S'assurer qu'Ollama écoute sur toutes les interfaces

Par défaut, Ollama écoute sur `127.0.0.1:11434`. Pour que les conteneurs Docker puissent y accéder via `host.docker.internal`, c'est suffisant. Mais vérifier que le service tourne :

```powershell
# Vérifier qu'Ollama est démarré
curl http://localhost:11434
# Réponse attendue : "Ollama is running"
```

> [!WARNING]
> **Si la commande échoue** : Lancer Ollama manuellement via le menu Windows ou exécuter `ollama serve` dans un terminal.

---

## Étape 2 — Préparer le Modèle NL2EL

### 2.1 Copier le fichier GGUF

Créer un dossier pour le modèle et y placer le fichier GGUF :

```powershell
mkdir C:\nl2el-model
# Copier le fichier mistral-7b-instruct-v0.3.Q4_K_M.gguf dans ce dossier
```

> [!NOTE]
> Le fichier `mistral-7b-instruct-v0.3.Q4_K_M.gguf` fait **4.37 Go**.
> C'est le modèle Mistral 7B fine-tuné et quantifié en Q4_K_M, exporté depuis Kaggle.

### 2.2 Créer le Modelfile

Créer le fichier `C:\nl2el-model\Modelfile` avec ce contenu exact :

```dockerfile
FROM ./mistral-7b-instruct-v0.3.Q4_K_M.gguf

TEMPLATE """{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
{{ .Response }}<|im_end|>
"""

SYSTEM """You are a SOC analyst assistant expert in Kibana Query Language (KQL) and Elastic Common Schema (ECS). Return only the query."""
PARAMETER num_ctx 1000
PARAMETER temperature 0.1
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|im_start|>"
```

> [!IMPORTANT]
> Le `SYSTEM` prompt est **critique**. C'est lui qui dit au modèle de retourner du KQL.
> Sans lui, le modèle peut retourner du ES|QL ou du texte libre.

### 2.3 Enregistrer le modèle dans Ollama

```powershell
cd C:\nl2el-model
ollama create kql-copilot-stateless -f Modelfile
```

Attendre que le processus se termine (peut prendre 1-2 minutes).

### 2.4 Tester le modèle

```powershell
ollama run kql-copilot-stateless "show failed login attempts"
```

**Résultat attendu** — Une requête KQL, par exemple :
```
event.action:"logon-failed" OR winlog.event_id:4625
```

Test rapide via API :
```powershell
curl -X POST http://localhost:11434/api/generate -H "Content-Type: application/json" -d '{\"model\": \"kql-copilot-stateless\", \"prompt\": \"show failed login attempts\", \"stream\": false, \"context\": []}'
```

> [!CAUTION]
> Si le modèle retourne du texte libre au lieu de KQL, vérifier que le `SYSTEM` prompt dans le Modelfile est correctement appliqué. Recréer le modèle avec `ollama create` si nécessaire.

---

## Étape 3 — Créer le Proxy Stateless (OpenAI-Compatible)

Le proxy traduit le format OpenAI (utilisé par LibreChat) vers le format Ollama natif, **en mode stateless**.

### 3.1 Créer le dossier du proxy

```powershell
mkdir C:\nl2el-proxy
```

### 3.2 Créer `server.py`

Créer le fichier `C:\nl2el-proxy\server.py` :

```python
"""
Stateless OpenAI-compatible proxy for kql-copilot-stateless.

Receives /v1/chat/completions from LibreChat, strips conversation history,
and calls Ollama /api/generate with context=[] (exactly like the CLI script).
This ensures every query is independent — no memory corruption.

Supports both streaming (SSE) and non-streaming responses.
"""

import os
import json
import time
import logging
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import URLError

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "kql-copilot-stateless")
PORT = int(os.getenv("PORT", "8082"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-5s  %(message)s")
log = logging.getLogger("stateless-proxy")


class StatelessProxy(BaseHTTPRequestHandler):
    """Translates OpenAI chat/completions → Ollama /api/generate (stateless)."""

    def do_POST(self):
        # Only handle /v1/chat/completions
        if "/chat/completions" not in self.path:
            self._respond(404, {"error": "Not found"})
            return

        try:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        except Exception:
            self._respond(400, {"error": "Invalid JSON"})
            return

        stream = body.get("stream", False)

        # Extract ONLY the last user message (ignore all history)
        messages = body.get("messages", [])
        user_msg = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_msg = msg["content"]
                break

        if not user_msg:
            self._respond(400, {"error": "No user message found"})
            return

        log.info("Query: %s (stream=%s)", user_msg, stream)

        # Call Ollama /api/generate with empty context — STATELESS, like CLI
        payload = json.dumps({
            "model": MODEL_NAME,
            "prompt": user_msg,
            "stream": False,
            "context": [],       # ← KEY: empty context = no memory between calls
        }).encode()

        try:
            req = Request(
                f"{OLLAMA_URL}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            resp = urlopen(req, timeout=300)
            result = json.loads(resp.read())
            answer = result.get("response", "").strip()
        except URLError as e:
            log.error("Ollama call failed: %s", e)
            self._respond(502, {"error": f"Ollama unreachable: {e}"})
            return
        except Exception as e:
            log.error("Unexpected error: %s", e)
            self._respond(500, {"error": str(e)})
            return

        log.info("Result: %s", answer)

        if stream:
            self._respond_stream(answer, result)
        else:
            self._respond_json(answer, result)

    def _respond_stream(self, answer, result):
        """Send response as SSE stream (what LibreChat expects)."""
        chat_id = f"chatcmpl-{int(time.time())}"

        # Chunk 1: role
        chunk_role = {
            "id": chat_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": MODEL_NAME,
            "choices": [{
                "index": 0,
                "delta": {"role": "assistant", "content": ""},
                "finish_reason": None,
            }],
        }

        # Chunk 2: content
        chunk_content = {
            "id": chat_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": MODEL_NAME,
            "choices": [{
                "index": 0,
                "delta": {"content": answer},
                "finish_reason": None,
            }],
        }

        # Chunk 3: finish
        chunk_done = {
            "id": chat_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": MODEL_NAME,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": result.get("prompt_eval_count", 0),
                "completion_tokens": result.get("eval_count", 0),
                "total_tokens": result.get("prompt_eval_count", 0) + result.get("eval_count", 0),
            },
        }

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        for chunk in [chunk_role, chunk_content, chunk_done]:
            line = f"data: {json.dumps(chunk)}\n\n"
            self.wfile.write(line.encode())
            self.wfile.flush()

        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True

    def _respond_json(self, answer, result):
        """Send response as regular JSON (for non-streaming clients)."""
        response = {
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": MODEL_NAME,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": answer},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": result.get("prompt_eval_count", 0),
                "completion_tokens": result.get("eval_count", 0),
                "total_tokens": result.get("prompt_eval_count", 0) + result.get("eval_count", 0),
            },
        }
        self._respond(200, response)

    def do_GET(self):
        # LibreChat calls /v1/models to discover available models
        if "/models" in self.path:
            self._respond(200, {
                "object": "list",
                "data": [{"id": MODEL_NAME, "object": "model", "owned_by": "ollama"}],
            })
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, fmt, *args):
        """Suppress default access logging (we do our own)."""
        pass


if __name__ == "__main__":
    log.info("Starting stateless proxy on 0.0.0.0:%d", PORT)
    log.info("Ollama: %s  Model: %s", OLLAMA_URL, MODEL_NAME)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), StatelessProxy)
    server.serve_forever()
```

### 3.3 Créer le `Dockerfile`

Créer le fichier `C:\nl2el-proxy\Dockerfile` :

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY server.py .

ENV OLLAMA_URL=http://host.docker.internal:11434
ENV MODEL_NAME=kql-copilot-stateless
ENV PORT=8082

EXPOSE 8082

CMD ["python", "server.py"]
```

> [!TIP]
> Ce Dockerfile n'a **aucune dépendance externe** (`pip install` n'est pas nécessaire).
> Le serveur utilise uniquement la bibliothèque standard de Python.
> C'est volontaire — cela rend le build ultra-rapide et l'image très légère.

### 3.4 Builder et lancer le proxy

```powershell
cd C:\nl2el-proxy
docker build -t nl2el-proxy .
docker run -d --name nl2el-proxy -p 8082:8082 --add-host=host.docker.internal:host-gateway nl2el-proxy
```

### 3.5 Tester le proxy

```powershell
curl -X POST http://localhost:8082/v1/chat/completions -H "Content-Type: application/json" -d '{\"model\": \"kql-copilot-stateless\", \"messages\": [{\"role\": \"user\", \"content\": \"show failed login attempts\"}], \"stream\": false}'
```

**Résultat attendu** — Réponse JSON au format OpenAI avec une requête KQL.

> [!WARNING]
> **S'assurer que Docker Desktop est lancé AVANT de faire `docker build`.**
> Sinon : `failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine`

---

## Étape 4 — Installer et Configurer LibreChat

### 4.1 Cloner LibreChat

```powershell
cd C:\
git clone https://github.com/danny-avila/LibreChat.git
cd LibreChat
```

### 4.2 Configurer le `.env`

Copier le fichier d'exemple :
```powershell
copy .env.example .env
```

Modifier les valeurs suivantes dans `.env` :

```ini
# ── Serveur ──
HOST=localhost
PORT=3080

# ── Authentification (générer des valeurs uniques !) ──
CREDS_KEY=f34be427ebb29de8d88c107a71546019685ed8b241d8f2ed00c3df97ad2566f0
CREDS_IV=e2341419ec3dd3d19b13a1a87fafcbfb

# ── Inscription ──
ALLOW_REGISTRATION=true

# ── MeiliSearch ──
MEILI_MASTER_KEY=DrhYf7zENyR6AlUCKmnz0eYASOQdl6zxH7s7MKFSfFCt

# ── Debug (utile pour le troubleshooting) ──
DEBUG_LOGGING=true
```

**Ajouter à la toute fin du fichier `.env`** :
```ini
CONFIG_PATH="/app/librechat.yaml"
```

> [!IMPORTANT]
> `CREDS_KEY` et `CREDS_IV` doivent être des chaînes hexadécimales.
> Pour générer les vôtres :
> ```powershell
> # Générer CREDS_KEY (32 bytes = 64 hex chars)
> python -c "import secrets; print(secrets.token_hex(32))"
> # Générer CREDS_IV (16 bytes = 32 hex chars)
> python -c "import secrets; print(secrets.token_hex(16))"
> ```

### 4.3 Créer le `librechat.yaml`

Créer le fichier `C:\LibreChat\librechat.yaml` :

```yaml
version: "1.3.9"

endpoints:
  custom:
    # ── KQL/ES|QL Translator (stateless proxy) ──
    # Chaque message est indépendant — aucune mémoire entre les requêtes.
    - name: "KQL Copilot"
      apiKey: "ollama"
      baseURL: "http://host.docker.internal:8082/v1/"
      models:
        default: ["kql-copilot-stateless"]
        fetch: false
      titleConvo: false
      summarize: false
      tools: false
```

> [!IMPORTANT]
> **Points critiques :**
> - `baseURL` utilise `host.docker.internal` (PAS `localhost`) car LibreChat tourne dans Docker
> - `fetch: false` — empêche LibreChat de faire des requêtes `/v1/models` qui causent des erreurs 401
> - `tools: false` — le KQL Copilot n'a pas besoin d'outils
> - `titleConvo: false` et `summarize: false` — évite des appels API inutiles au modèle

### 4.4 Créer le `docker-compose.override.yml`

Créer le fichier `C:\LibreChat\docker-compose.override.yml` :

```yaml
version: '3.4'
services:
  api:
    volumes:
      - type: bind
        source: ./librechat.yaml
        target: /app/librechat.yaml
```

> [!CAUTION]
> **Ce fichier est OBLIGATOIRE.** Sans lui, LibreChat ne lira pas votre `librechat.yaml`.
> Le docker-compose de base ne monte PAS ce fichier automatiquement.

---

## Étape 5 — Lancer le Tout

### 5.1 Ordre de démarrage

L'ordre est important. Suivre ces étapes dans l'ordre :

```powershell
# 1. S'assurer que Docker Desktop est lancé (via le menu Windows)

# 2. S'assurer qu'Ollama est démarré
ollama list
# Doit afficher "kql-copilot-stateless" dans la liste

# 3. Lancer le proxy NL2EL (si pas déjà fait)
docker start nl2el-proxy
# OU si le conteneur n'existe pas encore :
# docker run -d --name nl2el-proxy -p 8082:8082 --add-host=host.docker.internal:host-gateway nl2el-proxy

# 4. Lancer LibreChat
cd C:\LibreChat
docker compose up -d
```

### 5.2 Vérifier que tout est lancé

```powershell
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

**Conteneurs attendus** :
| Conteneur | Port | Statut |
|-----------|------|--------|
| `LibreChat` | 3080 | Up |
| `chat-mongodb` | 27017 | Up |
| `chat-meilisearch` | 7700 | Up |
| `vectordb` | 5432 | Up |
| `rag_api` | 8000 | Up |
| `nl2el-proxy` | 8082 | Up |

Ollama tourne nativement sur le port **11434** (pas dans Docker).

### 5.3 Vérifier les logs LibreChat

```powershell
docker logs LibreChat --tail 30
```

Chercher : `Server listening on port 3080` — cela confirme que LibreChat est prêt.

> [!WARNING]
> Si vous voyez `Failed to fetch models from openAI API ... 401` dans les logs, **c'est normal**.
> C'est LibreChat qui essaie de découvrir les modèles d'autres endpoints.
> Avec `fetch: false`, cela n'affecte pas le fonctionnement.

---

## Étape 6 — Créer un Preset dans LibreChat

> [!IMPORTANT]
> **Cette étape est CRITIQUE.** Sans le preset, le modèle peut retourner du ES|QL au lieu de KQL.
> C'est parce que l'API `/v1/chat/completions` d'Ollama n'applique PAS automatiquement le SYSTEM prompt du Modelfile comme le fait `/api/generate`.

### 6.1 Ouvrir LibreChat

Naviguer vers : **http://localhost:3080**

### 6.2 Créer le Preset

1. Sélectionner l'endpoint **"KQL Copilot"** en haut
2. Cliquer sur l'icône **⚙️ (paramètres)** à côté du sélecteur de modèle
3. Dans **"Custom Instructions"** (ou System Prompt), coller :

```
You are a SOC analyst assistant expert in Kibana Query Language (KQL) and Elastic Common Schema (ECS). Return only the query.
```

4. Régler la **temperature** à **0.01** (pour des résultats cohérents)
5. Sauvegarder comme Preset (ex: "KQL Copilot")

### 6.3 Tester

Envoyer dans le chat :
```
show failed login attempts
```

**Résultat attendu** — Une requête KQL pure :
```
event.action:"logon-failed" OR winlog.event_id:4625
```

---

## ✅ Vérification

### Checklist rapide

- [ ] `curl http://localhost:11434` → "Ollama is running"
- [ ] `ollama list` → affiche `kql-copilot-stateless`
- [ ] `curl http://localhost:8082/v1/models` → JSON avec `kql-copilot-stateless`
- [ ] `curl -X POST http://localhost:8082/v1/chat/completions ...` → réponse KQL
- [ ] `http://localhost:3080` → LibreChat accessible
- [ ] Chat avec "KQL Copilot" → retourne des requêtes KQL

---

## 🔌 Résumé des Ports

| Service | Port | Tourne dans | Accès |
|---------|------|-------------|-------|
| **LibreChat** | 3080 | Docker | `http://localhost:3080` |
| **Proxy NL2EL** | 8082 | Docker | `http://localhost:8082` |
| **Ollama** | 11434 | Windows (natif) | `http://localhost:11434` |
| **MongoDB** | 27017 | Docker | interne |
| **MeiliSearch** | 7700 | Docker | interne |

---

## 🐛 Erreurs Connues et Comment les Éviter

### ❌ Erreur : Docker Desktop pas lancé
```
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```
**✅ Solution** : Lancer Docker Desktop AVANT toute commande `docker`.

---

### ❌ Erreur : Le modèle retourne du ES|QL au lieu de KQL
```
FROM logs-* | WHERE winlog.event_id == 4625 | STATS ...
```
**Cause** : L'API `/v1/chat/completions` d'Ollama n'applique pas le SYSTEM prompt du Modelfile.

**✅ Solution** : Créer un Preset LibreChat avec le System Prompt (voir [Étape 6](#étape-6--créer-un-preset-dans-librechat)).

---

### ❌ Erreur : Réponses incohérentes / pollution par l'historique
**Cause** : LibreChat envoie toute la conversation au modèle. Le modèle KQL se "perd" avec du contexte en plus.

**✅ Solution** : Le proxy strip tout l'historique et envoie `context: []` — **c'est déjà géré** par le `server.py`.

---

### ❌ Erreur : `Cannot read properties of undefined (reading 'role')`
**Cause** : LibreChat envoie les requêtes avec `stream: true` par défaut. Si le serveur ne supporte pas le streaming SSE, ça crash.

**✅ Solution** : Le `server.py` fourni supporte le streaming SSE — **c'est déjà géré**.

---

### ❌ Erreur : Le spinner de LibreChat ne s'arrête jamais
**Cause** : Le header HTTP `Connection: keep-alive` maintient la connexion ouverte après le streaming.

**✅ Solution** : Le `server.py` utilise `Connection: close` et `self.close_connection = True` — **c'est déjà géré**.

---

### ❌ Erreur : `Failed to fetch models from openAI API ... 401`
**Cause** : LibreChat essaie de récupérer la liste des modèles depuis les endpoints.

**✅ Solution** : `fetch: false` dans `librechat.yaml` — **c'est déjà configuré**.

---

### ❌ Erreur : Port 8082 déjà occupé
```powershell
# Trouver le processus qui utilise le port
netstat -ano | findstr :8082
# Tuer le processus ou utiliser un autre port
docker stop nl2el-proxy
docker rm nl2el-proxy
```

---

### ❌ Erreur : `Ollama unreachable` depuis le proxy Docker
**Cause** : Le conteneur ne peut pas atteindre Ollama sur l'hôte.

**✅ Solution** : S'assurer que le conteneur est lancé avec `--add-host=host.docker.internal:host-gateway` :
```powershell
docker run -d --name nl2el-proxy -p 8082:8082 --add-host=host.docker.internal:host-gateway nl2el-proxy
```

---

### ❌ Erreur : Changements dans `librechat.yaml` non appliqués
**Cause** : LibreChat cache la config au démarrage.

**✅ Solution** : Redémarrer les conteneurs :
```powershell
cd C:\LibreChat
docker compose down
docker compose up -d
```

> [!CAUTION]
> **Ne pas utiliser** `docker compose restart`. Faire `down` puis `up` pour s'assurer que le fichier YAML est bien relu.

---

## 📁 Fichiers de Référence

### Structure finale sur la machine

```
C:\
├── nl2el-model\
│   ├── Modelfile                                    # Définition Ollama
│   └── mistral-7b-instruct-v0.3.Q4_K_M.gguf       # Modèle (4.4 Go)
│
├── nl2el-proxy\
│   ├── Dockerfile                                   # Image Docker du proxy
│   └── server.py                                    # Proxy stateless
│
└── LibreChat\
    ├── .env                                         # Configuration environnement
    ├── librechat.yaml                               # Configuration AI endpoints
    ├── docker-compose.yml                           # (fourni par LibreChat)
    └── docker-compose.override.yml                  # Monte librechat.yaml
```

### Résumé des composants

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Modèle NL2EL** | Mistral 7B Instruct v0.3 (GGUF Q4_K_M) | Convertit NL → KQL |
| **Ollama** | Runtime LLM local | Sert le modèle GGUF |
| **Proxy Stateless** | Python 3.11 (stdlib uniquement) | Adapte OpenAI → Ollama, force le stateless |
| **LibreChat** | Node.js + React (Docker) | Interface chat web |

---

## 🔄 Commandes Utiles

```powershell
# ── Relancer tout ──
docker start nl2el-proxy
cd C:\LibreChat && docker compose up -d

# ── Arrêter tout ──
cd C:\LibreChat && docker compose down
docker stop nl2el-proxy

# ── Voir les logs ──
docker logs nl2el-proxy --tail 20
docker logs LibreChat --tail 30

# ── Recréer le modèle Ollama ──
cd C:\nl2el-model
ollama rm kql-copilot-stateless
ollama create kql-copilot-stateless -f Modelfile

# ── Reconstruire le proxy ──
cd C:\nl2el-proxy
docker stop nl2el-proxy && docker rm nl2el-proxy
docker build -t nl2el-proxy .
docker run -d --name nl2el-proxy -p 8082:8082 --add-host=host.docker.internal:host-gateway nl2el-proxy
```

---

> **Temps de setup estimé** : ~30 minutes (sans compter le téléchargement du modèle GGUF).
