"""Personal Gemini Journal — an authenticated, privacy-first reflection app.

Security posture
----------------
* No secrets in source. Vertex AI authenticates with the Cloud Run service
  account; when the AI Studio path is used instead, GEMINI_API_KEY is injected
  from Secret Manager and never read from disk or code.
* Every route that touches user data verifies a Firebase ID token server-side.
* Firestore document paths are derived from the *verified* uid only, never
  from client-supplied input, so one user cannot address another's data.
* Sensitive strings are stripped from the text locally, before any bytes leave
  this process for the Gemini API. The mapping back to the real values stays in
  request memory and is never written to Firestore or sent upstream.
"""

import os
import re
import logging

from flask import Flask, request, jsonify, render_template

import firebase_admin
from firebase_admin import auth as fb_auth, firestore

from google import genai
from google.genai import types as genai_types

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("journal")

app = Flask(__name__)

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
MAX_TURNS = 12
MAX_CHARS = 6000

USE_VERTEX = os.environ.get("USE_VERTEX", "true").lower() == "true"
VERTEX_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
VERTEX_LOCATION = os.environ.get("VERTEX_LOCATION", "global")

_fs = None
_genai_client = None


def db():
    global _fs
    if _fs is None:
        if not firebase_admin._apps:
            firebase_admin.initialize_app()
        _fs = firestore.client()
    return _fs


def gemini():
    global _genai_client
    if _genai_client is None:
        if USE_VERTEX:
            if not VERTEX_PROJECT:
                raise RuntimeError("GOOGLE_CLOUD_PROJECT is not set.")
            _genai_client = genai.Client(
                vertexai=True,
                project=VERTEX_PROJECT,
                location=VERTEX_LOCATION,
            )
        else:
            key = os.environ.get("GEMINI_API_KEY")
            if not key:
                raise RuntimeError("GEMINI_API_KEY is not set.")
            _genai_client = genai.Client(api_key=key)
    return _genai_client


PATTERNS = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    ("LINK", re.compile(r"https?://\S+")),
    ("CARD", re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")),
    ("ID", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("PHONE", re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b")),
    ("AMOUNT", re.compile(r"(?:₹|Rs\.?\s?)\s?[\d,]+(?:\.\d{1,2})?", re.I)),
]

LABELS = {
    "EMAIL": "email address",
    "LINK": "link",
    "CARD": "card number",
    "ID": "ID number",
    "PAN": "tax ID",
    "PHONE": "phone number",
    "AMOUNT": "money amount",
    "NAME": "name",
}


def redact(text, protected_names=None):
    protected_names = protected_names or []
    mapping = {}
    summary = []
    counters = {}
    out = text

    def take(kind, value):
        for tok, orig in mapping.items():
            if orig == value and tok.startswith(f"[{kind}"):
                return tok
        counters[kind] = counters.get(kind, 0) + 1
        tok = f"[{kind}_{counters[kind]}]"
        mapping[tok] = value
        summary.append({"token": tok, "kind": kind, "label": LABELS.get(kind, kind.lower())})
        return tok

    for kind, pattern in PATTERNS:
        out = pattern.sub(lambda m: take(kind, m.group(0)), out)

    for name in protected_names:
        name = name.strip()
        if len(name) < 2:
            continue
        pattern = re.compile(rf"\b{re.escape(name)}\b", re.I)
        out = pattern.sub(lambda m: take("NAME", m.group(0)), out)

    return out, mapping, summary


def rehydrate(text, mapping):
    for token, original in mapping.items():
        text = text.replace(token, original)
    return text


SYSTEM_PROMPT = (
    "You are a reflective journalling companion. The person is thinking out "
    "loud, not asking for a task to be done. Respond to what they actually "
    "wrote in two or three short paragraphs: reflect the feeling back "
    "accurately, then ask one specific question that opens the thought further. "
    "Do not give advice unless asked. Do not use headings, bullet points or "
    "bold text. Some details appear as tokens like [NAME_1] or [PHONE_1] "
    "because they were withheld for privacy. Treat each token as a consistent "
    "stand-in and use it naturally in your reply. Never guess what a token "
    "hides and never comment on the tokens themselves."
)


def current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    try:
        decoded = fb_auth.verify_id_token(header.split(" ", 1)[1])
        return decoded["uid"]
    except Exception as exc:
        log.warning("token rejected: %s", type(exc).__name__)
        return None


def require_user():
    if not firebase_admin._apps:
        firebase_admin.initialize_app()
    uid = current_user()
    if not uid:
        return None, (jsonify({"error": "Sign in to continue."}), 401)
    return uid, None


def settings_ref(uid):
    return db().collection("users").document(uid)


def entries_ref(uid):
    return db().collection("users").document(uid).collection("entries")


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "model": MODEL,
        "backend": "vertex" if USE_VERTEX else "ai-studio",
        "location": VERTEX_LOCATION if USE_VERTEX else None,
    }


@app.get("/api/config")
def config():
    return jsonify({
        "apiKey": os.environ.get("FIREBASE_API_KEY", ""),
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", ""),
        "projectId": os.environ.get("FIREBASE_PROJECT_ID", ""),
        "appId": os.environ.get("FIREBASE_APP_ID", ""),
    })


@app.post("/api/preview")
def preview():
    uid, err = require_user()
    if err:
        return err
    text = (request.json or {}).get("text", "")[:MAX_CHARS]
    names = settings_ref(uid).get().to_dict() or {}
    redacted, _, summary = redact(text, names.get("protected_names", []))
    return jsonify({"redacted": redacted, "summary": summary})


@app.post("/api/reflect")
def reflect():
    uid, err = require_user()
    if err:
        return err

    text = (request.json or {}).get("text", "").strip()[:MAX_CHARS]
    if not text:
        return jsonify({"error": "Write something first."}), 400

    settings = settings_ref(uid).get().to_dict() or {}
    redacted, mapping, summary = redact(text, settings.get("protected_names", []))

    history = list(
        entries_ref(uid).order_by("created_at", direction=firestore.Query.DESCENDING)
        .limit(MAX_TURNS).stream()
    )
    contents = []
    for doc in reversed(history):
        d = doc.to_dict()
        contents.append(genai_types.Content(
            role="user", parts=[genai_types.Part(text=d.get("redacted", ""))]))
        contents.append(genai_types.Content(
            role="model", parts=[genai_types.Part(text=d.get("reply_redacted", ""))]))
    contents.append(genai_types.Content(
        role="user", parts=[genai_types.Part(text=redacted)]))

    try:
        response = gemini().models.generate_content(
            model=MODEL,
            contents=contents,
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.8,
                max_output_tokens=700,
            ),
        )
        reply_redacted = (response.text or "").strip()
    except Exception as exc:
        log.exception("gemini call failed")
        return jsonify({"error": f"Gemini could not answer: {exc}"}), 502

    reply = rehydrate(reply_redacted, mapping)

    doc = {
        "text": text,
        "redacted": redacted,
        "reply": reply,
        "reply_redacted": reply_redacted,
        "model": MODEL,
        "redactions": summary,
        "turn_count": len(history) + 1,
        "created_at": firestore.SERVER_TIMESTAMP,
    }
    ref = entries_ref(uid).document()
    ref.set(doc)

    return jsonify({
        "id": ref.id,
        "reply": reply,
        "receipt": {
            "sent_to_gemini": redacted,
            "withheld": summary,
            "model": MODEL,
            "stored_at": f"users/{uid}/entries/{ref.id}",
            "uid": uid,
            "turns_replayed": len(history),
        },
    })


@app.get("/api/entries")
def list_entries():
    uid, err = require_user()
    if err:
        return err
    docs = entries_ref(uid).order_by(
        "created_at", direction=firestore.Query.DESCENDING).limit(50).stream()
    out = []
    for doc in docs:
        d = doc.to_dict()
        created = d.get("created_at")
        out.append({
            "id": doc.id,
            "text": d.get("text", ""),
            "reply": d.get("reply", ""),
            "receipt": {
                "sent_to_gemini": d.get("redacted", ""),
                "withheld": d.get("redactions", []),
                "model": d.get("model", ""),
                "stored_at": f"users/{uid}/entries/{doc.id}",
                "uid": uid,
                "turns_replayed": max(0, d.get("turn_count", 1) - 1),
            },
            "created_at": created.isoformat() if created else None,
        })
    return jsonify({"entries": out})


@app.route("/api/protected-names", methods=["GET", "POST"])
def protected_names():
    uid, err = require_user()
    if err:
        return err
    if request.method == "GET":
        data = settings_ref(uid).get().to_dict() or {}
        return jsonify({"names": data.get("protected_names", [])})

    raw = (request.json or {}).get("names", [])
    names = [str(n).strip()[:40] for n in raw if str(n).strip()][:25]
    settings_ref(uid).set({"protected_names": names}, merge=True)
    return jsonify({"names": names})



PATTERN_RADAR_PROMPT = """
You are the Pattern Radar for a private personal journal.

Analyze ONLY the supplied journal entries. Do not diagnose mental health,
infer sensitive traits, or invent facts.

Return ONLY valid JSON with this exact structure:
{
  "themes": [
    {
      "name": "short theme name",
      "summary": "one concise sentence",
      "frequency": 0
    }
  ],
  "loops": [
    {
      "name": "short unresolved pattern",
      "summary": "one concise sentence"
    }
  ],
  "shift": "one concise sentence describing a meaningful change over time",
  "question": "one thoughtful question grounded in the journal"
}

Rules:
- Maximum 4 themes.
- Maximum 3 loops.
- frequency must be the number of supplied entries where the theme appears.
- Do not quote private identifiers.
- Use only evidence present in the entries.
- If there is not enough evidence for a section, return an empty array or a
  cautious statement.
"""


@app.route("/api/pattern-radar", methods=["GET", "POST"])
def pattern_radar():
    uid, err = require_user()
    if err:
        return err

    docs = list(
        entries_ref(uid)
        .order_by("created_at", direction=firestore.Query.ASCENDING)
        .limit(50)
        .stream()
    )

    if len(docs) < 3:
        return jsonify({
            "ready": False,
            "message": "Write at least 3 reflections to discover patterns."
        })

    journal_entries = []

    for i, doc in enumerate(docs, 1):
        d = doc.to_dict()
        journal_entries.append({
            "entry": i,
            "thought": d.get("redacted", ""),
            "reflection": d.get("reply_redacted", "")
        })

    prompt = (
        PATTERN_RADAR_PROMPT
        + "\n\nJOURNAL ENTRIES:\n"
        + __import__("json").dumps(journal_entries, ensure_ascii=False)
    )

    radar_schema = {
        "type": "OBJECT",
        "properties": {
            "themes": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "name": {"type": "STRING"},
                        "summary": {"type": "STRING"},
                        "frequency": {"type": "INTEGER"},
                    },
                    "required": ["name", "summary", "frequency"],
                },
            },
            "loops": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "name": {"type": "STRING"},
                        "summary": {"type": "STRING"},
                    },
                    "required": ["name", "summary"],
                },
            },
            "shift": {"type": "STRING"},
            "question": {"type": "STRING"},
        },
        "required": ["themes", "loops", "shift", "question"],
    }

    try:
        response = gemini().models.generate_content(
            model=MODEL,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=2000,
                response_mime_type="application/json",
                response_schema=radar_schema,
            ),
        )

        # Prefer the SDK's parsed structured result when available.
        result = getattr(response, "parsed", None)

        if result is None:
            raw = (response.text or "").strip()

            # Defensive cleanup if the model still returns a fenced JSON block.
            if raw.startswith("```"):
                raw = raw.replace("```json", "", 1).replace("```", "", 1).strip()

            result = __import__("json").loads(raw)

        if not isinstance(result, dict):
            raise ValueError("Gemini returned an unexpected Pattern Radar structure")

    except Exception as exc:
        log.exception("pattern radar failed")
        return jsonify({"error": f"Pattern Radar could not run: {exc}"}), 502

    return jsonify({
        "ready": True,
        "patterns": result,
        "entries_analyzed": len(docs),
        "model": MODEL,
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
