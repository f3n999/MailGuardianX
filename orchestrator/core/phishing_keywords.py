"""
Détection de mots-clés de phishing — sujet + aperçu du corps.

Tourne EXCLUSIVEMENT côté ingestion (graph_ingestor.py), là où le texte brut
de l'email existe encore en mémoire, avant que tout le reste du pipeline ne
travaille sur des métadonnées hashées. La fonction ci-dessous ne retourne
qu'un score et des noms de catégories génériques (jamais le texte de
l'email, jamais le mot-clé trouvé tel quel) : c'est ce résultat-là, et lui
seul, qui rejoint EmailMetadata puis la base de données. Le sujet et le
corps eux-mêmes ne sont jamais persistés ni transmis au-delà de cette
fonction — cohérent avec le principe de minimisation déjà appliqué au reste
du pipeline (hash SHA256 plutôt que contenu).

Catégories et seuils repris du moteur de détection phishing développé pour
TopChrono (SEC-TOPCHRONO V5) — même liste de mots, adaptée à un score 0-1
pour s'intégrer au scoring heuristique de MailGuardianX.
"""
from __future__ import annotations

import re

# ──────────────────── Mots-clés par catégorie ────────────────────

PHISHING_KEYWORDS: dict[str, list[str]] = {
    "urgence": [
        "urgent", "action requise", "immédiatement", "dernier délai",
        "expire bientot", "dans les 24 heures", "expiry", "temps limité",
        "agissez maintenant", "sans délai", "dernière chance",
        "awaiting approval", "review required",
    ],
    "compte_compromis": [
        "compte bloqué", "compte suspendu", "accès refusé",
        "activité suspecte", "connexion inhabituelle",
        "votre compte sera fermé", "sécurité compromise",
        "tentative de connexion", "accès non autorisé",
    ],
    "donnees_personnelles": [
        "mot de passe", "identifiants", "coordonnées bancaires",
        "numéro de carte", "code secret", "code pin",
        "informations personnelles", "données confidentielles", "cvv",
    ],
    "appels_action": [
        "cliquez ici", "cliquez maintenant", "vérifiez", "confirmer",
        "valider maintenant", "mettre à jour", "réinitialisez",
        "suivez ce lien", "ouvrir le document", "review",
    ],
    "finance": [
        "virement urgent", "transfert bancaire", "remboursement en attente",
        "facture impayée", "paiement refusé", "funding", "nda",
    ],
    "anglais": [
        "verify your account", "confirm your identity",
        "click here immediately", "reset password", "unusual activity",
        "account suspended", "dear customer", "dear user", "shared with you",
    ],
}

# Seuils — repris à l'identique de TopChrono V5
THRESHOLD_HIGH = 3
THRESHOLD_MEDIUM = 2

# Score 0-1 par palier, cohérent avec l'échelle du reste de l'heuristique
# MailGuardianX (cf. core/heuristics.py). Un seul mot-clé isolé n'ajoute
# rien : trop de faux positifs sur du vocabulaire métier légitime (ex.
# "mettre à jour" dans un mail RH normal).
SCORE_HIGH = 0.45
SCORE_MEDIUM = 0.25

_ALL_KEYWORDS: list[tuple[str, str]] = [
    (category, keyword)
    for category, keywords in PHISHING_KEYWORDS.items()
    for keyword in keywords
]


def score_phishing_keywords(subject: str, body_preview: str) -> dict:
    """
    Score un email sur la présence de mots-clés connus de phishing.

    :param subject: sujet brut de l'email (jamais retourné, jamais loggé)
    :param body_preview: aperçu du corps fourni par Graph (idem)
    :return: {"score": float, "matched_count": int, "categories": list[str]}
             — ni le texte ni les mots-clés littéraux ne sortent de cette
             fonction, uniquement le score et les noms de catégorie.
    """
    text = f"{subject} {body_preview}".lower()

    matched_categories: set[str] = set()
    matched_count = 0
    for category, keyword in _ALL_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", text, re.IGNORECASE):
            matched_count += 1
            matched_categories.add(category)

    if matched_count >= THRESHOLD_HIGH:
        score = SCORE_HIGH
    elif matched_count >= THRESHOLD_MEDIUM:
        score = SCORE_MEDIUM
    else:
        score = 0.0

    return {
        "score": score,
        "matched_count": matched_count,
        "categories": sorted(matched_categories),
    }
