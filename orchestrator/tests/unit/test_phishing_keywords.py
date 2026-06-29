"""
Tests du moteur de détection mots-clés phishing.
Vérifie le scoring par seuil et — point RGPD — qu'aucun texte brut
ni mot-clé littéral ne ressort de la fonction.
"""
from orchestrator.core.phishing_keywords import score_phishing_keywords


class TestPhishingKeywordScoring:
    def test_clean_email_zero_score(self):
        result = score_phishing_keywords(
            subject="Réunion équipe jeudi",
            body_preview="On se retrouve à 14h en salle B pour le point hebdo.",
        )
        assert result["score"] == 0.0
        assert result["categories"] == []

    def test_single_keyword_does_not_score(self):
        """Un seul mot-clé isolé est trop courant en usage légitime pour scorer."""
        result = score_phishing_keywords(
            subject="Merci de mettre à jour le tableau",
            body_preview="",
        )
        assert result["score"] == 0.0

    def test_two_keywords_medium_score(self):
        result = score_phishing_keywords(
            subject="Action requise sur votre compte",
            body_preview="Merci de vérifiez vos coordonnées dès que possible.",
        )
        assert result["score"] == 0.25
        assert result["matched_count"] == 2

    def test_three_plus_keywords_high_score(self):
        result = score_phishing_keywords(
            subject="Urgent : compte bloqué",
            body_preview=(
                "Votre compte sera fermé. Cliquez ici immédiatement et confirmer "
                "votre mot de passe pour éviter la suspension."
            ),
        )
        assert result["score"] == 0.45
        assert result["matched_count"] >= 3
        assert "urgence" in result["categories"]
        assert "compte_compromis" in result["categories"]

    def test_categories_only_no_literal_keyword_leaked(self):
        """Le résultat ne doit jamais contenir le texte d'entrée ni le mot trouvé."""
        subject = "Urgent : virement urgent requis maintenant"
        result = score_phishing_keywords(subject=subject, body_preview="")
        serialized = str(result)
        assert subject.lower() not in serialized.lower()
        assert "virement urgent" not in serialized

    def test_case_insensitive_and_word_boundary(self):
        result_upper = score_phishing_keywords("URGENT ACTION REQUISE", "CONFIRMER MAINTENANT")
        assert result_upper["score"] > 0
        # "review" ne doit pas matcher dans "preview" (frontière de mot)
        result_substr = score_phishing_keywords("Voici un preview du document", "")
        assert "appels_action" not in result_substr["categories"]

    def test_english_keywords_detected(self):
        result = score_phishing_keywords(
            subject="Your account suspended",
            body_preview="Please verify your account and confirm your identity now.",
        )
        assert result["score"] == 0.45
        assert "anglais" in result["categories"]
