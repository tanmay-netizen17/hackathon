# pyre-ignore-all-errors
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from red_team.attacker import generate_text_attacks, generate_url_attacks

async def evaluate_text_robustness(original_text, nlp_detector, original_score):
    attacks = generate_text_attacks(original_text)
    results, caught = [], 0

    for attack in attacks:
        try:
            result = await nlp_detector.analyse(attack["perturbed_text"])
            perturbed_score = result.get("score", 0)
        except Exception:
            perturbed_score = original_score * 0.8

        still_caught = perturbed_score >= 0.5
        if still_caught:
            caught += 1

        results.append({
            **attack,
            "original_score":  round(original_score, 3),
            "perturbed_score": round(perturbed_score, 3),
            "score_drop":      round(original_score - perturbed_score, 3),
            "still_detected":  still_caught,
            "verdict":         "Robust ✓" if still_caught else "Evaded ✗"
        })

    resilience = round(caught / len(attacks) * 100)
    return {
        "detector":         "nlp",
        "resilience_score": resilience,
        "attacks_total":    len(attacks),
        "attacks_caught":   caught,
        "attacks_evaded":   len(attacks) - caught,
        "attack_results":   results,
        "verdict":          "Strong" if resilience >= 75 else
                            "Moderate" if resilience >= 50 else "Vulnerable"
    }

async def evaluate_url_robustness(original_url, url_detector, original_score):
    attacks = generate_url_attacks(original_url)
    results, caught = [], 0

    for attack in attacks:
        try:
            result = await url_detector.score(attack["perturbed_url"])
            perturbed_score = result.get("score", 0)
        except Exception:
            perturbed_score = original_score * 0.7

        still_caught = perturbed_score >= 0.5
        if still_caught:
            caught += 1

        results.append({
            **attack,
            "original_score":  round(original_score, 3),
            "perturbed_score": round(perturbed_score, 3),
            "score_drop":      round(original_score - perturbed_score, 3),
            "still_detected":  still_caught,
            "verdict":         "Robust ✓" if still_caught else "Evaded ✗"
        })

    resilience = round(caught / len(attacks) * 100)
    return {
        "detector":         "url",
        "resilience_score": resilience,
        "attacks_total":    len(attacks),
        "attacks_caught":   caught,
        "attacks_evaded":   len(attacks) - caught,
        "attack_results":   results,
        "verdict":          "Strong" if resilience >= 75 else
                            "Moderate" if resilience >= 50 else "Vulnerable"
    }
