import asyncio
from .attacker import RedTeamAttacker

class RobustnessEvaluator:
    def evaluate(self, model_input: str, detector_type: str) -> dict:
        # Mock robustness testing
        return {
            "robustness_score": 0.92,
            "adversarial_detected": False,
            "perturbation_resistance": "High"
        }

    async def run_attack_suite(self, input_type: str, input_value: str) -> dict:
        """
        Generates mutations and tests them against the actual detectors.
        Returns a breakdown of success/failure and a final Resilience Score.
        """
        attacker = RedTeamAttacker()
        
        # 1. Generate mutations
        attacks = []
        if input_type == 'url':
            attacks = [
                {"name": "Homoglyph",  "mutated": attacker.generate_homoglyph_domain(input_value)},
                {"name": "Zero-Width", "mutated": attacker.inject_zero_width(input_value)},
                {"name": "Combined",   "mutated": attacker.generate_homoglyph_domain(attacker.inject_zero_width(input_value))}
            ]
        else:
            attacks = [
                {"name": "Synonym",    "mutated": attacker.obfuscate_text(input_value)},
                {"name": "Zero-Width", "mutated": attacker.inject_zero_width(input_value)},
                {"name": "Combined",   "mutated": attacker.obfuscate_text(attacker.inject_zero_width(input_value))}
            ]

        # 2. Run against orchestrator (lazy import to break circular dependency)
        import sys, os as _os
        _backend = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        if _backend not in sys.path:
            sys.path.insert(0, _backend)
        from main import get_orchestrator  # type: ignore[import]
        orc = get_orchestrator()
        
        results = []
        success_count = 0
        
        for attack in attacks:
            p = attack["mutated"]
            res = await orc.run(
                url=p if input_type == 'url' else None,
                text=p if input_type == 'text' else None
            )
            
            score = res.get("sentinel_score", 0)
            # If the model still flags it (>50), the attack FAILED (model is robust)
            attack_success = score < 60 
            
            results.append({
                "name": attack["name"],
                "mutated_input": p,
                "score": score,
                "success": attack_success
            })
            
            if not attack_success:
                success_count = success_count + 1  # Model was robust

        resilience_score = int((success_count / len(attacks)) * 100) if attacks else 100

        return {
            "resilience_score": resilience_score,
            "attacks": results
        }
