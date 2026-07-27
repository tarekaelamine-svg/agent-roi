from agent_roi import ConfidenceInputs, DecisionOutcome, SentinelRunner


def test_agent_can_return_output_and_confidence():
    runner = SentinelRunner()

    def agent(ctx, payload):
        return {
            "ok": True
        }, ConfidenceInputs(
            prob=0.99,
            margin=0.80,
            z_score=3.0,
            entropy=0.05,
            llm_self_score=0.95,
        )

    result = runner.run(agent, {})
    assert result.outcome is DecisionOutcome.ACCEPT
    assert result.output == {"ok": True}
