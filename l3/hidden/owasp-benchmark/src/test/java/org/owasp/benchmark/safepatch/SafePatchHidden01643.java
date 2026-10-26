package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01643 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01643 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.nested(org.owasp.benchmark.testcode.BenchmarkTest01643.class, "BenchmarkTest01643"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("5952062c8c4cc9a8e1ff98f17578fe6c378c0f8404ecf5afec8a1e0df3425b39", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest01643.class, "BenchmarkTest01643", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR");
  }
}
