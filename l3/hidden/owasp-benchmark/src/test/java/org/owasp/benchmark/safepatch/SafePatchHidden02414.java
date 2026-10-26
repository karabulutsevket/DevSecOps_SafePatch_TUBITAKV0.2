package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02414 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02414 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.commandHidden(org.owasp.benchmark.testcode.BenchmarkTest02414.class, "BenchmarkTest02414"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("5b95944194d8a8a453317b0f264476d1c1f6ccbbaaabff5fbce74daa0f344d6d", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest02414.class, "BenchmarkTest02414", "hello world"), "HIDDEN_BEHAVIOR");
  }
}
