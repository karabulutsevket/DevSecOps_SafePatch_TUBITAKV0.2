package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest00678 (generated, MIT); the verifier never runs it. */
class SafePatchHidden00678 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.sqlHidden(org.owasp.benchmark.testcode.BenchmarkTest00678.class, "BenchmarkTest00678"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("a37cb5c6651f39e38e192d0c1b6c748b147e0e763e7f6e4d2b6f6755b4fe79c2", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00678.class, "BenchmarkTest00678", "User01"), "HIDDEN_BEHAVIOR");
  }
}
