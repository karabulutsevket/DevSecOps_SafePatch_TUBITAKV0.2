package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01964 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01964 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.sqlHidden(org.owasp.benchmark.testcode.BenchmarkTest01964.class, "BenchmarkTest01964"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("1cdbd040685486d4bc9276630d62ea3bf9eefb5b924001690d91125ca4c8b2d0", HiddenSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01964.class, "BenchmarkTest01964", "User01"), "HIDDEN_BEHAVIOR");
  }
}
