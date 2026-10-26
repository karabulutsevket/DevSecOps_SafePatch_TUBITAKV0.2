package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01286 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01286 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.commandHidden(org.owasp.benchmark.testcode.BenchmarkTest01286.class, "BenchmarkTest01286"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("37fb146ef257511cac6e28778816c37ac5e74d8b81759384672e0062ce7fdcf7", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest01286.class, "BenchmarkTest01286", "hello world"), "HIDDEN_BEHAVIOR");
  }
}
