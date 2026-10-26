package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest00979 (generated, MIT); the verifier never runs it. */
class SafePatchHidden00979 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.commandHidden(org.owasp.benchmark.testcode.BenchmarkTest00979.class, "BenchmarkTest00979"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("e5416d6f9ed7b4c1806bec56f4eb8864d9ecf7b6fac5de20ba341594bdbf44c2", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest00979.class, "BenchmarkTest00979", "hello world"), "HIDDEN_BEHAVIOR");
  }
}
