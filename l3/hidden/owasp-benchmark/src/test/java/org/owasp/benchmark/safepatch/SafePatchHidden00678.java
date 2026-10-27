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
    assertEquals("816870c533007fe75ef14ccf3d87c4d561db6277ccfef93f2bc1d083be20cb84", HiddenSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00678.class, "BenchmarkTest00678", "User01"), "HIDDEN_BEHAVIOR");
  }
}
