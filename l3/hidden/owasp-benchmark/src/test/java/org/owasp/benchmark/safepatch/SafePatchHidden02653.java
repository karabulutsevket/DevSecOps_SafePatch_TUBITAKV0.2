package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02653 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02653 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.sqlHidden(org.owasp.benchmark.testcode.BenchmarkTest02653.class, "BenchmarkTest02653"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("7a0e20f50a193782e179deb06dd3d27a6fda5fb96d4c98cd69eb7097eb67f867", HiddenSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest02653.class, "BenchmarkTest02653", "User01"), "HIDDEN_BEHAVIOR");
  }
}
