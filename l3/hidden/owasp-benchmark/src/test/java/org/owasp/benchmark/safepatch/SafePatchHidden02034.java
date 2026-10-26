package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02034 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02034 {

  @Test
  void hiddenAttackHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.nested(org.owasp.benchmark.testcode.BenchmarkTest02034.class, "BenchmarkTest02034"), "HIDDEN_ATTACK");
  }

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("0a220919173abef40f09e5c9eee2bf2fdb3e3df3aea1a2b69e35951da5b373bd", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest02034.class, "BenchmarkTest02034", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR");
  }
}
