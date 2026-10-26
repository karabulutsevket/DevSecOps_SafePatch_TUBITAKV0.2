package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02556 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02556 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("b022cf092d6430c668d406544c13d31a5033eb00a84ad1a2d36398d9f50f52b2", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest02556.class, "BenchmarkTest02556", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR");
  }
}
