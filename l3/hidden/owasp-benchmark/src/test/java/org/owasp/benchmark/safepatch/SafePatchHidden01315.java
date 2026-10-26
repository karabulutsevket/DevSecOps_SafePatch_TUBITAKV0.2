package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01315 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01315 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("799b1aeb85d5ef8baedf4b8d61499bb223b6e1680ec6da33da76957d098c3fad", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01315.class, "BenchmarkTest01315", "User01"), "HIDDEN_BEHAVIOR");
  }
}
