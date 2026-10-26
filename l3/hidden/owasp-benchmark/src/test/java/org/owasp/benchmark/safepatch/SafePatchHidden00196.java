package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest00196 (generated, MIT); the verifier never runs it. */
class SafePatchHidden00196 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("be24dc59402db0531203fc6552034a0ae0a331eb836bddf1f5f44d1519c5da80", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00196.class, "BenchmarkTest00196", "User01"), "HIDDEN_BEHAVIOR");
  }
}
