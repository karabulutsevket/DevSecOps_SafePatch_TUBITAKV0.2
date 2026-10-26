package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01097 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01097 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("bcbf690c9c63833f9ec5975d68a87b3f21ffb8dc1fcb0e9b7812d8113beb9c5b", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01097.class, "BenchmarkTest01097", "User01"), "HIDDEN_BEHAVIOR");
  }
}
