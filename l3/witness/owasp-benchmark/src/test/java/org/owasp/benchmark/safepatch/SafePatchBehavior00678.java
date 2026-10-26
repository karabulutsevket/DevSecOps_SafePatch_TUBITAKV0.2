package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00678 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00678 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("2d9218e22fa4786dd6f3b1ccdab341c73f378d88ab44668e8652f86169abbd0d", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00678.class, "BenchmarkTest00678", "bar"), "BEHAVIOR_REGRESSION");
  }
}
