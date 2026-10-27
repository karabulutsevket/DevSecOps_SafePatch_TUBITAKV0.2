package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01087 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior01087 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("2d9218e22fa4786dd6f3b1ccdab341c73f378d88ab44668e8652f86169abbd0d", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01087.class, "BenchmarkTest01087", "bar"), "BEHAVIOR_REGRESSION");
  }
}
