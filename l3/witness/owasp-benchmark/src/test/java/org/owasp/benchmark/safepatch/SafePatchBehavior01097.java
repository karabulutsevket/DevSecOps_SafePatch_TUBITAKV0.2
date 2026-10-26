package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01097 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior01097 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("514134df76a24b47713f53714aef05dc4386a6c14cc06e431d204fc847554b87", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01097.class, "BenchmarkTest01097", "bar"), "BEHAVIOR_REGRESSION");
  }
}
