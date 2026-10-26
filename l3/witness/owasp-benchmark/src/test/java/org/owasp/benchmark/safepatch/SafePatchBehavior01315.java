package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01315 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior01315 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("799b1aeb85d5ef8baedf4b8d61499bb223b6e1680ec6da33da76957d098c3fad", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01315.class, "BenchmarkTest01315", "bar"), "BEHAVIOR_REGRESSION");
  }
}
