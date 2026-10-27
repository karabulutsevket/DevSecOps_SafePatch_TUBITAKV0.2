package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest02653 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior02653 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("cce367c581a7223f274ac40a241c81e5e67975e0e98856f6921c244c6fc10180", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest02653.class, "BenchmarkTest02653", "bar"), "BEHAVIOR_REGRESSION");
  }
}
