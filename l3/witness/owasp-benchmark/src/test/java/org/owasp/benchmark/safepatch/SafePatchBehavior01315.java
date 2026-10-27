package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01315 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior01315 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("a7d6a5b482d46ce516afed30d5021a27002c11a8d23a746bce857a3a8fd3c5d8", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest01315.class, "BenchmarkTest01315", "bar"), "BEHAVIOR_REGRESSION");
  }
}
