package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00331 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00331 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("61e2ea576c9e506a24575511dd8fd6265c5038f7c0ee97d59a73f40368f04492", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00331.class, "BenchmarkTest00331", "bar"), "BEHAVIOR_REGRESSION");
  }
}
