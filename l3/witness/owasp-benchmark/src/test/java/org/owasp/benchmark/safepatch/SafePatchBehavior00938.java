package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00938 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00938 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("753fd8f4f9706655794c7bd71dcb53706c52bdaa32a51e8d42133977fb7de205", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00938.class, "BenchmarkTest00938", "bar"), "BEHAVIOR_REGRESSION");
  }
}
