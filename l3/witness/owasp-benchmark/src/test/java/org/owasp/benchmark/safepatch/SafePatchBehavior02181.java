package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest02181 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior02181 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("2014d4e524331c91efb7f9868a06fae9fa0d76dcb54e79200d6e6e61767be2ca", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest02181.class, "BenchmarkTest02181", "bar"), "BEHAVIOR_REGRESSION");
  }
}
