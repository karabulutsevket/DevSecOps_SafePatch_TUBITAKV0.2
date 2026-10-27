package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00979 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00979 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("7dfc1eae936ef2d1f20e4ce2a08f81bb82c15d89cf4c639730b02e52ff9db4a7", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest00979.class, "BenchmarkTest00979", "safepatch"), "BEHAVIOR_REGRESSION");
  }
}
