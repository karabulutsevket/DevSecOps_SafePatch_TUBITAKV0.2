package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01794 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior01794 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("42b12c92185183ee39ab70724a4f685184d60de9e9fbd3f5df8c255c549e3618", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest01794.class, "BenchmarkTest01794", "safepatch"), "BEHAVIOR_REGRESSION");
  }
}
