package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest02091 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior02091 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("8c6242f912e15e5b3869937806c414f78743b3d0b12366d09846af174ac22cbb", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest02091.class, "BenchmarkTest02091", "bar"), "BEHAVIOR_REGRESSION");
  }
}
