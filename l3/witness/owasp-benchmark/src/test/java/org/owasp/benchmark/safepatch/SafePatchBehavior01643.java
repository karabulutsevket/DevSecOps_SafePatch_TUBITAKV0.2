package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01643 (generated, MIT): a benign file answers as in the original code. */
class SafePatchBehavior01643 {

  @Test
  void benignFileAnswersAsBefore() throws Exception {
    assertEquals("1730b2e92703ee0db5ea6fa8f8312f4c25e74bc538eaa95967edb0dc5efd9c4d", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest01643.class, "BenchmarkTest01643", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
