package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00452 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00452 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("1730b2e92703ee0db5ea6fa8f8312f4c25e74bc538eaa95967edb0dc5efd9c4d", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest00452.class, "BenchmarkTest00452", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
