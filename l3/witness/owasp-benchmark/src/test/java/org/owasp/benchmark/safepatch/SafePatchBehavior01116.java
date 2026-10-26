package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01116 (generated, MIT): a benign file answers as in the original code. */
class SafePatchBehavior01116 {

  @Test
  void benignFileAnswersAsBefore() throws Exception {
    assertEquals("413709504c7662945293033b5b49de9efe7847a0e84477e3a73ae9569d0fc612", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest01116.class, "BenchmarkTest01116", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
