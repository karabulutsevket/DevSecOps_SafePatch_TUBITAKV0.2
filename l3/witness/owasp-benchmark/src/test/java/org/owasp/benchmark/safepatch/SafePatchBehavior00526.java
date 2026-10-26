package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00526 (generated, MIT): a benign file answers as in the original code. */
class SafePatchBehavior00526 {

  @Test
  void benignFileAnswersAsBefore() throws Exception {
    assertEquals("a7690bc1b2dce6bdd026089acabcfd1027dd672fea5b29cffe2bd3b10ba4eacc", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest00526.class, "BenchmarkTest00526", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
