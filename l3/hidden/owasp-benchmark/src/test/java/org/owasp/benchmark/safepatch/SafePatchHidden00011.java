package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest00011 (generated, MIT); the verifier never runs it. */
class SafePatchHidden00011 {

  @Test
  void benignNameWithDotsAnswersAsBefore() throws Exception {
    assertEquals("f7fafe62c4fda8bb05e809c05548fa9c674f8180fddc7172dac50547f004b09b", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest00011.class, "BenchmarkTest00011", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR_DOTS");
  }
}
