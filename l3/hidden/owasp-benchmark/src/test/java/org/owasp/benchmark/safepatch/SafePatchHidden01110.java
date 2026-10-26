package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01110 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01110 {

  @Test
  void benignNameWithDotsAnswersAsBefore() throws Exception {
    assertEquals("bb937823271aedf623372b60f0ba7ac2ad3e6b7204a71b49fb0ddfaa9c70f30e", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest01110.class, "BenchmarkTest01110", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR_DOTS");
  }
}
