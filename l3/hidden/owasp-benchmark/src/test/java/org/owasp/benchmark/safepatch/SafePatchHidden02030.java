package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02030 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02030 {

  @Test
  void benignNameWithDotsAnswersAsBefore() throws Exception {
    assertEquals("13ed4970f475ea96470678e89900a95c16a5d32417da772106782ba4e2320b9d", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest02030.class, "BenchmarkTest02030", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR_DOTS");
  }
}
