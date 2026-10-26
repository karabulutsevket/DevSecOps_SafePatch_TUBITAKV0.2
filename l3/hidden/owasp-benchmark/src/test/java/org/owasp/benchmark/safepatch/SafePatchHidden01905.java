package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest01905 (generated, MIT); the verifier never runs it. */
class SafePatchHidden01905 {

  @Test
  void benignNameWithDotsAnswersAsBefore() throws Exception {
    assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest01905.class, "BenchmarkTest01905", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR_DOTS");
  }
}
