package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest01905 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior01905 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest01905.class, "BenchmarkTest01905", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
