package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest00196 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior00196 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("3f8f3ae53ee9c12dbe4ab3be2d309d96d4d388148ea256fb1bc5295df8ce92e0", WitnessSupport.sqlAnswer(org.owasp.benchmark.testcode.BenchmarkTest00196.class, "BenchmarkTest00196", "bar"), "BEHAVIOR_REGRESSION");
  }
}
