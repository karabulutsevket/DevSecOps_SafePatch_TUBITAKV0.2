package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02032 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02032 {

  @Test
  void climbingFromASubdirectoryHasNoEffect() throws Exception {
    assertEquals("", WitnessSupport.nested(org.owasp.benchmark.testcode.BenchmarkTest02032.class, "BenchmarkTest02032"), "HIDDEN_TRAVERSAL_NESTED");
  }

  @Test
  void benignNameWithDotsAnswersAsBefore() throws Exception {
    assertEquals("a1a7e2e14ba0c50302dcbd4435bb58d7ea80ccc8f3cb98ea040de50d414d6ff8", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest02032.class, "BenchmarkTest02032", WitnessSupport.DOTS), "HIDDEN_BEHAVIOR_DOTS");
  }
}
