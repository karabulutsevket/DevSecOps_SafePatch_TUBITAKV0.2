package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest02568 (generated, MIT): a benign file answers as in the original code. */
class SafePatchBehavior02568 {

  @Test
  void benignFileAnswersAsBefore() throws Exception {
    assertEquals("4cda68256b5f498fd3417c65774958e52fc48e326a44a364a03557022d7f0c8e", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest02568.class, "BenchmarkTest02568", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
