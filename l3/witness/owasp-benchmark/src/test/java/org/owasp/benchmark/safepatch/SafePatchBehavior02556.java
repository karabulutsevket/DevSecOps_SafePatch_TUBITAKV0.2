package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest02556 (generated, MIT): a benign file answers as in the original code. */
class SafePatchBehavior02556 {

  @Test
  void benignFileAnswersAsBefore() throws Exception {
    assertEquals("80bd067d1870cc3a93ab725dbc11866748f6da49ecd41a3bf9517848b473052b", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest02556.class, "BenchmarkTest02556", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
