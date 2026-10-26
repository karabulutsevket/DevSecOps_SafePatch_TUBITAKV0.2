package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 behaviour test for OWASP Benchmark BenchmarkTest02032 (generated, MIT): a benign input answers as in the original code. */
class SafePatchBehavior02032 {

  @Test
  void benignInputAnswersAsBefore() throws Exception {
    assertEquals("31842c96cf58fed3edfdd37088ad04b38d646f93b2a4f9d27f60d46641be1a05", WitnessSupport.benign(org.owasp.benchmark.testcode.BenchmarkTest02032.class, "BenchmarkTest02032", WitnessSupport.BENIGN), "BEHAVIOR_REGRESSION");
  }
}
