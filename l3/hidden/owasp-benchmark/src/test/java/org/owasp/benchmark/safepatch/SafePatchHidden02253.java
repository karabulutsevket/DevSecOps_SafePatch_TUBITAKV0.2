package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02253 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02253 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("55bb5e5718d25dfbbde5b3d6df3e95a50c3241b2d8dac131b9041dd8887a5268", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest02253.class, "BenchmarkTest02253", "hello world"), "HIDDEN_BEHAVIOR");
  }
}
