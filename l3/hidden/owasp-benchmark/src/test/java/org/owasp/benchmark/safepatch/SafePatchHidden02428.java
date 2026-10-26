package org.owasp.benchmark.safepatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** SafePatch L3 hidden evaluation test for OWASP Benchmark BenchmarkTest02428 (generated, MIT); the verifier never runs it. */
class SafePatchHidden02428 {

  @Test
  void anotherBenignInputAnswersAsBefore() throws Exception {
    assertEquals("8cb96cc8fb4262795593a783ba8c5479f18760431bc487101fa709e259f4ad9e", WitnessSupport.commandAnswer(org.owasp.benchmark.testcode.BenchmarkTest02428.class, "BenchmarkTest02428", "hello world"), "HIDDEN_BEHAVIOR");
  }
}
