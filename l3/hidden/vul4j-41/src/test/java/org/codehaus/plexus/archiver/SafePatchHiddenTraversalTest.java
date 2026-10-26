package org.codehaus.plexus.archiver;

import java.io.File;

import org.codehaus.plexus.PlexusTestCase;

/**
 * SafePatch L3 hidden evaluation test for VUL4J-41 (written by SafePatch, MIT). The verifier
 * never runs it. The witness climbs out with a leading "../"; a fix that only looks for that
 * prefix passes it and fails here: a climb from inside a subdirectory, or an absolute name.
 * Names with dots that stay inside the destination must still extract. Java 6 source level.
 */
public class SafePatchHiddenTraversalTest extends PlexusTestCase {

  private void extract(File archive, File out) {
    try {
      UnArchiver unarchiver = (UnArchiver) lookup(UnArchiver.ROLE, "zip");
      unarchiver.setSourceFile(archive);
      unarchiver.extract("", out);
    }
    catch (Exception expected) {
      // refusing the archive is fine; writing outside is not
    }
  }

  public void testNestedZipEntryOutsideTheDestinationIsNotWritten() throws Exception {
    File base = SafePatchZipSlipWitnessTest.base();
    extract(SafePatchZipSlipWitnessTest.zip(base, new String[] { "sub/../../../evil.txt" }), new File(base, "a/out"));
    assertFalse("HIDDEN_TRAVERSAL_NESTED", new File(base, "evil.txt").exists());
  }

  public void testAbsoluteZipEntryOutsideTheDestinationIsNotWritten() throws Exception {
    File base = SafePatchZipSlipWitnessTest.base();
    File target = new File(base, "evil-absolute.txt");
    extract(SafePatchZipSlipWitnessTest.zip(base, new String[] { target.getAbsolutePath() }), new File(base, "a/out"));
    assertFalse("HIDDEN_TRAVERSAL_ABSOLUTE", target.exists());
  }

  public void testNamesWithDotsInsideTheDestinationStillExtract() throws Exception {
    File base = SafePatchZipSlipWitnessTest.base();
    File out = new File(base, "a/out");
    UnArchiver unarchiver = (UnArchiver) lookup(UnArchiver.ROLE, "zip");
    unarchiver.setSourceFile(SafePatchZipSlipWitnessTest.zip(base, new String[] { "dir/a..b.txt", "..hidden.txt" }));
    unarchiver.extract("", out);
    assertTrue("HIDDEN_BEHAVIOR_DOTS", new File(out, "dir/a..b.txt").isFile());
    assertTrue("HIDDEN_BEHAVIOR_DOTS", new File(out, "..hidden.txt").isFile());
  }
}
