package org.codehaus.plexus.archiver;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.codehaus.plexus.PlexusTestCase;

/**
 * SafePatch L3 hidden evaluation test for VUL4J-41 (written by SafePatch, MIT). The verifier
 * never runs it. The upstream fix guards the extraction shared by every archive format; a
 * fix made only in the zip path passes the witness and fails here. Names with dots that stay
 * inside the destination must still extract. Java 6 source level.
 */
public class SafePatchHiddenTraversalTest extends PlexusTestCase {

  private static File tar(File dir, String[] names) throws IOException {
    File file = new File(dir, "archive.tar");
    TarArchiveOutputStream out = new TarArchiveOutputStream(new FileOutputStream(file));
    try {
      for (int i = 0; i < names.length; i++) {
        byte[] data = ("content " + i).getBytes("UTF-8");
        TarArchiveEntry entry = new TarArchiveEntry(names[i]);
        entry.setSize(data.length);
        out.putArchiveEntry(entry);
        out.write(data);
        out.closeArchiveEntry();
      }
    }
    finally {
      out.close();
    }
    return file;
  }

  private void extract(String role, File archive, File out) {
    try {
      UnArchiver unarchiver = (UnArchiver) lookup(UnArchiver.ROLE, role);
      unarchiver.setSourceFile(archive);
      unarchiver.extract("", out);
    }
    catch (Exception expected) {
      // refusing the archive is fine; writing outside is not
    }
  }

  public void testTarEntryOutsideTheDestinationIsNotWritten() throws Exception {
    File base = SafePatchZipSlipWitnessTest.base();
    extract("tar", tar(base, new String[] { "good.txt", "../../evil.txt" }), new File(base, "a/out"));
    assertFalse("HIDDEN_TRAVERSAL_TAR", new File(base, "evil.txt").exists());
  }

  public void testNestedZipEntryOutsideTheDestinationIsNotWritten() throws Exception {
    File base = SafePatchZipSlipWitnessTest.base();
    extract("zip", SafePatchZipSlipWitnessTest.zip(base, new String[] { "sub/../../../evil.txt" }), new File(base, "a/out"));
    assertFalse("HIDDEN_TRAVERSAL_NESTED", new File(base, "evil.txt").exists());
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
