package org.codehaus.plexus.archiver;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.codehaus.plexus.PlexusTestCase;

/**
 * SafePatch L3 security witness for VUL4J-41 (written by SafePatch, MIT). The Vul4J
 * proof-of-vulnerability also asserts the human fix's exception message, so it rejects a
 * correct fix that words its error differently; this witness checks only the effect: an
 * entry that climbs out of the destination is not written there. Java 6 source level.
 */
public class SafePatchZipSlipWitnessTest extends PlexusTestCase {

  static File zip(File dir, String[] names) throws IOException {
    File file = new File(dir, "archive.zip");
    ZipOutputStream out = new ZipOutputStream(new FileOutputStream(file));
    try {
      for (int i = 0; i < names.length; i++) {
        out.putNextEntry(new ZipEntry(names[i]));
        out.write(("content " + i).getBytes("UTF-8"));
        out.closeEntry();
      }
    }
    finally {
      out.close();
    }
    return file;
  }

  static File base() throws IOException {
    File base = File.createTempFile("witness", "");
    base.delete();
    if (!new File(base, "a/out").mkdirs()) {
      throw new IOException("cannot create " + base);
    }
    return base;
  }

  public void testZipEntryOutsideTheDestinationIsNotWritten() throws Exception {
    File base = base();
    UnArchiver unarchiver = (UnArchiver) lookup(UnArchiver.ROLE, "zip");
    unarchiver.setSourceFile(zip(base, new String[] { "good.txt", "../../evil.txt" }));
    try {
      unarchiver.extract("", new File(base, "a/out"));
    }
    catch (Exception expected) {
      // refusing the archive is fine; writing outside is not
    }
    assertFalse("PATH_TRAVERSAL_REGRESSION", new File(base, "evil.txt").exists());
  }
}
