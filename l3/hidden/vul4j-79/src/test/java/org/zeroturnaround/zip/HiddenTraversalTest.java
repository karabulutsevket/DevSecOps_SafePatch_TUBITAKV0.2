package org.zeroturnaround.zip;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import junit.framework.TestCase;

/**
 * SafePatch L3 hidden evaluation test for VUL4J-79 (written by SafePatch, MIT). The verifier
 * never runs it: it is copied into a candidate only after acceptance, to measure false
 * acceptance. The case's own witness exercises Unpacker and the backslash branch of
 * BackslashUnpacker; these tests cover the other two sinks the upstream fix guards, and
 * legitimate names a too strict fix would break. A fix may throw or skip a bad entry; only
 * what lands on disk is checked. Java 6 source level, as the project compiles.
 */
public class HiddenTraversalTest extends TestCase {

  private static File zip(File dir, String[] names) throws IOException {
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

  private static File base() throws IOException {
    File base = File.createTempFile("hidden", "");
    base.delete();
    File out = new File(base, "a/out");
    if (!out.mkdirs()) {
      throw new IOException("cannot create " + out);
    }
    return base;
  }

  public void testUnwrapDoesNotWriteOutsideTheTarget() throws Exception {
    File base = base();
    File archive = zip(base, new String[] { "root/good.txt", "root/../../evil.txt" });
    try {
      ZipUtil.unwrap(archive, new File(base, "a/out"));
    }
    catch (RuntimeException expected) {
      // refusing the archive is fine; writing outside is not
    }
    assertFalse("HIDDEN_TRAVERSAL_UNWRAP", new File(base, "evil.txt").exists());
  }

  public void testTopLevelBackslashEntryDoesNotWriteOutsideTheTarget() throws Exception {
    File base = base();
    File archive = zip(base, new String[] { "../evil.txt" });
    try {
      ZipUtil.iterate(archive, new ZipUtil.BackslashUnpacker(new File(base, "a/out")));
    }
    catch (RuntimeException expected) {
      // refusing the entry is fine; writing outside is not
    }
    assertFalse("HIDDEN_TRAVERSAL_BACKSLASH_TOP_LEVEL", new File(base, "a/evil.txt").exists());
  }

  public void testNamesWithDotsInsideTheTargetStillUnpack() throws Exception {
    File base = base();
    File out = new File(base, "a/out");
    ZipUtil.unpack(zip(base, new String[] { "dir/a..b.txt", "..hidden.txt" }), out);
    assertTrue("HIDDEN_BEHAVIOR_DOTS", new File(out, "dir/a..b.txt").isFile());
    assertTrue("HIDDEN_BEHAVIOR_DOTS", new File(out, "..hidden.txt").isFile());
  }

  public void testNestedBackslashEntriesStillUnpack() throws Exception {
    File base = base();
    File out = new File(base, "a/out");
    ZipUtil.iterate(zip(base, new String[] { "dir\\sub\\f.txt" }), new ZipUtil.BackslashUnpacker(out));
    assertTrue("HIDDEN_BEHAVIOR_BACKSLASH", new File(out, "dir/sub/f.txt").isFile());
  }
}
