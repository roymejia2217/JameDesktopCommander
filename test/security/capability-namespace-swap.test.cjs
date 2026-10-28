'use strict';

// T011 direct security work: exercised post-authorization swaps against the
// native capability handle, not an isolated/mock policy-state simulation.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const crate = path.resolve(__dirname, '../../native/capability-probe');
const dll = path.join(crate, 'target', 'release', process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
assert.ok(fs.statSync(dll).isFile(), 'Native proof MUST compile on this OS');
const addon = path.join(crate, 'target', 'release', 'jdc-capability-probe.node');
fs.copyFileSync(dll, addon);
const { RootCapability } = require(addon);
assert.equal(typeof RootCapability, 'function');

function withIsolatedRoot(callback) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-t011-real-swap-'));
  const allowed = path.join(base, 'allowed');
  const outside = path.join(base, 'outside');
  fs.mkdirSync(allowed);
  fs.mkdirSync(outside);
  const sentinel = path.join(outside, 'sentinel.bin');
  const original = Buffer.from([0x00, 0xff, 0x81, 0x77, 0x10]);
  fs.writeFileSync(sentinel, original);
  const cap = new RootCapability(allowed);
  let error;
  try {
    callback({ base, allowed, outside, sentinel, original, cap });
  } catch (cause) {
    error = cause;
  } finally {
    try {
      cap.close();
      assert.deepEqual(fs.readFileSync(sentinel), original,
        'Outside sentinel bytes changed during a native capability test');
    } catch (verificationError) {
      error = error
        ? new AggregateError([error, verificationError], 'Operation and outside integrity failed')
        : verificationError;
    } finally {
      fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
  if (error) throw error;
}

test('handle-relative mkdir, rename and list permit valid in-root work and deny traversal', () => {
  withIsolatedRoot(({ cap, allowed }) => {
    cap.createDirectory('a/b');
    cap.writeBytes(path.join('a', 'b', 'from.bin'), Buffer.from([0xff, 0x00]), 'rewrite');
    cap.moveRelative(path.join('a', 'b', 'from.bin'), path.join('a', 'b', 'to.bin'));
    assert.deepEqual(cap.listDirectory('a/b'), ['to.bin']);
    assert.deepEqual(cap.readBytes('a/b/to.bin'), Buffer.from([0xff, 0x00]));
    assert.deepEqual(fs.readFileSync(path.join(allowed, 'a', 'b', 'to.bin')),
      Buffer.from([0xff, 0x00]));

    assert.throws(() => cap.createDirectory('../outside/escaped'));
    assert.throws(() => cap.moveRelative('a/b/to.bin', '../outside/escaped'));
    assert.throws(() => cap.moveRelative('../outside/sentinel.bin', 'a/b/escaped'));
    assert.throws(() => cap.listDirectory('../outside'));
    assert.equal(fs.existsSync(path.join(allowed, 'a', 'b', 'to.bin')), true);
  });
});

test('real intermediate directory swap after pathname checkpoint cannot escape capability', () => {
  withIsolatedRoot(({ cap, allowed, outside, sentinel, original }) => {
    const gate = path.join(allowed, 'gate');
    const displaced = path.join(allowed, 'displaced-gate');
    const child = path.join(gate, 'inside.bin');
    const nativeFrom = path.join(allowed, 'safe-source.bin');
    fs.mkdirSync(gate);
    fs.writeFileSync(child, Buffer.from('internal'));
    fs.writeFileSync(nativeFrom, Buffer.from('source'));

    // Demonstrate that a pathname authorization checkpoint succeeded BEFORE
    // the namespace change. There is deliberately no vulnerable production
    // handler call in this fixture; only the native cap-std operations execute.
    assert.equal(fs.realpathSync(gate), path.join(fs.realpathSync(allowed), 'gate'));
    assert.equal(fs.readFileSync(child, 'utf8'), 'internal');

    fs.renameSync(gate, displaced);
    let swapInstalled = false;
    try {
      fs.symlinkSync(outside, gate, process.platform === 'win32' ? 'junction' : 'dir');
      swapInstalled = true;
      // A test in which the swap was blocked must FAIL, not count as proof.
      assert.ok(fs.lstatSync(gate).isSymbolicLink(), 'Namespace swap was not installed');
      assert.equal(fs.realpathSync(gate), fs.realpathSync(outside), 'Attacker-controlled path not reached');
      assert.deepEqual(fs.readFileSync(path.join(gate, 'sentinel.bin')), original);

      assert.throws(() => cap.writeBytes('gate/sentinel.bin',
        Buffer.from('outside write'), 'rewrite'));
      assert.throws(() => cap.readBytes('gate/sentinel.bin'));
      assert.throws(() => cap.statRelative('gate/sentinel.bin'));
      assert.throws(() => cap.removeFileRelative('gate/sentinel.bin'));
      assert.throws(() => cap.removeEmptyDirectoryRelative('gate'));
      assert.throws(() => cap.createDirectory('gate/created-outside'));
      assert.throws(() => cap.listDirectory('gate'));
      assert.throws(() => cap.moveRelative('safe-source.bin', 'gate/moved-outside.bin'));
      assert.throws(() => cap.moveRelative('gate/sentinel.bin', 'stolen.bin'));

      assert.deepEqual(fs.readFileSync(sentinel), original);
      assert.equal(fs.existsSync(path.join(outside, 'created-outside')), false);
      assert.equal(fs.existsSync(path.join(outside, 'moved-outside.bin')), false);
      assert.deepEqual(fs.readFileSync(nativeFrom), Buffer.from('source'));
      assert.equal(fs.existsSync(path.join(allowed, 'stolen.bin')), false);
    } finally {
      if (swapInstalled) fs.unlinkSync(gate);
      fs.renameSync(displaced, gate);
    }

    // In-root operations still work immediately after the namespace recovers.
    cap.createDirectory('gate/recovered');
    cap.writeBytes('gate/recovered/inside.bin', Buffer.from([0x11, 0x22]), 'rewrite');
    assert.deepEqual(cap.readBytes('gate/recovered/inside.bin'), Buffer.from([0x11, 0x22]));
  });
});

// Unlike a symlink, a hard link points to the same file object. Path-relative
// resolution alone cannot tell whether another name exists outside the root.
// These adversarial tests are intentionally strict: restricted-mode reads and
// modifications must deny aliases instead of leaking/changing outside bytes.
function installCrossRootHardLink(allowed, sentinel, original) {
  const relative = 'linked-outside-sentinel.bin';
  const alias = path.join(allowed, relative);
  fs.linkSync(sentinel, alias);
  const sourceInfo = fs.statSync(sentinel);
  const aliasInfo = fs.statSync(alias);
  // A runner unable to install and verify the attack must fail this test.
  assert.ok(sourceInfo.nlink >= 2, 'Hard-link alias setup did not increase link count');
  assert.equal(sourceInfo.dev, aliasInfo.dev, 'Hard-link alias must share a device');
  assert.equal(sourceInfo.ino, aliasInfo.ino, 'Hard-link alias must share file identity');
  assert.deepEqual(fs.readFileSync(alias), original, 'Hard-link alias was not installed');
  return relative;
}

test('native restricted read must reject a cross-root hard-link alias', () => {
  withIsolatedRoot(({ cap, allowed, sentinel, original }) => {
    const relative = installCrossRootHardLink(allowed, sentinel, original);
    assert.throws(() => cap.readBytes(relative),
      'A root-relative hard-link alias must not reveal outside file bytes');
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});

test('native restricted rewrite must not change outside bytes via a hard-link alias', () => {
  withIsolatedRoot(({ cap, allowed, sentinel, original }) => {
    const relative = installCrossRootHardLink(allowed, sentinel, original);
    assert.throws(() => cap.writeBytes(relative, Buffer.from([0x1a, 0x2b]), 'rewrite'),
      'A root-relative hard-link alias must not rewrite an outside file');
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});

test('native restricted append must not change outside bytes via a hard-link alias', () => {
  withIsolatedRoot(({ cap, allowed, sentinel, original }) => {
    const relative = installCrossRootHardLink(allowed, sentinel, original);
    assert.throws(() => cap.writeBytes(relative, Buffer.from([0x3c, 0x4d]), 'append'),
      'A root-relative hard-link alias must not append to an outside file');
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});

test('text read, text append and text rewrite reject a real cross-root alias', () => {
  withIsolatedRoot(({ cap, allowed, outside }) => {
    const outsideText = path.join(outside, 'outside-note.txt');
    fs.writeFileSync(outsideText, 'OUTSIDE-TEXT-ORIGINAL');
    const insideAlias = path.join(allowed, 'alias-note.txt');
    fs.linkSync(outsideText, insideAlias);
    assert.equal(fs.statSync(insideAlias).ino, fs.statSync(outsideText).ino);
    assert.ok(fs.statSync(outsideText).nlink >= 2);
    assert.throws(() => cap.readText('alias-note.txt'), /shared or nonregular object/i);
    assert.throws(() => cap.appendText('alias-note.txt', '-APPENDED'),
      /shared or nonregular object/i);
    assert.throws(() => cap.writeText('alias-note.txt', 'REWRITTEN'),
      /shared or nonregular object/i);
    assert.equal(fs.readFileSync(outsideText, 'utf8'), 'OUTSIDE-TEXT-ORIGINAL');
    assert.equal(fs.readFileSync(insideAlias, 'utf8'), 'OUTSIDE-TEXT-ORIGINAL');
  });
});

test('native restricted stat denies outside hard-link object metadata', () => {
  withIsolatedRoot(({ cap, allowed, sentinel, original }) => {
    const relative = installCrossRootHardLink(allowed, sentinel, original);
    assert.throws(() => cap.statRelative(relative), /shared or nonregular object/i,
      'A cross-root hard-link alias must not disclose outside object metadata');
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});

test('native restricted stat preserves valid single-link file and directory metadata', () => {
  withIsolatedRoot(({ cap, allowed }) => {
    fs.writeFileSync(path.join(allowed, 'legitimate.bin'), Buffer.from([1, 2, 3, 4]));
    fs.mkdirSync(path.join(allowed, 'legitimate-dir'));
    assert.deepEqual(cap.statRelative('legitimate.bin'), {
      kind: 'file', sizeBytes: '4',
    });
    const directory = cap.statRelative('legitimate-dir');
    assert.equal(directory.kind, 'directory');
    assert.match(directory.sizeBytes, /^\d+$/);
  });
});

test('final-component replacement with a hard link after an in-root checkpoint is denied', () => {
  withIsolatedRoot(({ cap, allowed, sentinel, original }) => {
    const name = 'linked-outside-sentinel.bin';
    const legitimate = path.join(allowed, name);
    const benign = Buffer.from([0x21, 0x22]);
    fs.writeFileSync(legitimate, benign);
    // Confirm legitimate in-root access before the attacker-controlled change.
    assert.deepEqual(cap.readBytes(name), benign);

    // Deterministic sequential interleaving: replace the final filename
    // after the checkpoint, before a native destructive write.
    fs.unlinkSync(legitimate);
    assert.equal(installCrossRootHardLink(allowed, sentinel, original), name);
    assert.throws(() => cap.writeBytes(name, Buffer.from([0xa0, 0xb1]), 'rewrite'),
      'Replacing an authorized final name with a hard link must not affect outside bytes');
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});

test('closed handle fails for all added directory operations', () => {
  withIsolatedRoot(({ cap }) => {
    cap.close();
    assert.throws(() => cap.createDirectory('nope'), /closed/i);
    assert.throws(() => cap.moveRelative('from', 'to'), /closed/i);
    assert.throws(() => cap.listDirectory('.'), /closed/i);
    assert.throws(() => cap.statRelative('.'), /closed/i);
    assert.throws(() => cap.removeFileRelative('nope'), /closed/i);
    assert.throws(() => cap.removeEmptyDirectoryRelative('nope'), /closed/i);
  });
});

test('native atomic byte rewrite denies a known multi-link object, preserving both names', () => {
  withIsolatedRoot(({ cap, allowed, sentinel, original }) => {
    const relative = installCrossRootHardLink(allowed, sentinel, original);
    const authorizedName = path.join(allowed, relative);
    // Cross-root aliases are never approved for restricted operations.
    // Independent inode replacement is insufficient to prove their origin.
    assert.throws(() => cap.writeBytes(relative, Buffer.from([0x61, 0x62, 0x63]), 'rewrite'),
      /shared or nonregular object/i);
    assert.deepEqual(fs.readFileSync(sentinel), original);
    assert.deepEqual(fs.readFileSync(authorizedName), original);
    assert.equal(fs.statSync(sentinel).ino, fs.statSync(authorizedName).ino);
  });
});

test('native atomic text rewrite also denies a known multi-link object', () => {
  withIsolatedRoot(({ cap, allowed, sentinel, original }) => {
    const relative = installCrossRootHardLink(allowed, sentinel, original);
    const authorizedName = path.join(allowed, relative);
    assert.throws(() => cap.writeText(relative, 'ALLOWED-REPLACEMENT'),
      /shared or nonregular object/i);
    assert.deepEqual(fs.readFileSync(sentinel), original);
    assert.deepEqual(fs.readFileSync(authorizedName), original);
    assert.equal(fs.statSync(sentinel).ino, fs.statSync(authorizedName).ino);
  });
});

test('single-link reads, appends and atomic rewrites remain usable', () => {
  withIsolatedRoot(({ cap, allowed }) => {
    const name = 'sole-owner.txt';
    fs.writeFileSync(path.join(allowed, name), 'initial');
    assert.equal(fs.statSync(path.join(allowed, name)).nlink, 1);
    assert.equal(cap.readText(name), 'initial');
    cap.appendText(name, '-append');
    assert.equal(cap.readText(name), 'initial-append');
    cap.writeText(name, 'fresh');
    assert.equal(cap.readText(name), 'fresh');
    cap.writeBytes(name, Buffer.from([0x01, 0x02]), 'append');
    assert.deepEqual(cap.readBytes(name), Buffer.from([0x66, 0x72, 0x65, 0x73, 0x68, 0x01, 0x02]));
    cap.writeBytes(name, Buffer.from([0x00, 0xff]), 'rewrite');
    assert.deepEqual(fs.readFileSync(path.join(allowed, name)), Buffer.from([0x00, 0xff]));
    cap.appendText('new-sole-owner.txt', 'created');
    assert.equal(cap.readText('new-sole-owner.txt'), 'created');
    assert.equal(fs.statSync(path.join(allowed, 'new-sole-owner.txt')).nlink, 1);
  });
});

test('atomic rewrite is repeatable and failed publication leaves no temporary file', () => {
  withIsolatedRoot(({ cap, allowed }) => {
    cap.createDirectory('nested');
    cap.writeText('nested/repeat.txt', 'first');
    cap.writeText('nested/repeat.txt', 'second');
    cap.writeBytes('nested/repeat.txt', Buffer.from([0x00, 0xfe]), 'rewrite');
    assert.deepEqual(fs.readFileSync(path.join(allowed, 'nested', 'repeat.txt')),
      Buffer.from([0x00, 0xfe]));
    assert.deepEqual(fs.readdirSync(path.join(allowed, 'nested')), ['repeat.txt']);

    cap.createDirectory('nested/target-directory');
    assert.throws(() => cap.writeText('nested/target-directory', 'should fail'));
    assert.deepEqual(fs.readdirSync(path.join(allowed, 'nested')).sort(),
      ['repeat.txt', 'target-directory']);
    assert.ok(fs.statSync(path.join(allowed, 'nested', 'target-directory')).isDirectory());
  });
});

test('native atomic rewrite must not bypass a protected read-only existing target', () => {
  withIsolatedRoot(({ cap, allowed }) => {
    const existing = path.join(allowed, 'read-only-target.bin');
    const original = Buffer.from('PRESERVE-PROTECTED-BYTES');
    fs.writeFileSync(existing, original);
    fs.chmodSync(existing, 0o444);
    try {
      assert.throws(() => cap.writeBytes('read-only-target.bin',
        Buffer.from('FORBIDDEN-REPLACE'), 'rewrite'),
      'A protected existing target must not be silently replaced');
      assert.deepEqual(fs.readFileSync(existing), original);
    } finally {
      fs.chmodSync(existing, 0o666);
    }
  });
});

test('native atomic rewrite must respect explicit Windows NTFS write-data denial',
  { skip: process.platform !== 'win32' }, () => {
    const { spawnSync } = require('node:child_process');
    function command(executable, args) {
      const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 8000,
        windowsHide: true });
      assert.equal(result.error, undefined,
        'Windows ACL command failed to start: ' + executable);
      assert.equal(result.status, 0, (result.stderr || result.stdout || '').trim());
      return result.stdout.trim();
    }
    const sid = command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value']);
    assert.match(sid, /^S-1-5-\d+(?:-\d+)+$/, 'Fixture requires current Windows SID');
    withIsolatedRoot(({ cap, allowed }) => {
      const target = path.join(allowed, 'deny-write-data.txt');
      fs.writeFileSync(target, Buffer.from('RETAIN-NTFS-PROTECTED-CONTENT'));
      try {
        command('icacls.exe', [target, '/deny', '*' + sid + ':(WD)']);
        assert.throws(() => fs.openSync(target, 'r+'), /EACCES|EPERM/,
          'Fixture must independently prove write-data denial at the OS boundary');
        assert.throws(() => cap.writeText('deny-write-data.txt', 'NOT-AUTHORIZED'),
          'Capability rewrite must not bypass an explicit target write-data denial');
        assert.equal(fs.readFileSync(target, 'utf8'), 'RETAIN-NTFS-PROTECTED-CONTENT');
      } finally {
        // Only remove an ACL added to our disposable fixture, never a user file.
        command('icacls.exe', [target, '/remove:d', '*' + sid]);
      }
    });
  });

test('native atomic rewrite preserves explicit target NTFS DACL protections',
  { skip: process.platform !== 'win32' }, () => {
    const { spawnSync } = require('node:child_process');
    function acl(args) {
      const result = spawnSync('icacls.exe', args,
        { encoding: 'utf8', timeout: 8000, windowsHide: true });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, (result.stderr || result.stdout || '').trim());
    }
    withIsolatedRoot(({ cap, base, allowed }) => {
      const target = path.join(allowed, 'explicit-dacl-target.txt');
      const before = path.join(base, 'dacl-before.txt');
      const after = path.join(base, 'dacl-after.txt');
      fs.writeFileSync(target, 'BEFORE');
      // ANONYMOUS LOGON is not this user. A denied READ_DATA ACE on the
      // existing object must not silently disappear on authorized rewrite.
      acl([target, '/deny', '*S-1-5-7:(RD)']);
      acl([target, '/save', before]);
      cap.writeText('explicit-dacl-target.txt', 'AFTER');
      acl([target, '/save', after]);
      assert.deepEqual(fs.readFileSync(after), fs.readFileSync(before),
        'atomic replacement must preserve explicit NTFS target DACL');
    });
  });

test('native atomic rewrite preserves protected NTFS DACL inheritance flags',
  { skip: process.platform !== 'win32' }, () => {
    const { spawnSync } = require('node:child_process');
    function acl(args) {
      const result = spawnSync('icacls.exe', args,
        { encoding: 'utf8', timeout: 8000, windowsHide: true });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, (result.stderr || result.stdout || '').trim());
    }
    withIsolatedRoot(({ cap, base, allowed }) => {
      const target = path.join(allowed, 'protected-inheritance.txt');
      const before = path.join(base, 'protected-acl-before.txt');
      const after = path.join(base, 'protected-acl-after.txt');
      fs.writeFileSync(target, 'BEFORE');
      // Convert inherited ACEs to explicit and protect the resulting DACL.
      acl([target, '/inheritance:d']);
      acl([target, '/save', before]);
      cap.writeText('protected-inheritance.txt', 'AFTER');
      acl([target, '/save', after]);
      assert.deepEqual(fs.readFileSync(after), fs.readFileSync(before),
        'replacement must preserve protected DACL inheritance configuration');
    });
  });

test('native atomic rewrite preserves existing NTFS mandatory integrity label',
  { skip: process.platform !== 'win32' }, () => {
    const { spawnSync } = require('node:child_process');
    const acl = (args) => {
      const proc = spawnSync('icacls.exe', args,
        { encoding: 'utf8', timeout: 8000, windowsHide: true });
      assert.equal(proc.error, undefined);
      assert.equal(proc.status, 0, (proc.stderr || proc.stdout || '').trim());
      return proc.stdout;
    };
    withIsolatedRoot(({ cap, base, allowed }) => {
      const target = path.join(allowed, 'low-integrity-target.txt');
      const before = path.join(base, 'integrity-before.txt');
      const after = path.join(base, 'integrity-after.txt');
      fs.writeFileSync(target, 'ORIGINAL-LOW-INTEGRITY');
      acl([target, '/setintegritylevel', 'L']);
      acl([target, '/save', before]);
      assert.match(acl([target]), /Mandatory Label|Mandatory Label\\Low Mandatory Level|Etiqueta obligatoria|S-1-16-4096|Low Mandatory Level/i,
        'Fixture must really install a low mandatory integrity label');
      cap.writeText('low-integrity-target.txt', 'AUTHORIZED-NEW-CONTENT');
      acl([target, '/save', after]);
      assert.deepEqual(fs.readFileSync(after), fs.readFileSync(before),
        'atomic replacement must preserve mandatory integrity level, not just DACL');
      assert.equal(fs.readFileSync(target, 'utf8'), 'AUTHORIZED-NEW-CONTENT');
    });
  });
