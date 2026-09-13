import * as assert from "assert";
import { ScanController } from "./scanController";

const inWorkspace = (uri: string): boolean => uri.startsWith("file:///project/");
const file = "file:///project/app.py";

{
  const scans = new ScanController();
  const obsolete = scans.startDocScan(file);
  scans.cancelDocScan(file);
  const latest = scans.startDocScan(file);
  scans.finishDocScan(file, obsolete);
  assert.ok(obsolete.signal.aborted);
  assert.ok(!scans.isDocCurrent(file, obsolete));
  assert.ok(scans.isDocCurrent(file, latest), "a cancelled request's finally cannot retire its replacement");
  assert.ok(scans.running, "stale completion must not hide current scan progress");
  scans.finishDocScan(file, latest);
  assert.ok(!scans.running);
}

{
  const scans = new ScanController();
  const workspace = scans.startWsScan(inWorkspace);
  const newerDocument = scans.startDocScan(file);
  scans.finishDocScan(file, newerDocument);
  assert.ok(!scans.canPublishWorkspace(workspace, file), "first-ever document scan outranks an older workspace scan even after it finishes");
  assert.ok(scans.canPublishWorkspace(workspace, "file:///project/unchanged.py"));
  scans.cancelDocScan("file:///project/closed.py");
  assert.ok(!scans.canPublishWorkspace(workspace, "file:///project/closed.py"), "closing or editing a file blocks stale workspace diagnostics without requiring a document scan");
}

{
  const scans = new ScanController();
  const olderDocument = scans.startDocScan(file);
  const outside = scans.startDocScan("file:///other/project.py");
  const workspace = scans.startWsScan(inWorkspace);
  assert.ok(olderDocument.signal.aborted, "a newer workspace scan retires older overlapping document work");
  assert.ok(!scans.isDocCurrent(file, olderDocument));
  assert.ok(scans.isDocCurrent("file:///other/project.py", outside), "another workspace's document remains independent");
  assert.ok(!scans.canPublishWorkspace(workspace, "file:///other/project.py"));
}

{
  const scans = new ScanController();
  const obsolete = scans.startWsScan(inWorkspace);
  scans.cancelAll();
  const latest = scans.startWsScan(inWorkspace);
  scans.finishWsScan(obsolete);
  assert.ok(!scans.isWsCurrent(obsolete));
  assert.ok(scans.isWsCurrent(latest), "configuration cancellation cannot recycle an old workspace request's identity");
  latest.abort();
  assert.ok(!scans.canPublishWorkspace(latest, file));
  assert.ok(!scans.running, "user cancellation stops progress even before asynchronous discovery finishes");
}

console.log("Scan ownership race regressions passed.");
