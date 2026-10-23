import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const ZERO_HASH = '0'.repeat(64);

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
}

function digest(value) {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}

export function createLedger(filePath) {
  const directory = path.dirname(filePath);

  async function readEvents() {
    try {
      const content = await readFile(filePath, 'utf8');
      return content.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw error;
    }
  }

  function snapshotOf(request) {
    if (!request) return null;
    return {
      status: request.status,
      decision: request.decision,
      actionHash: request.actionHash,
      approvedActionHash: request.approval ? request.approval.actionHash : null,
      policyVersion: request.policyVersion
    };
  }

  async function append({ type, request, actorId, details = {}, decisionPath = null }) {
    await mkdir(directory, { recursive: true });
    const events = await readEvents();
    const previous = events.length ? events[events.length - 1].hash : ZERO_HASH;
    const payload = {
      sequence: events.length + 1,
      occurredAt: new Date().toISOString(),
      type,
      requestId: request ? request.id : null,
      actorId: actorId || 'system',
      decisionPath: decisionPath || (request ? request.decisionPath : null),
      details,
      snapshot: snapshotOf(request),
      previousHash: previous
    };
    const event = { ...payload, hash: digest(payload) };
    await appendFile(filePath, JSON.stringify(event) + '\n', { encoding: 'utf8', flag: 'a' });
    return event;
  }

  async function verify(requests = []) {
    const events = await readEvents();
    let previous = ZERO_HASH;
    const latestSnapshots = new Map();

    for (let index = 0; index < events.length; index += 1) {
      const event = events[index];
      const payload = {
        sequence: event.sequence,
        occurredAt: event.occurredAt,
        type: event.type,
        requestId: event.requestId,
        actorId: event.actorId,
        decisionPath: event.decisionPath,
        details: event.details,
        snapshot: event.snapshot,
        previousHash: event.previousHash
      };
      if (event.sequence !== index + 1) return { valid: false, reason: 'Sequence mismatch at event ' + (index + 1), events };
      if (event.previousHash !== previous) return { valid: false, reason: 'Previous hash mismatch at event ' + (index + 1), events };
      const expected = digest(payload);
      if (event.hash !== expected) return { valid: false, reason: 'Event hash mismatch at event ' + (index + 1), events };
      if (event.requestId && event.snapshot) latestSnapshots.set(event.requestId, event.snapshot);
      previous = event.hash;
    }

    for (const request of requests) {
      const last = latestSnapshots.get(request.id);
      if (!last) return { valid: false, reason: 'No audit snapshot for request ' + request.id, events };
      const current = snapshotOf(request);
      if (canonicalize(last) !== canonicalize(current)) {
        return { valid: false, reason: 'Current request state does not match its latest audit snapshot: ' + request.id, events };
      }
    }

    return { valid: true, reason: 'Audit chain and request snapshots are valid.', events };
  }

  return { append, verify, readEvents };
}
