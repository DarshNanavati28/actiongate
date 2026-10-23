import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFile, rename, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AGENTS,
  POLICY_VERSION,
  createDemoAdvisory,
  evaluateAction,
  hashAction
} from './policy.js';
import { createLedger } from './ledger.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.resolve(process.env.ACTIONGATE_DATA_DIR || path.join(ROOT, 'data'));
const STATE_PATH = path.join(DATA_DIR, 'state.json');
const LEDGER_PATH = path.join(DATA_DIR, 'audit.jsonl');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const ACTORS = new Set(['maya.chen', 'lena.ortiz', 'omar.singh']);
const ADVISORY_MODE = ['unavailable', 'unusable', 'simulated'].includes(process.env.ACTIONGATE_ADVISORY_MODE)
  ? process.env.ACTIONGATE_ADVISORY_MODE
  : 'unavailable';

const ledger = createLedger(LEDGER_PATH);
let state = { requests: [] };
let mutationQueue = Promise.resolve();

class HttpError extends Error {
  constructor(status, message, code = 'REQUEST_ERROR') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function withMutation(operation) {
  const next = mutationQueue.then(operation, operation);
  mutationQueue = next.catch(() => {});
  return next;
}

function sendJson(response, status, data) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  response.end(JSON.stringify(data));
}

function actorIdFrom(request) {
  const value = request.headers['x-actiongate-actor-id'];
  if (typeof value !== 'string' || !ACTORS.has(value)) {
    throw new HttpError(401, 'Choose a recognized demo identity.', 'IDENTITY_REQUIRED');
  }
  return value;
}

function readJson(request, limit = 65536) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new HttpError(413, 'Request body is too large.', 'BODY_TOO_LARGE'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (size === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'Request body must be valid JSON.', 'INVALID_JSON'));
      }
    });
    request.on('error', reject);
  });
}

function cloneJson(value) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return null;
  }
}

function normalizeAction(input, requestedBy) {
  const body = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const rawArgs = cloneJson(body.arguments);
  return {
    agentId: typeof body.agentId === 'string' ? body.agentId.slice(0, 120) : '',
    type: typeof body.type === 'string' ? body.type.slice(0, 120) : '',
    requestedBy,
    description: typeof body.description === 'string' ? body.description.slice(0, 1000) : '',
    target: typeof body.target === 'string' ? body.target.slice(0, 240) : '',
    reversible: typeof body.reversible === 'boolean' ? body.reversible : null,
    arguments: rawArgs && typeof rawArgs === 'object' && !Array.isArray(rawArgs) ? rawArgs : null,
    untrustedContext: typeof body.untrustedContext === 'string' ? body.untrustedContext.slice(0, 4000) : ''
  };
}

function requestSnapshot(request, action, evaluation, status, approval = null) {
  return {
    id: request.id,
    createdAt: request.createdAt,
    updatedAt: new Date().toISOString(),
    action,
    actionHash: hashAction(action),
    decision: evaluation.decision,
    policyDecision: evaluation.policyDecision,
    status,
    reasonCodes: evaluation.reasonCodes,
    reasons: evaluation.reasons,
    decisionPath: evaluation.decisionPath,
    advisory: evaluation.advisory,
    policyVersion: POLICY_VERSION,
    approval,
    execution: request.execution || null
  };
}

async function persistState() {
  await mkdir(DATA_DIR, { recursive: true });
  const tempPath = STATE_PATH + '.tmp';
  await writeFile(tempPath, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
  await rename(tempPath, STATE_PATH);
}

async function loadState() {
  await mkdir(DATA_DIR, { recursive: true });
  try {
    const parsed = JSON.parse(await readFile(STATE_PATH, 'utf8'));
    if (!parsed || !Array.isArray(parsed.requests)) throw new Error('state must contain a requests list');
    state = parsed;
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('ActionGate state is unreadable; refusing to start: ' + error.message);
    await persistState();
  }
}

async function ensureHealthy() {
  const result = await ledger.verify(state.requests);
  if (!result.valid) {
    throw new HttpError(503, 'The audit history failed integrity verification. Authorization is paused.', 'AUDIT_INTEGRITY_FAILURE');
  }
  return result;
}

function statusFor(decision) {
  return decision === 'allowed' ? 'allowed' : decision === 'blocked' ? 'blocked' : 'held';
}

async function recordEvent(type, request, actorId, details = {}, decisionPath = null) {
  await ledger.append({ type, request, actorId, details, decisionPath });
}

function findRequest(id) {
  return state.requests.find((item) => item.id === id);
}

function safeRequest(request) {
  return request;
}

async function createRequest(body, actorId) {
  const action = normalizeAction(body, actorId);
  const advisory = createDemoAdvisory(action, ADVISORY_MODE);
  const evaluation = evaluateAction(action, advisory);
  const request = requestSnapshot(
    { id: randomUUID(), createdAt: new Date().toISOString(), execution: null },
    action,
    evaluation,
    statusFor(evaluation.decision)
  );
  state.requests.unshift(request);
  await persistState();
  await recordEvent('ACTION_DECIDED', request, actorId, {
    decision: request.decision,
    reasonCodes: request.reasonCodes,
    actionHash: request.actionHash
  });
  return request;
}

async function approveRequest(request, actorId, body) {
  if (request.status !== 'held') {
    await recordEvent('APPROVAL_REFUSED_NOT_HELD', request, actorId, { currentStatus: request.status });
    return { status: 409, body: { error: 'Only a held request can receive approval.', code: 'APPROVAL_NOT_PENDING' } };
  }
  if (actorId === request.action.requestedBy) {
    await recordEvent('APPROVAL_REFUSED_SELF', request, actorId, { requesterId: request.action.requestedBy });
    return { status: 403, body: { error: 'Requesters cannot approve their own requests.', code: 'SELF_APPROVAL' } };
  }
  if (body.actionHash !== request.actionHash) {
    await recordEvent('APPROVAL_REFUSED_HASH_MISMATCH', request, actorId, {
      submittedHash: typeof body.actionHash === 'string' ? body.actionHash : null,
      currentHash: request.actionHash
    });
    return { status: 409, body: { error: 'Approval must name the current exact action hash.', code: 'ACTION_HASH_MISMATCH' } };
  }

  const approval = {
    approverId: actorId,
    approvedAt: new Date().toISOString(),
    actionHash: request.actionHash,
    policyVersion: POLICY_VERSION
  };
  request.approval = approval;
  request.status = 'approved';
  request.decision = 'allowed';
  request.updatedAt = new Date().toISOString();
  await persistState();
  await recordEvent('APPROVAL_GRANTED', request, actorId, {
    approvedActionHash: approval.actionHash,
    policyVersion: approval.policyVersion
  });
  return { status: 200, body: request };
}

async function reviseRequest(request, actorId, body) {
  if (actorId !== request.action.requestedBy) {
    await recordEvent('REVISION_REFUSED_NOT_REQUESTER', request, actorId, { requesterId: request.action.requestedBy });
    return { status: 403, body: { error: 'Only the requester can revise this demo action.', code: 'REQUESTER_REQUIRED' } };
  }
  if (request.status === 'executed' || request.status === 'blocked') {
    await recordEvent('REVISION_REFUSED_TERMINAL_STATE', request, actorId, { currentStatus: request.status });
    return { status: 409, body: { error: 'This request is already in a terminal state.', code: 'REVISION_NOT_ALLOWED' } };
  }

  const actionInput = body && body.proposal && typeof body.proposal === 'object' ? body.proposal : body;
  const action = normalizeAction(actionInput, request.action.requestedBy);
  const advisory = createDemoAdvisory(action, ADVISORY_MODE);
  const evaluation = evaluateAction(action, advisory);
  Object.assign(request, requestSnapshot(request, action, evaluation, statusFor(evaluation.decision), null));
  request.updatedAt = new Date().toISOString();
  await persistState();
  await recordEvent('ACTION_REVISED_AND_REAUTHORIZED', request, actorId, {
    decision: request.decision,
    reasonCodes: request.reasonCodes,
    actionHash: request.actionHash,
    previousActionHash: body.previousActionHash || null
  });
  return { status: 200, body: request };
}

async function blockRequest(request, actorId) {
  if (['executed', 'blocked'].includes(request.status)) {
    await recordEvent('BLOCK_REFUSED_TERMINAL_STATE', request, actorId, { currentStatus: request.status });
    return { status: 409, body: { error: 'This request is already in a terminal state.', code: 'BLOCK_NOT_ALLOWED' } };
  }
  request.status = 'blocked';
  request.decision = 'blocked';
  request.policyDecision = 'blocked';
  request.reasonCodes = [...new Set([...(request.reasonCodes || []), 'HUMAN_BLOCK'])];
  request.reasons = [...(request.reasons || []), { code: 'HUMAN_BLOCK', message: 'A reviewer blocked this request.' }];
  request.approval = null;
  request.updatedAt = new Date().toISOString();
  await persistState();
  await recordEvent('ACTION_BLOCKED_BY_REVIEWER', request, actorId, { actionHash: request.actionHash });
  return { status: 200, body: request };
}

async function executeRequest(request, actorId, body) {
  if (!['allowed', 'approved'].includes(request.status)) {
    await recordEvent('EXECUTION_REFUSED_STATE', request, actorId, {
      currentStatus: request.status,
      submittedHash: body.actionHash || null
    });
    return { status: 409, body: { error: 'Only an allowed or approved request can execute.', code: 'EXECUTION_NOT_AUTHORIZED' } };
  }
  if (body.actionHash !== request.actionHash) {
    await recordEvent('EXECUTION_REFUSED_HASH_MISMATCH', request, actorId, {
      submittedHash: typeof body.actionHash === 'string' ? body.actionHash : null,
      approvedActionHash: request.approval ? request.approval.actionHash : null,
      currentActionHash: request.actionHash
    });
    return { status: 409, body: { error: 'The submitted action does not match the authorized version.', code: 'ACTION_HASH_MISMATCH' } };
  }

  const advisory = createDemoAdvisory(request.action, ADVISORY_MODE);
  const evaluation = evaluateAction(request.action, advisory);
  if (request.policyVersion !== POLICY_VERSION || evaluation.decision === 'blocked') {
    Object.assign(request, requestSnapshot(request, request.action, evaluation, 'blocked', null));
    await persistState();
    await recordEvent('EXECUTION_REFUSED_POLICY', request, actorId, {
      reasonCodes: evaluation.reasonCodes,
      currentPolicyVersion: POLICY_VERSION
    });
    return { status: 403, body: { error: 'Current policy does not permit execution.', code: 'POLICY_REAUTHORIZATION_REQUIRED', request } };
  }

  const hasMatchingApproval = request.approval
    && request.approval.actionHash === request.actionHash
    && request.approval.policyVersion === POLICY_VERSION
    && request.approval.approverId !== request.action.requestedBy;
  if (evaluation.decision === 'held' && !hasMatchingApproval) {
    Object.assign(request, requestSnapshot(request, request.action, evaluation, 'held', null));
    await persistState();
    await recordEvent('EXECUTION_REFUSED_REAUTHORIZATION', request, actorId, {
      reasonCodes: evaluation.reasonCodes,
      currentActionHash: request.actionHash
    });
    return { status: 409, body: { error: 'This action must be authorized again before execution.', code: 'REAUTHORIZATION_REQUIRED', request } };
  }

  if (request.approval && request.approval.actionHash !== request.actionHash) {
    Object.assign(request, requestSnapshot(request, request.action, evaluation, 'held', null));
    await persistState();
    await recordEvent('EXECUTION_REFUSED_STALE_APPROVAL', request, actorId, {
      approvedActionHash: request.approval ? request.approval.actionHash : null,
      currentActionHash: request.actionHash
    });
    return { status: 409, body: { error: 'Approval is stale because the action changed.', code: 'REAUTHORIZATION_REQUIRED', request } };
  }

  request.status = 'executed';
  request.decision = 'allowed';
  request.updatedAt = new Date().toISOString();
  request.execution = {
    mode: 'simulated',
    executedAt: request.updatedAt,
    note: 'No external system was contacted.'
  };
  await persistState();
  await recordEvent('ACTION_EXECUTED_SIMULATED', request, actorId, {
    actionHash: request.actionHash,
    executionMode: 'simulated'
  });
  return { status: 200, body: request };
}

function jsonError(error) {
  if (error instanceof HttpError) return { status: error.status, body: { error: error.message, code: error.code } };
  console.error('ActionGate request failed:', error);
  return { status: 500, body: { error: 'ActionGate could not complete the request.', code: 'INTERNAL_ERROR' } };
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml'
};

async function serveStatic(urlPath, response) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    throw new HttpError(400, 'Invalid URL path.', 'INVALID_PATH');
  }
  const requested = decoded === '/' ? '/index.html' : decoded;
  const filePath = path.resolve(PUBLIC_DIR, '.' + requested);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(404, 'Not found.', 'NOT_FOUND');
  try {
    const file = await readFile(filePath);
    const type = MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    response.writeHead(200, {
      'content-type': type,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      'referrer-policy': 'no-referrer'
    });
    response.end(file);
  } catch (error) {
    if (error.code === 'ENOENT') throw new HttpError(404, 'Not found.', 'NOT_FOUND');
    throw error;
  }
}

async function handle(request, response) {
  const url = new URL(request.url, 'http://' + request.headers.host);
  const method = request.method || 'GET';

  if (url.pathname === '/api/status' && method === 'GET') {
    const integrity = await ledger.verify(state.requests);
    return sendJson(response, 200, {
      name: 'ActionGate',
      mode: 'local-server',
      execution: 'simulated',
      advisoryMode: ADVISORY_MODE,
      policyVersion: POLICY_VERSION,
      integrity: { valid: integrity.valid, reason: integrity.reason },
      requestCount: state.requests.length
    });
  }

  if (url.pathname === '/api/policies' && method === 'GET') {
    return sendJson(response, 200, {
      policyVersion: POLICY_VERSION,
      agents: AGENTS,
      rules: [
        { action: 'delete_records', autoLimit: 10, hardLimit: 250, approval: 'bulk or irreversible' },
        { action: 'send_message', autoLimit: 20, hardLimit: 5000, approval: 'external, bulk, or irreversible' },
        { action: 'update_account', allowedFields: ['displayName', 'phone', 'contactEmail', 'timezone'], approval: 'irreversible' },
        { action: 'issue_refund', autoLimitMinor: 50000, hardLimitMinor: 500000, approval: 'over 500.00 USD or irreversible' }
      ]
    });
  }

  if (url.pathname === '/api/actions' && method === 'GET') {
    return sendJson(response, 200, { requests: state.requests });
  }

  if (url.pathname === '/api/audit' && method === 'GET') {
    const integrity = await ledger.verify(state.requests);
    return sendJson(response, 200, { integrity: { valid: integrity.valid, reason: integrity.reason }, events: integrity.events });
  }

  if (url.pathname === '/api/audit/verify' && method === 'POST') {
    const integrity = await ledger.verify(state.requests);
    return sendJson(response, integrity.valid ? 200 : 409, {
      valid: integrity.valid,
      reason: integrity.reason,
      eventCount: integrity.events.length
    });
  }

  if (url.pathname === '/api/actions' && method === 'POST') {
    const actorId = actorIdFrom(request);
    const body = await readJson(request);
    const result = await withMutation(async () => {
      await ensureHealthy();
      return createRequest(body, actorId);
    });
    return sendJson(response, 201, result);
  }

  const match = url.pathname.match(/^\/api\/actions\/([0-9a-f-]+)\/(approve|revise|block|execute)$/i);
  if (match && method === 'POST') {
    const actorId = actorIdFrom(request);
    const body = await readJson(request);
    const result = await withMutation(async () => {
      await ensureHealthy();
      const item = findRequest(match[1]);
      if (!item) throw new HttpError(404, 'Action request not found.', 'REQUEST_NOT_FOUND');
      if (match[2] === 'approve') return approveRequest(item, actorId, body);
      if (match[2] === 'revise') return reviseRequest(item, actorId, body);
      if (match[2] === 'block') return blockRequest(item, actorId);
      return executeRequest(item, actorId, body);
    });
    return sendJson(response, result.status, result.body);
  }

  if (url.pathname.startsWith('/api/')) throw new HttpError(404, 'API endpoint not found.', 'NOT_FOUND');
  if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'Method not allowed.', 'METHOD_NOT_ALLOWED');
  return serveStatic(url.pathname, response);
}

async function start() {
  await loadState();
  const startupIntegrity = await ledger.verify(state.requests);
  if (!startupIntegrity.valid) {
    console.error('ActionGate started in read-only mode: ' + startupIntegrity.reason);
  }
  const server = createServer(async (request, response) => {
    try {
      await handle(request, response);
    } catch (error) {
      const result = jsonError(error);
      if (!response.headersSent) sendJson(response, result.status, result.body);
      else response.destroy();
    }
  });
  server.listen(PORT, HOST, () => {
    console.log('ActionGate listening at http://' + HOST + ':' + PORT);
    console.log('Demo advisory mode: ' + ADVISORY_MODE + '; execution mode: simulated');
  });
}

start().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
