import { createHash } from 'node:crypto';

export const POLICY_VERSION = 'actiongate-policy-1.0.0';

export const AGENTS = Object.freeze({
  'crm-cleanup': Object.freeze(['delete_records', 'update_account']),
  'support-agent': Object.freeze(['send_message', 'update_account']),
  'billing-agent': Object.freeze(['issue_refund']),
  'marketing-agent': Object.freeze(['send_message'])
});

const ALLOWED_ACCOUNT_FIELDS = new Set(['displayName', 'phone', 'contactEmail', 'timezone']);
const SUPPORTED_ACTIONS = new Set(['delete_records', 'send_message', 'update_account', 'issue_refund']);

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
}

export function hashAction(action) {
  return createHash('sha256').update(canonicalize(action), 'utf8').digest('hex');
}

export function normalizeAdvisory(advisory) {
  if (!advisory || advisory.status === 'unavailable') {
    return { usable: false, source: 'unavailable', reason: 'AI advisory unavailable; policy-only path used.' };
  }

  if (advisory.status !== 'available' || !advisory.output || typeof advisory.output !== 'object') {
    return { usable: false, source: 'unusable', reason: 'AI advisory output was unusable; policy-only path used.' };
  }

  const output = advisory.output;
  const validRisk = ['low', 'medium', 'high'].includes(output.risk);
  const validIntent = typeof output.intent === 'string' && output.intent.trim().length > 0 && output.intent.length <= 160;
  const validSummary = typeof output.summary === 'string' && output.summary.trim().length > 0 && output.summary.length <= 240;

  if (!validRisk || !validIntent || !validSummary) {
    return { usable: false, source: 'unusable', reason: 'AI advisory output failed schema validation; policy-only path used.' };
  }

  return {
    usable: true,
    source: 'advisory+policy',
    risk: output.risk,
    intent: output.intent.trim(),
    summary: output.summary.trim()
  };
}

/**
 * Explicit policy always decides. A valid advisory can only raise an otherwise
 * allowed action to human review; it can never grant permission or clear a hold.
 */
export function evaluateAction(action, advisory) {
  const reasons = [];
  const add = (decision, code, message) => {
    reasons.push({ code, message });
    if (decision === 'blocked' || (decision === 'held' && result.decision === 'allowed')) {
      result.decision = decision;
    }
  };
  const result = { decision: 'allowed' };

  if (!action || typeof action !== 'object') {
    return {
      decision: 'blocked',
      policyDecision: 'blocked',
      reasonCodes: ['INVALID_ACTION'],
      reasons: [{ code: 'INVALID_ACTION', message: 'Action proposal must be a JSON object.' }],
      decisionPath: 'policy_only:invalid_input',
      advisory: normalizeAdvisory(null)
    };
  }

  const agentId = typeof action.agentId === 'string' ? action.agentId : '';
  const type = typeof action.type === 'string' ? action.type : '';
  const agentActions = AGENTS[agentId];

  if (!agentId || !agentActions) {
    add('blocked', 'UNKNOWN_AGENT', 'Agent is not registered. Unknown agents are denied by default.');
  }
  if (!SUPPORTED_ACTIONS.has(type)) {
    add('blocked', 'UNKNOWN_ACTION', 'Action type is not recognized and is denied by default.');
  }
  if (agentActions && SUPPORTED_ACTIONS.has(type) && !agentActions.includes(type)) {
    add('blocked', 'AGENT_PERMISSION', 'This agent is not permitted to use this action type.');
  }

  if (!action.requestedBy || typeof action.requestedBy !== 'string') {
    add('blocked', 'MISSING_REQUESTER', 'A verified requester identity is required.');
  }
  if (!action.description || typeof action.description !== 'string' || action.description.length > 1000) {
    add('blocked', 'INVALID_DESCRIPTION', 'A short action description is required.');
  }
  if (!action.target || typeof action.target !== 'string' || action.target.length > 240) {
    add('blocked', 'INVALID_TARGET', 'A target is required and must be at most 240 characters.');
  }
  if (typeof action.reversible !== 'boolean') {
    add('blocked', 'REVERSIBILITY_REQUIRED', 'Reversibility must be stated explicitly.');
  }
  if (!action.arguments || typeof action.arguments !== 'object' || Array.isArray(action.arguments)) {
    add('blocked', 'INVALID_ARGUMENTS', 'Action arguments must be a JSON object.');
  }

  const args = action.arguments && typeof action.arguments === 'object' ? action.arguments : {};

  if (SUPPORTED_ACTIONS.has(type) && agentActions && agentActions.includes(type)) {
    if (type === 'delete_records') {
      if (!Number.isSafeInteger(args.recordCount) || args.recordCount < 1) {
        add('blocked', 'INVALID_RECORD_COUNT', 'Record count must be a positive whole number.');
      } else if (args.recordCount > 250) {
        add('blocked', 'DELETE_LIMIT_EXCEEDED', 'This request exceeds the hard limit of 250 records.');
      } else if (args.recordCount > 10) {
        add('held', 'BULK_DELETE_REVIEW', 'Deleting more than 10 records requires human approval.');
      }
      if (action.reversible === false) {
        add('held', 'IRREVERSIBLE_ACTION', 'An irreversible deletion requires human approval.');
      }
    }

    if (type === 'send_message') {
      if (!Number.isSafeInteger(args.recipientCount) || args.recipientCount < 1) {
        add('blocked', 'INVALID_RECIPIENT_COUNT', 'Recipient count must be a positive whole number.');
      } else if (args.recipientCount > 5000) {
        add('blocked', 'RECIPIENT_LIMIT_EXCEEDED', 'This request exceeds the hard limit of 5,000 recipients.');
      } else if (args.recipientCount > 20) {
        add('held', 'BULK_MESSAGE_REVIEW', 'Sending to more than 20 recipients requires human approval.');
      }
      if (args.external === true) {
        add('held', 'EXTERNAL_MESSAGE_REVIEW', 'External messages require human approval.');
      } else if (args.external !== false) {
        add('blocked', 'RECIPIENT_SCOPE_REQUIRED', 'Recipient scope must be explicitly marked external or internal.');
      }
      if (action.reversible === false) {
        add('held', 'IRREVERSIBLE_ACTION', 'A sent message cannot be recalled and requires human approval.');
      }
    }

    if (type === 'update_account') {
      if (!Array.isArray(args.fields) || args.fields.length < 1 || args.fields.some((field) => typeof field !== 'string')) {
        add('blocked', 'INVALID_ACCOUNT_FIELDS', 'At least one account field must be specified.');
      } else {
        const unknownFields = args.fields.filter((field) => !ALLOWED_ACCOUNT_FIELDS.has(field));
        if (unknownFields.length > 0) {
          add('blocked', 'FIELD_NOT_PERMITTED', 'One or more requested account fields are outside the permitted field list.');
        }
      }
      if (action.reversible === false) {
        add('held', 'IRREVERSIBLE_ACTION', 'An irreversible account change requires human approval.');
      }
    }

    if (type === 'issue_refund') {
      if (!Number.isSafeInteger(args.amountMinor) || args.amountMinor < 1) {
        add('blocked', 'INVALID_REFUND_AMOUNT', 'Refund amount must be a positive integer in minor currency units.');
      } else if (args.amountMinor > 500000) {
        add('blocked', 'REFUND_LIMIT_EXCEEDED', 'This refund exceeds the hard limit of 5,000.00 USD.');
      } else if (args.amountMinor > 50000) {
        add('held', 'HIGH_VALUE_REFUND_REVIEW', 'Refunds above 500.00 USD require human approval.');
      }
      if (action.reversible === false) {
        add('held', 'IRREVERSIBLE_ACTION', 'An irreversible refund requires human approval.');
      }
    }
  }

  const normalizedAdvisory = normalizeAdvisory(advisory);
  if (normalizedAdvisory.usable && normalizedAdvisory.risk === 'high' && result.decision === 'allowed') {
    add('held', 'ADVISORY_ESCALATION', 'The advisory flagged high risk, so policy requires human review.');
  }

  const decisionPath = normalizedAdvisory.usable
    ? 'advisory+policy'
    : 'policy_only:' + normalizedAdvisory.source;

  return {
    decision: result.decision,
    policyDecision: reasons.some((reason) => reason.code === 'ADVISORY_ESCALATION')
      ? 'allowed'
      : result.decision,
    reasonCodes: [...new Set(reasons.map((reason) => reason.code))],
    reasons,
    decisionPath,
    advisory: normalizedAdvisory
  };
}

export function createDemoAdvisory(action, mode = 'unavailable') {
  if (mode === 'unavailable') return { status: 'unavailable' };
  if (mode === 'unusable') return { status: 'available', output: { risk: 'severe', intent: 42 } };

  const text = ((action.description || '') + ' ' + (action.untrustedContext || '')).toLowerCase();
  const highRiskLanguage = ['ignore previous instructions', 'bypass', 'disable safeguards', 'send credentials']
    .some((phrase) => text.includes(phrase));
  const risk = highRiskLanguage ? 'high' : 'low';
  return {
    status: 'available',
    output: {
      risk,
      intent: action.description || 'Unspecified action',
      summary: highRiskLanguage
        ? 'The advisory found language that may be attempting to redirect the agent.'
        : 'The advisory found no high-risk language in the request context.'
    }
  };
}
