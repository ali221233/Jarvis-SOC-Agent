// ============================================================
// Jarvis — Tier Enforcement Engine
// Every tool call passes through here. No exceptions.
// Tier 1: immediate. Tier 2: confirm. Tier 3: double-confirm + passphrase.
// ============================================================

const { v4: uuidv4 } = require('uuid');
const { logAction } = require('./logger');
const persona = require('./persona');

// Pending actions awaiting confirmation
const pendingActions = new Map();

function createPendingAction(toolName, tier, params, description, execute) {
  const actionId = uuidv4();
  const action = {
    id: actionId,
    toolName,
    tier,
    params,
    description,
    execute,
    confirmations: 0,
    requiredConfirmations: tier === 3 ? 2 : 1,
    passphraseVerified: false,
    createdAt: new Date().toISOString(),
    status: 'pending',
  };
  pendingActions.set(actionId, action);

  // Auto-expire after 5 minutes
  setTimeout(() => {
    if (pendingActions.has(actionId) && pendingActions.get(actionId).status === 'pending') {
      pendingActions.delete(actionId);
      logAction(`Pending action expired: ${toolName}`, tier, {
        tool: toolName,
        params,
        status: 'expired',
      });
    }
  }, 5 * 60 * 1000);

  return action;
}

async function enforce(toolName, tier, params, description, executeFn) {
  // Tier 1 — execute immediately
  if (tier === 1) {
    try {
      const result = await executeFn(params);
      logAction(`Executed ${toolName}`, 1, {
        tool: toolName,
        params,
        result: summarizeResult(result),
        status: 'completed',
      });
      return { status: 'completed', result };
    } catch (err) {
      logAction(`Failed ${toolName}: ${err.message}`, 1, {
        tool: toolName,
        params,
        status: 'error',
        result: err.message,
      });
      return { status: 'error', error: err.message };
    }
  }

  // Tier 2 & 3 — require confirmation
  const action = createPendingAction(toolName, tier, params, description, executeFn);
  const message = persona.tierConfirmationMessage(tier, description);

  logAction(`Awaiting confirmation for ${toolName} (Tier ${tier})`, tier, {
    tool: toolName,
    params,
    status: 'pending',
  });

  return {
    status: 'pending_confirmation',
    actionId: action.id,
    tier,
    message,
    requiredConfirmations: action.requiredConfirmations,
    passphraseRequired: tier === 3,
  };
}

async function confirm(actionId, passphraseVerified = false) {
  const action = pendingActions.get(actionId);
  if (!action) {
    return { status: 'error', error: 'Action not found or expired.' };
  }
  if (action.status !== 'pending') {
    return { status: 'error', error: `Action already ${action.status}.` };
  }

  action.confirmations += 1;

  if (passphraseVerified) {
    action.passphraseVerified = true;
  }

  // Check if all confirmations received
  if (action.confirmations < action.requiredConfirmations) {
    return {
      status: 'pending_confirmation',
      actionId,
      message: `Confirmation ${action.confirmations} of ${action.requiredConfirmations} received. Confirm again, ${persona.ADDRESS}.`,
      confirmationsRemaining: action.requiredConfirmations - action.confirmations,
      passphraseRequired: action.tier === 3 && !action.passphraseVerified,
    };
  }

  // Tier 3: require passphrase verification
  if (action.tier === 3 && !action.passphraseVerified) {
    return {
      status: 'pending_confirmation',
      actionId,
      message: persona.templates.passphraseRequired(),
      passphraseRequired: true,
    };
  }

  // All gates passed — execute
  try {
    action.status = 'executing';
    const result = await action.execute(action.params);
    action.status = 'completed';
    pendingActions.delete(actionId);

    logAction(`Confirmed and executed ${action.toolName} (Tier ${action.tier})`, action.tier, {
      tool: action.toolName,
      params: action.params,
      result: summarizeResult(result),
      status: 'completed',
    });

    return { status: 'completed', result };
  } catch (err) {
    action.status = 'error';
    pendingActions.delete(actionId);

    logAction(`Confirmed but failed ${action.toolName}: ${err.message}`, action.tier, {
      tool: action.toolName,
      params: action.params,
      status: 'error',
      result: err.message,
    });

    return { status: 'error', error: err.message };
  }
}

function getPendingActions() {
  return Array.from(pendingActions.values()).filter(a => a.status === 'pending');
}

function cancelAction(actionId) {
  const action = pendingActions.get(actionId);
  if (action) {
    action.status = 'cancelled';
    pendingActions.delete(actionId);
    logAction(`Cancelled ${action.toolName}`, action.tier, {
      tool: action.toolName,
      status: 'cancelled',
    });
    return { status: 'cancelled', message: `Cancelled ${action.toolName}.` };
  }
  return { status: 'error', error: 'Action not found.' };
}

function summarizeResult(result) {
  if (!result) return null;
  const str = JSON.stringify(result);
  return str.length > 500 ? str.substring(0, 500) + '...' : str;
}

module.exports = { enforce, confirm, getPendingActions, cancelAction };
