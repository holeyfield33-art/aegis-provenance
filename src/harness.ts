import type { Receipt, Span, ModelAction, ProviderMessage } from './types.js';
import { wrapSpan, verifySpanIntegrity } from './ingest.js';
import { assembleContext } from './assembly.js';
import { decideAttribution } from './attribution.js';
import { createReceipt, GENESIS_HASH } from './receipt.js';
import { ReceiptStore } from './receipt-store.js';
import { getSigningKey, derivePublicKey } from './crypto/keys.js';
import { normalizeToolKey } from './tool-contracts.js';
import { AegisBlockedError, AegisReceiptError, AegisAttributionError, AegisVerificationError } from './types.js';

export interface ModelClientResponse {
  type: 'text' | 'tool_call';
  text?: string;
  tool_name?: string;
  tool_args?: unknown;
}

export interface ModelClient {
  call(messages: ProviderMessage[]): Promise<ModelClientResponse>;
}


export interface HarnessOptions {
  system: string;
  userMessage: string;
  retrievedSpans: Array<{ origin: Span['origin']; content: string; meta?: Partial<Span['meta']> }>;
  /** Already-signed spans (e.g. persisted or wire-transported). Verified before use like every other span. */
  signedSpans?: Span[];
  tools: Array<{ name: string; description: string }>;
  modelClient: ModelClient;
  receiptStore?: ReceiptStore;
}

export interface HarnessResult {
  response: ModelClientResponse;
  receipt: Receipt;
}

export async function runAegis(options: HarnessOptions): Promise<HarnessResult> {
  const spans: Span[] = [];

  try {
    spans.push(wrapSpan({ origin: 'system', content: options.system }));
    spans.push(wrapSpan({ origin: 'user-session', content: options.userMessage }));

    for (const retrieved of options.retrievedSpans) {
      spans.push(wrapSpan({ origin: retrieved.origin, content: retrieved.content, meta: retrieved.meta }));
    }
  } catch (cause) {
    throw new AegisReceiptError(`Failed during ingest: ${cause instanceof Error ? cause.message : String(cause)}`);
  }

  if (options.signedSpans) {
    spans.push(...options.signedSpans);
  }

  const publicKey = derivePublicKey(getSigningKey());
  for (const span of spans) {
    const integrity = verifySpanIntegrity(span, publicKey);
    if (!integrity.valid) {
      throw new AegisVerificationError(`Span verification failed, refusing to assemble context: ${integrity.reason}`);
    }
  }

  const assembled = assembleContext(spans);

  const modelResponse = await options.modelClient.call(assembled.messages);

  // Resolve the model's tool name to a registered tool. A real dispatcher is
  // lenient only to a case/spacing/punctuation variant of an EXPLICITLY
  // REGISTERED tool name (`SendEmail`/`send-email` -> a registered `send_email`).
  // It does NOT expand semantic aliases (`mail`, `send_http`, `post`): those
  // still fail closed as unregistered, so registering one tool never implicitly
  // authorizes model output under a different name. A caller that wants a tool
  // reachable under extra names registers those names explicitly. (Contract
  // CLASSIFICATION downstream is still alias-aware, so if a deployment does
  // register `send_http`, it is correctly enforced as a network egress tool.)
  const registeredByKey = new Map<string, string>();
  for (const tool of options.tools) {
    registeredByKey.set(normalizeToolKey(tool.name), tool.name);
  }

  let resolvedToolName = modelResponse.tool_name;
  if (modelResponse.type === 'tool_call') {
    if (!modelResponse.tool_name) {
      throw new AegisAttributionError('Model returned a tool_call response without a tool_name.');
    }
    const canonical = registeredByKey.get(normalizeToolKey(modelResponse.tool_name));
    if (!canonical) {
      throw new AegisAttributionError(`Model returned an unregistered tool_name: ${modelResponse.tool_name}`);
    }
    resolvedToolName = canonical;
  }

  const action: ModelAction = {
    type: modelResponse.type,
    tool_name: resolvedToolName,
    tool_args: modelResponse.tool_args
  };

  const attribution = decideAttribution(
    action.tool_name ?? '',
    action.tool_args,
    assembled.canaryMap,
    spans,
    undefined,
    modelResponse.text
  );
  const receiptData: Omit<Receipt, 'receipt_hash'> = {
    request_id: `req-${Date.now()}`,
    ts: new Date().toISOString(),
    span_ids: spans.map((span) => span.id),
    model_action: action,
    attribution: {
      provenanceMatch: attribution.attribution,
      canaryTriggered: attribution.canary.triggered,
      sensitiveAction: attribution.sensitiveAction
    },
    verdict: attribution.verdict,
    reason: attribution.reason,
    prev_receipt_hash: GENESIS_HASH
  };

  let receipt: Receipt;
  try {
    if (options.receiptStore) {
      receipt = await options.receiptStore.appendReceipt(receiptData);
    } else {
      receipt = createReceipt(receiptData);
    }
  } catch (cause) {
    throw new AegisReceiptError(`Receipt persistence failed: ${cause instanceof Error ? cause.message : String(cause)}`);
  }

  if (attribution.verdict === 'block') {
    throw new AegisBlockedError(attribution.reason, receipt.receipt_hash);
  }

  // Return the CANONICAL tool name that was actually enforced and signed into
  // the receipt, not the raw name the model emitted. Otherwise a caller could
  // execute a call whose name differs from what the immutable receipt attests
  // (e.g. `SendEmail` returned while `send_email` was enforced/receipted). For a
  // tool call, response.tool_name is guaranteed to equal
  // receipt.model_action.tool_name.
  const response: ModelClientResponse =
    modelResponse.type === 'tool_call' ? { ...modelResponse, tool_name: resolvedToolName } : modelResponse;

  return { response, receipt };
}
