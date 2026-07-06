export type Origin =
  | 'system'
  | 'user-session'
  | 'tool-result'
  | 'untrusted-web'
  | 'untrusted-file'
  | 'memory'
  | 'model';

export type Trust = 'actionable' | 'inert';

export interface SpanMeta {
  source_uri?: string;
  ingested_at: string;
  parent_span?: string;
}

export interface Span {
  id: string;
  origin: Origin;
  trust: Trust;
  content: string;
  meta: SpanMeta;
  sig: string;
}

export type ModelActionType = 'text' | 'tool_call';

export interface ModelAction {
  type: ModelActionType;
  tool_name?: string;
  tool_args?: unknown;
}

export type ProviderRole = 'system' | 'user' | 'assistant';

export interface ProviderMessage {
  role: ProviderRole;
  content: string;
  metadata?: Record<string, unknown>;
}

export interface AssembledContext {
  messages: ProviderMessage[];
  canaryMap: Record<string, string>;
}

export interface AttributionResult {
  provenanceMatch: {
    inertOnly: boolean;
    actionablePresent: boolean;
    matchedSpanIds: string[];
  };
  canaryTriggered: boolean;
  sensitiveAction: boolean;
}

export type AegisVerdict = 'allow' | 'block' | 'flag';

export interface Receipt {
  request_id: string;
  ts: string;
  span_ids: string[];
  model_action: ModelAction;
  attribution: AttributionResult;
  verdict: AegisVerdict;
  reason: string;
  prev_receipt_hash: string;
  receipt_hash: string;
}

export class AegisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AegisError';
  }
}

export class AegisBlockedError extends AegisError {
  public readonly receiptId: string;

  constructor(message: string, receiptId: string) {
    super(message);
    this.name = 'AegisBlockedError';
    this.receiptId = receiptId;
  }
}

export class AegisSigningError extends AegisError {
  constructor(message: string) {
    super(message);
    this.name = 'AegisSigningError';
  }
}

export class AegisReceiptError extends AegisError {
  constructor(message: string) {
    super(message);
    this.name = 'AegisReceiptError';
  }
}

export class AegisAttributionError extends AegisError {
  constructor(message: string) {
    super(message);
    this.name = 'AegisAttributionError';
  }
}
