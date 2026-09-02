// Tool identity + egress-contract resolution for the enforcement layer.
//
// A real agent dispatcher is lenient: `SendEmail`, `send-email`, `mail`,
// `send_http`, `http_request` all route to the same underlying tool. Aegis must
// classify a call by the tool it would REACH, not by a fragile prefix guess —
// a `/^send_/` heuristic wrongly reads `send_http` as an email tool and never
// extracts its URL host, masking an unauthorized destination (a contract-
// confusion bypass).
//
// This module is the single, explicit source of that mapping for the
// enforcement side. It intentionally mirrors the alias set the independent
// differential tool oracle (src/testing/tool-oracle.ts) uses, so the two agree
// on which tool a name reaches — but it is a separate implementation (the
// oracle must not import Aegis code), which is corroboration, not circularity.

export type CanonicalTool =
  | 'send_email'
  | 'http_post'
  | 'read_file'
  | 'delete_file'
  | 'transfer_funds'
  | 'set_permission'
  | 'search';

/** Canonical tool -> the alias tokens/spellings a lenient dispatcher accepts. */
const TOOL_ALIASES: Record<CanonicalTool, string[]> = {
  send_email: ['sendemail', 'send_email', 'sendmail', 'send_mail', 'emailsend', 'email_send', 'email', 'mail', 'sendemailmessage'],
  http_post: ['httppost', 'http_post', 'httprequest', 'http_request', 'post', 'upload', 'webhook', 'sendhttp', 'send_http', 'httpsend'],
  read_file: ['readfile', 'read_file', 'read', 'openfile', 'open_file', 'open', 'cat', 'loadfile', 'load_file', 'getfile', 'get_file', 'fileread'],
  delete_file: ['deletefile', 'delete_file', 'delete', 'remove', 'removefile', 'rm', 'unlink', 'erase', 'wipe', 'purge', 'destroy'],
  transfer_funds: ['transferfunds', 'transfer_funds', 'transfer', 'wire', 'wiretransfer', 'sendfunds', 'send_funds', 'sendmoney', 'send_money', 'remit', 'pay', 'payment'],
  set_permission: ['setpermission', 'set_permission', 'setpermissions', 'grantpermission', 'grant', 'chmod', 'setacl', 'set_acl', 'changepermission', 'elevate', 'escalate'],
  search: ['search', 'searchindex', 'search_index', 'query', 'lookup', 'find', 'grep', 'retrieve']
};

/** Normalize a tool name to a comparison key: lowercase, strip non-alphanumerics. */
export function normalizeToolKey(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

const ALIAS_LOOKUP: Map<string, CanonicalTool> = (() => {
  const map = new Map<string, CanonicalTool>();
  for (const [canonical, aliases] of Object.entries(TOOL_ALIASES) as Array<[CanonicalTool, string[]]>) {
    map.set(normalizeToolKey(canonical), canonical);
    for (const alias of aliases) {
      map.set(normalizeToolKey(alias), canonical);
    }
  }
  return map;
})();

/**
 * Resolve a proposed tool name to the canonical tool a lenient dispatcher would
 * reach, or null when nothing documented matches (an unknown tool). Matching is
 * exact-on-normalized-key only — deliberately NOT the oracle's token-subset
 * fallback — so an unrecognized name resolves to null and receives no positive
 * egress authorization rather than being guessed into a contract.
 */
export function resolveCanonicalTool(name: string): CanonicalTool | null {
  if (!name) {
    return null;
  }
  const key = normalizeToolKey(name);
  return key ? ALIAS_LOOKUP.get(key) ?? null : null;
}

export type EgressContract = 'email' | 'network' | 'none';

/**
 * The egress-destination contract for a tool name:
 *   - 'email'   : transmits to email recipients (send_email + its aliases).
 *   - 'network' : transmits to URL hosts (http_post + its aliases).
 *   - 'none'    : carries no email/host egress destination here; an unknown
 *                 tool is never positively authorized on egress grounds.
 */
export function egressContract(name: string): EgressContract {
  switch (resolveCanonicalTool(name)) {
    case 'send_email':
      return 'email';
    case 'http_post':
      return 'network';
    default:
      return 'none';
  }
}
