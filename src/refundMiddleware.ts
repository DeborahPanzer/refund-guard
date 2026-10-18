import * as crypto from 'crypto';

export type DisputeState = 'NONE' | 'INQUIRY_OPEN' | 'CHARGEBACK_FILED' | 'WON' | 'LOST';
export type RefundStatus = 'SUCCEEDED' | 'BLOCKED_BY_DISPUTE' | 'DUPLICATE_IGNORED';

export interface RefundRequest {
  chargeId: string;
  refundAmountMinor: number;
  capturedAmountMinor: number;
  currency: string;
  reason: 'DUPLICATE' | 'FRAUDULENT' | 'REQUESTED_BY_CUSTOMER';
  idempotencyKey: string;
  actorId: string;
}

export interface AuditLogEntry {
  entryId: string;
  chargeId: string;
  action: string;
  status: RefundStatus;
  amountMinor: number;
  previousChainHash: string;
  entryHash: string;
  timestamp: string;
}

/**
 * RefundGuardMiddleware protects marketplace platforms against double-refunding
 * and processes automated dispute mitigation based on real-time gateway state sync.
 */
export class RefundGuardMiddleware {
  private readonly disputeRegistry = new Map<string, DisputeState>();
  private readonly refundedTotals = new Map<string, number>();
  private readonly processedKeys = new Map<string, AuditLogEntry>();
  private readonly auditTrail: AuditLogEntry[] = [];

  /**
   * Synchronizes real-time dispute state from payment gateway webhooks (e.g., Stripe/Adyen).
   */
  public syncDisputeState(chargeId: string, state: DisputeState): void {
    this.disputeRegistry.set(chargeId, state);
  }

  /**
   * Executes an idempotent refund with dispute mitigation checks and cryptographic audit logging.
   */
  public executeRefund(req: RefundRequest): AuditLogEntry {
    if (this.processedKeys.has(req.idempotencyKey)) {
      const existing = this.processedKeys.get(req.idempotencyKey)!;
      return { ...existing, status: 'DUPLICATE_IGNORED' };
    }

    const activeDispute = this.disputeRegistry.get(req.chargeId) ?? 'NONE';
    if (activeDispute === 'INQUIRY_OPEN' || activeDispute === 'CHARGEBACK_FILED') {
      return this.appendAuditEntry(req, 'BLOCKED_BY_DISPUTE');
    }

    const alreadyRefunded = this.refundedTotals.get(req.chargeId) ?? 0;
    if (alreadyRefunded + req.refundAmountMinor > req.capturedAmountMinor) {
      throw new Error(
        `refund-guard: Refund amount (${req.refundAmountMinor}) exceeds remaining refundable balance for charge ${req.chargeId}.`
      );
    }

    this.refundedTotals.set(req.chargeId, alreadyRefunded + req.refundAmountMinor);
    const entry = this.appendAuditEntry(req, 'SUCCEEDED');
    this.processedKeys.set(req.idempotencyKey, entry);
    return entry;
  }

  public getAuditTrail(): ReadonlyArray<AuditLogEntry> {
    return this.auditTrail;
  }

  private appendAuditEntry(req: RefundRequest, status: RefundStatus): AuditLogEntry {
    const previousChainHash =
      this.auditTrail.length > 0
        ? this.auditTrail[this.auditTrail.length - 1].entryHash
        : '0'.repeat(64);

    const timestamp = new Date().toISOString();
    const rawPayload = `${previousChainHash}:${req.chargeId}:${req.refundAmountMinor}:${status}:${timestamp}`;
    const entryHash = crypto.createHash('sha256').update(rawPayload).digest('hex');

    const entry: AuditLogEntry = {
      entryId: `aud_${crypto.randomBytes(8).toString('hex')}`,
      chargeId: req.chargeId,
      action: `REFUND_${req.reason}`,
      status,
      amountMinor: req.refundAmountMinor,
      previousChainHash,
      entryHash,
      timestamp,
    };

    this.auditTrail.push(entry);
    return entry;
  }
}
