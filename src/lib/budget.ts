/**
 * Per-scan request accounting.
 *
 * "Passive" is a claim about volume as much as intent. One scan already makes
 * around twenty requests to the target, and the roadmap adds paths. Without a
 * central ceiling, each new check quietly raises the load an anonymous visitor
 * can aim at someone else's site through an embedded form — which is how a
 * polite scanner becomes a nuisance and how our egress addresses end up on
 * blocklists.
 *
 * The budget is enforced in the HTTP client rather than per check, so it
 * cannot be forgotten by the next check someone writes.
 */

export class BudgetExhaustedError extends Error {
  readonly code = 'budget_exhausted';
  constructor(limit: number) {
    super(`scan request budget exhausted (${limit} requests to the target)`);
    this.name = 'BudgetExhaustedError';
  }
}

export class RequestBudget {
  readonly limit: number;
  private spent = 0;
  /** Requests refused because the budget ran out. */
  private refused = 0;

  constructor(limit: number) {
    this.limit = limit;
  }

  /** Claim one request, or throw if there is nothing left. */
  claim(): void {
    if (this.spent >= this.limit) {
      this.refused += 1;
      throw new BudgetExhaustedError(this.limit);
    }
    this.spent += 1;
  }

  get used(): number {
    return this.spent;
  }

  get remaining(): number {
    return Math.max(0, this.limit - this.spent);
  }

  get exhausted(): boolean {
    return this.spent >= this.limit;
  }

  get refusedCount(): number {
    return this.refused;
  }

  snapshot(): { used: number; limit: number; refused: number } {
    return { used: this.spent, limit: this.limit, refused: this.refused };
  }
}

export function isBudgetError(err: unknown): boolean {
  return err instanceof BudgetExhaustedError;
}
