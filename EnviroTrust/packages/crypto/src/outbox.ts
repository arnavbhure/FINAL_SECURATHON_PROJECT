import fs from 'node:fs';
import path from 'node:path';

export interface OutboxDestinationState {
  url: string;
  status: 'PENDING' | 'ACCEPTED' | 'FAILED';
  httpStatus?: number | undefined;
  lastAttemptAt?: string | undefined;
  error?: string | undefined;
}

export interface OutboxEntry<TEnvelope = unknown> {
  id: string; // messageId
  envelopeType: 'TELEMETRY' | 'HEARTBEAT' | 'OPERATIONS_CONTEXT';
  envelope: TEnvelope;
  primary: OutboxDestinationState;
  witness: OutboxDestinationState;
  createdAt: string;
  attempts: number;
}

export class OutboxManager {
  private readonly outboxDir: string;

  constructor(outboxDir?: string) {
    this.outboxDir = outboxDir || path.resolve(process.cwd(), 'local-secrets/outbox');
    fs.mkdirSync(this.outboxDir, { recursive: true });
  }

  public getOutboxDir(): string {
    return this.outboxDir;
  }

  public saveEntry<T>(entry: OutboxEntry<T>): void {
    const filePath = path.join(this.outboxDir, `${entryCleanId(entry.id)}.json`);
    fs.writeFileSync(filePath, JSON.stringify(entry, null, 2), 'utf-8');
  }

  public getEntry<T>(id: string): OutboxEntry<T> | null {
    const filePath = path.join(this.outboxDir, `${entryCleanId(id)}.json`);
    if (!fs.existsSync(filePath)) return null;
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as OutboxEntry<T>;
    } catch {
      return null;
    }
  }

  public listPendingEntries<T>(): OutboxEntry<T>[] {
    if (!fs.existsSync(this.outboxDir)) return [];
    const files = fs.readdirSync(this.outboxDir).filter((f) => f.endsWith('.json'));
    const entries: OutboxEntry<T>[] = [];
    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(this.outboxDir, file), 'utf-8');
        const entry = JSON.parse(content) as OutboxEntry<T>;
        if (entry.primary.status !== 'ACCEPTED' || entry.witness.status !== 'ACCEPTED') {
          entries.push(entry);
        }
      } catch {
        // Skip corrupted or unreadable files safely
      }
    }
    return entries;
  }

  public markDestinationAccepted(id: string, destination: 'primary' | 'witness', httpStatus = 201): void {
    const entry = this.getEntry(id);
    if (!entry) return;
    entry[destination].status = 'ACCEPTED';
    entry[destination].httpStatus = httpStatus;
    entry[destination].lastAttemptAt = new Date().toISOString();

    if (entry.primary.status === 'ACCEPTED' && entry.witness.status === 'ACCEPTED') {
      this.removeEntry(id);
    } else {
      this.saveEntry(entry);
    }
  }

  public markDestinationFailed(
    id: string,
    destination: 'primary' | 'witness',
    error: string,
    httpStatus?: number
  ): void {
    const entry = this.getEntry(id);
    if (!entry) return;
    entry[destination].status = 'FAILED';
    if (httpStatus !== undefined) entry[destination].httpStatus = httpStatus;
    entry[destination].error = error;
    entry[destination].lastAttemptAt = new Date().toISOString();
    entry.attempts++;
    this.saveEntry(entry);
  }

  public removeEntry(id: string): void {
    const filePath = path.join(this.outboxDir, `${entryCleanId(id)}.json`);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch {
        // ignored
      }
    }
  }

  public clearAll(): void {
    if (!fs.existsSync(this.outboxDir)) return;
    const files = fs.readdirSync(this.outboxDir).filter((f) => f.endsWith('.json'));
    for (const f of files) {
      try {
        fs.unlinkSync(path.join(this.outboxDir, f));
      } catch {
        // ignored
      }
    }
  }
}

function entryCleanId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, '_');
}
