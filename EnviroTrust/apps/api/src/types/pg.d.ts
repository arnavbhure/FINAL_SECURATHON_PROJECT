declare module 'pg' {
  import { EventEmitter } from 'node:events';

  export interface QueryResultRow {
    [column: string]: unknown;
  }

  export interface QueryResult<R extends QueryResultRow = QueryResultRow> {
    rows: R[];
    fields: Array<{ name: string; dataTypeID: number }>;
    rowCount: number | null;
    command: string;
  }

  export interface PoolClient extends EventEmitter {
    query<R extends QueryResultRow = QueryResultRow>(
      queryTextOrConfig: string,
      values?: unknown[]
    ): Promise<QueryResult<R>>;
    release(err?: Error | boolean): void;
  }

  export interface PoolConfig {
    connectionString?: string;
    user?: string;
    database?: string;
    password?: string | (() => string | Promise<string>);
    port?: number;
    host?: string;
    max?: number;
    min?: number;
    idleTimeoutMillis?: number;
    connectionTimeoutMillis?: number;
  }

  export class Pool extends EventEmitter {
    constructor(config?: PoolConfig);
    connect(): Promise<PoolClient>;
    query<R extends QueryResultRow = QueryResultRow>(
      queryTextOrConfig: string,
      values?: unknown[]
    ): Promise<QueryResult<R>>;
    end(): Promise<void>;
    totalCount: number;
    idleCount: number;
    waitingCount: number;
  }

  const pg: {
    Pool: typeof Pool;
  };

  export default pg;
}
