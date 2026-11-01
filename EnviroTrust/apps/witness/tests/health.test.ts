import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createWitnessApp } from '../src/app.js';

describe('Simulated Witness — Health Endpoints', () => {
  let server: Server;
  let baseUrl: string;

  before(async () => {
    const { app } = createWitnessApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('GET /health returns 200 with witness service UP', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { status: string; service: string; timestamp: string };
    assert.equal(body.status, 'UP');
    assert.equal(body.service, 'envirotrust-witness');
    assert.ok(body.timestamp);
  });

  it('GET /witness/v1/health returns 200 with metadata', async () => {
    const res = await fetch(`${baseUrl}/witness/v1/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      status: string;
      service: string;
      version: string;
      witnessId: string;
      displayName: string;
      checkpointInterval: number;
      timestamp: string;
    };
    assert.equal(body.status, 'UP');
    assert.equal(body.service, 'envirotrust-witness');
    assert.equal(body.version, '1.0.0');
    assert.equal(body.witnessId, 'WITNESS-001');
    assert.equal(body.displayName, 'Simulated Independent Witness');
    assert.equal(body.checkpointInterval, 10);
    assert.ok(body.timestamp);
  });

  it('GET /witness/v1/unknown-route returns 404 JSON', async () => {
    const res = await fetch(`${baseUrl}/witness/v1/unknown-route`);
    assert.equal(res.status, 404);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
    assert.equal(body.code, 'NOT_FOUND');
  });
});
