import { Ajv2020, type ValidateFunction, type ErrorObject } from 'ajv/dist/2020.js';
import _addFormats from 'ajv-formats';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const addFormats = ((_addFormats as unknown as { default?: (instance: Ajv2020) => void }).default ||
  _addFormats) as unknown as (instance: Ajv2020) => void;

import type {
  TelemetryPayload,
  SignedTelemetryEnvelope,
  HeartbeatPayload,
  SignedHeartbeatEnvelope,
  OpsContextPayload,
  SignedOpsContextEnvelope,
  TamperEventPayload,
  SignedTamperEnvelope,
  WitnessCheckpointPayload,
  MlAnalysisRequest,
  MlAnalysisResult,
  ValidationResult,
  ValidationErrorDetail,
} from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function loadSchema(filename: string): Record<string, unknown> {
  const possiblePaths = [
    path.resolve(__dirname, 'schemas', filename),
    path.resolve(__dirname, '../src/schemas', filename),
    path.resolve(__dirname, '../../src/schemas', filename),
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p, 'utf-8');
      return JSON.parse(raw) as Record<string, unknown>;
    }
  }
  throw new Error(`Schema file not found: ${filename}`);
}

// Load all 8 canonical schemas
export const schemas = {
  telemetry: loadSchema('telemetry.schema.json'),
  signedTelemetryEnvelope: loadSchema('signed-telemetry-envelope.schema.json'),
  heartbeat: loadSchema('heartbeat.schema.json'),
  signedHeartbeatEnvelope: loadSchema('signed-heartbeat-envelope.schema.json'),
  opsContext: loadSchema('ops-context.schema.json'),
  signedOpsContextEnvelope: loadSchema('signed-ops-context-envelope.schema.json'),
  mlRequest: loadSchema('ml-request.schema.json'),
  mlResult: loadSchema('ml-result.schema.json'),
  witnessCheckpoint: loadSchema('witness-checkpoint.schema.json'),
  tamperEvent: loadSchema('tamper-event.schema.json'),
  signedTamperEnvelope: loadSchema('signed-tamper-envelope.schema.json'),
};

// Initialize AJV with Draft 2020-12 support and format validation
const ajv = new Ajv2020({
  allErrors: true,
  strict: false,
});

// Add standard formats (date-time, uuid, etc.)
addFormats(ajv);

// Register base schemas with explicit keys matching $ref references
ajv.addSchema(schemas.telemetry, 'telemetry.schema.json');
ajv.addSchema(schemas.heartbeat, 'heartbeat.schema.json');
ajv.addSchema(schemas.opsContext, 'ops-context.schema.json');
ajv.addSchema(schemas.tamperEvent, 'tamper-event.schema.json');

// Compile validators
const validateTelemetryFn = ajv.compile(schemas.telemetry);
const validateSignedTelemetryEnvelopeFn = ajv.compile(schemas.signedTelemetryEnvelope);
const validateHeartbeatFn = ajv.compile(schemas.heartbeat);
const validateSignedHeartbeatEnvelopeFn = ajv.compile(schemas.signedHeartbeatEnvelope);
const validateOpsContextFn = ajv.compile(schemas.opsContext);
const validateSignedOpsContextEnvelopeFn = ajv.compile(schemas.signedOpsContextEnvelope);
const validateMlRequestFn = ajv.compile(schemas.mlRequest);
const validateMlResultFn = ajv.compile(schemas.mlResult);
const validateWitnessCheckpointFn = ajv.compile(schemas.witnessCheckpoint);
const validateTamperFn = ajv.compile(schemas.tamperEvent);
const validateSignedTamperEnvelopeFn = ajv.compile(schemas.signedTamperEnvelope);

function formatErrors(errors: ErrorObject[] | null | undefined): ValidationErrorDetail[] {
  if (!errors || errors.length === 0) {
    return [{ path: 'root', message: 'Unknown validation failure', keyword: 'unknown', params: {} }];
  }
  return errors.map((err) => ({
    path: err.instancePath || (err.params && 'missingProperty' in err.params ? `/${String(err.params['missingProperty'])}` : '/'),
    message: err.message || 'Validation failed',
    keyword: err.keyword,
    params: (err.params as Record<string, unknown>) || {},
  }));
}

function runValidator<T>(validateFn: ValidateFunction, data: unknown): ValidationResult<T> {
  const valid = validateFn(data);
  if (valid) {
    return { valid: true, data: data as T };
  }
  return { valid: false, errors: formatErrors(validateFn.errors) };
}

export function validateTelemetryPayload(data: unknown): ValidationResult<TelemetryPayload> {
  return runValidator(validateTelemetryFn, data);
}

export function validateSignedTelemetryEnvelope(data: unknown): ValidationResult<SignedTelemetryEnvelope> {
  return runValidator(validateSignedTelemetryEnvelopeFn, data);
}

export function validateHeartbeatPayload(data: unknown): ValidationResult<HeartbeatPayload> {
  return runValidator(validateHeartbeatFn, data);
}

export function validateSignedHeartbeatEnvelope(data: unknown): ValidationResult<SignedHeartbeatEnvelope> {
  return runValidator(validateSignedHeartbeatEnvelopeFn, data);
}

export function validateOpsContextPayload(data: unknown): ValidationResult<OpsContextPayload> {
  return runValidator(validateOpsContextFn, data);
}

export function validateSignedOpsContextEnvelope(data: unknown): ValidationResult<SignedOpsContextEnvelope> {
  return runValidator(validateSignedOpsContextEnvelopeFn, data);
}

export function validateMlRequest(data: unknown): ValidationResult<MlAnalysisRequest> {
  return runValidator(validateMlRequestFn, data);
}

export function validateMlResult(data: unknown): ValidationResult<MlAnalysisResult> {
  return runValidator(validateMlResultFn, data);
}

export function validateWitnessCheckpointPayload(data: unknown): ValidationResult<WitnessCheckpointPayload> {
  return runValidator(validateWitnessCheckpointFn, data);
}

export function validateTamperPayload(data: unknown): ValidationResult<TamperEventPayload> {
  return runValidator(validateTamperFn, data);
}

export function validateSignedTamperEnvelope(data: unknown): ValidationResult<SignedTamperEnvelope> {
  return runValidator(validateSignedTamperEnvelopeFn, data);
}
