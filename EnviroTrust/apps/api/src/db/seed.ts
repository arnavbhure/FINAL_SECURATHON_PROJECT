/**
 * Demo User Provisioning Utility
 *
 * Provisions initial demo user accounts with bcrypt password hashes and site memberships:
 * 1. admin@envirotrust.local    - PLATFORM_ADMIN (Global site access)
 * 2. operator@envirotrust.local - FACTORY_OPERATOR (Assigned strictly to PLANT-001)
 * 3. auditor@envirotrust.local  - REGULATOR_AUDITOR (Assigned strictly to PLANT-001)
 */

import bcrypt from 'bcryptjs';
import { getDbPool } from './connection.js';
import { UserRepository, type UserRole } from '../repositories/user.repository.js';
import { runMigrations } from './migrate.js';

interface DemoUserDefinition {
  fullName: string;
  email: string;
  role: UserRole;
  assignedSiteCodes: string[];
}

const DEMO_USERS: DemoUserDefinition[] = [
  {
    fullName: 'System Administrator',
    email: 'admin@envirotrust.local',
    role: 'PLATFORM_ADMIN',
    assignedSiteCodes: ['PLANT-001', 'PLANT-002'],
  },
  {
    fullName: 'Factory Plant Operator',
    email: 'operator@envirotrust.local',
    role: 'FACTORY_OPERATOR',
    assignedSiteCodes: ['PLANT-001'],
  },
  {
    fullName: 'Regulatory Compliance Auditor',
    email: 'auditor@envirotrust.local',
    role: 'REGULATOR_AUDITOR',
    assignedSiteCodes: ['PLANT-001'],
  },
];

export async function seedDemoUsers(): Promise<void> {
  const pool = getDbPool();
  await runMigrations(pool);

  const userRepo = new UserRepository(pool);
  const defaultPassword = process.env['DEMO_USER_PASSWORD'] || 'DemoPassword123!';
  const passwordHash = await bcrypt.hash(defaultPassword, 10);

  // Cache site IDs by code
  const siteRes = await pool.query<{ id: string; site_code: string }>('SELECT id, site_code FROM sites');
  const siteMap = new Map<string, string>();
  for (const s of siteRes.rows) {
    siteMap.set(s.site_code, s.id);
  }

  for (const def of DEMO_USERS) {
    const existing = await userRepo.findByEmail(def.email);
    let userId: string;

    if (!existing) {
      const created = await userRepo.createUser({
        fullName: def.fullName,
        email: def.email,
        passwordHash,
        role: def.role,
        status: 'ACTIVE',
      });
      userId = created.id;
    } else {
      await pool.query(
        `UPDATE users
         SET full_name = $1, password_hash = $2, role = $3, status = 'ACTIVE', updated_at = now()
         WHERE id = $4`,
        [def.fullName, passwordHash, def.role, existing.id]
      );
      userId = existing.id;
    }

    // Assign site memberships
    for (const siteCode of def.assignedSiteCodes) {
      const siteId = siteMap.get(siteCode);
      if (siteId) {
        await userRepo.assignSiteMembership(userId, siteId);
      }
    }
  }
}

