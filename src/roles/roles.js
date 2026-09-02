// Role/permission model. Roles have a stable `id` and a mutable `name` —
// same pattern as users (stable `id`, mutable `username`) — so renaming
// a role never breaks anything that references it by id. Permissions are
// plain strings; this module doesn't know or care what they mean to your
// application, it just stores and checks membership.

import crypto from 'node:crypto'

// Seed roles created on first bootstrap. All fields (including `name`)
// are freely editable afterwards via a RoleStore — these are starting
// points, not a fixed enum. `admin`'s wildcard permission is the one
// structural special case: it always passes hasPermission() regardless
// of what's in its permissions array, so it can't be locked out by an
// editing mistake.
const WILDCARD_PERMISSION = '*'

function defaultRoles () {
  const now = new Date().toISOString()
  return [
    {
      id: 'role-admin',
      name: 'Admin',
      permissions: [WILDCARD_PERMISSION],
      isBuiltIn: true,
      createdAt: now
    },
    {
      id: 'role-privileged-1',
      name: 'Privilege 1',
      permissions: [],
      isBuiltIn: true,
      createdAt: now
    },
    {
      id: 'role-privileged-2',
      name: 'Privilege 2',
      permissions: [],
      isBuiltIn: true,
      createdAt: now
    },
    {
      id: 'role-read-only',
      name: 'Read Only',
      permissions: ['read'],
      isBuiltIn: true,
      createdAt: now
    }
  ]
}

function newRoleId () {
  return `role-${crypto.randomUUID()}`
}

function hasPermission (role, permission) {
  if (!role) return false
  return role.permissions.includes(WILDCARD_PERMISSION) || role.permissions.includes(permission)
}

/**
 * @param {object[]} roles the account's assigned roles (already resolved
 *   from RoleStore by their ids)
 */
function anyRoleHasPermission (roles, permission) {
  return roles.some((role) => hasPermission(role, permission))
}

export {
  WILDCARD_PERMISSION,
  defaultRoles,
  newRoleId,
  hasPermission,
  anyRoleHasPermission
}
