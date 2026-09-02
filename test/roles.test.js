import { test } from 'node:test'
import assert from 'node:assert/strict'

import * as roles from '../src/roles/roles.js'

test('default roles include admin (wildcard), two unlabeled privilege tiers, and read-only', () => {
  const seeded = roles.defaultRoles()
  const ids = seeded.map((r) => r.id)
  assert.deepEqual(ids.sort(), ['role-admin', 'role-privileged-1', 'role-privileged-2', 'role-read-only'].sort())

  const admin = seeded.find((r) => r.id === 'role-admin')
  assert.deepEqual(admin.permissions, [roles.WILDCARD_PERMISSION])
})

test('admin (wildcard) role has every permission, including ones invented later', () => {
  const admin = roles.defaultRoles().find((r) => r.id === 'role-admin')
  assert.equal(roles.hasPermission(admin, 'anything.at.all'), true)
  assert.equal(roles.hasPermission(admin, 'a.permission.nobody.has.defined.yet'), true)
})

test('read-only role has exactly the read permission, nothing else', () => {
  const readOnly = roles.defaultRoles().find((r) => r.id === 'role-read-only')
  assert.equal(roles.hasPermission(readOnly, 'read'), true)
  assert.equal(roles.hasPermission(readOnly, 'write'), false)
})

test('renaming a role (changing `name`) does not affect permission checks, which key off `id`', () => {
  const role = { id: 'role-x', name: 'Original Name', permissions: ['edit'] }
  assert.equal(roles.hasPermission(role, 'edit'), true)
  const renamed = { ...role, name: 'Totally Different Name' }
  assert.equal(roles.hasPermission(renamed, 'edit'), true) // unaffected by the rename
})

test('anyRoleHasPermission checks across multiple assigned roles', () => {
  const editorRole = { id: 'role-editor', name: 'Editor', permissions: ['edit'] }
  const viewerRole = { id: 'role-viewer', name: 'Viewer', permissions: ['read'] }
  assert.equal(roles.anyRoleHasPermission([viewerRole], 'edit'), false)
  assert.equal(roles.anyRoleHasPermission([viewerRole, editorRole], 'edit'), true)
})

test('a role with no permissions and no wildcard grants nothing', () => {
  const empty = { id: 'role-empty', name: 'Empty', permissions: [] }
  assert.equal(roles.hasPermission(empty, 'read'), false)
  assert.equal(roles.hasPermission(empty, roles.WILDCARD_PERMISSION), false)
})

test('newRoleId produces unique, stable-looking ids', () => {
  const a = roles.newRoleId()
  const b = roles.newRoleId()
  assert.notEqual(a, b)
  assert.match(a, /^role-/)
})
