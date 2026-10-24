const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { createWebCredentials } = require('../web-credentials')

const password = 'G9#xW3!tR8@vN2$q'
function fixture (t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'anubis-web-roles-'))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  return directory
}

test('credentials encrypt at rest, verify using device-specific KDF and survive restart', async t => {
  const directory = fixture(t)
  const id = crypto.randomUUID()
  const other = crypto.randomUUID()
  const store = createWebCredentials(directory)
  assert.equal(store.metadata(id).configured, false)
  const result = await store.set(id, password, 0)
  assert.equal(result.revision, 1)
  assert.equal(JSON.stringify(result).includes(password), false)
  const saved = fs.readFileSync(path.join(directory, 'web-admin.json'), 'utf8')
  assert.equal(saved.includes(password), false)
  assert.equal(saved.includes(Buffer.from(password).toString('base64')), false)
  assert.equal((await store.verify(id, password)), 1)
  assert.equal(await store.verify(id, 'Wrong9!xW3!tR8@vN2'), null)
  assert.equal(await store.verify(other, password), null)
  const reopened = createWebCredentials(directory)
  assert.equal(await reopened.verify(id, password), 1)
  assert.equal(reopened.reveal(id).password, password)
  await reopened.set(other, password, 0)
  const records = JSON.parse(fs.readFileSync(path.join(directory, 'web-admin.json')))
  assert.notEqual(records[id].hash, records[other].hash)
  assert.notEqual(records[id].encrypted, records[other].encrypted)
})

test('empty, common and stale credentials are refused; concurrent rotation is compare-and-set', async t => {
  const store = createWebCredentials(fixture(t))
  const id = crypto.randomUUID()
  for (const value of ['', 'password', 'Password123456789!', 'Anubis-Web-Default9!', 'aaaaAAAAAAAA1111!!!!']) {
    await assert.rejects(store.set(id, value, 0), { status: 400 })
  }
  await store.set(id, password, 0)
  await assert.rejects(store.set(id, password, 0), { status: 409 })
  const updates = await Promise.allSettled([
    store.set(id, 'C3%xQ9!uH4@zM8&k', 1),
    store.set(id, 'P8*xJ4!uZ6@rK2&b', 1)
  ])
  assert.equal(updates.filter(value => value.status === 'fulfilled').length, 1)
  assert.equal(updates.find(value => value.status === 'rejected').reason.status, 409)
  assert.equal(await store.verify(id, password), null)
})

test('missing keys, tampered ciphertext and swapped device records fail closed', async t => {
  const directory = fixture(t)
  const store = createWebCredentials(directory)
  const id = crypto.randomUUID()
  await store.set(id, password, 0)
  const file = path.join(directory, 'web-admin.json')
  const records = JSON.parse(fs.readFileSync(file))
  const saved = JSON.stringify(records)
  const modified = structuredClone(records)
  modified[id].hash = '0'.repeat(128)
  fs.writeFileSync(file, JSON.stringify(modified), { mode: 0o600 })
  assert.throws(() => createWebCredentials(directory), 'verifier metadata is authenticated by the independent key')
  const other = crypto.randomUUID()
  records[other] = records[id]
  delete records[id]
  fs.writeFileSync(file, JSON.stringify(records), { mode: 0o600 })
  assert.throws(() => createWebCredentials(directory))
  fs.writeFileSync(file, saved, { mode: 0o600 })
  fs.unlinkSync(path.join(directory, 'web-admin.key'))
  assert.throws(() => createWebCredentials(directory), /key is missing/)
})

test('failed persistence does not replace the working credential or acknowledge success', async t => {
  const directory = fixture(t)
  const store = createWebCredentials(directory)
  const id = crypto.randomUUID()
  await store.set(id, password, 0)
  const rename = t.mock.method(fs, 'renameSync', () => {
    throw Object.assign(new Error('fixture persistence denied'), { code: 'EACCES' })
  })
  await assert.rejects(store.set(id, 'C3%xQ9!uH4@zM8&k', 1), /persistence denied/)
  rename.mock.restore()
  assert.equal(store.metadata(id).revision, 1)
  assert.equal(await store.verify(id, password), 1)
  assert.equal(createWebCredentials(directory).reveal(id).password, password)
  assert.deepEqual(fs.readdirSync(directory).sort(), ['web-admin.json', 'web-admin.key'])
})
