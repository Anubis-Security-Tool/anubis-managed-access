'use strict'

const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const { promisify } = require('node:util')
const scrypt = promisify(crypto.scrypt)
const invalid = (message, status = 400) => Object.assign(new Error(message), { status })
const hex = (value, length) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${length}}$`).test(value)
const aad = (id, record) => Buffer.from(JSON.stringify([id, record.revision, record.updatedAt, record.salt, record.hash]))

function createWebCredentials (directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
  const keyPath = path.join(directory, 'web-admin.key')
  const file = path.join(directory, 'web-admin.json')
  function privateRead (name) {
    if (fs.lstatSync(name).isSymbolicLink()) throw new Error('Web credential symlinks are not allowed')
    const fd = fs.openSync(name, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0))
    try {
      const stat = fs.fstatSync(fd)
      if (!stat.isFile() || stat.size > 1024 * 1024 ||
          (process.platform !== 'win32' && (stat.mode & 0o077))) throw new Error('Web credential file permissions are not private')
      return fs.readFileSync(fd)
    } finally { fs.closeSync(fd) }
  }
  let key
  try { key = privateRead(keyPath) } catch (error) {
    if (error.code !== 'ENOENT') throw error
    if (fs.existsSync(file)) throw new Error('Web credential encryption key is missing')
    try { fs.writeFileSync(keyPath, crypto.randomBytes(32), { flag: 'wx', mode: 0o600 }) } catch (error) {
      if (error.code !== 'EEXIST') throw error
    }
    key = privateRead(keyPath)
  }
  if (key.length !== 32) throw new Error('Invalid Web credential encryption key')
  let records = {}
  try { records = JSON.parse(privateRead(file).toString()) } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (!records || Array.isArray(records) || typeof records !== 'object') throw new Error('Invalid Web credential store')
  const decrypt = (id, record) => {
    if (!Number.isSafeInteger(record?.revision) || record.revision < 1 ||
        !Number.isSafeInteger(record.updatedAt) || !hex(record.salt, 32) || !hex(record.hash, 128) ||
        !hex(record.iv, 24) || !hex(record.tag, 32) || !hex(record.encrypted, record.encrypted?.length) ||
        record.encrypted.length < 32 || record.encrypted.length > 2048) throw new Error('Invalid Web credential record')
    const cipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'hex'))
    cipher.setAAD(aad(id, record))
    cipher.setAuthTag(Buffer.from(record.tag, 'hex'))
    return Buffer.concat([cipher.update(Buffer.from(record.encrypted, 'hex')), cipher.final()])
  }
  for (const [id, record] of Object.entries(records)) {
    if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error('Invalid Web credential device')
    decrypt(id, record).fill(0)
  }
  const metadata = id => ({
    configured: !!records[id],
    revision: records[id]?.revision || 0,
    updatedAt: records[id]?.updatedAt || null,
    role: 'administrator',
    workspace: 'SYSTEM',
    userPasswordSource: 'device-local-file'
  })
  return {
    metadata,
    async set (id, password, revision) {
      if (typeof password !== 'string' || Buffer.byteLength(password) < 16 || Buffer.byteLength(password) > 1024 ||
          password.trim() !== password || !/[a-z]/.test(password) || !/[A-Z]/.test(password) ||
          !/[0-9]/.test(password) || !/[^a-zA-Z0-9]/.test(password) ||
          /password|administrator|anubis|qwerty|123456|changeme|letmein|default/i.test(password) ||
          new Set(password).size < 8) throw invalid('Use a unique 16-1024 byte password with uppercase, lowercase, number and symbol; common defaults are not accepted')
      if (!Number.isSafeInteger(revision) || revision !== metadata(id).revision) throw invalid('Credential changed; reload before saving', 409)
      const salt = crypto.randomBytes(16).toString('hex')
      const bytes = Buffer.from(password)
      try {
        const derived = await scrypt(bytes, salt, 64)
        if (revision !== metadata(id).revision) throw invalid('Credential changed; reload before saving', 409)
        const nextRevision = revision + 1
        const iv = crypto.randomBytes(12)
        const record = {
          revision: nextRevision,
          updatedAt: Date.now(),
          salt,
          hash: derived.toString('hex')
        }
        derived.fill(0)
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
        cipher.setAAD(aad(id, record))
        record.iv = iv.toString('hex')
        record.encrypted = Buffer.concat([cipher.update(bytes), cipher.final()]).toString('hex')
        record.tag = cipher.getAuthTag().toString('hex')
        const next = { ...records, [id]: record }
        const temporary = file + '.' + crypto.randomBytes(8).toString('hex') + '.next'
        try {
          fs.writeFileSync(temporary, JSON.stringify(next), { flag: 'wx', mode: 0o600 })
          fs.renameSync(temporary, file)
        } catch (error) {
          try { fs.unlinkSync(temporary) } catch (error) { if (error.code !== 'ENOENT') throw error }
          throw error
        }
        records = next
        return metadata(id)
      } finally { bytes.fill(0) }
    },
    async verify (id, password) {
      const record = records[id]
      const revision = record?.revision
      const bytes = Buffer.from(password)
      try {
        const actual = await scrypt(bytes, record?.salt || '0'.repeat(32), 64)
        const expected = record ? Buffer.from(record.hash, 'hex') : Buffer.alloc(64)
        const valid = crypto.timingSafeEqual(actual, expected)
        return valid && !!record && records[id] === record ? revision : null
      } finally { bytes.fill(0) }
    },
    reveal (id) {
      if (!records[id]) throw invalid('Web administrator password is not configured', 404)
      const bytes = decrypt(id, records[id])
      try { return { ...metadata(id), password: bytes.toString() } } finally { bytes.fill(0) }
    }
  }
}

module.exports = { createWebCredentials }
