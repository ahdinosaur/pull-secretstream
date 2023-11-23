const test = require('node:test')
const assert = require('node:assert')
const pull = require('pull-stream')
const { randomBytes } = require('crypto')
const { KEY_SIZE, createEncryptStream, createDecryptStream } = require('../')

test('test basic encryptStream and decryptStream', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEY_SIZE)

  const plaintext1 = Buffer.from('hello world')

  await new Promise((resolve, reject) => {
    pull(
      pull.values([plaintext1]),
      createEncryptStream(key),
      pull.through((ciphertext) => {
        console.log('Encrypted: ', ciphertext)
      }),
      createDecryptStream(key),
      pull.concat((err, plaintext2) => {
        if (err) return reject(err)
        assert.equal(plaintext2.toString('ascii'), plaintext1.toString('ascii'))
        resolve()
      }),
    )
  })
})
