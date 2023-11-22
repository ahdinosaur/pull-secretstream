const test = require('node:test')
const assert = require('node:assert')
const pull = require('pull-stream')
const { randomBytes } = require('crypto')
const { KEYBYTES, createBoxStream, createUnboxStream } = require('../')

test('test basic boxStream and unboxStream', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEYBYTES)

  const plaintext1 = Buffer.from('hello world')

  await new Promise((resolve, reject) => {
    pull(
      pull.values([plaintext1]),
      createBoxStream(key),
      pull.through((ciphertext) => {
        console.log('Encrypted: ', ciphertext)
      }),
      createUnboxStream(key),
      pull.concat((err, plaintext2) => {
        if (err) return reject(err)
        assert.equal(plaintext2.toString('ascii'), plaintext1.toString('ascii'))
        resolve()
      }),
    )
  })
})
