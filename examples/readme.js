const { randomBytes } = require('crypto')
const pull = require('pull-stream')
const { KEY_SIZE, createEncryptStream, createDecryptStream } = require('../')

// generate a random secret, `KEYBYTES` bytes long.
const key = randomBytes(KEY_SIZE)

const plaintext1 = Buffer.from('hello world')

pull(
  pull.values([plaintext1]),

  // encrypt every byte
  createEncryptStream(key),

  // the encrypted stream
  pull.through((ciphertext) => {
    console.log('Encrypted: ', ciphertext)
  }),

  //decrypt every byte
  createDecryptStream(key),

  pull.concat((err, plaintext2) => {
    if (err) throw err
    console.log('Decrypted: ', plaintext2)
  }),
)
