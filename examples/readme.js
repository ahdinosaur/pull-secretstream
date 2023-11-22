const { randomBytes } = require('crypto')
const pull = require('pull-stream')
const { KEYBYTES, createBoxStream, createUnboxStream } = require('../')

// generate a random secret, `KEYBYTES` bytes long.
const key = randomBytes(KEYBYTES)

const plaintext1 = Buffer.from('hello world')

pull(
  pull.values([plaintext1]),

  // encrypt every byte
  createBoxStream(key),

  // the encrypted stream
  pull.through((ciphertext) => {
    console.log('Encrypted: ', ciphertext)
  }),

  //decrypt every byte
  createUnboxStream(key),

  pull.concat((err, plaintext2) => {
    if (err) throw err
    console.log('Decrypted: ', plaintext2)
  }),
)
