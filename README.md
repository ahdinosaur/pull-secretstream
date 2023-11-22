# pull-secretstream

replacement for [`pull-box-stream`](https://github.com/dominictarr/pull-box-stream) using libsodium's [secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)

## example

```js
const { randomBytes } = require('crypto')
const pull = require('pull-stream')
const { KEYBYTES, createBoxStream, createUnboxStream } = require('pull-secretstream')

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
```
