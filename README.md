# pull-secretstream

Replacement for [`pull-box-stream`](https://github.com/dominictarr/pull-box-stream) using libsodium's [secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)

Uses a fixed ciphertext block size. (By default: 512 bytes.)

## Example

```js
const { randomBytes } = require('crypto')
const pull = require('pull-stream')
const { KEY_SIZE, createEncryptStream, createDecryptStream } = require('pull-secretstream')

// generate a random secret, `KEY_SIZE` bytes long.
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
```

## API

### `createEncryptStream(key, ciphertextBlockSize = DEFAULT_BLOCK_SIZE)`

Returns a "through" pull-stream that:

- first sends the secretstream header,
- then encrypts incoming plaintext as secretstream ciphertext (of a fixed block size, padding if necessary),
- and when done, sends a secrestream message marked as the final.

### `createDecryptStream(key, ciphertextBlockSize = DEFAULT_BLOCK_SIZE)`

Returns a "through" pull-stream that:

- first recives the secretstream header,
- then decrypts incoming secretstream ciphertext as plaintext (unpadding if necessary),
- and is done when a secretstream message marked as final is received.

### `DEFAULT_BLOCK_SIZE`

512 bytes

### `KEY_SIZE`

32 bytes

### `getPlaintextBlockSize(ciphertextBlockSize)`

`cipherBlockSize` - 17 bytes (secretstream's additional data)

### `MINIMUM_PADDING`

1 byte: the minimum amount of space needed for padding in each plaintext block.
