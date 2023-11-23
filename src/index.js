const { sodium_pad, sodium_unpad } = require('sodium-universal')
const {
  KEYBYTES: KEY_SIZE,
  HEADERBYTES: HEADER_SIZE,
  ABYTES: A_SIZE,
  Push,
  Pull,
} = require('sodium-secretstream')
const pushStreamToPullStream = require('push-stream-to-pull-stream')
const createDebug = require('debug')
const Pipeable = require('push-stream/pipeable')
const { BufferList } = require('bl')

const DEFAULT_BLOCK_SIZE = 512 // bytes

createDebug.formatters.h = (v) => {
  return v.toString('hex')
}

const debug = createDebug('pull-secretstream')

function plaintextBlockSize(ciphertextBlockSize = DEFAULT_BLOCK_SIZE) {
  return ciphertextBlockSize - A_SIZE
}

class EncryptStream extends Pipeable {
  constructor(key, ciphertextBlockSize = DEFAULT_BLOCK_SIZE) {
    super()

    if (key.length !== KEY_SIZE) {
      throw new Error(`pull-secretstream/EncryptStream: key must be byte length of ${KEY_SIZE}`)
    }

    this.paused = true
    this.ended = false
    this.source = this.sink = null

    this.debugKey = key.slice(0, 2)
    this.encrypter = new Push(key)
    this.hasSentHeader = false

    this.plaintextBlockSize = plaintextBlockSize(ciphertextBlockSize)
    this.plaintextBufferList = new BufferList()
  }

  resume() {
    if (this.source && this.sink) {
      this.paused = this.sink.paused

      if (!this.paused) {
        if (!this.hasSentHeader) {
          const header = this.encrypter.header
          debug('%h : encrypter sending header %h', this.debugKey, header)
          this.hasSentHeader = true
          this.sink.write(header)
        }

        while (this.plaintextBufferList.length >= this.plaintextBlockSize) {
          const plaintextBlock = this.plaintextBufferList.slice(0, this.plaintextBlockSize)
          this.plaintextBufferList.consume(this.plaintextBlockSize)
          debug('%h : encrypting block %h', this.debugKey, plaintextBlock)
          const ciphertext = this.encrypter.next(plaintextBlock)
          debug('%h : encrypted ciphertext %h', this.debugKey, ciphertext)
          this.sink.write(ciphertext)
        }

        if (this.plaintextBufferList.length > 0) {
          const plaintextBlock = Buffer.alloc(this.plaintextBlockSize)
          this.plaintextBufferList.copy(plaintextBlock, 0, 0, this.plaintextBufferList.length)
          this.plaintextBufferList.consume(this.plaintextBufferList.length)
          sodium_pad(plaintextBlock, plaintextBlock.byteLength, this.plaintextBlockSize)
          debug('%h : encrypting padded block %h', this.debugKey, plaintextBlock)
          const ciphertext = this.encrypter.next(plaintextBlock)
          debug('%h : encrypted ciphertext %h', this.debugKey, ciphertext)
          this.sink.write(ciphertext)
        }

        this.source.resume()
      }
    }
  }

  end(err) {
    this.ended = err || true

    if (err && err !== true && this.sink) {
      return this.sink.end(err)
    }

    this.resume()

    const final = this.encrypter.final()
    debug('%h : encrypter final %h', this.debugKey, final)
    this.sink.write(final)
  }

  abort(err) {
    this.ended = err
    return this.source.abort(err)
  }

  write(plaintext) {
    if (!Buffer.isBuffer(plaintext)) {
      throw new Error('pull-secretstream/EncryptStream: plaintext must be buffer')
    }
    debug('%h : plaintext %h', this.debugKey, plaintext)

    this.plaintextBufferList.append(plaintext)

    if (this.sink && !this.sink.paused) {
      this.resume()
    }
  }
}

function createEncryptStream(key, blockSize = DEFAULT_BLOCK_SIZE) {
  return pushStreamToPullStream.transform(new EncryptStream(key, blockSize))
}

class DecryptStream extends Pipeable {
  constructor(key, ciphertextBlockSize = DEFAULT_BLOCK_SIZE) {
    super()

    if (key.length !== KEY_SIZE) {
      throw new Error(`pull-secretstream/DecryptStream: key must be byte length of ${KEY_SIZE}`)
    }

    this.paused = true
    this.ended = false
    this.source = this.sink = null

    this.debugKey = key.slice(0, 2)
    this.decrypter = new Pull(key)
    this.hasReceivedHeader = false

    this.ciphertextBlockSize = ciphertextBlockSize
    this.ciphertextBufferList = new BufferList()
  }

  resume() {
    if (this.source && this.sink) {
      this.paused = this.sink.paused

      if (!this.paused) {
        if (!this.hasReceivedHeader) {
          if (this.ciphertextBufferList.length >= HEADER_SIZE) {
            const header = this.ciphertextBufferList.slice(0, HEADER_SIZE)
            this.ciphertextBufferList.consume(HEADER_SIZE)
            this.decrypter.init(header)
            this.hasReceivedHeader = true
          } else {
            return
          }
        }

        while (this.ciphertextBufferList.length >= this.ciphertextBlockSize) {
          const ciphertextBlock = this.ciphertextBufferList.slice(0, this.ciphertextBlockSize)
          this.ciphertextBufferList.consume(this.ciphertextBlockSize)
          debug('%h : decrypting block %h', this.debugKey, ciphertextBlock)
          const plaintext = this.decrypter.next(ciphertextBlock)
          debug('%h : decrypted plaintext %h', this.debugKey, plaintext)
          this.sink.write(plaintext)

          if (this.decrypter.final) {
            debug('%h : decrypter final', this.debugKey)
            this.end()
            break
          }

          this.source.resume()
        }
      }
    }
  }

  end(err) {
    this.ended = err || true

    if (err && err !== true && this.sink) {
      return this.sink.end(err)
    }

    this.resume()

    if (!this.decrypter.final) {
      this.sink.end(new Error('pull-secretstream/decryptStream: stream ended before final tag'))
    } else {
      this.sink.end()
    }
  }

  abort(err) {
    this.ended = err
    return this.source.abort(err)
  }

  write(ciphertext) {
    if (!Buffer.isBuffer(ciphertext)) {
      throw new Error('pull-secretstream/DecryptStream: ciphertext must be buffer')
    }
    debug('%h : ciphertext %h', this.debugKey, ciphertext)

    this.ciphertextBufferList.append(ciphertext)

    if (this.sink && !this.sink.paused) {
      this.resume()
    }
  }
}

function createDecryptStream(key, blockSize = DEFAULT_BLOCK_SIZE) {
  return pushStreamToPullStream.transform(new DecryptStream(key, blockSize))
}

module.exports = {
  DEFAULT_BLOCK_SIZE,
  KEY_SIZE,
  createEncryptStream,
  EncryptStream,
  createDecryptStream,
  DecryptStream,
}
