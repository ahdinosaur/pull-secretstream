const { KEYBYTES, HEADERBYTES, ABYTES, Push, Pull } = require('sodium-secretstream')
const { BufferList } = require('bl')
const pull = require('pull-stream/pull')
const pullCat = require('pull-cat')
const pullHeader = require('pull-header')
const pullThrough = require('pull-through')
const createDebug = require('debug')
const { sodium_pad, sodium_unpad } = require('sodium-universal')

const DEFAULT_BLOCK_SIZE = 512 // bytes

createDebug.formatters.h = (v) => {
  return v.toString('hex')
}

const debug = createDebug('pull-secretstream')

module.exports = {
  KEYBYTES,
  createEncryptStream,
  createDecryptStream,
  getPlaintextBlockSize,
}

function getPlaintextBlockSize(ciphertextBlockSize = DEFAULT_BLOCK_SIZE) {
  return ciphertextBlockSize - ABYTES
}

function createEncryptStream(key, ciphertextBlockSize = DEFAULT_BLOCK_SIZE) {
  if (key.length !== KEYBYTES) {
    throw new Error(`pull-secretstream/createEncryptStream: key must be byte length of ${KEYBYTES}`)
  }

  const debugKey = key.slice(0, 2)
  const encrypter = new Push(key)
  const plaintextBlockSize = getPlaintextBlockSize(ciphertextBlockSize)
  const plaintextBufferList = new BufferList()

  const sendHeader = () => {
    let hasSentHeader = false
    return (end, cb) => {
      if (end) cb(end)
      else if (!hasSentHeader) {
        const header = encrypter.header
        debug('%h : encrypter sending header %h', debugKey, header)
        hasSentHeader = true
        cb(null, header)
      } else {
        cb(true)
      }
    }
  }

  const encryptMap = pullThrough(
    function encryptThroughData(plaintext) {
      plaintextBufferList.append(plaintext)

      while (plaintextBufferList.length >= plaintextBlockSize) {
        const plaintextBlock = plaintextBufferList.slice(0, plaintextBlockSize)
        plaintextBufferList.consume(plaintextBlockSize)
        debug('%h : encrypting block %h', debugKey, plaintextBlock)
        const ciphertext = encrypter.next(plaintextBlock)
        debug('%h : encrypted ciphertext %h', debugKey, ciphertext)
        this.queue(ciphertext)
      }

      if (plaintextBufferList.length > 0) {
        const plaintextLength = plaintextBufferList.length
        const plaintextBlock = Buffer.alloc(plaintextBlockSize)
        plaintextBufferList.copy(plaintextBlock, 0, 0, plaintextLength)
        plaintextBufferList.consume(plaintextLength)
        sodium_pad(plaintextBlock, plaintextLength, plaintextBlockSize)
        debug('%h : encrypting padded block %h', debugKey, plaintextBlock)
        const ciphertext = encrypter.next(plaintextBlock)
        debug('%h : encrypted ciphertext %h', debugKey, ciphertext)
        this.queue(ciphertext)
      }
    },
    function encryptThroughEnd() {
      const finalBlock = Buffer.alloc(plaintextBlockSize)
      sodium_pad(finalBlock, 0, plaintextBlockSize)
      const final = encrypter.final(finalBlock, Buffer.allocUnsafe(plaintextBlockSize + ABYTES))
      debug('%h : encrypter final %h', debugKey, final)
      this.queue(final)
      this.queue(null)
    },
  )

  return (stream) => {
    return pullCat([sendHeader(), pull(stream, encryptMap)])
  }
}

function createDecryptStream(key, ciphertextBlockSize = DEFAULT_BLOCK_SIZE) {
  if (key.length !== KEYBYTES) {
    throw new Error(`pull-secretstream/createDecryptStream: key must be byte length of ${KEYBYTES}`)
  }

  const debugKey = key.slice(0, 2)
  const decrypter = new Pull(key)
  const plaintextBlockSize = getPlaintextBlockSize(ciphertextBlockSize)
  const ciphertextBufferList = new BufferList()

  const receiveHeader = pullHeader(HEADERBYTES, (header) => {
    debug('%h : decrypter receiving header %h', debugKey, header)
    decrypter.init(header)
  })

  const decryptMap = pullThrough(
    function decryptThroughData(ciphertext) {
      ciphertextBufferList.append(ciphertext)

      while (ciphertextBufferList.length >= ciphertextBlockSize) {
        const ciphertextBlock = ciphertextBufferList.slice(0, ciphertextBlockSize)
        ciphertextBufferList.consume(ciphertextBlockSize)
        debug('%h : decrypting block %h', debugKey, ciphertextBlock)
        const plaintextBlock = decrypter.next(ciphertextBlock)
        debug('%h : decrypted plaintext %h', debugKey, plaintextBlock)
        const plaintextLength = sodium_unpad(
          plaintextBlock,
          plaintextBlock.length,
          plaintextBlockSize,
        )
        const plaintext = plaintextBlock.slice(0, plaintextLength)
        debug('%h : unpadded plaintext %h', debugKey, plaintext)
        this.queue(plaintext)

        if (decrypter.final) {
          debug('%h : decrypter final', debugKey)
          this.emit('end')
          break
        }
      }
    },
    function decryptThroughEnd() {
      /*
      if (!decrypter.final) {
        this.emit(
          'error',
          new Error('pull-secretstream/decryptStream: stream ended before final tag'),
        )
      }
      */
      // otherwise the stream should have already been ended.
    },
  )

  return (stream) => {
    return pull(stream, receiveHeader, decryptMap)
  }
}
