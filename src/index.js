const { KEYBYTES, HEADERBYTES, ABYTES, Push, Pull } = require('sodium-secretstream')
const { BufferList } = require('bl')
const pull = require('pull-stream/pull')
const pullEmpty = require('pull-stream/sources/empty')
const pullOnce = require('pull-stream/sources/once')
const pullError = require('pull-stream/sources/error')
const pullFlatten = require('pull-stream/throughs/flatten')
const pullMapLast = require('pull-map-last')
const pullCat = require('pull-cat')
const pullHeader = require('pull-header')
const pullPushable = require('pull-pushable')
const pullThrough = require('pull-through')
const createDebug = require('debug')
const { sodium_pad, sodium_unpad } = require('sodium-universal')
const b4a = require('b4a')

const DEFAULT_BLOCK_SIZE = 512 // bytes

createDebug.formatters.h = (v) => {
  return v.toString('hex')
}

const debug = createDebug('pull-secretstream')

module.exports = {
  KEY_SIZE: KEYBYTES,
  DEFAULT_BLOCK_SIZE,
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

  const encryptMap = () => {
    let hasQueuedMicrotask = false
    let hasEnded = false

    return pull(
      pullMapLast(
        function encryptMapData(plaintext) {
          plaintextBufferList.append(plaintext)

          // for each event loop, run one microtask that will
          //   encrypt and send all of our queued buffers.
          //   (including the final marker if we ended.)
          if (!hasQueuedMicrotask) {
            debug('%h : queued microtask', debugKey)
            hasQueuedMicrotask = true
            const pushable = pullPushable(true)
            queueMicrotask(() => {
              debug('%h : running microtask', debugKey)
              hasQueuedMicrotask = false
              try {
                pushCiphertexts(pushable.push, hasEnded)
                pushable.end()
              } catch (err) {
                pushable.end(err)
              }
            })
            return pushable.source
          }

          return pullEmpty()
        },
        function encryptMapEnd() {
          debug('%h : ending encrypt map', debugKey)

          hasEnded = true

          // if we have a microtask, that will send the final marker.
          if (!hasQueuedMicrotask) {
            try {
              const final = getFinal()
              return pullOnce(final)
            } catch (err) {
              return pullError(err)
            }
          }

          return pullEmpty()
        },
      ),
      pullFlatten(),
    )
  }

  return (stream) => {
    return pullCat([sendHeader(), pull(stream, encryptMap())])
  }

  function pushCiphertexts(push, hasEnded) {
    // while we still have enough bytes to send full blocks
    while (plaintextBufferList.length >= plaintextBlockSize) {
      const plaintextBlock = plaintextBufferList.slice(0, plaintextBlockSize)
      plaintextBufferList.consume(plaintextBlockSize)
      debug('%h : encrypting block %h', debugKey, plaintextBlock)
      const ciphertext = encrypter.next(plaintextBlock)
      debug('%h : encrypted ciphertext %h', debugKey, ciphertext)
      push(ciphertext)
    }

    // send the remaining as a padded block
    if (plaintextBufferList.length > 0) {
      const plaintextLength = plaintextBufferList.length
      const plaintextBlock = Buffer.alloc(plaintextBlockSize)
      plaintextBufferList.copy(plaintextBlock, 0, 0, plaintextLength)
      plaintextBufferList.consume(plaintextLength)
      sodium_pad(plaintextBlock, plaintextLength, plaintextBlockSize)
      debug('%h : encrypting padded block %h', debugKey, plaintextBlock)
      let ciphertext
      if (!hasEnded) {
        ciphertext = encrypter.next(plaintextBlock)
        debug('%h : encrypted ciphertext %h', debugKey, ciphertext)
      } else {
        ciphertext = encrypter.final(plaintextBlock, b4a.allocUnsafe(plaintextBlockSize + ABYTES))
        debug('%h : encrypted final %h', debugKey, ciphertext)
      }
      push(ciphertext)
    }
  }

  function getFinal() {
    // send a block full of zeros with the final marker
    const finalBlock = Buffer.alloc(plaintextBlockSize)
    sodium_pad(finalBlock, 0, plaintextBlockSize)
    const final = encrypter.final(finalBlock, b4a.allocUnsafe(plaintextBlockSize + ABYTES))
    debug('%h : encrypted final %h', debugKey, final)
    return final
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

      // while we still have enough bytes for full blocks
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
        if (plaintext.byteLength > 0) {
          this.queue(plaintext)
        }

        if (decrypter.final) {
          debug('%h : decrypter final', debugKey)
          break
        }
      }
    },
    function decryptThroughEnd() {
      if (!decrypter.final) {
        this.emit(
          'error',
          new Error('pull-secretstream/decryptStream: stream ended before final tag'),
        )
      }
      this.queue(null)
    },
  )

  return (stream) => {
    return pull(stream, receiveHeader, decryptMap)
  }
}
