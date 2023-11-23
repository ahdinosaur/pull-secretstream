const { KEYBYTES, HEADERBYTES, Push, Pull } = require('sodium-secretstream')
const pull = require('pull-stream/pull')
const pullCat = require('pull-cat')
const pullHeader = require('pull-header')
const pullThrough = require('pull-through')
const createDebug = require('debug')

createDebug.formatters.h = (v) => {
  return v.toString('hex')
}

const debug = createDebug('pull-secretstream')

module.exports = {
  KEYBYTES,
  createEncryptStream,
  createDecryptStream,
}

function createEncryptStream(key) {
  if (key.length !== KEYBYTES) {
    throw new Error(`pull-secretstream/createEncryptStream: key must be byte length of ${KEYBYTES}`)
  }
  const debugKey = key.slice(0, 2)

  const encrypter = new Push(key)

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
      debug('%h : encrypting plaintext %h', debugKey, plaintext)
      const ciphertext = encrypter.next(plaintext)
      debug('%h : encrypted ciphertext %h', debugKey, ciphertext)
      this.queue(ciphertext)
    },
    function encryptThroughEnd() {
      const final = encrypter.final()
      debug('%h : encrypter final %h', debugKey, final)
      this.queue(final)
      this.queue(null)
    },
  )

  return (stream) => {
    return pullCat([sendHeader(), pull(stream, encryptMap)])
  }
}

function createDecryptStream(key) {
  if (key.length !== KEYBYTES) {
    throw new Error(`pull-secretstream/createDecryptStream: key must be byte length of ${KEYBYTES}`)
  }
  const debugKey = key.slice(0, 2)

  const decrypter = new Pull(key)

  const receiveHeader = pullHeader(HEADERBYTES, (header) => {
    debug('%h : decrypter receiving header %h', debugKey, header)
    decrypter.init(header)
  })

  const decryptMap = pullThrough(
    function decryptThroughData(ciphertext) {
      debug('%h : decrypting ciphertext %h', debugKey, ciphertext)
      const plaintext = decrypter.next(ciphertext)
      debug('%h : decrypted ciphertext %h', debugKey, plaintext)
      this.queue(plaintext)
      if (decrypter.final) {
        debug('%h : decrypter final', debugKey)
        this.emit('end')
      }
    },
    function decryptThroughEnd() {
      if (!decrypter.final) {
        this.emit(
          'error',
          new Error('pull-secretstream/decryptStream: stream ended before final tag'),
        )
      }
      // otherwise the stream should have already been ended.
    },
  )

  return (stream) => {
    return pull(stream, receiveHeader, decryptMap)
  }
}
