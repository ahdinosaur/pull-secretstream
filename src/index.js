const { KEYBYTES, HEADERBYTES, Push, Pull } = require('sodium-secretstream')
const pull = require('pull-stream/pull')
const pullCat = require('pull-cat')
const pullMapLast = require('pull-map-last')
const pullHeader = require('pull-header')
const pullThrough = require('pull-through')

module.exports = {
  KEYBYTES,
  createEncryptStream,
  createDecryptStream,
}

function createEncryptStream(key) {
  if (key.length !== KEYBYTES) {
    throw new Error(`pull-secretstream/createEncryptStream: key must be byte length of ${KEYBYTES}`)
  }

  const encrypter = new Push(key)

  const sendHeader = pull.values([encrypter.header])

  const encryptMap = pullMapLast(
    (plaintext) => {
      return encrypter.next(plaintext)
    },
    () => {
      return encrypter.final()
    },
  )

  return (stream) => {
    return pullCat([sendHeader, pull(stream, encryptMap)])
  }
}

function createDecryptStream(key) {
  if (key.length !== KEYBYTES) {
    throw new Error(`pull-secretstream/createDecryptStream: key must be byte length of ${KEYBYTES}`)
  }

  const decrypter = new Pull(key)

  const receiveHeader = pullHeader(HEADERBYTES, (header) => {
    decrypter.init(header)
  })

  const decryptMap = pullThrough(
    function decryptThroughData(ciphertext) {
      this.queue(decrypter.next(ciphertext))
      if (decrypter.final) {
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
