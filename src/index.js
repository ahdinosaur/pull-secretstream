const { KEYBYTES, HEADERBYTES, Push, Pull } = require('sodium-secretstream')
const pull = require('pull-stream/pull')
const pullMap = require('pull-stream/throughs/map')
const pullCat = require('pull-cat')
const pullMapLast = require('pull-map-last')
const pullHeader = require('pull-header')

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

  const decryptMap = pullMap((ciphertext) => {
    return decrypter.next(ciphertext)
  })

  return (stream) => {
    return pull(stream, receiveHeader, decryptMap)
  }
}
