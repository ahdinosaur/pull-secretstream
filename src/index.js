const { KEYBYTES, HEADERBYTES, Push, Pull } = require('sodium-secretstream')
const pull = require('pull-stream/pull')
const pullMap = require('pull-stream/throughs/map')
const pullCat = require('pull-cat')
const pullMapLast = require('pull-map-last')
const pullHeader = require('pull-header')

module.exports = {
  KEYBYTES,
  createBoxStream,
  createUnboxStream,
}

function createBoxStream(key) {
  const boxer = new Push(key)

  const sendHeader = pull.values([boxer.header])

  const boxMap = pullMapLast(
    (plaintext) => {
      return boxer.next(plaintext)
    },
    () => {
      return boxer.final()
    },
  )

  return (stream) => {
    return pullCat([sendHeader, pull(stream, boxMap)])
  }
}

function createUnboxStream(key) {
  const unboxer = new Pull(key)

  const receiveHeader = pullHeader(HEADERBYTES, (header) => {
    unboxer.init(header)
  })

  const unboxMap = pullMap((ciphertext) => {
    return unboxer.next(ciphertext)
  })

  return (stream) => {
    return pull(stream, receiveHeader, unboxMap)
  }
}
