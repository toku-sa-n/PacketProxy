/*
 * Copyright (c) 2008, Interactive Pulp, LLC
 * All rights reserved.
 */
package packetproxy.common

import java.math.BigInteger
import java.util.Random
import packetproxy.util.Logging.errWithStackTrace

/** An unofficial implementation of the ARC4 cipher algorithm. */
class ARC4 : Cloneable {
  private var key: ByteArray
  private var state = ByteArray(256)
  private var x = 0
  private var y = 0

  /** Constructs a new ARC4 object with a randomly generated encryption key. */
  constructor() {
    key = BigInteger(2048, Random()).toByteArray()
    reset()
  }

  /**
   * Constructs a new ARC4 object with the specified encryption key. The key can be at most 256
   * bytes in length.
   */
  constructor(key: ByteArray) {
    this.key = key.copyOf(minOf(256, key.size))
    reset()
  }

  /** Resets the cipher to start encrypting a new stream of data. */
  fun reset() {
    for (i in 0 until 256) state[i] = i.toByte()
    var j = 0
    for (i in 0 until 256) {
      j = (j + state[i] + key[i % key.size]) and 0xff
      val temp = state[i]
      state[i] = state[j]
      state[j] = temp
    }
    x = 0
    y = 0
  }

  /** Crypts the data. */
  fun crypt(data: ByteArray) {
    crypt(data, data)
  }

  /** Crypts the data from the input array to the output array. */
  fun crypt(input: ByteArray, output: ByteArray) {
    for (i in input.indices) {
      x = (x + 1) and 0xff
      y = (state[x] + y) and 0xff
      val temp = state[x]
      state[x] = state[y]
      state[y] = temp
      output[i] = (input[i].toInt() xor state[(state[x] + state[y]) and 0xff].toInt()).toByte()
    }
  }

  public override fun clone(): Any =
    try {
      (super.clone() as ARC4).also {
        it.key = key.clone()
        it.state = state.clone()
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
      throw IllegalStateException("Failed to clone ARC4", e)
    }
}
