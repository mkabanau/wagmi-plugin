import { DidKeyPlugin } from "@mkabanau/core"
import * as crypto from "./crypto"
import { verifyMessage,computeAddress } from 'ethers/lib/utils'

import { SECP256K1_PUB_DID_PREFIX } from "./prefixes"
import * as uint8arrays from "uint8arrays" 

export const secp256k1Plugin: DidKeyPlugin = {
// The varint encoding is described here: https://github.com/multiformats/unsigned-varint
  prefix: SECP256K1_PUB_DID_PREFIX,
  jwtAlg: "secp256k1",
  verifySignature: async (did: string, data: Uint8Array, sig: Uint8Array) => {
    const publicKey = crypto.didToPublicKey(did)
    const recoveredAddress = computeAddress(publicKey)
    let encodedSig = uint8arrays.toString(sig)
    let address = verifyMessage(data, encodedSig)
    console.log(address, "===",recoveredAddress)
    return recoveredAddress === address
  }
}