import { SECP256K1_PUB_DID_PREFIX } from "./prefixes"
import { didFromKeyBytes, keyBytesFromDid } from "./util"

export const didToPublicKey = (did: string): Uint8Array => {
  return keyBytesFromDid(did, SECP256K1_PUB_DID_PREFIX)
}

export const publicKeyToDid = (pubkey: Uint8Array): string => {
  return didFromKeyBytes(pubkey, SECP256K1_PUB_DID_PREFIX)
}
