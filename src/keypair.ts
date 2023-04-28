import * as uint8arrays from "uint8arrays"
import * as ed25519 from "@stablelib/ed25519"
import * as crypto from "./crypto"

import { DidableKey, Encodings, ExportableKey } from "@mkabanau/core"

import { signMessage } from "@wagmi/core"
import { fetchSigner } from '@wagmi/core'
import { InjectedConnector } from '@wagmi/core/connectors/injected'
// import { Signer } from "ethers"
import { verifyMessage, recoverPublicKey, hashMessage, arrayify } from 'ethers/lib/utils'


export class Secp256k1 implements DidableKey, ExportableKey {

  public jwtAlg = "secp256k1"

  private secretKey: Uint8Array
  private publicKey: Uint8Array
  private exportable: boolean

  constructor(secretKey: Uint8Array, publicKey: Uint8Array, exportable: boolean) {
    this.secretKey = secretKey
    this.publicKey = publicKey
    this.exportable = exportable
  }

  static async create(params?: {
    exportable: boolean
  }): Promise<Secp256k1> {
    const { exportable } = params || {}
    const keypair = ed25519.generateKeyPair()
    // const { address } = await connect({
    //   connector: new InjectedConnector(),
    // })

    let signer = await fetchSigner()
    let pubkey: Uint8Array
    if (!signer) {
      throw Error("signer is not found")
    }
    console.log('fetch signer')
    const address = await signer.getAddress()
    console.log(signer)
    console.log(address)
    let msg = "recover pb"
    let sig = await signer.signMessage(msg)

    let publicKey = recoverPublicKey(arrayify(hashMessage(msg)), sig)
    pubkey = arrayify(publicKey)
    console.log("public key", publicKey)
    let recoverdAddress = verifyMessage(msg, sig)
    console.log("recovered address", recoverdAddress)

    await ({
      connector: new InjectedConnector(),
    })
    console.log("connect when key is created")
    return new Secp256k1(keypair.secretKey, pubkey, exportable ?? false)
  }

  static fromSecretKey(key: string, params?: {
    format?: Encodings
    exportable?: boolean
  }): Secp256k1 {
    const { format = "base64pad", exportable = false } = params || {}
    const secretKey = uint8arrays.fromString(key, format)
    const publicKey = ed25519.extractPublicKeyFromSecretKey(secretKey)
    return new Secp256k1(secretKey, publicKey, exportable)
  }

  did(): string {
    return crypto.publicKeyToDid(this.publicKey)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    
    const stringSig = await signMessage({ "message": msg })
    console.log("messafe", msg)
    console.log("signed by wallet:", stringSig)
    //const stringSig = "0x111"
    let sig = uint8arrays.fromString(stringSig)
    return sig
  }

  async export(format: Encodings = "base64pad"): Promise<string> {
    if (!this.exportable) {
      throw new Error("Key is not exportable")
    }
    return uint8arrays.toString(this.secretKey, format)
  }

}


export default Secp256k1
