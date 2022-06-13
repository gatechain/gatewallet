const circomlib = require('circomlib')
const { utils, Scalar, bn128 } = require('ffjavascript');
const { ethers } = require('ethers')
const base64url = require('base64url')
const jsSha3 = require('js-sha3')

const Fr = bn128.Fr;
const { METAMASK_MESSAGE, CREATE_ACCOUNT_AUTH_MESSAGE, EIP_712_VERSION, EIP_712_PROVIDER, CONTRACT_ADDRESSES, ContractNames } = require('./const.js');

export function hexToBuffer(hexString) {
    return Buffer.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)))
}

export function padZeros(string, length) {
    if (length > string.length) { string = '0'.repeat(length - string.length) + string }
    return string
  }

  function hexToBase64BJJ(bjjCompressedHex) {
    // swap endian
    const bjjScalar = Scalar.fromString(bjjCompressedHex, 16)
    const bjjBuff = utils.leInt2Buff(bjjScalar, 32)
    const bjjSwap = padZeros(utils.beBuff2int(bjjBuff).toString(16), 64)
  
    const bjjSwapBuffer = Buffer.from(bjjSwap, 'hex')
  
    let sum = 0
  
    for (let i = 0; i < bjjSwapBuffer.length; i++) {
      sum += bjjSwapBuffer[i]
      sum = sum % 2 ** 8
    }
  
    const sumBuff = Buffer.alloc(1)
    sumBuff.writeUInt8(sum)
  
    const finalBuffBjj = Buffer.concat([bjjSwapBuffer, sumBuff])
  
    return `gate:${base64url.encode(finalBuffBjj)}`
  }


/**
 * @class
 * Manage Babyjubjub keys
 * Perform standard wallet actions like signing
 */
class GateWallet {
    constructor(privateKey, gateEthereumAddress, config) {
        if (privateKey.length !== 32) {
            throw new Error('Private key buffer must be 32 bytes')
        }
        if (config) {
            this.config = config 
        } else {
            this.config = {
                METAMASK_MESSAGE,
                EIP_712_PROVIDER,
                EIP_712_VERSION,
                CONTRACT_ADDRESSES,
                CREATE_ACCOUNT_AUTH_MESSAGE
            }
        }

        console.log(privateKey, gateEthereumAddress, config)

        // if (!isHermezEthereumAddress(gateEthereumAddress)) {
        //     throw new Error('Invalid Hermez Ethereum address')
        // }
        const publicKey = circomlib.eddsa.prv2pub(privateKey)
        this.privateKey = privateKey
        this.publicKey = [publicKey[0].toString(), publicKey[1].toString()]
        this.publicKeyHex = [publicKey[0].toString(16), publicKey[1].toString(16)]

        const compressedPublicKey = utils.leBuff2int(circomlib.babyJub.packPoint(publicKey))
        this.publicKeyCompressed = compressedPublicKey.toString()
        this.publicKeyCompressedHex = ethers.utils.hexZeroPad(`0x${compressedPublicKey.toString(16)}`, 32).slice(2)
        this.publicKeyBase64 = hexToBase64BJJ(this.publicKeyCompressedHex)
        this.gateEthereumAddress = gateEthereumAddress

    }

    getHashMessage (val) {
        return Fr.e(val)
    }

    getSignature(transaction, encodedTransaction) {
        //   const hashMessage = buildTransactionHashMessage(encodedTransaction)
        try {
            const hashMessage = this.getHashMessage(encodedTransaction);
            const signature = circomlib.eddsa.signPoseidon(this.privateKey, hashMessage)
            return signature;
        } catch (error) {
            throw new Error('Signature Error.')  
        }
    }

    /**
     * @param {String} hashMessage 
     * @param {String} signature 
     * @returns {boolean}
     */
    verifySignature (hashMessage, signature) {
        // 验证签名
        const isTrur = circomlib.eddsa.verifyPoseidon(hashMessage, signature, circomlib.eddsa.prv2pub(this.privateKey))
        return isTrur
    }

    signTransaction_(transaction, signature) {
        const packedSignature = circomlib.eddsa.packSignature(signature)
        transaction.signature = packedSignature.toString('hex')
        return transaction
    }

    signTransaction (transaction, encodedTransaction) {
        const signature = this.getSignature(transaction, encodedTransaction)
        const hashMessage = this.getHashMessage(encodedTransaction);
        const isTrur = this.verifySignature(hashMessage, signature)

        if (!isTrur) {
            throw new Error('Error: verifySignature is false.')
        }
        return this.signTransaction_(transaction, signature)
    }

    async signCreateAccountAuthorization(provider, signer) {
        const chainId = (await provider.getNetwork()).chainId
        const bJJ = this.publicKeyCompressedHex.startsWith('0x') ? this.publicKeyCompressedHex : `0x${this.publicKeyCompressedHex}`
        const domain = {
            name:  this.config.EIP_712_PROVIDER,
            version: this.config.EIP_712_VERSION,
            chainId,
            verifyingContract: this.config.CONTRACT_ADDRESSES[ContractNames.GateChain]
        }
        const types = {
            Authorise: [
                { name: 'Provider', type: 'string' },
                { name: 'Authorisation', type: 'string' },
                { name: 'BJJKey', type: 'bytes32' }
            ]
        }
        const value = {
            Provider: EIP_712_PROVIDER,
            Authorisation: this.config.CREATE_ACCOUNT_AUTH_MESSAGE,
            BJJKey: bJJ
        }
        return signer._signTypedData(domain, types, value)
    }
}


/**
 * Create GateWallet instance.
 * @param {*} signer 
 * @returns {object} {gateWallet,  gateEthereumAddress}
 */
async function createWalletFromGateChainAccount(signer, config) {
    const metamask_message = (config && config.METAMASK_MESSAGE ) ? config.METAMASK_MESSAGE :  METAMASK_MESSAGE
    const gtAddress = await signer.getAddress()
    const gateAddress = `gate:${gtAddress}`;
    const signature = await signer.signMessage(metamask_message)
    const hashedSignature = jsSha3.keccak256(signature)
    const bufferSignature = hexToBuffer(hashedSignature)
    const gateWallet = new GateWallet(bufferSignature, gateAddress, config)
    return { gateWallet, gateAddress}
}

export default {
    GateWallet,
    createWalletFromGateChainAccount
}