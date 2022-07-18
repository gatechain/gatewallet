const circomlib = require('circomlib')
const { utils, Scalar } = require('ffjavascript');
const { ethers } = require('ethers')
const base64url = require('base64url')
const jsSha3 = require('js-sha3')

const { METAMASK_MESSAGE, CREATE_ACCOUNT_AUTH_MESSAGE, EIP_712_VERSION, EIP_712_PROVIDER, CONTRACT_ADDRESSES, ContractNames } = require('./const.js');

export function hexToBuffer(hexString) {
    return Buffer.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)))
}
export function bufToHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), x => ('00' + x.toString(16)).slice(-2)).join('')
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
        this.config = {
            METAMASK_MESSAGE,
            EIP_712_PROVIDER,
            EIP_712_VERSION,
            CONTRACT_ADDRESSES,
            CREATE_ACCOUNT_AUTH_MESSAGE,
            contractLeftMap: {
                BTC: 0,
                ETH: 1
            },
            contractRightMap: {
                USDC: 0,
                USDT: 1
            }
        }

        if (config) {
            this.config = {
                ...this.config,
                ...config
            } 
            console.log('config', config, 'this.config', this.config)
        }
        const publicKey = circomlib.eddsa.prv2pub(privateKey)
        this.privateKey = privateKey
        this.privateKeyHex = bufToHex(privateKey)
        this.publicKey = [publicKey[0].toString(), publicKey[1].toString()]
        this.publicKeyHex = [publicKey[0].toString(16), publicKey[1].toString(16)]

        const compressedPublicKey = utils.leBuff2int(circomlib.babyJub.packPoint(publicKey))
        this.publicKeyCompressed = compressedPublicKey.toString()
        this.publicKeyCompressedHex = ethers.utils.hexZeroPad(`0x${compressedPublicKey.toString(16)}`, 32).slice(2)
        this.publicKeyBase64 = hexToBase64BJJ(this.publicKeyCompressedHex)
        this.gateEthereumAddress = gateEthereumAddress

    }
    /**
     * Builds the message to hash. Used when signing transactions
     * @param {Object} encodedTransaction - Transaction object return from `encodeTransaction`
     * @returns {Scalar} Message to sign
     */
    buildTransactionHashMessage(tx, type) {
       return buildTransactionHashMessage(tx, type, this.config)
    }

    getHashMessage (tx, type) {
        return this.buildTransactionHashMessage(tx, type)
    }

    getSignature(transaction, type) {
        try {
            const hashMessage = this.getHashMessage(transaction, type);
            const signature = circomlib.eddsa.signPoseidon(this.privateKey, hashMessage)
            const packedSignature = circomlib.eddsa.packSignature(signature)
            return '0x' + packedSignature.toString('hex')
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
        const signature = await signer._signTypedData(domain, types, value)
        
        return {
            signature,
            ...value
        }
    }
}

/**
 * Builds the message to hash. Used when signing transactions
 * @param {Object} encodedTransaction - Transaction object return from `encodeTransaction`
 * @returns {Scalar} Message to sign
 */
function buildTransactionHashMessage(tx, type, config) {
    let txCompressedData 

    switch (type) {
        case 'order':
            txCompressedData = buildOrderCompressedData(tx, config)
            break;

        case 'cancelOrder':
            txCompressedData = buildCancelOrderCompressedData(tx)
            break;
        case 'withdraw':
            txCompressedData = buildWithdrawCompressedData(tx)
            break;
        default:
            throw new Error('type can be order cancelOrder withdraw')
    }

    const h = circomlib.poseidon([
        txCompressedData
    ])

    return h
}


/**
 * Encode tx compressed data
 * @param {Object} tx - Transaction object returned by `encodeTransaction`
 * @returns {Scalar} Encoded tx compressed data
 * @private
 */
function buildOrderCompressedData(tx, config) {
    const {contractLeftMap, contractRightMap} = config
    let res = Scalar.e(0)
    let contract_left = tx.contract.split('_')[0]
    let contract_right = tx.contract.split('_')[1]

    if (!contractLeftMap[contract_left].toString()) {
        throw Error(`${contract_left} does not exist in ${JSON.stringify(contractLeftMap)}`)
    }
    if (!contractRightMap[contract_right].toString()) {
        throw Error(`${contract_right} does not exist in ${JSON.stringify(contractRightMap)}`)
    }

    res = Scalar.add(res, tx.user_id || 0)

    let left = contract_left === 'BTC' ? 0 : 1
    res = Scalar.add(res, Scalar.shl(left || 0, 48))

    let right = contract_right === 'USDC' ? 0 : 1
    res = Scalar.add(res, Scalar.shl(right || 0, 56))

    let size_ = tx.size >= 0 ? 0 : 1;
    res = Scalar.add(res, Scalar.shl(size_ || 0, 60))

    res = Scalar.add(res, Scalar.shl(tx.size || 0, 61))

    let price= parseFloat(`0.${tx.price}`) * 10^18;
    res = Scalar.add(res, Scalar.shl(price || 0, 124));
    return res
}

function buildCancelOrderCompressedData(tx) {
    let res = Scalar.e(0)

    res = Scalar.add(res, tx.user_id || 0)
    res = Scalar.add(res, Scalar.shl(tx.order_id || 0, 48))
    return res
}

function buildWithdrawCompressedData(tx) {
    let res = Scalar.e(0)

    res = Scalar.add(res, tx.user_id || 0)
    res = Scalar.add(res, Scalar.shl(tx.amount * 10^18 || 0, 48))
    return res
}

/**
 * Create GateWallet instance.
 * @param {*} signer 
 * @returns {object} {gateWallet,  gateEthereumAddress}
 */
 async function createWalletFromGateChainAccount(signer, config, privateKeyHex) {
    const gtAddress = await signer.getAddress()
    const gateAddress = `gate:${gtAddress}`;

    let bufferSignature
    if (privateKeyHex) {
        bufferSignature = hexToBuffer(privateKeyHex)
    } else {
        const metamask_message = (config && config.METAMASK_MESSAGE ) ? config.METAMASK_MESSAGE :  METAMASK_MESSAGE
        const signature = await signer.signMessage(metamask_message)
        const hashedSignature = jsSha3.keccak256(signature)
        bufferSignature = hexToBuffer(hashedSignature)
    }
   
    const gateWallet = new GateWallet(bufferSignature, gateAddress, config)
    return { gateWallet, gateAddress}
}


export default {
    GateWallet,
    createWalletFromGateChainAccount,
    buildTransactionHashMessage
}