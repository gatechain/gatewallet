const circomlib = require("circomlib");
const { utils, Scalar } = require("ffjavascript");
const { ethers } = require("ethers");
const base64url = require("base64url");
const jsSha3 = require("js-sha3");
const Deciamls = require("decimal.js");

const {
  METAMASK_MESSAGE,
  CREATE_ACCOUNT_AUTH_MESSAGE,
  EIP_712_VERSION,
  EIP_712_PROVIDER,
  CONTRACT_ADDRESSES,
  ContractNames,
} = require("./const.js");

function hexToBuffer(hexString) {
  return Buffer.from(
    hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
  );
}

function bufToHex(buf) {
  return Array.prototype.map
    .call(new Uint8Array(buf), (x) => ("00" + x.toString(16)).slice(-2))
    .join("");
}

function padZeros(string, length) {
  if (length > string.length) {
    string = "0".repeat(length - string.length) + string;
  }
  return string;
}

function hexToBase64BJJ(bjjCompressedHex) {
  // swap endian
  const bjjScalar = Scalar.fromString(bjjCompressedHex, 16);
  const bjjBuff = utils.leInt2Buff(bjjScalar, 32);
  const bjjSwap = padZeros(utils.beBuff2int(bjjBuff).toString(16), 64);

  const bjjSwapBuffer = Buffer.from(bjjSwap, "hex");

  let sum = 0;

  for (let i = 0; i < bjjSwapBuffer.length; i++) {
    sum += bjjSwapBuffer[i];
    sum = sum % 2 ** 8;
  }

  const sumBuff = Buffer.alloc(1);
  sumBuff.writeUInt8(sum);

  const finalBuffBjj = Buffer.concat([bjjSwapBuffer, sumBuff]);

  return `gate:${base64url.encode(finalBuffBjj)}`;
}

/**
 * @class
 * Manage Babyjubjub keys
 * Perform standard wallet actions like signing
 */
class GateWallet {
  constructor(privateKey, gateEthereumAddress, config) {
    if (privateKey.length !== 32) {
      throw new Error("Private key buffer must be 32 bytes");
    }
    this.config = {
      METAMASK_MESSAGE,
      EIP_712_PROVIDER,
      EIP_712_VERSION,
      CONTRACT_ADDRESSES,
      CREATE_ACCOUNT_AUTH_MESSAGE,
      contractNames: [], //eg: ['BTC_USDT']
    };

    if (config) {
      this.config = {
        ...this.config,
        ...config,
      };
      console.log("config----", config, "this.config", this.config);
    }
    const publicKey = circomlib.eddsa.prv2pub(privateKey);
    this.privateKey = privateKey;
    this.privateKeyHex = bufToHex(privateKey);
    this.publicKey = [publicKey[0].toString(), publicKey[1].toString()];
    this.publicKeyHex = [publicKey[0].toString(16), publicKey[1].toString(16)];

    const compressedPublicKey = utils.leBuff2int(
      circomlib.babyJub.packPoint(publicKey)
    );
    this.publicKeyCompressed = compressedPublicKey.toString();
    this.publicKeyCompressedHex = ethers.utils
      .hexZeroPad(`0x${compressedPublicKey.toString(16)}`, 32)
      .slice(2);
    this.publicKeyBase64 = hexToBase64BJJ(this.publicKeyCompressedHex);
    this.gateEthereumAddress = gateEthereumAddress;
  }
  /**
   * Builds the message to hash. Used when signing transactions
   * @param {Object} encodedTransaction - Transaction object return from `encodeTransaction`
   * @returns {Scalar} Message to sign
   */
  buildTransactionHashMessage(tx, type) {
    return buildTransactionHashMessage(tx, type, this.config);
  }

  getHashMessage(tx, type) {
    return this.buildTransactionHashMessage(tx, type);
  }

  getSignature(transaction, type) {
    try {
      const hashMessage = this.getHashMessage(transaction, type);
      const signature = circomlib.eddsa.signPoseidon(
        this.privateKey,
        hashMessage
      );
      const packedSignature = circomlib.eddsa.packSignature(signature);
      return "0x" + packedSignature.toString("hex");
    } catch (error) {
      throw new Error("Signature Error.");
    }
  }

  /**
   * @param {String} hashMessage
   * @param {String} signature
   * @returns {boolean}
   */
  verifySignature(hashMessage, signature) {
    // 验证签名
    const isTrur = circomlib.eddsa.verifyPoseidon(
      hashMessage,
      signature,
      circomlib.eddsa.prv2pub(this.privateKey)
    );
    return isTrur;
  }

  async signCreateAccountAuthorization(provider, signer) {
    const chainId = (await provider.getNetwork()).chainId;
    const bJJ = this.publicKeyCompressedHex.startsWith("0x")
      ? this.publicKeyCompressedHex
      : `0x${this.publicKeyCompressedHex}`;
    const domain = {
      name: this.config.EIP_712_PROVIDER,
      version: this.config.EIP_712_VERSION,
      chainId,
      verifyingContract:
        this.config.CONTRACT_ADDRESSES[ContractNames.GateChain],
    };
    const types = {
      Authorise: [
        { name: "Provider", type: "string" },
        { name: "Authorisation", type: "string" },
        { name: "BJJKey", type: "bytes32" },
      ],
    };
    const value = {
      Provider: EIP_712_PROVIDER,
      Authorisation: this.config.CREATE_ACCOUNT_AUTH_MESSAGE,
      BJJKey: bJJ,
    };
    const signature = await signer._signTypedData(domain, types, value);

    return {
      signature,
      ...value,
    };
  }
}

/**
 * Builds the message to hash. Used when signing transactions
 * @param {Object} encodedTransaction - Transaction object return from `encodeTransaction`
 * @returns {Scalar} Message to sign
 */
function buildTransactionHashMessage(tx, type, config) {
  let txCompressedData;

  switch (type) {
    case "order":
      txCompressedData = buildOrderCompressedData(tx, config);
      break;

    case "cancelOrder":
      txCompressedData = buildCancelOrderCompressedData(tx);
      break;
    case "withdraw":
      txCompressedData = buildWithdrawCompressedData(tx);
      break;
    default:
      throw new Error("type can be order cancelOrder withdraw");
  }

  const h = circomlib.poseidon([txCompressedData]);

  return h;
}

/**
 * Encode tx compressed data
 * @param {Object} tx - Transaction object returned by `encodeTransaction`
 * @returns {Scalar} Encoded tx compressed data
 * @private
 */
function buildOrderCompressedData(tx, config) {
  const { contractNames } = config;
  const contractId = getContractId(contractNames, tx.contract);
  if (!contractId) {
    console.warn("The market does not exist");
    throw new Error("The market does not exist");
  }
  let res = Scalar.e(0);

  res = Scalar.add(res, tx.user_id || 0);

  res = Scalar.add(res, Scalar.shl(contractId || 0, 48));

  let price = new Deciamls(tx.price).mul(Math.pow(10, 18)).toFixed();
  res = Scalar.add(res, Scalar.shl(price || 0, 64));

  res = Scalar.add(res, Scalar.shl(Math.abs(tx.size) || 0, 192));

  let size_ = tx.size >= 0 ? 0 : 1;
  res = Scalar.add(res, Scalar.shl(size_ || 0, 255));
  return res;
}

function buildCancelOrderCompressedData(tx) {
  let res = Scalar.e(0);

  res = Scalar.add(res, tx.user_id || 0);
  res = Scalar.add(res, Scalar.shl(tx.order_id || 0, 48));
  return res;
}

function buildWithdrawCompressedData(tx) {
  let res = Scalar.e(0);

  res = Scalar.add(res, tx.user_id || 0);
  const amount = new Deciamls(tx.amount).mul(Math.pow(10, 18)).toFixed();
  res = Scalar.add(res, Scalar.shl(amount || 0, 48));
  return res;
}

/**
 * Create GateWallet instance.
 * @param {*} signer
 * @returns {object} {gateWallet,  gateEthereumAddress}
 */
async function createWalletFromGateChainAccount(signer, config, privateKeyHex) {
  const gtAddress = await signer.getAddress();
  const gateAddress = `gate:${gtAddress}`;

  let bufferSignature;
  if (privateKeyHex) {
    bufferSignature = hexToBuffer(privateKeyHex);
  } else {
    const metamask_message =
      config && config.METAMASK_MESSAGE
        ? config.METAMASK_MESSAGE
        : METAMASK_MESSAGE;
    const signature = await signer.signMessage(metamask_message);
    const hashedSignature = jsSha3.keccak256(signature);
    bufferSignature = hexToBuffer(hashedSignature);
  }

  const gateWallet = new GateWallet(bufferSignature, gateAddress, config);
  return { gateWallet, gateAddress };
}

function getContractId(contractNames, _name) {
  for (let index = 0; index < contractNames.length; index++) {
    const contractName = contractNames[index];
    if (_name === contractName) {
      return 256 + index;
    }
  }
}

module.exports = {
  GateWallet,
  createWalletFromGateChainAccount,
  buildTransactionHashMessage,
  hexToBuffer,
  bufToHex,
  padZeros,
  hexToBase64BJJ,
  getContractId,
};
