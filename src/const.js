const METAMASK_MESSAGE = 'GateChain Network account access.\n\nSign this message if you are in a trusted application only.'

const CREATE_ACCOUNT_AUTH_MESSAGE = 'Account creation'
const EIP_712_VERSION = '1'
const EIP_712_PROVIDER = 'GateChain Network'

const ContractNames = {
  GateChain: 'GateChain',
  WithdrawalDelayer: 'WithdrawalDelayer'
}

const CONTRACT_ADDRESSES = {
  [ContractNames.GateChain]: '',
  [ContractNames.WithdrawalDelayer]: ''
}

export {
  METAMASK_MESSAGE,
  CREATE_ACCOUNT_AUTH_MESSAGE,
  EIP_712_VERSION,
  EIP_712_PROVIDER,
  CONTRACT_ADDRESSES,
  ContractNames,
}
