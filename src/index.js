import MetaMaskOnboarding from '@metamask/onboarding'
// eslint-disable-next-line camelcase
import { encrypt, recoverPersonalSignature, recoverTypedSignatureLegacy, recoverTypedSignature, recoverTypedSignature_v4 } from 'eth-sig-util'
import { ethers } from 'ethers'
import { toChecksumAddress } from 'ethereumjs-util'
import { piggybankBytecode, piggybankAbi } from '../bin/contracts/Piggybank.json'
import { javierCoinAbi } from '../bin/contracts/JavierCoin.json'
import { hasAnOwnerAbi } from '../bin/contracts/HasAnOwner.json'
import { jhcAbi } from '../bin/contracts/JHC.json'

let ethersProvider
let piggybankFactory

const NETWORKS = {
  1: 'Mainnet',
  4: 'Rinkeby',
  5: 'Goerli',
  42: 'Kovan',
}

const currentUrl = new URL(window.location.href)
const forwarderOrigin = currentUrl.hostname === 'localhost'
  ? 'http://localhost:9010'
  : undefined

const { isMetaMaskInstalled } = MetaMaskOnboarding

const sectionClass = document.getElementsByClassName('section-class')

// Dapp Status Section
const statusDiv = document.getElementById('status')
const networkDiv = document.getElementById('network')
const chainIdDiv = document.getElementById('chainId')
const accountsDiv = document.getElementById('accounts')

// Basic Actions Section
const connectButton = document.getElementById('connectButton')
const getAccountsButton = document.getElementById('getAccounts')
const getAccountsResults = document.getElementById('getAccountsResult')

// Permissions Actions Section
const requestPermissionsButton = document.getElementById('requestPermissions')
const getPermissionsButton = document.getElementById('getPermissions')
const permissionsResult = document.getElementById('permissionsResult')

// Contract Section
const deployButton = document.getElementById('deployButton')
const depositButton = document.getElementById('depositButton')
const showMeTheMoneyButton = document.getElementById('showMeTheMoneyButton')
const showMeTheMoneyButtonKovan = document.getElementById('showMeTheMoneyButton_kovan')
const showMeTheMoneyButtonGoerli = document.getElementById('showMeTheMoneyButton_goerli')
const useSuperPowersGoerli = document.getElementById('useSuperPowers_goerli')
const withdrawButton = document.getElementById('withdrawButton')
const contractStatus = document.getElementById('contractStatus')

// Send Eth Section
const sendButton = document.getElementById('sendButton')
const sendResult = document.getElementById('sendResult')

// Send Tokens Section
const tokenAddress = document.getElementById('tokenAddress')
const createToken = document.getElementById('createToken')
const approveTokens = document.getElementById('approveTokens')
const transferTokensWithoutGas = document.getElementById('transferTokensWithoutGas')
const tokenResult = document.getElementById('tokenResult')

// Encrypt / Decrypt Section
const getEncryptionKeyButton = document.getElementById('getEncryptionKeyButton')
const encryptMessageInput = document.getElementById('encryptMessageInput')
const encryptButton = document.getElementById('encryptButton')
const decryptButton = document.getElementById('decryptButton')
const encryptionKeyDisplay = document.getElementById('encryptionKeyDisplay')
const ciphertextDisplay = document.getElementById('ciphertextDisplay')
const cleartextDisplay = document.getElementById('cleartextDisplay')

// Ethereum Signature Section
const ethSign = document.getElementById('ethSign')
const ethSignResult = document.getElementById('ethSignResult')
const personalSign = document.getElementById('personalSign')
const personalSignResult = document.getElementById('personalSignResult')
const personalSignVerify = document.getElementById('personalSignVerify')
const personalSignVerifySigUtilResult = document.getElementById('personalSignVerifySigUtilResult')
const personalSignVerifyECRecoverResult = document.getElementById('personalSignVerifyECRecoverResult')
const signTypedData = document.getElementById('signTypedData')
const signTypedDataResult = document.getElementById('signTypedDataResult')
const signTypedDataVerify = document.getElementById('signTypedDataVerify')
const signTypedDataVerifyResult = document.getElementById('signTypedDataVerifyResult')
const signTypedDataV3 = document.getElementById('signTypedDataV3')
const signTypedDataV3Result = document.getElementById('signTypedDataV3Result')
const signTypedDataV3Verify = document.getElementById('signTypedDataV3Verify')
const signTypedDataV3VerifyResult = document.getElementById('signTypedDataV3VerifyResult')
const signTypedDataV4 = document.getElementById('signTypedDataV4')
const signTypedDataV4Result = document.getElementById('signTypedDataV4Result')
const signTypedDataV4Verify = document.getElementById('signTypedDataV4Verify')
const signTypedDataV4VerifyResult = document.getElementById('signTypedDataV4VerifyResult')

const signTypedContentsId = document.getElementById('signTypedContentsId')
const complianceProjectId = document.getElementById('complianceProjectId')
const complianceClientId = document.getElementById('complianceClientId')

const complianceButton = document.getElementById('complianceButton')
const complianceResult = document.getElementById('complianceResult')

const disableSections = (disable) => {
  for (let i = 0; i < sectionClass.length; i++) {
    if (disable) {
      sectionClass[i].classList.add('disabled')
    } else {
      sectionClass[i].classList.remove('disabled')
    }
  }
}

const initialize = async () => {
  try {
    if (!isMetaMaskInstalled()) {
      statusDiv.innerText = 'Please, install MetaMask!'
      networkDiv.innerText = 'No network'
      disableSections(true)
      return
    }

    // We must specify the network as 'any' for ethers to allow network changes
    ethersProvider = new ethers.providers.Web3Provider(window.ethereum, 'any')
    piggybankFactory = new ethers.ContractFactory(
      piggybankAbi,
      piggybankBytecode,
      ethersProvider.getSigner(),
    )
  } catch (error) {
    console.error(error)
  }

  let onboarding
  try {
    onboarding = new MetaMaskOnboarding({ forwarderOrigin })
  } catch (error) {
    console.error(error)
  }

  let accounts
  let accountButtonsInitialized = false

  const tstTokenAdress = '0x722dd3F80BAC40c951b51BdD28Dd19d435762180'
  const javierCoinAdressKovan = '0xF4312f38f1139C2aa1c1dA54EF38F9ef1628dcB9'
  const johannCoinCoinAddressGoerli = '0x7603A62b21A85f5cD02baE3389F35F1AcBaB0Ab2'

  const tokenContract = new ethers.Contract(tstTokenAdress, javierCoinAbi, ethersProvider.getSigner())

  // eslint-disable-next-line camelcase
  const tokenContract_kovan = new ethers.Contract(javierCoinAdressKovan, javierCoinAbi, ethersProvider.getSigner())

  // eslint-disable-next-line camelcase
  const tokenContract_goerli = new ethers.Contract(johannCoinCoinAddressGoerli, jhcAbi, ethersProvider.getSigner())

  // eslint-disable-next-line camelcase
  const hasOwnerContract_goerli = new ethers.Contract(johannCoinCoinAddressGoerli, hasAnOwnerAbi, ethersProvider.getSigner())

  tokenAddress.innerText = tstTokenAdress.toString()

  const isMetaMaskConnected = () => accounts && accounts.length > 0

  const onClickInstall = () => {
    connectButton.innerText = 'Onboarding in progress'
    connectButton.disabled = true
    onboarding.startOnboarding()
  }

  const onClickConnect = async () => {
    try {
      const newAccounts = await ethereum.request({
        method: 'eth_requestAccounts',
      })
      handleNewAccounts(newAccounts)
    } catch (error) {
      console.error(error)
    }
  }

  const clearTextDisplays = () => {
    encryptionKeyDisplay.innerText = ''
    encryptMessageInput.value = ''
    ciphertextDisplay.innerText = ''
    cleartextDisplay.innerText = ''
    statusDiv.innerText = ''
  }

  const toggleButtons = (toogle, networkId) => {
    deployButton.disabled = toogle
    sendButton.disabled = toogle
    createToken.disabled = toogle
    getEncryptionKeyButton.disabled = toogle
    ethSign.disabled = toogle
    personalSign.disabled = toogle
    signTypedData.disabled = toogle
    signTypedDataV3.disabled = toogle
    signTypedDataV4.disabled = toogle

    if (networkId === 4) {
      showMeTheMoneyButton.disabled = false
    } else if (networkId === 5) {
      showMeTheMoneyButtonGoerli.disabled = false
      useSuperPowersGoerli.disabled = false
      approveTokens.disabled = false
    } else if (networkId === 42) {
      showMeTheMoneyButtonKovan.disabled = false
    } else {
      showMeTheMoneyButton.disabled = NETWORKS[networkId] ? toogle : true
      showMeTheMoneyButtonKovan.disabled = NETWORKS[networkId] ? toogle : true
      showMeTheMoneyButtonGoerli.disabled = NETWORKS[networkId] ? toogle : true
      useSuperPowersGoerli.disabled = NETWORKS[networkId] ? toogle : true
      approveTokens.disabled = NETWORKS[networkId] ? toogle : true
    }
  }

  const updateButtons = async () => {
    const networkId = Number(await ethereum.request({
      method: 'net_version',
    }))
    const accountButtonsDisabled = !isMetaMaskInstalled() || !isMetaMaskConnected() || networkId === 1
    if (accountButtonsDisabled) {
      clearTextDisplays()
      toggleButtons(true)
    } else {
      toggleButtons(false)
    }

    if (!isMetaMaskInstalled()) {
      statusDiv.innerText = 'Click here to install MetaMask!'
      connectButton.disabled = false
      toggleButtons(true)
    } else if (isMetaMaskConnected()) {
      statusDiv.innerText = 'Connected'
      connectButton.innerText = 'Connected'
      connectButton.disabled = true
      getAccountsButton.disabled = false
      toggleButtons(true)
      disableSections(false)
      if (onboarding) {
        onboarding.stopOnboarding()
      }
    // eslint-disable-next-line no-negated-condition
    } else if (!isMetaMaskConnected()) {
      statusDiv.innerText = 'Extension is blocked'
      connectButton.disabled = false
      getAccountsButton.disabled = true
      connectButton.innerText = 'Connect'
      connectButton.onclick = onClickConnect
      disableSections(true)
    } else {
      statusDiv.innerText = 'Connected'
      connectButton.disabled = true
      getAccountsButton.disabled = false
      connectButton.innerText = 'Connected'
      disableSections(false)
    }

    toggleButtons(Boolean(networkId === 1 || !isMetaMaskConnected()), networkId)
  }

  showMeTheMoneyButton.onclick = async () => {
    const toAddress = '0x7E654d251Da770A068413677967F6d3Ea2FeA9E4' // get from input
    const actualAmount = '1000000000000000000' // 18 decimals
    try {
      const result = await tokenContract.showMeTheMoney(toAddress, actualAmount)
      console.log(result)
      contractStatus.innerHTML = 'Called contract'
    } catch (e) {
      console.log(e)
      contractStatus.innerHTML = e.message
    }
  }

  showMeTheMoneyButtonKovan.onclick = async () => {

    const _accounts = await ethereum.request({
      method: 'eth_accounts',
    })

    const toAddress = _accounts[0] // get from input
    const actualAmount = '1000000000000000000' // 18 decimals
    try {
      const result = await tokenContract_kovan.showMeTheMoney(toAddress, actualAmount)
      console.log(result)
      contractStatus.innerHTML = 'Called contract'
    } catch (e) {
      console.log(e)
      contractStatus.innerHTML = e.message
    }
  }

  showMeTheMoneyButtonGoerli.onclick = async () => {

    const _accounts = await ethereum.request({
      method: 'eth_accounts',
    })

    const toAddress = _accounts[0] // get from input
    const actualAmount = '1000000000000000000' // 18 decimals
    try {
      const result = await tokenContract_goerli.showMeTheMoney(toAddress, actualAmount)
      console.log(result)
      contractStatus.innerHTML = 'Called contract'
    } catch (e) {
      console.log(e)
      contractStatus.innerHTML = e.message
    }
  }

  useSuperPowersGoerli.onclick = async () => {
    try {
      const result = await hasOwnerContract_goerli.useSuperPowers({
        gasLimit: 50000,
      })
      console.log(result)
      contractStatus.innerHTML = 'Called contract'
    } catch (e) {
      console.log(e)
      contractStatus.innerHTML = e.message
    }
  }

  const initializeAccountButtons = () => {

    if (accountButtonsInitialized) {
      return
    }
    accountButtonsInitialized = true

    /**
     * Contract Interactions
     */

    deployButton.onclick = async () => {
      let contract
      contractStatus.innerHTML = 'Deploying'

      try {
        contract = await piggybankFactory.deploy()
        await contract.deployTransaction.wait()
      } catch (error) {
        contractStatus.innerHTML = 'Deployment Failed'
        throw error
      }

      if (contract.address === undefined) {
        return
      }

      console.log(`Contract mined! address: ${contract.address} transactionHash: ${contract.transactionHash}`)
      contractStatus.innerHTML = 'Deployed'
      depositButton.disabled = false
      withdrawButton.disabled = false

      depositButton.onclick = async () => {
        contractStatus.innerHTML = 'Deposit initiated'
        const result = await contract.deposit({
          from: accounts[0],
          value: '0x3782dace9d900000',
        })
        console.log(result)
        contractStatus.innerHTML = 'Deposit completed'
      }

      withdrawButton.onclick = async () => {
        const result = await contract.withdraw(
          '0xde0b6b3a7640000',
          { from: accounts[0] },
        )
        console.log(result)
        contractStatus.innerHTML = 'Withdrawn'
      }

      console.log(contract)
    }

    /**
     * Sending ETH
     */

    sendButton.onclick = async () => {
      try {
        const result = await ethersProvider.getSigner().sendTransaction({
          to: '0xC0e6D519242CF0C21087aa9Ab1898caC15065207',
          value: '0x10000000000000',
          gasLimit: 21000,
          gasPrice: 20000000000,
        })
        sendResult.innerText = 'success'
        console.log(result)
      } catch (e) {
        sendResult.innerText = e.message
      }
    }

    /**
     * ERC20 Token
     */

    approveTokens.onclick = async () => {
      try {
        const result = await tokenContract_goerli.approve('0xfa7d31e376a785837496f2d27454a53520e23994', '70000', {
          from: accounts[0],
          gasLimit: 60000,
          gasPrice: '20000000000',
        })
        console.log('result', result)
        tokenResult.innerText = 'Success!'
      } catch (e) {
        console.error(e.message)
        tokenResult.innerText = e.message
      }
    }

    transferTokensWithoutGas.onclick = async () => {
      const result = await tokenContract.transfer('0x2f318C334780961FB129D2a6c30D0763d9a5C970', '15000', {
        gasPrice: '20000000000',
      })
      console.log('result', result)
    }

    /**
     * Permissions
     */

    requestPermissionsButton.onclick = async () => {
      try {
        const permissionsArray = await ethereum.request({
          method: 'wallet_requestPermissions',
          params: [{ eth_accounts: {} }],
        })
        permissionsResult.innerHTML = getPermissionsDisplayString(permissionsArray)
      } catch (err) {
        console.error(err)
        permissionsResult.innerHTML = `Error: ${err.message}`
      }
    }

    getPermissionsButton.onclick = async () => {
      try {
        const permissionsArray = await ethereum.request({
          method: 'wallet_getPermissions',
        })
        permissionsResult.innerHTML = getPermissionsDisplayString(permissionsArray)
      } catch (err) {
        console.error(err)
        permissionsResult.innerHTML = `Error: ${err.message}`
      }
    }

    getAccountsButton.onclick = async () => {
      try {
        const _accounts = await ethereum.request({
          method: 'eth_accounts',
        })
        getAccountsResults.innerHTML = _accounts[0] || 'Not able to get accounts'
      } catch (err) {
        console.error(err)
        getAccountsResults.innerHTML = `Error: ${err.message}`
      }
    }

    /**
     * Encrypt / Decrypt
     */

    getEncryptionKeyButton.onclick = async () => {
      try {
        encryptionKeyDisplay.innerText = await ethereum.request({
          method: 'eth_getEncryptionPublicKey',
          params: [accounts[0]],
        })
        encryptMessageInput.disabled = false
      } catch (error) {
        encryptionKeyDisplay.innerText = `Error: ${error.message}`
        encryptMessageInput.disabled = true
        encryptButton.disabled = true
        decryptButton.disabled = true
      }
    }

    encryptMessageInput.onkeyup = () => {
      if (
        !getEncryptionKeyButton.disabled &&
        encryptMessageInput.value.length > 0
      ) {
        if (encryptButton.disabled) {
          encryptButton.disabled = false
        }
      } else if (!encryptButton.disabled) {
        encryptButton.disabled = true
      }
    }

    encryptButton.onclick = () => {
      try {
        ciphertextDisplay.innerText = stringifiableToHex(encrypt(
          encryptionKeyDisplay.innerText,
          { 'data': encryptMessageInput.value },
          'x25519-xsalsa20-poly1305',
        ))
        decryptButton.disabled = false
      } catch (error) {
        ciphertextDisplay.innerText = `Error: ${error.message}`
        decryptButton.disabled = true
      }
    }

    decryptButton.onclick = async () => {
      try {
        cleartextDisplay.innerText = await ethereum.request({
          method: 'eth_decrypt',
          params: [ciphertextDisplay.innerText, ethereum.selectedAddress],
        })
      } catch (error) {
        cleartextDisplay.innerText = `Error: ${error.message}`
      }
    }
  }

  /**
   * eth_sign
   */
  ethSign.onclick = async () => {
    try {
      // const msg = 'Sample message to hash for signature'
      // const msgHash = keccak256(msg)
      const msg = '0x879a053d4800c6354e76c7985a865d2922c82fb5b3f4577b2fe08b998954f2e0'
      const ethResult = await ethereum.request({
        method: 'eth_sign',
        params: [accounts[0], msg],
      })
      ethSignResult.innerHTML = JSON.stringify(ethResult)
    } catch (err) {
      console.error(err)
      ethSign.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   * Personal Sign
   */
  personalSign.onclick = async () => {
    const exampleMessage = 'Example `personal_sign` message'
    try {
      const from = accounts[0]
      const msg = `0x${Buffer.from(exampleMessage, 'utf8').toString('hex')}`
      const sign = await ethereum.request({
        method: 'personal_sign',
        params: [msg, from, 'Example password'],
      })
      personalSignResult.innerHTML = sign
      personalSignVerify.disabled = false
    } catch (err) {
      console.error(err)
      personalSign.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   * Personal Sign Verify
   */
  personalSignVerify.onclick = async () => {
    const exampleMessage = 'Example `personal_sign` message'
    try {
      const from = accounts[0]
      const msg = `0x${Buffer.from(exampleMessage, 'utf8').toString('hex')}`
      const sign = personalSignResult.innerHTML
      const recoveredAddr = recoverPersonalSignature({
        'data': msg,
        'sig': sign,
      })
      if (recoveredAddr === from) {
        console.log(`SigUtil Successfully verified signer as ${recoveredAddr}`)
        personalSignVerifySigUtilResult.innerHTML = recoveredAddr
      } else {
        console.log(`SigUtil Failed to verify signer when comparing ${recoveredAddr} to ${from}`)
        console.log(`Failed comparing ${recoveredAddr} to ${from}`)
      }
      const ecRecoverAddr = await ethereum.request({
        method: 'personal_ecRecover',
        params: [msg, sign],
      })
      if (ecRecoverAddr === from) {
        console.log(`Successfully ecRecovered signer as ${ecRecoverAddr}`)
        personalSignVerifyECRecoverResult.innerHTML = ecRecoverAddr
      } else {
        console.log(`Failed to verify signer when comparing ${ecRecoverAddr} to ${from}`)
      }
    } catch (err) {
      console.error(err)
      personalSignVerifySigUtilResult.innerHTML = `Error: ${err.message}`
      personalSignVerifyECRecoverResult.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   * Sign Typed Data Test
   */
  signTypedData.onclick = async () => {
    const msgParams = [
      {
        type: 'string',
        name: 'Message',
        value: 'Hi, Alice!',
      },
      {
        type: 'uint32',
        name: 'A number',
        value: '1337',
      },
    ]
    try {
      const from = accounts[0]
      const sign = await ethereum.request({
        method: 'eth_signTypedData',
        params: [msgParams, from],
      })
      signTypedDataResult.innerHTML = sign
      signTypedDataVerify.disabled = false
    } catch (err) {
      console.error(err)
      signTypedDataResult.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   * Sign Typed Data Verification
   */
  signTypedDataVerify.onclick = async () => {
    const msgParams = [
      {
        type: 'string',
        name: 'Message',
        value: 'Hi, Alice!',
      },
      {
        type: 'uint32',
        name: 'A number',
        value: '1337',
      },
    ]
    try {
      const from = accounts[0]
      const sign = signTypedDataResult.innerHTML
      const recoveredAddr = await recoverTypedSignatureLegacy({
        'data': msgParams,
        'sig': sign,
      })
      if (toChecksumAddress(recoveredAddr) === toChecksumAddress(from)) {
        console.log(`Successfully verified signer as ${recoveredAddr}`)
        signTypedDataVerifyResult.innerHTML = recoveredAddr
      } else {
        console.log(`Failed to verify signer when comparing ${recoveredAddr} to ${from}`)
      }
    } catch (err) {
      console.error(err)
      signTypedDataV3VerifyResult.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   * Sign Typed Data Version 3 Test
   */
  signTypedDataV3.onclick = async () => {
    const networkId = parseInt(networkDiv.innerHTML, 10)
    const chainId = parseInt(chainIdDiv.innerHTML, 16) || networkId

    const msgParams = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: {
        sender: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        recipient: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      },
    }
    try {
      const from = accounts[0]
      const sign = await ethereum.request({
        method: 'eth_signTypedData_v3',
        params: [from, JSON.stringify(msgParams)],
      })
      signTypedDataV3Result.innerHTML = sign
      signTypedDataV3Verify.disabled = false
    } catch (err) {
      console.error(err)
      signTypedDataV3Result.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   * Sign Typed Data V3 Verification
   */
  signTypedDataV3Verify.onclick = async () => {
    const networkId = parseInt(networkDiv.innerHTML, 10)
    const chainId = parseInt(chainIdDiv.innerHTML, 16) || networkId

    const msgParams = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: {
        sender: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        recipient: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      },
    }
    try {
      const from = accounts[0]
      const sign = signTypedDataV3Result.innerHTML
      const recoveredAddr = await recoverTypedSignature({
        'data': msgParams,
        'sig': sign,
      })
      if (toChecksumAddress(recoveredAddr) === toChecksumAddress(from)) {
        console.log(`Successfully verified signer as ${recoveredAddr}`)
        signTypedDataV3VerifyResult.innerHTML = recoveredAddr
      } else {
        console.log(`Failed to verify signer when comparing ${recoveredAddr} to ${from}`)
      }
    } catch (err) {
      console.error(err)
      signTypedDataV3VerifyResult.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   * Sign Typed Data V4
   */
  signTypedDataV4.onclick = async () => {
    const contents = signTypedContentsId.value
    const networkId = parseInt(networkDiv.innerHTML, 10)
    const chainId = parseInt(chainIdDiv.innerHTML, 16) || networkId
    const msgParams = {
      domain: {
        chainId,
        name: 'Test Stuff',
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        version: '1',
      },
      message: {
        contents,
        to: {
          name: 'Bob',
          wallet: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
      },
      primaryType: 'Message',
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Message: [
          { name: 'contents', type: 'string' },
          { name: 'to', type: 'Person' },
        ],
        Person: [
          {
            'name': 'name',
            'type': 'string',
          },
          {
            'name': 'wallet',
            'type': 'address',
          },
        ],
      },
    }
    try {
      const from = accounts[0]
      const sign = await ethereum.request({
        method: 'eth_signTypedData_v4',
        params: [from, JSON.stringify(msgParams)],
      })
      signTypedDataV4Result.innerHTML = sign
      signTypedDataV4Verify.disabled = false
    } catch (err) {
      console.error(err)
      signTypedDataV4Result.innerHTML = `Error: ${err.message}`
    }
  }

  /**
   *  Sign Typed Data V4 Verification
   */
  signTypedDataV4Verify.onclick = async () => {
    const contents = signTypedContentsId.value

    const networkId = parseInt(networkDiv.innerHTML, 10)
    const chainId = parseInt(chainIdDiv.innerHTML, 16) || networkId
    const msgParams = {
      domain: {
        chainId,
        name: 'Test Stuff',
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        version: '1',
      },
      message: {
        contents,
        to: {
          name: 'Bob',
          wallet: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
      },
      primaryType: 'Message',
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Message: [
          { name: 'contents', type: 'string' },
          { name: 'to', type: 'Person' },
        ],
        Person: [
          {
            'name': 'name',
            'type': 'string',
          },
          {
            'name': 'wallet',
            'type': 'address',
          },
        ],
      },
    }
    try {
      const from = accounts[0]
      const sign = signTypedDataV4Result.innerHTML
      const recoveredAddr = recoverTypedSignature_v4({
        'data': msgParams,
        'sig': sign,
      })
      if (toChecksumAddress(recoveredAddr) === toChecksumAddress(from)) {
        console.log(`Successfully verified signer as ${recoveredAddr}`)
        signTypedDataV4VerifyResult.innerHTML = recoveredAddr
      } else {
        console.log(`Failed to verify signer when comparing ${recoveredAddr} to ${from}`)
      }
    } catch (err) {
      console.error(err)
      signTypedDataV4VerifyResult.innerHTML = `Error: ${err.message}`
    }
  }

  complianceButton.onclick = async () => {
    const projectId = complianceProjectId.value
    const clientId = complianceClientId.value

    try {
      const result = await window.ethereum.request({
        'method': 'metamaskinstitutional_authenticate',
        'params': {
          'origin': 'mmitest.compliance.codefi.network',
          'token': {
            clientId,
            projectId,
          },
          'feature': 'compliance',
          'service': 'codefi-compliance',
          'labels': [
            {
              'key': 'service',
              'value': 'Codefi Compliance',
            },
            {
              'key': 'token.projectId',
              'value': 'Some project name',
            },
          ],
        },
      })

      complianceResult.innerHTML = result
    } catch (err) {
      complianceResult.innerHTML = `Error: ${err.message}`
    }
  }

  function handleNewAccounts (newAccounts) {
    accounts = newAccounts
    accountsDiv.innerHTML = accounts
    if (isMetaMaskConnected()) {
      initializeAccountButtons()
    }
    updateButtons()
  }

  function handleNewChain (chainId) {
    chainIdDiv.innerHTML = chainId
  }

  function handleNewNetwork (networkId) {
    networkDiv.innerHTML = `Currently on network ${networkId} (${NETWORKS[networkId]})`
    updateButtons()
  }

  async function getNetworkAndChainId () {
    try {
      const chainId = await ethereum.request({
        method: 'eth_chainId',
      })
      handleNewChain(chainId)

      const networkId = await ethereum.request({
        method: 'net_version',
      })
      handleNewNetwork(networkId)
    } catch (err) {
      console.error(err)
    }
  }

  updateButtons()

  if (isMetaMaskInstalled()) {

    ethereum.autoRefreshOnNetworkChange = false
    getNetworkAndChainId()

    ethereum.on('chainChanged', handleNewChain)
    ethereum.on('networkChanged', handleNewNetwork)
    ethereum.on('accountsChanged', handleNewAccounts)

    try {
      const newAccounts = await ethereum.request({
        method: 'eth_accounts',
      })
      handleNewAccounts(newAccounts)
    } catch (err) {
      console.error('Error on init when getting accounts', err)
    }
  }
}

window.addEventListener('DOMContentLoaded', initialize)

// utils

function getPermissionsDisplayString (permissionsArray) {
  if (permissionsArray.length === 0) {
    return 'No permissions found.'
  }
  const permissionNames = permissionsArray.map((perm) => perm.parentCapability)
  return permissionNames.reduce((acc, name) => `${acc}${name}, `, '').replace(/, $/u, '')
}

function stringifiableToHex (value) {
  return ethers.utils.hexlify(Buffer.from(JSON.stringify(value)))
}
