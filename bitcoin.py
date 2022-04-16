from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress, P2shAddress, PrivateKey, PublicKey
from bitcoinutils.script import Script
from bitcoinutils.proxy import NodeProxy
from tools import Output
from typing import Union
from bitcoinutils.utils import to_satoshis #Another utility to convert satoshis back to BTC might be usefull - Pull request (github.com/karask/python-bitcoin-utils) ?
from bitcoinutils.constants import SATOSHIS_PER_BITCOIN
import constants as const
from exceptions import NO_UTXOS, NOT_ENOUGH_FUNDS, INVALID_TRANSACTION, NO_CONNECTION, INVALID_PUBLIC_KEY

class Bitcoin:
    NETWORKS = {const.MAINNET,const.TESTNET,const.REGTEST}

    def __init__(self,network=const.MAINNET, rpcuser=None, rpcpassword=None, host='127.0.0.1'):
        setup(network)
        self.network = network
        self.rpcuser = rpcuser
        self.rpcpassword = rpcpassword
        self.host = host

    def createMultisigScript(self,numberOfRequiredSignatures:int,keys:list) -> list:
        '''
        Returns a Bitcoin script (in a list) for multi signature transactions\n
        Expected keys parameter format :\n
        [
            {
                Output.PUBLIC_KEY:''
            },
            . . .
        ]
        '''
        script = [numberOfRequiredSignatures]
        for adr in keys:
            if not Output.PUBLIC_KEY in adr: continue
            publicKey = adr[Output.PUBLIC_KEY]
            if not Bitcoin.isPublicKeyValid(publicKey):
                raise INVALID_PUBLIC_KEY
            script.append(publicKey)
        script.append(int(len(keys)))
        script.append('OP_CHECKMULTISIG')
        return script

    def addSignaturesToTransaction(self,rawTransactionHex:str,signatures:dict) -> str:
        '''
        Add signatures to transaction and return a signed or partially signed transaction in raw hex format\n
        Expected signatures parameter format:\n
        {
            'TXIS1': [ <list of bitcoin script commands and arguments> ],
            'TXIS1': [ <list of bitcoin script commands and arguments> ],
            . . .
        }
        '''
        transaction = Transaction.from_raw(rawTransactionHex)
        for tx in transaction.inputs:
            if tx.txid in signatures:
                tx.script_sig = Script(signatures[tx.txid])
        return transaction.serialize()

    def getAddressFromScript(self,script:list) -> str:
        '''
        Returns an address given a Bitcoin script (in a list)
        '''
        return P2shAddress.from_script(Script(script)).to_string()

    def getScriptInHex(self,script:list) -> str:
        '''
        Returns the hex value of the given script (script given in a list)
        '''
        return Script(script).to_hex()

    def createKeys(self,seed = None):
        '''
        Create a private - public key pair and returns the private key WIF, the public key hex and the corresponding address
        '''
        if type(seed) == str:
            seed = int.from_bytes(seed.encode(), 'little')
        privateKey = PrivateKey(secret_exponent=seed)
        publicKey = privateKey.get_public_key()
        #Return privateKey in WIF format and address from public Key
        return privateKey.to_wif(), publicKey.to_hex(), publicKey.get_address().to_string()

    def createTransaction(self,amount:float,fee:float,addressFrom:str,addressTo:str) -> str:
        '''
        Checks the balance of the addressFrom and if it has enough funds, create an unsigned transaction.
        Return the created unsigned transaction in raw hex format
        '''
        UTXOs = self.getUTXOs(addressFrom)
        if UTXOs.getUTXOs() is None:
            raise NO_UTXOS(addressFrom)

        #Convert amounts to satoshis
        amount = to_satoshis(amount)
        fee = to_satoshis(fee)

        #Check if the total amount of all UTXOs related to that address is enough
        totalUTXOAmount = to_satoshis(UTXOs.getBalance())
        if amount + fee > totalUTXOAmount:
            raise NOT_ENOUGH_FUNDS(totalUTXOAmount / SATOSHIS_PER_BITCOIN)

        #Gather needed UTXOs to create the transaction
        amountNeeded = amount + fee
        inputTransactions = []
        for tx in UTXOs.getUTXOs():
            inputTransactions.append(
                TxInput(
                    txid = tx[Output.TRANSACTION_ID],
                    txout_index = tx[Output.PREVIOUS_TRANSACTION_UTXO_INDEX]
            ))
            amountNeeded -= to_satoshis(tx[Output.AMOUNT])
            if amountNeeded <= 0:
                break #Exit loop, we have enough funds in the UTXOs gathered to sent the selected amount

        if amountNeeded > 0:#<= This should never be true as it is already checked above, but just in case :D
            raise NOT_ENOUGH_FUNDS(totalUTXOAmount)

        if addressTo[0].isdigit():
            receiverScript = Script(['OP_HASH160',P2shAddress(addressTo).to_hash160(),'OP_EQUAL'])
        else:
            receiverScript = P2pkhAddress(addressTo).to_script_pub_key()

        if addressFrom[0].isdigit():
            # P2shAddress(addressFrom) would be nice to have a to_script_pub_key method - Create pull request (github.com/karask/python-bitcoin-utils)
            senderScript = Script(['OP_HASH160',P2shAddress(addressFrom).to_hash160(),'OP_EQUAL'])
        else:
            senderScript = P2pkhAddress(addressFrom).to_script_pub_key()

        #Send the amount to the receiver :
        outputTransactions = []
        outputTransactions.append(
            TxOutput(amount,receiverScript)
        )

        #Send the remaining amount back to the sender :
        if amountNeeded < 0:
            outputTransactions.append(
                TxOutput(-1*amountNeeded,senderScript)
            )

        return Transaction(inputTransactions,outputTransactions).serialize()

    def getTransactionInputs(self,rawTransaction:str):
        '''
        Returns the UTXO inputs for the given transaction (UTXOs from another transaction)
        '''
        transaction = Transaction.from_raw(rawTransaction)
        return transaction.inputs

    def signUTXO(self,privateKey:str,rawUnsignedTransaction:str,txIndex:int,redeemScript:list) -> str:
        '''
        Returns the signature of a UTXO (selected with the txIndex from the given rawUnsignedTransaction) that
        was produced by the given private key
        '''
        key = PrivateKey(wif=privateKey)
        transaction = Transaction.from_raw(rawUnsignedTransaction)
        return key.sign_input(transaction,txIndex,Script(redeemScript))

    def isAddressValid(self,address:str) -> bool:
        '''
        Checks the validity of a bitcoin address
        '''
        try:
            _ = P2pkhAddress.from_address(address)
            return True
        except:
            try:
                _ = P2shAddress.from_address(address)
                return True
            except:
                return False

    def getUTXOs(self,address:str) -> Output:
        '''
        Returns an instance of Output with the list of UTXOs gathered from Network
        Network command : scantxoutset start "addr( <address> )"
        '''
        proxy = self.__proxy()
        if proxy == None: return None
        #return proxy.batch_([["listunspent",0,99999,[address]]])
        results = proxy.batch_([["scantxoutset","start",[f"addr({address})"]]])
        results = results[0]

        #Sort UTXOs from biggest to smallest
        results[const.UTXO_UNSPENTS].sort(key=lambda x: x[const.UTXO_UNSPENTS_AMOUNT], reverse=True)

        output = Output(Output.BALANCE)
        output.addBalance(float(results[const.UTXO_TOTAL_AMOUNT]))
        for tx in results[const.UTXO_UNSPENTS]:
            output.addUtxo(tx[const.UTXO_UNSPENTS_TXID],tx[const.UTXO_UNSPENTS_VOUT],float(tx[const.UTXO_UNSPENTS_AMOUNT]))
        return output

    def sendTransaction(self,rawTransactionHex:str) -> Output:
        '''
        Send the transaction to the Network
        Network command : sendrawtransaction <transactionHex>
        '''
        try:
            _ = Transaction.from_raw(rawTransactionHex)
        except:
            raise INVALID_TRANSACTION
        proxy = self.__proxy()
        results = proxy.batch_([["sendrawtransaction",rawTransactionHex]])
        output = Output(Output.TRANSACTION_ID)
        output.addValue(Output.TRANSACTION_ID,results)
        return output

#================#
# Static methods #
#================#
    @staticmethod
    def isPublicKeyValid(publicKey):
        try:
            _ = PublicKey(publicKey)
        except:
            return False
        return True

#======================================================================================#
# Private methods - Well not exactly private but please don't use them out of scope :D #
#======================================================================================#

    def __proxy(self) -> NodeProxy:
        '''
        Returns an instance of NodeProxy that can be used to send commands to the network.
        Every time you need to send a command get another instance using this method to avoid
        failure executing the command due to drop in connection
        '''
        try:
            return NodeProxy(rpcuser=self.rpcuser, rpcpassword=self.rpcpassword, host=self.host).get_proxy()
        except:
            pass
        raise NO_CONNECTION(self.network,self.rpcuser,self.rpcpassword,self.host)