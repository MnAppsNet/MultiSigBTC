from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress, P2shAddress, PrivateKey, PublicKey, P2wshAddress, P2wpkhAddress
from bitcoinutils.script import Script
from bitcoinutils.proxy import NodeProxy
from tools import Output
from typing import Union
from bitcoinutils.utils import to_satoshis #Another utility to convert satoshis back to BTC might be usefull - Pull request (github.com/karask/python-bitcoin-utils) ?
from bitcoinutils.constants import SATOSHIS_PER_BITCOIN
from constants import UTXO, Network, AddressType
from exceptions import NO_UTXOS, NOT_ENOUGH_FUNDS, INVALID_TRANSACTION, NO_CONNECTION, INVALID_PUBLIC_KEY, INVALID_ADDRESS, NO_UTXO_AMOUNT_SEGWIT

class Bitcoin:
    NETWORKS = {Network.MAINNET,Network.TESTNET,Network.REGTEST}

    def __init__(self,network=Network.MAINNET, rpcuser=None, rpcpassword=None, host='127.0.0.1'):
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

    def addSignaturesToTransaction(self,rawTransactionHex:str,signatures:dict, hasSegwit:bool) -> str:
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
        transaction.has_segwit = hasSegwit
        for tx in transaction.inputs:
            if tx.txid in signatures:
                script = Script(signatures[tx.txid])
                if hasSegwit:
                    transaction.witnesses.append(script)
                else:
                    tx.script_sig = script
        return transaction.serialize()

    def getAddressFromScript(self,script:list,addressType=AddressType.SEGWIT) -> str:
        '''
        Returns an address given a Bitcoin script (in a list)
        '''
        if addressType == AddressType.LEGACY:
            return P2shAddress.from_script(Script(script)).to_string()
        return P2wshAddress.from_script(Script(script)).to_string()

    def getScriptInHex(self,script:list) -> str:
        '''
        Returns the hex value of the given script (script given in a list)
        '''
        return Script(script).to_hex()

    def createKeys(self,addressType=AddressType.SEGWIT,seed = None):
        '''
        Create a private - public key pair and returns the private key WIF, the public key hex and the corresponding address
        '''
        if type(seed) == str:
            seed = int.from_bytes(seed.encode(), 'little')
        privateKey = PrivateKey(secret_exponent=seed)
        publicKey = privateKey.get_public_key()
        if addressType == AddressType.LEGACY:
            address = publicKey.get_address().to_string()
        else:
            address = publicKey.get_segwit_address().to_string()
        #Return privateKey in WIF format and address from public Key
        return privateKey.to_wif(), publicKey.to_hex(), address

    def createTransaction(self,amount:float,fee:float,addressFrom:str,addressTo:str, UTXOs:Output = None):
        '''
        Checks the balance of the addressFrom and if it has enough funds, create an unsigned transaction.
        Return the created unsigned transaction in raw hex format
        '''
        if UTXOs is None:
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
        neededUTXOs = []
        for tx in UTXOs.getUTXOs():
            inputTransactions.append(
                TxInput(
                    txid = tx[Output.TRANSACTION_ID],
                    txout_index = tx[Output.PREVIOUS_TRANSACTION_UTXO_INDEX]
            ))
            amountNeeded -= to_satoshis(tx[Output.AMOUNT])
            neededUTXOs.append(tx)
            if amountNeeded <= 0:
                break #Exit loop, we have enough funds in the UTXOs gathered to sent the selected amount
        UTXOs.removeUTXOs()
        UTXOs.addUtxos(neededUTXOs)
        if amountNeeded > 0:#<= This should never be true as it is already checked above, but just in case :D
            raise NOT_ENOUGH_FUNDS(totalUTXOAmount)

        if self.__checkAddressType(addressTo,P2shAddress):
            # P2shAddress(addressFrom) would be nice to have a to_script_pub_key method - Create pull request (github.com/karask/python-bitcoin-utils)
            receiverScript = Script(['OP_HASH160',P2shAddress(addressTo).to_hash160(),'OP_EQUAL'])
        elif self.__checkAddressType(addressTo,P2pkhAddress):
            receiverScript = P2pkhAddress(addressTo).to_script_pub_key()
        elif self.__checkAddressType(addressTo,P2wpkhAddress):
            receiverScript = P2wpkhAddress(addressTo).to_script_pub_key()
        elif self.__checkAddressType(addressTo,P2wshAddress):
            receiverScript = P2wshAddress(addressTo).to_script_pub_key()
        else:
            raise INVALID_ADDRESS(addressTo)

        if self.__checkAddressType(addressFrom,P2shAddress):
            senderScript = Script(['OP_HASH160',P2shAddress(addressFrom).to_hash160(),'OP_EQUAL'])
        elif self.__checkAddressType(addressFrom,P2pkhAddress):
            senderScript = P2pkhAddress(addressFrom).to_script_pub_key()
        elif self.__checkAddressType(addressFrom,P2wpkhAddress):
            senderScript = P2wpkhAddress(addressFrom).to_script_pub_key()
        elif self.__checkAddressType(addressFrom,P2wshAddress):
            senderScript = P2wshAddress(addressFrom).to_script_pub_key()
        else:
            raise INVALID_ADDRESS(addressFrom)

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

        return Transaction(
            inputTransactions,
            outputTransactions,
            has_segwit=self.isSegwitAddress(addressFrom) ).serialize()

    def getTransactionWitness(self,rawTransaction:str):
        '''
        Returns the witness of the transaction (if it has segwit else it returns empty lsit)
        '''
        transaction = Transaction.from_raw(rawTransaction)
        return transaction.witnesses

    def getTransactionInputs(self,rawTransaction:str):
        '''
        Returns the UTXO inputs for the given transaction (UTXOs from another transaction)
        '''
        transaction = Transaction.from_raw(rawTransaction)
        return transaction.inputs

    def signUTXO(self,privateKey:str,rawUnsignedTransaction:str,txIndex:int,redeemScript:list,segwit:bool,UTXOAmount = None) -> str:
        '''
        Returns the signature of a UTXO (selected with the txIndex from the given rawUnsignedTransaction) that
        was produced by the given private key
        '''
        key = PrivateKey(wif=privateKey)
        transaction = Transaction.from_raw(rawUnsignedTransaction)
        if segwit:
            if UTXOAmount == None: raise NO_UTXO_AMOUNT_SEGWIT
            UTXOAmount = to_satoshis(float(UTXOAmount))
            return key.sign_segwit_input(transaction,txIndex,Script(redeemScript),UTXOAmount)
        return key.sign_input(transaction,txIndex,Script(redeemScript))

    def isLegacyAddress(self,address):
        '''
        Check if address given is a legacy address
        '''
        keyTypes = [P2pkhAddress,P2shAddress]
        for keyType in keyTypes:
            try:
                if self.__checkAddressType(address,keyType) : return True
            except:
                continue
        return False

    def isSegwitAddress(self,address):
        '''
        Check if address given is a segwit address
        '''
        keyTypes = [P2wshAddress,P2wpkhAddress]
        for keyType in keyTypes:
            try:
                if self.__checkAddressType(address,keyType) : return True
            except:
                continue
        return False

    def isAddressValid(self,address:str) -> bool:
        '''
        Checks the validity of a bitcoin address
        '''
        if self.isSegwitAddress(address): return True
        if self.isLegacyAddress(address): return True
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
        results[UTXO.UNSPENTS].sort(key=lambda x: x[UTXO.UNSPENTS_AMOUNT], reverse=True)

        output = Output(Output.BALANCE)
        output.addBalance(float(results[UTXO.TOTAL_AMOUNT]))
        for tx in results[UTXO.UNSPENTS]:
            output.addUtxo(tx[UTXO.UNSPENTS_TXID],tx[UTXO.UNSPENTS_VOUT],float(tx[UTXO.UNSPENTS_AMOUNT]))
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

    def __checkAddressType(self,address:str,addressClass):
        '''
        Check if the address is the type of the given addressClass
        addressClass options : P2pkhAddress,P2shAddress,P2wshAddress,P2wpkhAddress
        '''
        try:
            _ = addressClass.from_address(address)
            return True
        except:
            return False