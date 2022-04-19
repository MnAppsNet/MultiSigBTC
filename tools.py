import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from exceptions import NAME_NOT_UNIQUE, FAILED_TO_DECRYPT_KEY, FAILED_TO_LOAD_JSON
from typing import Union
import argparse

class Output:
#This class is used to handle all inputs and outputs of data

#=====================#
# Parameter constants #
#=====================#============================================
    NAME = 'name'
    KEYS = 'keys'
    ADDRESS = 'address'
    SEGWIT = 'segwit'
    PUBLIC_KEY = 'public'
    PRIVATE_KEY = 'private'
    SIGNATURES_REQUIRED = 'signatures_required'
    SCRIPT = "script"
    TYPE = "type"
    UNSIGNED_TRANSACTION = "unsigned_transaction"
    SIGNED_TRANSACTION = "signed_transaction"
    TRANSACTION_ID = "txid"
    PREVIOUS_TRANSACTION_UTXO_INDEX = "vout"
    AMOUNT = "amount"
    SIGNATURE = "signature"
    SIGNATURES = "signatures"
    MULTISIG_ADDRESS = "multisig_address"
    MULTISIG_TRANSACTION = "multisig_transaction"
    EXCEPTION = "exception"
    UNDEFINED = "undefined"
    BALANCE = "balance"
    UTXOS = "UTXOs"

#==============#
# Constructors #
#==============#===================================================
    def __init__(self,type):
        self.output = {}
        self.output[Output.TYPE] = type

    @staticmethod
    def Load(path):
        '''
        Create an instance of Output given the file path containing an JSON string derived from an Output instance
        '''
        output = Output(Output.UNDEFINED)
        output.load(path)
        return output

    @staticmethod
    def LoadFromJSON(rawJson:str):
        '''
        Create an instance of Output using a JSON string
        '''
        output = Output(Output.UNDEFINED)
        output.output = json.loads(rawJson)
        return output

#==========================#
# Add parameters to output #
#==========================#=======================================
    def addKey(self,name,publicKey,privateKey = None, password = None):
        '''
        Add a key in the Output instance. If the instance is of type Output.P2PKH_ADDRESS, a single key is maintained,
        a second execution of the method will overwrite the previous key. Else a list of keys is maintains and every new
        execution of the command will append a new key.

        /!\ NOTE: The key name is an identifier and needs to be unique /!\
        '''
        if self.keyNameExists(name):
            raise NAME_NOT_UNIQUE

        if privateKey != None and password != None:
            privateKey = Security.encrypt(privateKey,password)

        if self.output[Output.TYPE] == Output.ADDRESS:
            #If wallet with a single P2PKH address, don't create list
            if not Output.KEYS in self.output: self.output[Output.KEYS] = {}
            self.output[Output.KEYS][Output.NAME] = name
            self.output[Output.KEYS][Output.PUBLIC_KEY] = publicKey
            self.output[Output.KEYS][Output.PRIVATE_KEY] = privateKey
            return
        else:
            if not Output.KEYS in self.output: self.output[Output.KEYS] = []
            self.output[Output.KEYS].append({
                Output.NAME:name,
                Output.PUBLIC_KEY:publicKey,
                Output.PRIVATE_KEY:privateKey
            })

    def addSignature(self,keyName:str,signature:str,transactionIndex):
        '''
        Add a signature in the object containing the list of signatures inside the Output instance.
        '''
        transactionIndex = str(transactionIndex)
        if not Output.SIGNATURES in self.output: self.output[Output.SIGNATURES] = {}
        if transactionIndex in self.output[Output.SIGNATURES]:
            #Check ig exists and if so update and return :
            for sig in self.output[Output.SIGNATURES][transactionIndex]:
                if sig[Output.NAME] != keyName: continue
                sig[Output.SIGNATURE] = signature
                return;
        else:
            #Create new list :
            self.output[Output.SIGNATURES][transactionIndex] = []

        self.output[Output.SIGNATURES][transactionIndex].append({
                    Output.SIGNATURE: signature,
                    Output.NAME: keyName
                    })

    def addSignatures(self,signatures:dict):
        '''
        Creates an object with list of signatures in the Output instance.
        Expected signatures object format:
        { 'TXID1': [
            { Output.NAME: '',
              Output.SIGNATURE: ''},
            . . .
            ],
         'TXID2': [
            { Output.NAME: '',
               Output.SIGNATURE: ''},
            . . .
            ],
        }
        '''
        for id in signatures:
            for signature in signatures[id]:
                self.addSignature(signature[Output.NAME],signature[Output.SIGNATURE],id)

    def addUtxo(self,txid:str,vout:int,amount:float):
        '''
        Add a UTXO in the list of UTXOs in the Output instance. If this UTXOs list doesn't exists, it creates it.
        '''
        if not Output.UTXOS in self.output : self.output[Output.UTXOS] = []

        ##Search if exists already and if it does update and return :
        #for utxo in self.output[Output.UTXOS]:
        #    if not Output.TRANSACTION_ID in utxo: continue
        #    if utxo[Output.TRANSACTION_ID] == txid:
        #        utxo[Output.PREVIOUS_TRANSACTION_UTXO_INDEX] = vout
        #        utxo[Output.AMOUNT] = amount
        #        return

        self.output[Output.UTXOS].append(
            {
                Output.TRANSACTION_ID : txid,
                Output.PREVIOUS_TRANSACTION_UTXO_INDEX : vout,
                Output.AMOUNT : amount
            }
        )

    def addUtxos(self,utxos:list):
        for utxo in utxos:
            if not(Output.TRANSACTION_ID in utxo and Output.PREVIOUS_TRANSACTION_UTXO_INDEX in utxo and Output.AMOUNT in utxo):
                continue
            self.addUtxo(utxo[Output.TRANSACTION_ID],utxo[Output.PREVIOUS_TRANSACTION_UTXO_INDEX],utxo[Output.AMOUNT])

    def addKeyName(self,keyName):
        '''
        Add the name of the key.
        This method applies only on outputs that do not contain a list of keys but a single key.
        If executed by an instance that maintains a list of keys, nothing will happen
        For now only Output instances of type Output.P2PKH_ADDRESS contains a single key.
        '''
        if type(self.output[Output.KEYS]) == dict:
            self.output[Output.KEYS][Output.NAME] = keyName

    def addKeys(self,keys:list):
        '''
        Add a list of keys in the Output instance.
        Expected keys list format :
        [
            {
                Output.NAME:'',
                Output.PUBLIC_KEY:'',
                Output.PRIVATE_KEY:''
            },
            . . .
        ]
        '''
        self.addValue(Output.KEYS,keys)

    def addAddress(self,address:str):
        '''
        Add an address in the Output instance
        '''
        self.addValue(Output.ADDRESS,address)

    def addScript(self,script:list):
        '''
        Add a script in the Output instance. The script is a list of commands.
        '''
        self.addValue(Output.SCRIPT,script)

    def addUnsignedTransaction(self,rawTransactionHex:str):
        '''
        Add an unsigned transaction in raw hex format
        '''
        self.addValue(Output.UNSIGNED_TRANSACTION,rawTransactionHex)

    def addSignedTransaction(self,rawTransactionHex:str):
        '''
        Add an unsigned transaction in raw hex format
        '''
        self.addValue(Output.SIGNED_TRANSACTION,rawTransactionHex)

    def addNumberOfRequiredSignatures(self,value:int):
        '''
        Add the number of required signatures in the Output instance
        '''
        self.addValue(Output.SIGNATURES_REQUIRED,value)

    def addBalance(self,balance:float):
        '''
        Add a balance in the Output instance
        '''
        self.addValue(Output.BALANCE,balance)

    def addSegwitFlag(self,hasSegwit:bool):
        '''
        Add a segwit flag to true of false depending if the transaction has segwit inputs or not
        '''
        self.addValue(Output.SEGWIT,hasSegwit)

    def addValue(self,parameter,value):
        '''
        Add a value for the given parameter in the Output instance
        '''
        self.output[parameter] = value

#==========================#
# Remove value from output #
#==========================#=======================================
    def removeUTXOs(self):
        self.removeProperty(Output.UTXOS)

    def removeProperty(self,property):
        try:
            self.output.pop(property, None)
        except:
            pass

#============================#
# Get parameters from output #
#============================#=====================================
    def getTransactionSignatures(self,transactionIndex) -> list:
        '''
        Return a list of objects with keys Output.NAME and Output.SIGNATURE
        [
            { Output.NAME: '',
              Output.SIGNATURE: ''},
            . . .
        ]
        '''
        if not Output.SIGNATURES in self.output : return []
        if not str(transactionIndex) in self.output[Output.SIGNATURES] : return []
        return self.output[Output.SIGNATURES][str(transactionIndex)]

    def getPrivateKey(self,password) -> Union[str,None]:
        '''
        Returns the private key decrypted if any. Currently only Output instances of type Output.P2PKH_ADDRESS are expected to contain private keys
        '''
        if self.output[Output.TYPE] != Output.ADDRESS:
            return None #Only wallets with P2PKH addresses contains the private key
        try:
            privateKey = Security.decrypt(self.output[Output.KEYS][Output.PRIVATE_KEY],password)
        except:
            raise FAILED_TO_DECRYPT_KEY
        return privateKey

    def getKeyName(self) -> Union[str,None]:
        '''
        Returns the name of the key in case the Output.KEYS property is a object and not a list. For now this is the case only with Outcome instances of type Output.P2PKH_ADDRESS
        '''
        if not Output.KEYS in self.output: return None
        if type(self.output[Output.KEYS]) == dict:
            return self.output[Output.KEYS][Output.NAME]
        return None

    def getOutput(self) -> dict:
        '''
        Returns the output object with all the properties added
        '''
        return self.output

    def getNumberOfRequiredSignatures(self) -> Union[int,None]:
        '''
        Returns the number of required signatured for a multi signature transaction
        '''
        required = self.getValue(Output.SIGNATURES_REQUIRED)
        return int(required) if required != None else None

    def getAddress(self) -> Union[str,None]:
        '''
        Returns the address if any
        '''
        return self.getValue(Output.ADDRESS)

    def getScript(self)-> Union[str,None]:
        '''
        Returns the script if any
        '''
        return self.getValue(Output.SCRIPT)

    def getUnsignedTransaction(self) -> Union[str,None]:
        '''
        Returns the unsigned transaction if any
        '''
        return self.getValue(Output.UNSIGNED_TRANSACTION)

    def getSignedTransaction(self) -> Union[str,None]:
        '''
        Returns the signed transaction if any
        '''
        return self.getValue(Output.SIGNED_TRANSACTION)

    def getSignatures(self) -> dict:
        '''
        Return an object with that contains the input transaction ids as a key and a list of all the signatures are their value
        { 'TXID1': [
            { Output.NAME: '',
              Output.SIGNATURE: ''},
            . . .
            ],
         'TXID2': [
            { Output.NAME: '',
               Output.SIGNATURE: ''},
            . . .
            ],
        }
        '''
        singatures = self.getValue(Output.SIGNATURES)
        return singatures if singatures != None else []

    def getKeys(self) -> Union[list,dict]:
        '''
        Returns an object (or if the output contains multiple keys a list of objects) with keys Output.NAME, Output.PUBLIC_KEY:publicKey, Output.PRIVATE_KEY:privateKey
        {
            Output.NAME:name,
            Output.PUBLIC_KEY:publicKey,
            Output.PRIVATE_KEY:privateKey
        }
        '''
        keys = self.getValue(Output.KEYS)
        return keys if keys != None else []

    def getType(self) -> Union[str,None]:
        '''
        Return the type of output object
        '''
        type = self.getValue(Output.TYPE)
        return type if type != None else Output.UNDEFINED

    def getBalance(self)-> Union[float,None]:
        '''
        Return the balance if any
        '''
        balance = self.getValue(Output.BALANCE)
        return float(balance) if balance != None else 0.0

    def getUTXOs(self) -> list:
        '''
        Returns a list of objects containing the keys Output.TRANSACTION_ID, Output.PREVIOUS_TRANSACTION_UTXO_INDEX, Output.Amount
        [
            {
                Output.TRANSACTION_ID : "",
                Output.PREVIOUS_TRANSACTION_UTXO_INDEX : "",
                Output.Amount : 0.00
            }
        ]
        '''
        UTXOs = self.getValue(Output.UTXOS)
        return UTXOs if UTXOs != None else []

    def getSegwitFlag(self) -> bool:
        '''
        Returns true or false depending on the value of the segwit flag
        '''
        hasSegwit = self.getValue(Output.SEGWIT)
        return hasSegwit if hasSegwit != None else False

    def getValue(self,parameter):
        '''
        Get the value of a specific parameter of the Output instance
        '''
        return self.output[parameter] if parameter in self.output else None

#======================#
# Other output methods #
#======================#===========================================
    def hasProperty(self,property):
        '''
        Returns true if the property exists in the Output instance, else returns false
        '''
        if property in self.output:
            return True
        return False

    def keyNameExists(self,name) -> bool:
        '''
        Check if the name already exists in the Output.KEYS property
        '''
        if not Output.KEYS in self.output: return False
        if type(self.output[Output.KEYS]) == list:
            return len([x for x in self.output[Output.KEYS] if x[Output.NAME] == name]) > 0
        else:
            return False

    def save(self,path):
        '''
        Save the output instance in the given path
        '''
        file = open(path, "w")
        file.write(json.dumps(self.output))
        file.close()

    def load(self,path):
        '''
        Load the file from the given path and create an output instance
        '''
        file = open(path, "r")
        lines = file.readlines()
        jsonLines = ""
        for line in lines:
            jsonLines += line
        try:
            self.output = json.loads(jsonLines)
        except:
            raise FAILED_TO_LOAD_JSON
        file.close()

    def sortKeys(self):
        '''
        Sorts the list of keys and signatures in descending order
        '''
        sorting = lambda x: x[Output.NAME]

        #Sort public keys :
        if Output.KEYS in self.output:
            if type(self.output[Output.KEYS]) == list:
                self.output[Output.KEYS].sort(key=sorting, reverse=True)
        #Sort signatures :
        if Output.SIGNATURES in self.output:
            for tx_index in self.output[Output.SIGNATURES]:
                if type(self.output[Output.SIGNATURES][tx_index]) != list:
                    continue
                self.output[Output.SIGNATURES][tx_index].sort(key=sorting, reverse=True)

#=========================#
# Encryption / Decryption #
#=========================#========================================
class Security:
#This is a static class used to encrypt and decrypt data using AES

    @staticmethod
    def encrypt(raw, password) -> str:
        '''
        Encrypts data using AES. The result is a BAse64 string.
        '''
        BS = AES.block_size
        private_key = hashlib.sha256(password.encode("utf-8")).digest()
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        raw = base64.b64encode(pad(raw).encode('utf8'))
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key= private_key, mode= AES.MODE_CFB,iv= iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf8')

    @staticmethod
    def decrypt(enc, password) -> str:
        '''
        Decrypts data that was encrypted with AES. Returns the result in UTF-8 string.
        '''
        private_key = hashlib.sha256(password.encode("utf-8")).digest()
        unpad = lambda s: s[:-ord(s[-1:])]
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(private_key, AES.MODE_CFB, iv)
        return unpad(base64.b64decode(cipher.decrypt(enc[AES.block_size:])).decode('utf8'))


class HelpAction(argparse._HelpAction):

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()

        # retrieve subparsers from parser
        subparsers_actions = [
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)]
        # there will probably only be one subparser_action,
        # but better save than sorry
        for subparsers_action in subparsers_actions:
            # get all subparsers and print help
            for choice, subparser in subparsers_action.choices.items():
                print("\n{}".format(choice))
                print(subparser.format_help())

        parser.exit()


def getArgument(input,argument,isList=False):
    return getattr(input,argument) if isList else ( getattr(input,argument)[0] if getattr(input,argument) != None else None )