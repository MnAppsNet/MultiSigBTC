from numpy import RAISE
import tools
from pathlib import Path
from bitcoin import Bitcoin
from exceptions import INVALID_PUBLIC_KEY, INVALID_PATH, INVALID_PARAMETER, INVALID_INPUT, INVALID_ADDRESS, NOT_ENOUGH_SIGNATURES, AMOUNT_NOT_FLOAT, KEY_NAME_NOT_FOUND, NOT_CORRECT_FILE
from tools import Output

def createMultisigAddress(signaturesRequired:int,keys:list,bitcoin:Bitcoin,path:str = None):
    '''
    Create a new Multi Signature Address
        signaturesRequired  : number of signatures required to unlock a UTXO
        keys                : The keys to be used, see option below
            Option 1 : Pairs of names of the keys (can be whatever, needs to be unique) and public keys (ex. John key1 Bob key2 ...)
            Option 2 : The paths of the files containing the key to be used
        bitcoin : An instance of the class Bitcoin
        path    : Path to save the results
    '''
    multisigAddress = tools.Output(Output.MULTISIG_ADDRESS)

    try:
        signaturesRequired = int(signaturesRequired)
    except:
        raise INVALID_PARAMETER(argumentIndex-1)

    multisigAddress.addNumberOfRequiredSignatures(signaturesRequired)

    #Gather public keys and their names :
    argumentIndex = 0 #This index is used to gather data from keys list
    while True:
        publicKey = None
        #Get name of the key:
        argumentIndex, name = __getParameter(keys,argumentIndex)

        if name == None: break #< Exit if nothing else to gather

        if (Path(name).is_file()):
            #Check if input is a file, then load data from settings file:
            key = Output.Load(name)
            name = key.getKeys()[Output.NAME]
            publicKey = key.getKeys()[Output.PUBLIC_KEY]
        else:
            try:
                #Check if input is the json content of the expected file:
                key = Output.LoadFromJSON(name)
                name = key.getKeys()[Output.NAME]
                publicKey = key.getKeys()[Output.PUBLIC_KEY]
            except:
                pass

        #Get the public key :
        if publicKey == None:
            argumentIndex, publicKey = __getParameter(keys,argumentIndex)
            if not Bitcoin.isPublicKeyValid(publicKey):
                raise INVALID_INPUT(publicKey)

        if publicKey == None: break #< Exit if nothing else to gather

        if not Bitcoin.isPublicKeyValid(publicKey):
            raise INVALID_PUBLIC_KEY(publicKey)

        #Store gathered name and public key :
        multisigAddress.addKey(name,publicKey)

    multisigAddress.sortKeys() #<= Sort keys by name to keep the same order every time we create the script
    redeem_script = bitcoin.createMultisigScript(multisigAddress.getNumberOfRequiredSignatures(),multisigAddress.getKeys())
    address = bitcoin.getAddressFromScript(redeem_script)
    multisigAddress.addAddress(address)
    multisigAddress.addScript(redeem_script)

    if path != None:
        if not Path(path).parents[0].is_dir():
            raise INVALID_PATH(path)
        multisigAddress.save(path)

    return multisigAddress.getOutput()

def createNewAddress(name:str,password:str,seed:str,bitcoin:Bitcoin,path:str = None):
    '''
    Create a new Public - Private key pair and the corresponding address
        name    : name of the address
        password: password to lock private key
        seed    : the seed to be used for random number generator
        bitcoin : An instance of the class Bitcoin
        path    : Path to save the results
    '''
    address = tools.Output(Output.P2PKH_ADDRESS)

    privKey, publicKey, btcAddress = bitcoin.createKeys(seed)
    address.addKey(name,publicKey,privKey,password)
    address.addAddress(btcAddress)
    if path != None:
        if not Path(path).parents[0].is_dir():
            raise INVALID_PATH(path)
        address.save(path)

    return address.getOutput()

def createMultisigTransaction(receiver:str,amount,fee,file,bitcoin:Bitcoin,path:str = None):
    '''
    Create a multi signature transaction
        receiver : Address to send the funds to or a json file containing the address
        amount   : Amount to spend
        fee      : Fee to pay
        file     : The file containing all multi signature keys, redeem script and the required number of signatures, or the content in JSON
        bitcoin : An instance of the class Bitcoin
        path    : Path to save the results
    '''

    #Check if the receiver is given by a file :
    if Path(receiver).is_file():
        try:
            receiver = Output.Load(receiver)
            receiver = receiver.getAddress()
        except:
            raise INVALID_INPUT(file)

    if not Path(file).is_file():
        try:
            keys = Output.LoadFromJSON(file)
        except:
            raise INVALID_INPUT(file)
    else:
        keys = Output.Load(file)

    #Create the transaction :
    sender = keys.getAddress()
    try:
        amount = float(amount)
        fee = float(fee)
    except:
        raise AMOUNT_NOT_FLOAT
    rawTransaction = bitcoin.createTransaction(amount,fee,sender,receiver)
    transaction = Output(Output.MULTISIG_TRANSACTION)
    transaction.addUnsignedTransaction(rawTransaction)
    transaction.addKeys(keys.getKeys())
    transaction.addScript(keys.getScript())
    transaction.addNumberOfRequiredSignatures(keys.getNumberOfRequiredSignatures())

    #Save results if a path is provided :
    if path != None:
        if not Path(path).parents[0].is_dir():
            raise INVALID_PATH(path)
        transaction.save(path)

    return transaction.getOutput()

def getPrivateKey(encrypted,password):
    '''
    Decrypts the private key and returns it in WIF uncompressed format
        encrypted : path of the wallet file or encrypted private key string
        password  : password to unlock private key
    '''

    settings = tools.Output(Output.P2PKH_ADDRESS)

    if Path(encrypted).is_file():
        settings.load(encrypted)
    else:
        settings.addAddress("","",encrypted)

    return settings.getPrivateKey(password)

def signMultisigTransaction(transaction,addressFile_or_key,password_or_name,bitcoin:Bitcoin,savePath:str):
    '''
    Create a multi signature transaction
        transaction             : The file containing all multi signature keys or the content in JSON\n
        Option 1:
            addressFile_or_key  : The address file containing the encrypted private key (created with createNewAddress method)
            password_or_name    : The password to decrypt the private key
        Option 2:
            addressFile_or_key  : The private key itself
            password_or_name    : The name of the key as provided during the multi signature creation (method createMultisigAddress).
                                  This Important to keep the correct order of the keys!
    '''

    #Get the file with the transaction :
    if not Path(transaction).is_file():
        try:
            transaction = Output.LoadFromJSON(transaction)
        except:
            raise INVALID_INPUT(transaction)
    else:
        transaction = Output.Load(transaction)

    expectingName = False #<= Set to true if addressFile_or_key parameter is a key

    #Get the file with the keys :
    if not Path(addressFile_or_key).is_file():
        #Expecting the private key itself if not address, this means that instead of a password we expect the name
        key = addressFile_or_key
        address = Output(Output.P2PKH_ADDRESS)
        address.addKey(None,None,key)
        expectingName = True
    else:
        address =  Output.Load(addressFile_or_key)

    #Get the password, private key, key name, raw transaction in Hex and the redeem script :
    if expectingName:
        if not transaction.keyNameExists(password_or_name):
            raise KEY_NAME_NOT_FOUND(password_or_name)
        address.addKeyName(password_or_name)
    else:
        privateKey = address.getPrivateKey(password_or_name)

    keyName = address.getKeyName()
    rawTransactionHex = transaction.getUnsignedTransaction()
    redeemScript = transaction.getScript()

    #Loop on each input transaction we need to sign and generate signatures
    txIndex = 0
    for tx in bitcoin.getTransactionInputs(rawTransactionHex):
        signature = bitcoin.signUTXO(privateKey,rawTransactionHex,txIndex,redeemScript)
        transaction.addSignature(keyName,signature,tx.txid)
        txIndex += 1

    transaction.sortKeys()

    #Save results if a path is provided :
    if savePath != None:
        if not Path(savePath).parents[0].is_dir():
            raise INVALID_PATH(savePath)
        transaction.save(savePath)

    return transaction.getOutput()

def sendTransaction(transaction,bitcoin:Bitcoin):
    '''
    Sends a transaction to the given network
        transaction : A file containing the signed transaction or the signed transaction in raw hex format
    '''

    #Check if transaction given is a file. If so, load data from it :
    if Path(transaction).is_file():
        transaction = Output.Load(transaction)
        transaction = transaction.getSignedTransaction()

    return bitcoin.sendTransaction(transaction).getOutput()

def createdSignedTransaction(transaction,bitcoin:Bitcoin,savePath:str):
    '''
    Get the signed transaction that can be submitted to the Network. Returns the raw hex format of the transaction.
        transaction : The file path or the json string of the transaction with all the transaction details and signatures.
                      It can be created with the methods createMultisigTransaction() and signMultisigTransaction()
    '''

    #Get the file with the transaction and signatures :
    if not Path(transaction).is_file():
        try:
            transaction = Output.LoadFromJSON(transaction)
        except:
            raise INVALID_INPUT(transaction)
    else:
        transaction = Output.Load(transaction)

    if not transaction.hasProperty(Output.SIGNATURES):
        raise NOT_CORRECT_FILE(Output.SIGNATURES)

    transaction.sortKeys()
    redeemScript = transaction.getScript()
    unsignedTransaction = transaction.getUnsignedTransaction()

    signatures = {}
    for tx in bitcoin.getTransactionInputs(unsignedTransaction):
        scriptSig = ['OP_0'] #<= We set an extra element in scriptSig due to a bug with OP_CHECKMULTISIG. It pops one extra element
        requiredSignatures = transaction.getNumberOfRequiredSignatures()
        txSignatures = transaction.getTransactionSignatures(tx.txid)
        if len(txSignatures) < requiredSignatures:
            raise NOT_ENOUGH_SIGNATURES(len(txSignatures),requiredSignatures)
        for signature in txSignatures:
            scriptSig.append(signature[Output.SIGNATURE])
            requiredSignatures -= 1
            if requiredSignatures <= 0: break; #Got only the amount of signatures needed <- Issue : The first signatures might be invalid but the rest valid, a validity check is needed {!}
        scriptSig.append(bitcoin.getScriptInHex(redeemScript))
        signatures[tx.txid] = scriptSig

    #Add signatures in the transaction :
    signedTransaction = bitcoin.addSignaturesToTransaction(unsignedTransaction,signatures)

    transaction.addSignedTransaction(signedTransaction)

    #Save results if a path is provided :
    if savePath != None:
        if not Path(savePath).parents[0].is_dir():
            raise INVALID_PATH(savePath)
        transaction.save(savePath)

    return signedTransaction

def getAddressBalance(address,bitcoin:Bitcoin):
    '''
    Get a list with all the UTXOs related to the address along with the total balance
        address : The address to use or an output file containing the address
    '''

    #Check if address is a file and get it's content :
    if Path(address).is_file():
        address = Output.Load(address)
        address = address.getAddress()

    if not bitcoin.isAddressValid(address):
        raise INVALID_ADDRESS(address)

    return bitcoin.getUTXOs(address).getOutput()

def __getParameter(args:list,argsIndex:int):
    try:
        value = args[argsIndex]
        argsIndex += 1
    except:
        value = None
    return argsIndex, value