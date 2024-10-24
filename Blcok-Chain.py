import hashlib
import time
import ecdsa

# hashlib 模块中的算法 要求输入是字节类型的对象，而不是字符串，所以需要重写sha256函数
def sha256(datahash):
    sha256 = hashlib.sha256()
    sha256.update(datahash.encode("utf-8"))
    return sha256.hexdigest()

# 通过这个类，获得用户的私钥与公钥
class genKeyPair:
    def __init__(self, name):
        self.name = name
        self.privateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.publicKey = self.privateKey.get_verifying_key()

class Transaction:
    # Sender:发送方 Receiver:接收方 Amount:转账金额
    def __init__(self, Sender, Receiver, Amount):
        self.Sender = Sender
        self.Receiver = Receiver
        self.Amount = Amount

    def __str__(self):
        return f"From: {self.Sender}, To: {self.Receiver}, Amount: {self.Amount}"

    def ComputeHash(self):
        data_to_hash = str(self.Sender) + str(self.Receiver) + str(self.Amount)
        return str(sha256(data_to_hash)).encode()

    # 这里也可以通过形参来获取privateKey 如 def sign(self, privateKey):
    def sign(self):
        self.signature = self.Sender.privateKey.sign(self.ComputeHash())
        return self.signature

    # 用于判断签名是否合法
    def isValid(self, vk):
        if self.Sender == "":
            return True
        try:
            vk.verify(self.signature, self.ComputeHash())   # 如果验证成功verify将返回True
        except ecdsa.keys.BadDigestError:
            return False
        return True


class Block:
    def __init__(self, transactions, previousHash):
        self.transactions = transactions
        self.previousHash = previousHash
        self.timestamp = time.time()   # 时间戳
        self.nonce = 1  # 用于找到符合条件哈希值的随机数
        self.hash = self.ComputeHash()

    def __str__(self):
        #   在Python中，当你使用字符串的join方法时，它会将列表中的每个元素转换为字符串。
        #   如果列表中的元素是自定义对象，并且你提供了__str__方法，那么join方法会调用每个对象的__str__方法来获取它们的字符串表示形式。
        return f"Transaction: {' --> '.join([str(transaction) for transaction in self.transactions])}, \n" \
               f"Previous Hash: {self.previousHash}, \n" \
               f"Hash: {self.hash}, Nonce: {self.nonce}, Timestamp: {self.timestamp}"

    def ComputeHash(self):
        data_to_hash = str(self.transactions) + self.previousHash + str(self.nonce) + str(self.timestamp)
        return str(sha256(data_to_hash))

    # 这个函数是获取符合困难度的前导0
    def countLeadingZeros(self, difficulty):
        answer = ""
        for i in range(0, difficulty):
            answer += "0"
        return answer

    # 找到符合条件的Hash值
    def mine(self, difficulty):
        self.validateBlockTransactions()   # 在挖矿前需要验证交易是否合法
        # 下面是使挖出来的区块必须满足所设难度的前导0
        while True:
            self.hash = self.ComputeHash()
            if self.hash[:difficulty] != self.countLeadingZeros(difficulty):
                self.nonce += 1
            else:
                break
        print("挖矿结束", self.hash)

    # 该函数用于判断交易是否合法
    def validateBlockTransactions(self):
        for transaction in self.transactions:
            if transaction.Sender == "":
                continue
            if not transaction.isValid(transaction.Sender.publicKey):
                raise Warning("invalid transaction found in transaction -- 发现异常交易")

    # 这个函数用于打印某个区块
    def showBlock(self):
        print(f"Block: {{\n"
              f"    {' --> '.join([str(transaction) for transaction in self.transactions])} \n"
              f"    previousHash: {self.previousHash}, \n"
              f"    Hash: {self.hash}, \n"
              f"    Nonce: {self.nonce}, \n"
              f"    timestamp:{self.timestamp}\n"
              f"}}")


class Chain:
    def __init__(self):
        self.chain = [self.constructTheGenesisBlock()]   # chain是一个包含区块的数组，初始化时：里面有一个创世区块.
        self.transactionpool = []  # 这是一个交易池，用于存储交易
        self.mineReward = 50  # 这是挖出新区块后，系统发放给矿工的奖励
        self.difficulty = 2    # 这是这条区块链上系统设置的挖矿难度，其实就是哈希值前导0的个数

    # 该函数用于生成一个创世区块
    def constructTheGenesisBlock(self):
        genesisBlock = Block("创世区块", "")  # 创世区块并不包含上一个区块的哈希值
        return genesisBlock

    # 用于打印出这一条区块链上所有 区块的信息
    def showChain(self):
        for i in self.chain:
            i.showBlock()

    # 用于获取前一个区块的Hash值
    def getPreviousHash(self):
        previousHash = self.chain[len(self.chain) - 1].hash
        return previousHash

    # 添加transaction 到 transactionPool里
    def addTransaction(self, transaction):
        if transaction.Sender == "" or transaction.isValid(transaction.Sender.publicKey):
            print("valid transaction--添加成功")
            self.transactionpool.append(transaction)
        else:
            raise Warning("invalid transaction--添加失败")

    # 1.将第一笔发放奖励的交易加入到矿池 2.挖出新区快 3.将新区块加入到链上 4.清空交易池
    def addBlock(self, AccountDealingAddress):
        # AccountDealingAddress就是记账人的地址（其实就是成功挖到区块的矿工 的地址）
        # 发放开采成功的旷工奖励
        self.mineRewardTransaction = Transaction("", AccountDealingAddress, self.mineReward)
        self.transactionpool.append(self.mineRewardTransaction)   # 将交易加入到交易池中
        # 挖矿
        newBlock = Block(self.transactionpool, self.getPreviousHash())
        newBlock.mine(self.difficulty)
        # 添加区块到区块链上,并且清空transactionpool
        self.chain.append(newBlock)
        self.transactionpool = []

    # 检查数据data是否被篡改
    # 检查Hash是否被篡改，导致断链
    def checkChain(self):
        if len(self.chain) == 1:
            if self.chain[0].hash != self.chain[0].ComputeHash():
                return False
            return True

        for i in range(1, len(self.chain)):
            TheCurrentBlock = self.chain[i]
            TheCurrentBlock.validateBlockTransactions()
            if TheCurrentBlock.hash != TheCurrentBlock.ComputeHash():
                print("数据被篡改了！")
                return False
            previousBlock = self.chain[i - 1]
            if TheCurrentBlock.previousHash != previousBlock.hash:
                print("前后区块断链了！")
                return False
        return True

lsmcoin = Chain()

sender = genKeyPair("Sender")
privateKeySender = sender.privateKey
publicKeySender = sender.publicKey

receiver = genKeyPair('Receiver')
privateKeyReceived = receiver.privateKey
publicKeyReceived = receiver.publicKey

t1 = Transaction(sender, receiver, 20)
t1.sign()
print(t1.isValid(publicKeySender))

lsmcoin.addTransaction(t1)
lsmcoin.addBlock("AccountDealingAddress")

print(lsmcoin.checkChain())
lsmcoin.showChain()



