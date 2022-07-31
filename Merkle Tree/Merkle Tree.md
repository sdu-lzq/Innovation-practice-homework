### Merkle Tree

![image-20220730163720881](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730163720881.png)

Merkel树的实现原理如图，和哈希列表一样，把数据分成小的数据块，最下面的叶节点包含存储数据或其哈希值，非叶子节点（包括中间节点和根节点）都是它两个孩子节点内容的hash值。

```python
#向上逐步迭代生成merkel树
def generate_Tree(blocks):
    depth = math.ceil(math.log2(len(blocks)+1))
    #The depth of the tree.
    Treenode = [[hashlib.sha256(('0x00'+data).encode()).hexdigest() for data in blocks]]
    assert Treenode[0][-1] != Treenode[0][-2]
    #对最后两个元素进行检测，是否是篡改以后相等
    #将每一个元素进行hash运算
    for i in range(depth):
        lay_number = len(Treenode[i]) #每一层的个数
        #print(lay_number)
        Treenode.append([hashlib.sha256(('0x01'+Treenode[i][j*2]).encode()+('0x01'+Treenode[i][j*2+1]).encode()).hexdigest() for j in range(int(lay_number/2))])
        if lay_number%2!=0:
            Treenode[i+1].append(Treenode[i][-1]) 
    
    return Treenode
```

[Merkle Tree 实现细节及（不）存在性证明 - 简书 (jianshu.com)](https://www.jianshu.com/p/bfe990be3a21)

存在性证明

当有全节点收到这个MSG_MERKLEBLOCK请求之后，利用传过来的交易信息在自己的区块链数据库中进行查询，并把验证路径返回给请求源，SPV节点拿到验证路径之后，再做一次merkle校验

Alice要证明自己的一笔transaction属于某一区块，需要给出该transcation在某一区块中的序号，然后由叶节点由主链计算回Root节点，并验证Root节点的value

```python
def Inclusion_Proof(element,Treenode):
    value = (hashlib.sha256(('0x00'+element).encode())).hexdigest()
    #判断是不是一个单独的数据块
    depth = len(Treenode)
    path = []
    if value in Treenode[0]:
        index = Treenode[0].index(value)
    else:
        print("The element not in the merkle tree.")
        return
    #print(depth-1)
    for i in range(depth):
        if index%2 ==  0:
            if index+1 != len(Treenode[i]):
                path.append(['left',Treenode[i][index+1]])
            #将这个值放入merkel树
        else:
            path.append(['right',Treenode[i][index-1]])
        index = int(index/2)
    #这里应该注意hash拼接的顺序
    for w in path:
        if w[0] == 'left':
            value = hashlib.sha256(('0x01'+value).encode()+('0x01'+w[1]).encode()).hexdigest()
        else:
            value = hashlib.sha256(('0x01'+w[1]).encode()+('0x01'+value).encode()).hexdigest()
    #print(Treenode[depth-1][0])
    if value == Treenode[depth-1][0]:
        print("Inclusion proof correct.")
    else:
        print("Inclusion proof false.")
```

不存在性证明

不存在性证明基于交易是排序的，通过对比pre与next确定Merkle根进行存在性证明，并锁定pre和next在Merkle Tree TXID Nodes中的位置，并对相应区块进行不确定性证明

如TX3(3) 和TX4(5) 相邻,我们可以对TXn(4)的不存在性进行证明

```python

#不存在性证明基于交易是排序的
def Exclusion_proof(element,Treenode,blocks):
    Value = hashlib.sha256(element.encode()).hexdigest()
    if Value in Treenode[0]:
        print('element exist.')
    else:
        length = len(Treenode[0])
        for i in range(length-1):
            if blocks[i]<element and blocks[i+1]>element:
                print('Pre:',blocks[i])
                Inclusion_Proof(blocks[i],Treenode)
                print('Next:',blocks[i+1])
                Inclusion_Proof(blocks[i+1],Treenode)
            else:
                continue
    return 

```

#### 结果验证

可以直接对验证代码进行运行

也可以用Generate_data随机对block数据进行生成，也可以改变block大小进行验证

![image-20220730172926460](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730172926460.png)
