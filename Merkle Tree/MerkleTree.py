import hashlib
from multiprocessing.dummy import Value
import random
import string
import math
from numpy import block


#随机生成元素
def Generate_data_block(blocknumber):
    blocks = []  #用来存储块数据
    for i in range(blocknumber):
        number = [random.choice(string.digits) for _ in range(10)]
        blocks.append(''.join(number)) #将生成的数组迭代数据进行一个合并
    return blocks


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




# for i in range(5):
#     print(Treenode[i])



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
                print("Exclusion proof correct.")
            else:
                continue
    return 


# blocks = Generate_data_block(10)
#可以调整规模进行生成
blocks = ['1','10','8','9','3','6']
for i in blocks:
    print("TX{} value:{}".format(blocks.index(i),i))
Treenode = generate_Tree(blocks)
#print(Treenode)
print("对TX5的存在性证明")
Inclusion_Proof('6',Treenode)

Sort_blocks = sorted(blocks)
Treenode2 = generate_Tree(Sort_blocks)
print("证明一笔交易不存在性 value:4")
Exclusion_proof('4',Treenode2,Sort_blocks)