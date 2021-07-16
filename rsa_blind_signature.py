import time
import OpenSSL
import warnings
import binascii#用于16进制到2进制的转换
import base64
from Crypto.Util import number#生成大素数模块

warnings.filterwarnings("ignore")

#RSA签名的相关参数
p = number.getPrime(1024) #生成1024bit大素数
q = number.getPrime(1024) #生成1024bit大素数
n = p*q 

e = number.getPrime(60)    #随机获得60位素数，这样一定满足与phi互素

#欧几里得算法求最大公因数
def gcd(a ,b): 
    while a!= 0:
        a, b = b % a, a
    return b

#扩展欧几里得算法求模逆
def reverse(a ,m)  :  
    if gcd(a ,m )!=1:
        return None
    u1  ,u3 = 0 , m
    v1  ,v3 = 1  ,a
    while v3!=0:
        q = u3//v3
        v1 ,v3 ,u1 ,u3 = (u1 - q *v1) ,(u3 - q *v3) ,v1 ,v3
    return u1 % m

#RSA的签名函数
def rsa_sign(mp):
    phi = (p - 1) * (q - 1)   #即欧拉函数φ(n)
    d=reverse(e,phi)
    sp=pow(mp,d,n)
    return sp

#RSA的验签函数
def rsa_verify(flag):
    c = pow(flag, e, n)
    mpp = hex(c)[2:]  # 16进制的整型数据
    mpp=binascii.a2b_hex(mpp) #十六进制转换为二进制字节流
    mpp=mpp.decode()  #字节流转换为字符串
    return  mpp

#计票函数
def score(votes,message):
    votes[message]+=1
    return votes

#投票人发送消息，选举委员会进行签名的函数
def running(fl):
    k = number.getPrime(512) #随机数k
    kni = reverse(k, n) #k的逆
    l = len(fl)  # 经测试，1024bit的p和q能够加密字符串的最大长度为256
    list1 = [] #用来存hash值的base64编码
    z = 0#统计分组个数
    while l > 256:#长度大于256了就分组
        list1.append(fl[z * 256:(z + 1) * 256])
        l -= 256
        z += 1
    list1.append(fl[z * 256:(z + 1) * 256])

    mpo=''  #mp=k^e*m mod n的拼接
    spo = '' #sp=mp^d mod n的拼接
    so='' #s=kni*sp mod n的拼接
    flag = '' #计票人计算结果的拼接
    time=1
    for mpp in list1:    #此时mpp为base64格式，需要连续进行格式转换
        m = mpp.encode()  # 将字符串转换为二进制比特流
        m = binascii.b2a_hex(m)  # 将二进制流装换为十六进制比特流
        m = int(m, 16)  # 将十六进制比特流装换为整型数据
        print('第', time, '段m为：', m)
        mp = pow(k, e, n) * m % n  #投票人计算mp=k^e*m mod n
        print('第', time, '段需要签名的mp为：', m)
        mpo+=str(mp)
        sp = rsa_sign(mp)  #选举委员会进行签名，将签名后的值sp=mp^d mod n发给投票人
        print('第',time,'段签名后的sp为：',sp)
        spo+=str(sp)
        s = sp * kni % n #投票人计算s=kni*sp mod n
        print('第',time,'段投票人处理后的s为：',s)
        so += str(s)

        mpp = rsa_verify(s) #投票人将s发给计票人让他认证签名并计票
        print('第', time, '段投票人得到的hash值的base64编码为：', mpp)
        flag += mpp
        time+=1
    return mpo,spo,so,flag

if __name__ == '__main__':
    key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open("secret.key").read()) #导入OpenSSL的秘钥
    votes={'刘':0,'董':0,'李':0,'罗':0,'匡':0,'王':0,'许':0,'陈':0,'胡':0,'郑':0}
    print('欢迎来到rsa盲签名算法的电子选举系统：',end='')
    menu = """
########################################################
    1. 投票
    2. 结束投票
当前的票数为：
"""
	#显示当前票数情况
    print(menu, end='')
    for i in votes:
        print(i,'：',votes[i])
    print('########################################################')
    person=[]#投票人列表
    flag=1#预设flag值以进入循环
    while flag != '2':
        flag = input('请输入要执行的操作的序号：')
        while flag not in ['1','2']:#输入不合法就重新输入
            print('请输入正确的操作！')
            flag = input('\n请输入要执行的操作的序号：')  	
        message = input('请输入你要投票的人的姓名：')
        while message not in votes.keys():#输入错误就重新输入
        	print('没有找到该选手，请重新投票！')
        	message = input('\n请输入你要投票的人的姓名：')

        t=str(time.time())[-5:]#取时间戳的最后5位作为投票人的唯一标识
        haxi = OpenSSL.crypto.sign(key,message+t, 'sha1')#openssl输出的hash值经过特殊编码，因此需转化为其他编码才能使用
        haxi=base64.b64encode(haxi).decode() # 转换为BASE64的格式
 

        #签名方
        mp,sp,s,mpp=running(haxi)#运行整体函数，将选举委员会的签名s，和验证方对签名的验证结果mpp返回。
        # print('投票人需要签名的mp为：',mp)
        # print('选举委员会需要签名的sp为：',sp)
        print('投票人处理后的s为：',s)
        print('投票人待发送的三元组为',(message,t,s))#消息，标识，签名3元组

        #若验证方的验证结果mpp，与明文所产生的hash值相同，则说明验证成功，投票合法。
        if haxi==mpp:
            print('经验证，验证方对投票人签名的验证结果，与投票人明文+标识产生的hash结果一致！')
            print('计票人验证成功！')
            votes=score(votes,message)#计票
            person.append((message,t))#将投票结果计入投票人列表
        #显示当前票数情况
        print(menu, end='')
        for i in votes:
            print(i, '：', votes[i])
        print('投票情况：')
        print(person)
        print('########################################################')