class DECRIPTION():
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IPInverse = [4, 1, 3, 5, 7, 2, 8, 6]
    ExtendP = [4, 1, 2, 3, 2, 3, 4, 1]
    SP = [2, 4, 3, 1]
    SB1 = [[1, 0, 3, 2],
           [3, 2, 1, 0],
           [0, 2, 1, 3],
           [3, 1, 0, 2]]
    SB2 = [[0, 1, 2, 3],
           [2, 3, 1, 0],
           [3, 0, 1, 2],
           [2, 1, 0, 3]]
    K = []
    K1 = []
    K2 = []

    def __init__(self) -> None:
        pass

    def GetKey(self):
        return ''.join(map(str, self.K))

    def GroupPlaintext(self, plaintext: list) -> list:
        #将密文按8bit一组进行分组
        if len(plaintext) % 8 != 0:
            raise ValueError("密文长度必须为8的倍数")
        return [plaintext[i:i + 8] for i in range(0, len(plaintext), 8)]

    def Decryption(self, plaintext: list) -> list:
        #对分组后的明文进行解密
        groups = self.GroupPlaintext(plaintext)
        decrypted_groups = [self._decrypt_8bit(group) for group in groups]
        return [bit for group in decrypted_groups for bit in group]  # 合并分组密文

    def _decrypt_8bit(self, InputBits):
        Step0 = self.PBox(InputBits=InputBits, PermutationTable=self.IP, OutPutLength=8)
        Step1 = self.FeistelFunction(Step0, self.K2, self.K1)
        return self.PBox(InputBits=Step1, PermutationTable=self.IPInverse, OutPutLength=8)

    def XOR(self, list1, list2):
        return [bit1 ^ bit2 for bit1, bit2 in zip(list1, list2)]

    def FeistelFunction(self, InputBits: list, K1, K2):
        RightPart = InputBits[-4:]
        LeftPart = InputBits[:4]
        AfterEP = self.PBox(InputBits=RightPart, PermutationTable=self.ExtendP, OutPutLength=8)
        AfterXOR = self.XOR(AfterEP, K1)
        AfterS1 = self.SBox(InputBits=AfterXOR[:4], SubstitutionBox=self.SB1)
        AfterS2 = self.SBox(InputBits=AfterXOR[-4:], SubstitutionBox=self.SB2)
        OutPut0 = self.PBox(InputBits=AfterS1 + AfterS2, PermutationTable=self.SP, OutPutLength=4)

        # 直接交换
        Temp = LeftPart
        LeftPart = RightPart
        RightPart = self.XOR(Temp, OutPut0)

        AfterEP = self.PBox(InputBits=RightPart, PermutationTable=self.ExtendP, OutPutLength=8)
        AfterXOR = self.XOR(AfterEP, K2)
        AfterS1 = self.SBox(InputBits=AfterXOR[:4], SubstitutionBox=self.SB1)
        AfterS2 = self.SBox(InputBits=AfterXOR[-4:], SubstitutionBox=self.SB2)
        OutPut0 = self.PBox(InputBits=AfterS1 + AfterS2, PermutationTable=self.SP, OutPutLength=4)
        LeftResult = self.XOR(LeftPart, OutPut0)
        RightResult = RightPart

        return LeftResult + RightResult

    def SetKey(self, InputBits: list):
        """列表形式给定10bit密钥,并且生成对应的子密钥"""
        self.K = InputBits
        AfterP10 = self.PBox(InputBits=self.K, PermutationTable=self.P10, OutPutLength=10)
        LeftPartV1 = [AfterP10[:5][(i + 1) % 5] for i in range(5)]
        RightPartV1 = [AfterP10[-5:][(i + 1) % 5] for i in range(5)]
        self.K1 = self.PBox(InputBits=LeftPartV1 + RightPartV1, PermutationTable=self.P8, OutPutLength=8)
        LeftPartV2 = [AfterP10[:5][(i + 2) % 5] for i in range(5)]
        RightPartV2 = [AfterP10[-5:][(i + 2) % 5] for i in range(5)]
        self.K2 = self.PBox(InputBits=LeftPartV2 + RightPartV2, PermutationTable=self.P8, OutPutLength=8)




    def BinaryList2Decimal(self, InputBits: list):
        BinaryString = ''.join(str(bit) for bit in InputBits)
        Decimal = int(BinaryString, 2)
        return Decimal

    def Decimal2BinaryList(self, Number: int):
        BinaryString = bin(Number)
        BinaryList = [int(x) for x in BinaryString[2:]]
        while len(BinaryList) < 2:
            BinaryList.insert(0, 0)
        return BinaryList

    def PBox(self, InputBits, PermutationTable, OutPutLength):
        """
        置换盒，需要用列表的形式传入任意bit数据，并且给定置换表,并且要求填入输出长度
        """
        output_bits = [InputBits[i - 1] for i in PermutationTable]
        return output_bits[:OutPutLength]

    def SBox(self, InputBits, SubstitutionBox):
        # 混淆盒，需要用列表的形式传入4bit数据，并且给定二维数组混淆表
        RowBinary = [InputBits[0], InputBits[3]]
        ColumnBinary = [InputBits[1], InputBits[2]]
        Row = self.BinaryList2Decimal(RowBinary)
        Column = self.BinaryList2Decimal(ColumnBinary)
        return self.Decimal2BinaryList(SubstitutionBox[Row][Column])

if __name__ == "__main__":
   user_input_C = input("请输入密文：")
   C=[]
   for bit in user_input_C:
       C.append(ord(bit) - ord('0'))
   print(C)
   print(type(user_input_C))
   user_input_K = input("请输入密钥：")
   K = [int(bit) for bit in user_input_K]  # 转换为整型列表
   machine = DECRIPTION()
   machine.SetKey(K)
   P = machine.Decryption(C)
   m = ''.join(map(str, P))
   print(m)
   n = binary_string_to_chars(m)
   print("解密结果为：", n)
