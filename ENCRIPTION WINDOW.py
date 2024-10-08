import tkinter as tk
from tkinter import messagebox
import random


class ENCRIPTION():
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
        # 将明文按8bit一组进行分组
        if len(plaintext) % 8 != 0:
            raise ValueError("明文长度必须为8的倍数")
        return [plaintext[i:i + 8] for i in range(0, len(plaintext), 8)]

    def Encryption(self, plaintext: list) -> list:
        # 对分组后的明文进行加密
        groups = self.GroupPlaintext(plaintext)
        encrypted_groups = [self._encrypt_8bit(group) for group in groups]
        return [bit for group in encrypted_groups for bit in group]  # 合并分组密文

    def _encrypt_8bit(self, InputBits):
        Step0 = self.PBox(InputBits=InputBits, PermutationTable=self.IP, OutPutLength=8)
        Step1 = self.FeistelFunction(Step0, self.K1, self.K2)
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

    def SetKey(self):
        """列表形式给定10bit密钥，并且生成对应的子密钥"""
        self.K = [random.choice([0, 1]) for _ in range(10)]
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
        BinaryString = bin(Number)[2:]  # 只取二进制表示的部分
        BinaryList = [int(x) for x in BinaryString]
        # 如果长度不足4位，进行填充
        while len(BinaryList) < 4:
            BinaryList.insert(0, 0)
        return BinaryList

    def PBox(self, InputBits, PermutationTable, OutPutLength):
        """
        置换盒，需要用列表的形式传入任意bit数据，并且给定置换表，并且要求填入输出长度
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


def encrypt():
    plaintext = entry_plaintext.get()
    if not plaintext:
        messagebox.showerror("错误", "明文不能为空！")
        return

    # 将明文转换为整数列表，假设每个字符转换为其ASCII值并填充至8的倍数
    plaintext_bits = []
    for char in plaintext:
        bits = [int(x) for x in format(ord(char), '08b')]  # 每个字符转换为8位二进制
        plaintext_bits.extend(bits)

    # 确保明文长度为8的倍数
    while len(plaintext_bits) % 8 != 0:
        plaintext_bits.append(0)  # 填充0使长度为8的倍数

    try:
        # 创建ENCRIPTION实例并进行加密
        encription = ENCRIPTION()
        encription.SetKey()  # 生成密钥
        ciphertext = encription.Encryption(plaintext_bits)
        key_label.config(text=f"Generated Key: {encription.K}")

        # 检查ciphertext是否有效
        if not isinstance(ciphertext, list):
            raise ValueError("加密返回的密文不是列表")

        # 将密文转换为二进制字符串
        ciphertext_str = ''.join(str(bit) for bit in ciphertext)

        # 将密文转换为二进制数组（使用列表表示）
        ciphertext_list_str = ', '.join(str(bit) for bit in ciphertext)

        label_ciphertext.config(text="密文（二进制数组）: [" + ciphertext_list_str + "]")

    except Exception as e:
        messagebox.showerror("错误", f"加密过程中出现错误: {str(e)}")


# 创建GUI界面
root = tk.Tk()
root.title("加密工具")

# 明文输入
label_plaintext = tk.Label(root, text="请输入明文:")
label_plaintext.pack()

entry_plaintext = tk.Entry(root, width=50)
entry_plaintext.pack()

# 加密按钮
btn_encrypt = tk.Button(root, text="加密", command=encrypt)
btn_encrypt.pack()

# 密钥显示
key_label = tk.Label(root, text="Generated Key: ")
key_label.pack()

# 密文输出
label_ciphertext = tk.Label(root, text="密文:")
label_ciphertext.pack()

# 启动GUI主循环
root.mainloop()