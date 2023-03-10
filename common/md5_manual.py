import binascii
import hashlib
import math
import struct
from loguru import logger


class Md5Manual:
    """
    手动实现md5算法
    """
    def __init__(self):


        self.muilt_block = False
        self.msg_len = None
        logger.debug("init......")
        # 初始向量
        self.A, self.B, self.C, self.D = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        # 循环左移的位移位数
        self.r = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
             ]
        # 使用正弦函数产生的位随机数，也就是书本上的T[i]
        self.k = [int(math.floor(abs(math.sin(i + 1)) * (2 ** 32))) for i in range(64)]

    def _count_worth_leng(self, target_str: bytes):
        count = 0
        for index, i in enumerate(target_str):
            # print(hex(i))
            if hex(i) == '0x80' and hex(target_str[index+1]) == '0x0':

                print("yes")
                break
            count += 1
        print(f"意义长度：{count}")
        return count

    def padding_str(self, message=None):
        """不足64B时的填充算法"""
        # 计算位的长度
        logger.debug("正在填充")
        m_l = len(message)
        if self.muilt_block:
            logger.debug("启用了父类长度")
            m_l = self.msg_len
        length = struct.pack('<Q', (m_l) * 8)  # unsigned long long 8B
        logger.debug(f"长度({m_l}):{length}")
        # 长度不足64位消息自行填充
        logger.debug(f"填充前的msg({len(message)}): {message}")
        # if len(message) < 64:
        blank_padding = b""
        message += b'\x80'  # 10000000
        if 56 < len(message) < 64:
            blank_padding += b'\x00' * (56 + 64 - len(message))
        else:
            blank_padding = b'\x00' * (56 - len(message) % 64)
        logger.debug(f"空填充为（{len(blank_padding)}）:{blank_padding}")
        if len(blank_padding) > 0:
            message += blank_padding
        # print type(length)
        logger.debug(f"填充padding的msg({len(message)}): {message}")
        message += length
        logger.debug(f"填充后的msg({len(message)}): {message}")
        return message

    def init_mess(self, message):
        """
        数据预处理
        :param message:
        :return:
        """
        # print(message)
        # print(len(message))
        logger.debug(f"message: {message}")
        logger.debug(f"字符串长度{len(message)}")

        # print(length)
        # print(f"字符串长度{length}")
        self.msg_len = len(message)
        if(self.msg_len) > 64:
            self.muilt_block = True
        # 按照 512bit/64B 一组进行处理
        while len(message) > 64:
            self.solve(message[:64])
            message = message[64:]

        message = self.padding_str(message)
        while len(message) > 64:
            self.solve(message[:64])
            message = message[64:]
        self.solve(message[:64])

    def solve(self, chunk):
        """
        计算具体块的压缩算法（不用关心）
        :param chunk:
        :return:
        """

        logger.debug(f"分块长度：{len(chunk)}")
        logger.debug(f"分块内容：{chunk}")
        w = list(struct.unpack('<' + 'I' * 16, chunk))  # 分成16个组，I代表1组32位
        # print(w)
        logger.debug(hex(self.A))
        a, b, c, d = self.A, self.B, self.C, self.D

        for i in range(64):  # 64轮运算
            if i < 16:  # 每一轮运算只用到了b,c,d三个
                f = (b & c) | ((~b) & d)
                flag = i  # 用于标识处于第几组信息
            elif i < 32:
                f = (b & d) | (c & (~d))
                flag = (5 * i + 1) % 16
            elif i < 48:
                f = (b ^ c ^ d)
                flag = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                flag = (7 * i) % 16
            # print(f"flag is : {flag}")
            tmp = b + self._lrot((a + f + self.k[i] + w[flag]) & 0xffffffff, self.r[i])  # &0xffffffff为了类型转换
            a, b, c, d = d, tmp & 0xffffffff, b, c
            # print(hex(a).replace("0x","").replace("L",""), hex(b).replace("0x","").replace("L","") , hex(c).replace("0x","").replace("L",""), hex(d).replace("0x","").replace("L",""))
        # 输出
        self.A = (self.A + a) & 0xffffffff
        self.B = (self.B + b) & 0xffffffff
        self.C = (self.C + c) & 0xffffffff
        self.D = (self.D + d) & 0xffffffff
        logger.debug(f"块计算后A：{self.hex_digest()}")

    def _lrot(self, x, n):
        """循环左移"""
        return (x << n) | (x >> 32 - n)

    def digest(self):
        """打包"""
        return struct.pack('<IIII', self.A, self.B, self.C, self.D)

    def hex_digest(self):
        """转化为16进制"""
        # print(self.digest())
        return binascii.hexlify(self.digest()).decode()

    def run(self, mess) -> str:
        self.__init__()
        # print(type(mess))
        if type(mess) is str:
            # print("1111")
            logger.debug("字符串")
            self.init_mess(mess.encode())
        else:
            logger.debug("字节")
            self.init_mess(mess)
        out_put = self.hex_digest()

        return out_put

    def test_func(self): ...


md5_manual = Md5Manual()

if __name__ == '__main__':
    test_str = "1"*56
    print(test_str)
    print(hashlib.md5(test_str.encode()).hexdigest())
    print(md5_manual.run(test_str.encode()))
