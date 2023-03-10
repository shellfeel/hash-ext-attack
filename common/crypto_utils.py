class CryptoUtils:

    @staticmethod
    def trans_str_origin2_bytes(strings: str):
        """
        写入指定bute数据
        :param strings:
        :return:
        """
        plain_text = strings
        tmp_b_array = bytearray()
        for index, i in enumerate(plain_text):
            index += 1
            if index % 2 == 0:
                tmp_str = plain_text[index - 2:index]
                tmp_str = int(tmp_str, 16)
                tmp_b_array.append(tmp_str)
        return tmp_b_array



