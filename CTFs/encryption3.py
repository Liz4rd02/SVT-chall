flag = b"txw\x7fkr;ohwtz\x82\x81nypw\x84\x89v\x82\x8aw\x7f\x8f\x89\x99"

real_flag = bytes(flag[i] - i - 1 for i in range(len(flag)))
print(real_flag)
