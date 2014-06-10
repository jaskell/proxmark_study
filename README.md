proxmark_study
==============

study algorithm about proxmark 

学习有关 Mifare classes 受到攻击的原理
1) Dismantling.MIFARE.Classic-ESORICS.2008 介绍了相关的弱点及利用这些弱点进行攻击的原理
2) Implementing_an_RFID_MIFARE_CLASSIC_Attack 根据这些原理实现了相关的代码

主要参考了以上两篇文章,用go语言实现了部分相关的代码:
1) 根据截获的密钥流恢复LFSR的状态
2) 回溯LFSR状态得到密钥

以上代码实现中会得到两个保存semi-status的大表,文章2中通过先用快速排序算法然后比较相同项来得到密钥.
在用go语言实现时,我改为把两张表用堆的形式保存,然后从堆中取出最小项进行比较的方法,可以提高一些效率.

