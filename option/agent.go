package option

import (
	"crypto/rand"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
	"net"
	"os"
	"time"
)

var sendBuffer = make([]byte, 1024)
var receiveBuffer = make([]byte, 1024)
var rBuffer = make([]byte, 1024)
var key = make([]byte, 16)
var kong = make([]byte, 1024)

func receive(conn1 *net.UDPConn) int {
	mark := 0
	for {
		err := conn1.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			return 1
		}
		_, _, err = conn1.ReadFromUDP(receiveBuffer)
		if err != nil {
			if mark >= 10 {
				fmt.Println("超时次数过多")
				os.Exit(1)
			}
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() { // 超时错误
				fmt.Println("接收超时，进行重传...")
				mark++
				sendto(conn1)
				time.Sleep(1 * time.Second) // 等待1秒后再次尝试接收数据包
				continue
			} else { // 其他错误
				fmt.Println("接收数据失败:", err)
				return 1
			}
		}
		return 0
	}
}
func sendto(conn1 *net.UDPConn) int {

	// 发送数据
	_, err := conn1.Write(sendBuffer)
	if err != nil {
		fmt.Println("发送数据失败:", err)
		return 1
	}

	fmt.Println("报文已成功发送！")
	return 0
}
func request(conn1 *net.UDPConn) int {
	sendBuffer[0] = '0'
	sendBuffer[1] = '1'
	sendBuffer[2] = '0'
	sendBuffer[3] = '1'
	for {
		erc := sendto(conn1)
		if erc != 0 {
			continue
		}
		erc = receive(conn1)
		if erc != 0 {
			continue
		}
		if receiveBuffer[1] == '3' && receiveBuffer[3] == '1' {
			fmt.Println("receive the request")
			return 0
		}
		if receiveBuffer[1] == '4' {
			fmt.Println("something wrong!")
			return 1
		}
	}
}

func KeyNegotiation(conn1 *net.UDPConn) *sm2.PrivateKey {
	ida := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'} //测试用标识号
	var xxx = rand.Reader

	priv, _ := sm2.GenerateKey(xxx)
	var temp = rand.Reader
	temppri, _ := sm2.GenerateKey(temp)
	i := 32

	sendBuffer[0] = '0'
	sendBuffer[1] = '5'
	sendBuffer[2] = '0'
	sendBuffer[3] = '1'
	count := 4
	for i > 0 {
		sendBuffer[count] = priv.PublicKey.X.Bytes()[count-4]
		sendBuffer[count+32] = priv.PublicKey.Y.Bytes()[count-4]
		count++
		i--
	} //将代理的公钥写入包中，传递公钥x，y
	i = 32
	count = 68
	for i > 0 {
		sendBuffer[count] = temppri.PublicKey.X.Bytes()[count-68]
		sendBuffer[count+32] = temppri.PublicKey.Y.Bytes()[count-68]
		count++
		i--
	}
	i = len(ida)
	count = 132
	for i > 0 {
		sendBuffer[count] = ida[count-132]
		count++
		i--
	}
	for {
		err := sendto(conn1)
		if err != 0 {
			continue
		}
		err = receive(conn1)
		if err != 0 {
			continue
		}

		copy(sendBuffer[:], kong[:])

		break
	}
	db, _ := sm2.GenerateKey(rand.Reader)
	db.PublicKey.X.SetBytes(receiveBuffer[4:36])
	db.PublicKey.Y.SetBytes(receiveBuffer[36:68])
	db.PublicKey.Curve = sm2.P256Sm2()

	rb, _ := sm2.GenerateKey(rand.Reader)
	rb.PublicKey.X.SetBytes(receiveBuffer[68:100])
	rb.PublicKey.Y.SetBytes(receiveBuffer[100:132])
	rb.PublicKey.Curve = sm2.P256Sm2()

	idb := receiveBuffer[132:148]
	key, _, _, _ = sm2.KeyExchangeA(16, ida, idb, priv, &db.PublicKey, temppri, &rb.PublicKey)
	return priv
}
func byteToString(b []byte) string {
	ret := ""
	for i := 0; i < len(b); i++ {
		ret += fmt.Sprintf("%02x", b[i])
	}
	return ret
}

func SM2(randd *sm2.PrivateKey, data []byte) {
	priv := randd                                 // 生成密钥对
	msg := data                                   //在这里传包
	sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		fmt.Println("%s", err)
		return
	}
	i := len(string(sign))
	sendBuffer[6] = byte(i - 70)
	count := 7
	for i > 0 {
		sendBuffer[count] = sign[count-7]
		count++
		i--
	}
	fmt.Println(string(sendBuffer)) //签名

}
func SM3(data []byte) {
	msg := data
	// 生成测试文件
	hash1 := sm3.Sm3Sum(msg)
	fmt.Println(hash1)
	i := len(string(hash1))
	count := 991
	for i > 0 {
		sendBuffer[count] = hash1[count-991]
		count++
		i--
	}
	fmt.Printf("%s\n", byteToString(hash1))
}
func SM4(n int, data []byte) {

	fmt.Printf("key = %v\n", key)

	cbcMsg, err := sm4.Sm4Cbc(key, data, true)
	cbcDec, err := sm4.Sm4Cbc(key, cbcMsg, false)
	sendBuffer[4] = byte(len(cbcMsg) / (1 << 8))
	sendBuffer[5] = byte(len(cbcMsg) % (1 << 8))
	if err != nil {
		fmt.Println("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcDec = %x\n", cbcDec)

	if err != nil {
		fmt.Println("sm4 enc error:%s", err)
	}
	i := len(string(cbcMsg))
	count := 79
	for i > 0 {
		sendBuffer[count] = cbcMsg[count-79]
		count++
		i--
	}
	fmt.Printf("cbcMsg = %x\n", cbcMsg)

}
func Agent(conn, conn1 *net.UDPConn, buffer []byte, number int) {
	flag := 0
	//接收加工传输
	for {
		var data = make([]byte, 1024)
		// 处理数据
		if flag == 0 {
			data = buffer[0:number]
			//fmt.Printf("接收到来自 %s 的数据: %s\n", conn.RemoteAddr().String(), string(data))
			flag = 1
		} else {
			n, addr, err := conn.ReadFromUDP(rBuffer)
			if err != nil {
				fmt.Println("读取数据失败:", err)
				continue
			}
			fmt.Printf("接收到来自 %s 的数据: %s\n", addr.String(), string(data))
			data = rBuffer[0:n]

		}
		erc1 := request(conn1)
		if erc1 != 0 {
			fmt.Println("请求拒绝")
			copy(sendBuffer[:], kong[:])
			copy(receiveBuffer[:], kong[:])
			continue
		}
		//密钥协商#######################
		var randd = KeyNegotiation(conn1)
		n := len(data)
		//###############################
		sendBuffer[1] = byte('2')

		SM2(randd, data) //由此函数将签名信息加入发送缓冲区
		SM4(n, data)     //由此函数将密文信息加入发送缓冲区
		SM3(data)        //由此函数将校验码加入接收缓冲区

		for {
			erc := sendto(conn1) //发送函数
			if erc != 0 {
				os.Exit(1)
			}
			erc = receive(conn1)
			if erc != 0 {
				os.Exit(1)
			}

			if receiveBuffer[1] == '5' {
				fmt.Println("timeout!")
				continue
			}
			break
		}
		copy(sendBuffer[:], kong[:])
		copy(receiveBuffer[:], kong[:])
		continue
	}
}
