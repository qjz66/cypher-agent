package main

import (
	"fmt"
	"github.com/tjfoc/gmsm/option"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var m = make(map[string]int, 10)

func main() {
	address := "192.168.3.3"
	port := 12345

	// 创建UDP地址################监听树莓派
	udpAddress, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		fmt.Println("解析UDP地址失败:", err)
		return
	}

	// 创建UDP连接
	conn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		fmt.Println("监听UDP端口失败:", err)
		return
	}
	defer conn.Close()

	fmt.Println("UDP服务器已启动，等待接收数据...")
	// 创建UDP地址################数据中心端口

	// 监听地址和端口

	destination := "192.168.3.2:12345"
	// 解析目标地址
	addr1, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		fmt.Println("解析目标地址失败:", err)
		return
	}

	// 创建UDP连接
	conn1, err := net.DialUDP("udp", nil, addr1)

	if err != nil {
		fmt.Println("创建UDP连接失败:", err)
		return
	}

	defer conn1.Close()
	for i := 0; i < 5; i++ {
		go func() {
			buffer := make([]byte, 1024)
			n, _, err := conn.ReadFromUDP(buffer)
			if err != nil {
				fmt.Println("Error accepting connection:", err)
			} else {
				option.Agent(conn, conn1, buffer, n)
			}
		}()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
