package main

import (
	"fmt"
	// "sync"
	// "time"
	"os"
	// "github.com/tatsushid/go-fastping"
)

// func pindHost(ip string) (unreachable bool, err error) {
// 	pinger := fastping.NewPinger()
// 	ra, err := net.ResolveIPAddr("ip4:icmp", ip)
// 	if err != nil {
// 		fmt.Printf("Ошибка разрешения адреса для %s: %v\n", ip, err)
// 		return true, err
// 	}

// 	pinger.AddIPAddr(ra)
// 	received := false
// 	pinger.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
// 		received = true
// 		fmt.Printf("Получен ответ от %s: время=%v\n", addr.String(), rtt)
// 	}
// 	pinger.OnIdle = func() {
// 		// Пинг завершён
// 	}

// 	// Настройки пинга
// 	pinger.MaxRTT = time.Second * 5 // Таймаут
// 	pinger.Size = 64                // Размер пакета
// 	// pinger.Count = 4                // Количество пакетов

// 	// fmt.Printf("PING %s:\n", ip)
// 	err = pinger.Run()
// 	if err != nil {
// 		fmt.Printf("Ошибка при выполнении пинга для %s: %v\n", ip, err)
// 		return true, err
// 	}

// 	if !received {
// 		return true, nil // Хост недоступен
// 	}
// 	return false, nil
// }

// func countIP(ipAddr net.IP, maskStr net.IPMask) (ip string, countIp int64, err error) {
// 	// Получаем строковое представление IP
// 	ip = ipAddr.String()

// 	// Проверяем, что IP-адрес является IPv4
// 	if ipAddr.To4() == nil {
// 		return "", 0, fmt.Errorf("поддерживаются только IPv4-адреса")
// 	}

// 	// Получаем количество битов в маске
// 	ones, _ := maskStr.Size()
// 	if ones == 0 {
// 		return "", 0, fmt.Errorf("некорректная маска подсети")
// 	}

// 	// Количество хостовых битов
// 	hostBits := 32 - ones

// 	// Количество IP-адресов
// 	countIp = 1 << hostBits

// 	// Для подсети отнимаем 2 адреса (сетевой и широковещательный), если это не /31 или /32
// 	if hostBits > 1 {
// 		countIp -= 2
// 	}

// 	return ip, countIp, nil
// }

// // generateIPs генерирует список IP-адресов в подсети
// func generateIPs(networkIP net.IP, mask net.IPMask) ([]string, error) {
// 	// Проверяем, что IP — IPv4
// 	if networkIP.To4() == nil {
// 		return nil, fmt.Errorf("поддерживаются только IPv4-адреса")
// 	}

// 	// Получаем количество битов в маске
// 	ones, _ := mask.Size()
// 	if ones == 0 {
// 		return nil, fmt.Errorf("некорректная маска подсети")
// 	}

// 	// Количество хостовых битов
// 	hostBits := 32 - ones
// 	totalIPs := int64(1 << hostBits)

// 	// Определяем диапазон адресов
// 	var start, end int64
// 	if hostBits <= 1 { // /31 или /32
// 		start = 0
// 		end = totalIPs
// 	} else {
// 		start = 1           // Пропускаем сетевой адрес
// 		end = totalIPs - 1  // Пропускаем широковещательный адрес
// 	}

// 	// Генерируем IP-адреса
// 	var ips []string
// 	for i := start; i < end; i++ {
// 		ipInt := ipToUint32(networkIP) + uint32(i)
// 		newIP := uint32ToIP(ipInt)
// 		ips = append(ips, newIP.String())
// 	}

// 	return ips, nil
// }

// // ipToUint32 преобразует net.IP (IPv4) в uint32
// func ipToUint32(ip net.IP) uint32 {
// 	ip = ip.To4()
// 	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
// }

// // uint32ToIP преобразует uint32 в net.IP (IPv4)
// func uint32ToIP(n uint32) net.IP {
// 	return net.IP{
// 		byte(n >> 24),
// 		byte(n >> 16),
// 		byte(n >> 8),
// 		byte(n),
// 	}
// }

func printHelp() {
	fmt.Println("Использование: ipscan <тип_сканирования> <диапазон_IP_или_список>")
	fmt.Println("Типы сканирования:")
	fmt.Println("  -sn <диапазон_IP> Пинг-сканирование, например:   -sn 192.168.9.1-100")
	fmt.Println("  -sn <список_IP>   Пинг-сканирование, например:   -sn 192.168.9.1,3,5,100")
	fmt.Println("  -sp <диапазон_IP> Сканирование портов, например: -sp 192.168.9.1-100")
	fmt.Println("  -sp <список_IP>   Сканирование портов, например: -sp 192.168.9.1,3,5,100")
	fmt.Println("Дополнительно:")
	fmt.Println("  /help Показать это сообщение")
}

func main() {
if len(os.Args) < 2 {
		fmt.Println("Ошибка: укажите диапазон IP или список адресов")
		printHelp()
		os.Exit(1)
	}

	// Проверяем, запрошена ли справка
	if os.Args[1] == "/help" {
		printHelp()
		os.Exit(0)
	}

	// Получаем аргумент с IP-диапазоном или списком
	if os.Args[1] != "" && os.Args[2] != ""{
		ipRange := os.Args[1] + " " + os.Args[2]
	    fmt.Println(ipRange)
	}
}