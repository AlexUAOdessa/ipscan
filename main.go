// Программа ipscan выполняет пинг-сканирование или сканирование портов для диапазона IP-адресов.
// Использование: ipscan <тип_сканирования> <диапазон_IP_или_список>

package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipscan/fastping"
)

// printHelp выводит справку по использованию программы.
func printHelp() {
	fmt.Printf("************ Программа разработана @Alex версия 0.1 ************\n\n")
	fmt.Printf("Использование: ipscan <тип_сканирования> <диапазон_IP_или_список>\n\n")
	fmt.Println("Типы сканирования:")
	fmt.Println("  -sl <диапазон_IP> Пинг-сканирование")
	fmt.Println("  -sl <список_IP>   Пинг-сканирование")
	fmt.Println("  -sn <диапазон_IP> Пинг-сканирование с возвратом ИМЕНИ host")
	fmt.Println("  -sn <список_IP>   Пинг-сканирование с возвратом ИМЕНИ host")
	fmt.Println("  -sh <диапазон_IP> HTTP-пинг (TCP-пинг на порт 80)")
	fmt.Println("  -sh <список_IP>   HTTP-пинг (TCP-пинг на порт 80)")
	fmt.Println("  -su <диапазон_IP> UDP-пинг")
	fmt.Println("  -su <список_IP>   UDP-пинг")
	fmt.Println("  -sp <диапазон_IP> Сканирование портов")
	fmt.Println("  -sp <список_IP>   Сканирование портов")
	fmt.Println("      <диапазон_IP> Например: -sl 192.168.0.1-100")
	fmt.Printf("      <список_IP>   Например: -sl 192.168.0.1,3,5,100\n\n")
	fmt.Println("Дополнительно:")
	fmt.Println("  /help Показать это сообщение")
}

// ParseArgs парсит аргументы командной строки и возвращает список IP-адресов.
func ParseArgs(args []string) (string, []string, error) {
	if len(args) < 3 {
		return "", nil, fmt.Errorf("недостаточно аргументов: ожидается <программа> <тип_сканирования> <диапазон_или_список>")
	}
	if args[1] != "-sl" && args[1] != "-sh" && args[1] != "-sp" && args[1] != "-su" && args[1] != "-sn"{
		return "", nil, fmt.Errorf("неподдерживаемый тип сканирования: %s, ожидается -sl, -sh или -sp", args[1])
	}
	if args[2] == "" {
		return "", nil, fmt.Errorf("диапазон или список IP не указан")
	}
	cleanedArg := strings.ReplaceAll(args[2], " ", "")
	var result []string
	if strings.Contains(cleanedArg, "-") {
		rangeParts := strings.Split(cleanedArg, "-")
		if len(rangeParts) != 2 {
			return "", nil, fmt.Errorf("неверный формат диапазона: %s", cleanedArg)
		}
		startParts := strings.Split(rangeParts[0], ".")
		if len(startParts) != 4 {
			return "", nil, fmt.Errorf("неверный формат начального IP: %s", rangeParts[0])
		}
		startOctet, err := strconv.Atoi(startParts[3])
		if err != nil {
			return "", nil, fmt.Errorf("неверный октет в начальном IP: %v", err)
		}
		endOctet, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return "", nil, fmt.Errorf("неверный конечный октет: %v", err)
		}
		if startOctet > endOctet || startOctet < 0 || endOctet > 255 {
			return "", nil, fmt.Errorf("недопустимый диапазон октетов: %d-%d", startOctet, endOctet)
		}
		baseIP := strings.Join(startParts[:3], ".")
		for i := startOctet; i <= endOctet; i++ {
			result = append(result, fmt.Sprintf("%s.%d", baseIP, i))
		}
	} else {
		parts := strings.Split(cleanedArg, ",")
		if len(parts) < 1 {
			return "", nil, fmt.Errorf("неверный формат списка IP: %s", cleanedArg)
		}
		firstParts := strings.Split(parts[0], ".")
		if len(firstParts) != 4 {
			return "", nil, fmt.Errorf("неверный формат первого IP: %s", parts[0])
		}
		baseIP := strings.Join(firstParts[:3], ".")
		for _, part := range parts {
			var fullIP string
			if strings.Contains(part, ".") {
				fullIP = part
			} else {
				octet, err := strconv.Atoi(part)
				if err != nil {
					return "", nil, fmt.Errorf("неверный октет в списке: %s", part)
				}
				fullIP = fmt.Sprintf("%s.%d", baseIP, octet)
			}
			if !isValidIP(fullIP) {
				return "", nil, fmt.Errorf("недопустимый IP-адрес: %s", fullIP)
			}
			result = append(result, fullIP)
		}
	}
	return args[1], result, nil
}

// isValidIP проверяет, является ли строка валидным IPv4-адресом.
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

// pingHost выполняет ICMP-пинг для указанного IP-адреса.
func pingHost(ip string, key string) (unreachable bool, receivedHost string, err error) {
	var receivedIP string
	pinger := fastping.NewPinger()
		// Установка сети на UDP, если флаг useUDP активен

	if key == "-su" {
		pinger.Network("udp")
	}

	ra, err := net.ResolveIPAddr("ip4:icmp", ip)
	if err != nil {
		fmt.Printf("Ошибка разрешения адреса для %s: %v\n", ip, err)
		return true, "", err
	}
	pinger.AddIPAddr(ra)
	received := false
	var rtt time.Duration
	pinger.OnRecv = func(addr *net.IPAddr, duration time.Duration) {
		received = true
		rtt = duration
		receivedIP = fmt.Sprintf("Получен ответ от %s: время=%v", addr.String(), rtt)
	}
	pinger.OnIdle = func() {}
	pinger.MaxRTT = 5 * time.Second
	pinger.Size = 64
	if err := pinger.Run(); err != nil {
		receivedIP = fmt.Sprintf("Ошибка при выполнении пинга для %s: %v", ip, err)
		return true, receivedIP, err
	}
	if received {
		return false, receivedIP, nil
	}
	return true, receivedIP, nil
}

// pingHostHTTP выполняет TCP-пинг на порт 80 для указанного IP-адреса.
func pingHostHTTP(ip string) (unreachable bool, receivedHost string, err error) {
	pinger := fastping.NewPinger()
	err = pinger.TCPPing(ip, 80, 5*time.Second)
	if err != nil {
		receivedHost = fmt.Sprintf("Ошибка при выполнении HTTP-пинга для %s: %v", ip, err)
		return true, receivedHost, err
	}
	receivedHost = fmt.Sprintf("Получен ответ от %s: порт 80 открыт", ip)
	return false, receivedHost, nil
}

// pingHostName выполняет пинг с возвратом имени хоста для указанного IP-адреса.
func pingHostName(ip string) (unreachable bool, receivedHost string, err error) {
	pinger := fastping.NewPinger()
	name, err := pinger.NamePing(ip,  5*time.Second)
	if err != nil {
		receivedHost = fmt.Sprintf("Ошибка при выполнении Name-пинга для %s", ip)
		return true, ip , err
	}
	receivedHost = fmt.Sprintf("Получен ответ от %s ИМЯ хоста %s", ip, name)
	return false, receivedHost, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Ошибка: укажите тип сканирования и диапазон IP или список адресов")
		printHelp()
		os.Exit(1)
	}
	if os.Args[1] == "/help" {
		printHelp()
		os.Exit(0)
	}
	key, ips, err := ParseArgs(os.Args)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		printHelp()
		os.Exit(1)
	}

	// Многопоточная обработка IP-адресов
	var wg sync.WaitGroup
	var mu sync.Mutex
	var listHost []string
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			var unreachable bool
			var receivedHost string
			var err error
			if key == "-sl" {
				unreachable, receivedHost, err = pingHost(ip, key)
			} else if key == "-su" {
				unreachable, receivedHost, err = pingHost(ip, key)
			} else if key == "-sh" {
				unreachable, receivedHost, err = pingHostHTTP(ip)
			} else if key == "-sn" {
				unreachable, receivedHost, err = pingHostName(ip)
			} else {
				// Для -sp (сканирование портов) пока не реализовано
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// Ошибка уже выведена в pingHost или pingHostHTTP
				return
			}
			if !unreachable {
				listHost = append(listHost, receivedHost)
			}
		}(ip)
	}
	wg.Wait()

	// Сортировка доступных хостов по числовым октетам IP-адреса
	sort.Slice(listHost, func(i, j int) bool {
		// Извлекаем IP-адрес из строки вида "Получен ответ от <IP>: ..."
		getIP := func(s string) string {
			parts := strings.Split(s, " ")
			if len(parts) >= 4 {
				return strings.Split(parts[3], ":")[0] // Извлекаем IP из "192.168.9.135: время=..."
			}
			return ""
		}
		ip1 := getIP(listHost[i])
		ip2 := getIP(listHost[j])

		// Разделяем IP-адреса на октеты
		ip1Parts := strings.Split(ip1, ".")
		ip2Parts := strings.Split(ip2, ".")

		// Сравниваем октеты
		for k := 0; k < 4; k++ {
			num1, _ := strconv.Atoi(ip1Parts[k])
			num2, _ := strconv.Atoi(ip2Parts[k])
			if num1 != num2 {
				return num1 < num2
			}
		}
		return false
	})

	switch key {
	case "-sl":
		fmt.Println("ICMP ping")
	case "-sn":
		fmt.Println("Name ping")
	case "-sh":
		fmt.Println("HTTP ping")
	case "-su":
		fmt.Println("ÜDP ping")
	case "-sp":
		fmt.Println("Port scan (not implemented)")
	}

	// Вывод отсортированного списка доступных хостов
	for _, host := range listHost {
		fmt.Println(host)
	}
}