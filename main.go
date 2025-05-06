package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipscan/fastping"
)

// MaxGoroutines определяет максимальное количество одновременно выполняющихся горутин.
const MaxGoroutines = 50

// printHelp выводит справку по использованию программы.
func printHelp() {
	fmt.Printf("************ Программа разработана @Alex версия 0.7 ************\n\n")
	fmt.Printf("Использование: ipscan <тип_сканирования> <диапазон_IP_или_список>[:порты]\n\n")
	fmt.Println("Типы сканирования:")
	fmt.Println("  -sl <диапазон_IP> Пинг-сканирование (ICMP)")
	fmt.Println("  -sl <список_IP>   Пинг-сканирование (ICMP)")
	fmt.Println("  -sn <диапазон_IP> Пинг-сканирование с возвратом имени хоста")
	fmt.Println("  -sn <список_IP>   Пинг-сканирование с возвратом имени хоста")
	fmt.Println("  -sh <диапазон_IP> HTTP-пинг (TCP-пинг на порт 80)")
	fmt.Println("  -sh <список_IP>   HTTP-пинг (TCP-пинг на порт 80)")
	fmt.Println("  -su <диапазон_IP>[:порты] UDP-пинг (ICMP, если порты не указаны)")
	fmt.Println("  -su <список_IP>[:порты]   UDP-пинг (ICMP, если порты не указаны)")
	fmt.Println("  -sp <диапазон_IP>:<порты> Сканирование TCP-портов")
	fmt.Println("  -sp <список_IP>:<порты>   Сканирование TCP-портов")
	fmt.Println("      <диапазон_IP> Например: -su 192.168.0.0/16:53-130,226,445")
	fmt.Println("                            или -su 192.168.0.0-192.168.255.255:53-130")
	fmt.Println("                            или -su 192.168.0.1-100:53-130")
	fmt.Println("      <список_IP>   Например: -su 192.168.0.1,3,5,100:53,123")
	fmt.Println("      <порты>       Диапазон (80-85) или список (80,443,3389)")
	fmt.Println("      Популярные TCP-порты: 21 (FTP), 22 (SSH), 23 (Telnet), 80 (HTTP), 443 (HTTPS), 3389 (RDP), 8080 (HTTP-alt)")
	fmt.Println("      Популярные UDP-порты: 53 (DNS), 67/68 (DHCP), 123 (NTP), 161 (SNMP), 137/138 (NetBIOS), 514 (Syslog), 1812/1813 (RADIUS)")
	fmt.Printf("\nДополнительно:\n")
	fmt.Println("  /help Показать это сообщение")
}

// cidrToIPs преобразует CIDR-нотацию в список IP-адресов.
func cidrToIPs(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	// Удаляем сетевой и широковещательный адреса, если маска меньше /31
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// incIP увеличивает IP-адрес на 1.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ipRangeToIPs генерирует список IP-адресов из диапазона <начальный_IP>-<конечный_IP>.
func ipRangeToIPs(startIP, endIP string) ([]string, error) {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)
	if start == nil || end == nil {
		return nil, fmt.Errorf("недопустимый формат IP: %s или %s", startIP, endIP)
	}
	start = start.To4()
	end = end.To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("поддерживаются только IPv4: %s или %s", startIP, endIP)
	}

	var ips []string
	for ip := start; !ipAfter(ip, end); ip = append(net.IP(nil), ip...) {
		ips = append(ips, ip.String())
		incIP(ip)
	}
	// Добавляем конечный IP только если он ещё не включён
	if ip := net.ParseIP(end.String()); ipAfter(ip, start) || ip.Equal(start) {
		ips = append(ips, end.String())
	}
	return ips, nil
}

// ipAfter проверяет, находится ли IP1 после IP2.
func ipAfter(ip1, ip2 net.IP) bool {
	for i := 0; i < len(ip1); i++ {
		if ip1[i] != ip2[i] {
			return ip1[i] > ip2[i]
		}
	}
	return false
}

// ParseArgs парсит аргументы командной строки и возвращает тип сканирования, список IP-адресов и список портов (если указаны).
func ParseArgs(args []string) (string, []string, []int, error) {
	if len(args) < 3 {
		return "", nil, nil, fmt.Errorf("недостаточно аргументов: ожидается <программа> <тип_сканирования> <диапазон_или_список>[:порты]")
	}
	if args[1] != "-sl" && args[1] != "-sh" && args[1] != "-sp" && args[1] != "-su" && args[1] != "-sn" {
		return "", nil, nil, fmt.Errorf("неподдерживаемый тип сканирования: %s, ожидается -sl, -sh, -sp, -su или -sn", args[1])
	}
	if args[2] == "" {
		return "", nil, nil, fmt.Errorf("диапазон или список IP не указан")
	}

	// Извлечение портов, если указаны
	cleanedArg := strings.ReplaceAll(args[2], " ", "")
	var ports []int
	var ipInput string
	if strings.Contains(cleanedArg, ":") {
		parts := strings.Split(cleanedArg, ":")
		if len(parts) != 2 {
			return "", nil, nil, fmt.Errorf("неверный формат портов: %s", cleanedArg)
		}
		ipInput = parts[0]
		portStr := parts[1]
		portParts := strings.Split(portStr, ",")
		for _, part := range portParts {
			if strings.Contains(part, "-") {
				// Обработка диапазона портов
				rangeParts := strings.Split(part, "-")
				if len(rangeParts) != 2 {
					return "", nil, nil, fmt.Errorf("неверный формат диапазона портов: %s", part)
				}
				startPort, err := strconv.Atoi(rangeParts[0])
				if err != nil || startPort < 1 || startPort > 65535 {
					return "", nil, nil, fmt.Errorf("недопустимый начальный порт: %s", rangeParts[0])
				}
				endPort, err := strconv.Atoi(rangeParts[1])
				if err != nil || endPort < 1 || endPort > 65535 {
					return "", nil, nil, fmt.Errorf("недопустимый конечный порт: %s", rangeParts[1])
				}
				if startPort > endPort {
					return "", nil, nil, fmt.Errorf("начальный порт (%d) больше конечного (%d)", startPort, endPort)
				}
				for p := startPort; p <= endPort; p++ {
					ports = append(ports, p)
				}
			} else {
				// Обработка отдельного порта
				port, err := strconv.Atoi(part)
				if err != nil || port < 1 || port > 65535 {
					return "", nil, nil, fmt.Errorf("недопустимый порт: %s", part)
				}
				ports = append(ports, port)
			}
		}
		// Удаление дубликатов и сортировка портов
		ports = removeDuplicatesAndSort(ports)
	} else {
		ipInput = cleanedArg
	}

	var result []string
	// Карта для удаления дубликатов IP
	seenIPs := make(map[string]bool)
	// Обработка CIDR-нотации (например, 192.168.0.0/16)
	if strings.Contains(ipInput, "/") {
		ips, err := cidrToIPs(ipInput)
		if err != nil {
			return "", nil, nil, fmt.Errorf("неверный формат CIDR: %v", err)
		}
		for _, ip := range ips {
			if !seenIPs[ip] {
				seenIPs[ip] = true
				result = append(result, ip)
			}
		}
	} else if strings.Contains(ipInput, "-") {
		// Обработка диапазона IP (например, 192.168.0.0-192.168.255.255 или 192.168.0.1-100)
		rangeParts := strings.Split(ipInput, "-")
		if len(rangeParts) != 2 {
			return "", nil, nil, fmt.Errorf("неверный формат диапазона: %s", ipInput)
		}
		startIP := rangeParts[0]
		endIP := rangeParts[1]

		// Проверяем, является ли диапазон диапазоном последнего октета (например, 192.168.0.1-100)
		startParts := strings.Split(startIP, ".")
		if len(startParts) == 4 && !strings.Contains(endIP, ".") {
			startOctet, err := strconv.Atoi(startParts[3])
			if err != nil {
				return "", nil, nil, fmt.Errorf("неверный октет в начальном IP: %v", err)
			}
			endOctet, err := strconv.Atoi(endIP)
			if err != nil {
				return "", nil, nil, fmt.Errorf("неверный конечный октет: %v", err)
			}
			if startOctet > endOctet || startOctet < 0 || endOctet > 255 {
				return "", nil, nil, fmt.Errorf("недопустимый диапазон октетов: %d-%d", startOctet, endOctet)
			}
			baseIP := strings.Join(startParts[:3], ".")
			for i := startOctet; i <= endOctet; i++ {
				ip := fmt.Sprintf("%s.%d", baseIP, i)
				if !seenIPs[ip] {
					seenIPs[ip] = true
					result = append(result, ip)
				}
			}
		} else {
			// Полный диапазон IP (например, 192.168.0.0-192.168.255.255)
			ips, err := ipRangeToIPs(startIP, endIP)
			if err != nil {
				return "", nil, nil, fmt.Errorf("неверный диапазон IP: %v", err)
			}
			for _, ip := range ips {
				if !seenIPs[ip] {
					seenIPs[ip] = true
					result = append(result, ip)
				}
			}
		}
	} else {
		// Обработка списка IP (например, 192.168.0.1,3,5,100)
		parts := strings.Split(ipInput, ",")
		if len(parts) < 1 {
			return "", nil, nil, fmt.Errorf("неверный формат списка IP: %s", ipInput)
		}
		firstParts := strings.Split(parts[0], ".")
		if len(firstParts) != 4 {
			return "", nil, nil, fmt.Errorf("неверный формат первого IP: %s", parts[0])
		}
		baseIP := strings.Join(firstParts[:3], ".")
		for _, part := range parts {
			var fullIP string
			if strings.Contains(part, ".") {
				fullIP = part
			} else {
				octet, err := strconv.Atoi(part)
				if err != nil {
					return "", nil, nil, fmt.Errorf("неверный октет в списке: %s", part)
				}
				fullIP = fmt.Sprintf("%s.%d", baseIP, octet)
			}
			if !isValidIP(fullIP) {
				return "", nil, nil, fmt.Errorf("недопустимый IP-адрес: %s", fullIP)
			}
			if !seenIPs[fullIP] {
				seenIPs[fullIP] = true
				result = append(result, fullIP)
			}
		}
	}
	return args[1], result, ports, nil
}

// removeDuplicatesAndSort удаляет дубликаты из списка портов и сортирует его.
func removeDuplicatesAndSort(ports []int) []int {
	seen := make(map[int]bool)
	var result []int
	for _, port := range ports {
		if !seen[port] {
			seen[port] = true
			result = append(result, port)
		}
	}
	sort.Ints(result)
	return result
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
	name, err := pinger.NamePing(ip, 5*time.Second)
	if err != nil {
		receivedHost = fmt.Sprintf("Ошибка при выполнении Name-пинга для %s", ip)
		return true, ip, err
	}
	receivedHost = fmt.Sprintf("Получен ответ от %s ИМЯ хоста %s", ip, name)
	return false, receivedHost, nil
}

// pingHostUDP выполняет UDP-пинг на указанные порты для указанного IP-адреса.
func pingHostUDP(ip string, ports []int) (unreachable bool, receivedHosts []string, err error) {
	var results []string
	unreachable = true // Считаем хост недоступным, если ни один порт не открыт

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("udp", addr, 5*time.Second)
		if err != nil {
			results = append(results, fmt.Sprintf("Ошибка при выполнении UDP-пинга для %s:%d: %v", ip, port, err))
			continue
		}
		defer conn.Close()

		// Отправляем тестовый пакет
		_, err = conn.Write([]byte("ping"))
		if err != nil {
			results = append(results, fmt.Sprintf("Ошибка при отправке UDP-пакета для %s:%d: %v", ip, port, err))
			continue
		}

		// Устанавливаем таймаут на чтение ответа
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1024)
		_, err = conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Если таймаут, предполагаем, что порт открыт
				results = append(results, fmt.Sprintf("Получен ответ от %s:%d: порт открыт (нет ICMP Port Unreachable)", ip, port))
				unreachable = false
			} else if strings.Contains(err.Error(), "port unreachable") {
				results = append(results, fmt.Sprintf("Порт %d закрыт на %s: ICMP Port Unreachable", port, ip))
			} else {
				results = append(results, fmt.Sprintf("Ошибка при чтении ответа от %s:%d: %v", ip, port, err))
			}
			continue
		}

		results = append(results, fmt.Sprintf("Получен ответ от %s:%d: порт открыт", ip, port))
		unreachable = false
	}

	if len(results) == 0 {
		return true, nil, fmt.Errorf("нет результатов для %s", ip)
	}

	return unreachable, results, nil
}

// pingHostTCP выполняет TCP-пинг на указанные порты для указанного IP-адреса.
func pingHostTCP(ip string, ports []int) (unreachable bool, receivedHosts []string, err error) {
	var results []string
	unreachable = true // Считаем хост недоступным, если ни один порт не открыт

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			// results = append(results, fmt.Sprintf("Порт %d закрыт на %s: %v", port, ip, err))
			continue
		}
		defer conn.Close()
		results = append(results, fmt.Sprintf("Получен ответ от %s:%d: порт открыт", ip, port))
		unreachable = false
	}

	if len(results) == 0 {
		return true, nil, fmt.Errorf("нет результатов для %s", ip)
	}

	return unreachable, results, nil
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
	key, ips, ports, err := ParseArgs(os.Args)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		printHelp()
		os.Exit(1)
	}

	// Проверка для -sp: порты обязательны
	if key == "-sp" && len(ports) == 0 {
		fmt.Println("Ошибка: для -sp необходимо указать порты (например, :80,443 или :80-85)")
		printHelp()
		os.Exit(1)
	}

	// Многопоточная обработка IP-адресов с ограничением количества горутин
	var wg sync.WaitGroup
	var mu sync.Mutex
	var listHost []string
	// Карта для отслеживания уникальных строк результатов
	seenResults := make(map[string]bool)
	semaphore := make(chan struct{}, MaxGoroutines)

	for _, ip := range ips {
		// Ограничиваем количество одновременно выполняющихся горутин
		semaphore <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Освобождаем семафор после завершения горутины

			var unreachable bool
			var receivedHost string
			var receivedHosts []string
			var err error
			if key == "-sl" {
				unreachable, receivedHost, err = pingHost(ip, key)
				if !unreachable && err == nil {
					mu.Lock()
					if !seenResults[receivedHost] {
						seenResults[receivedHost] = true
						listHost = append(listHost, receivedHost)
					}
					mu.Unlock()
				}
			} else if key == "-su" {
				if len(ports) > 0 {
					unreachable, receivedHosts, err = pingHostUDP(ip, ports)
					if !unreachable && err == nil {
						mu.Lock()
						for _, host := range receivedHosts {
							if !seenResults[host] {
								seenResults[host] = true
								listHost = append(listHost, host)
							}
						}
						mu.Unlock()
					}
				} else {
					unreachable, receivedHost, err = pingHost(ip, key)
					if !unreachable && err == nil {
						mu.Lock()
						if !seenResults[receivedHost] {
							seenResults[receivedHost] = true
							listHost = append(listHost, receivedHost)
						}
						mu.Unlock()
					}
				}
			} else if key == "-sh" {
				unreachable, receivedHost, err = pingHostHTTP(ip)
				if !unreachable && err == nil {
					mu.Lock()
					if !seenResults[receivedHost] {
						seenResults[receivedHost] = true
						listHost = append(listHost, receivedHost)
					}
					mu.Unlock()
				}
			} else if key == "-sn" {
				unreachable, receivedHost, err = pingHostName(ip)
				if !unreachable && err == nil {
					mu.Lock()
					if !seenResults[receivedHost] {
						seenResults[receivedHost] = true
						listHost = append(listHost, receivedHost)
					}
					mu.Unlock()
				}
			} else if key == "-sp" {
				unreachable, receivedHosts, err = pingHostTCP(ip, ports)
				if !unreachable && err == nil {
					mu.Lock()
					for _, host := range receivedHosts {
						if !seenResults[host] {
							seenResults[host] = true
							listHost = append(listHost, host)
						}
					}
					mu.Unlock()
				}
			}
			if err != nil {
				// Ошибка уже выведена в соответствующей функции
				return
			}
		}(ip)
	}
	wg.Wait()

	// Сортировка доступных хостов по IP и портам
	// Фильтруем только строки с открытыми портами
	var openHosts []string
	for _, host := range listHost {
		if strings.Contains(host, ": порт открыт") {
			openHosts = append(openHosts, host)
		}
	}

	sort.Slice(openHosts, func(i, j int) bool {
		getIPAndPort := func(s string) (string, int) {
			// Используем регулярное выражение для извлечения IP и порта
			re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+):(\d+)`)
			matches := re.FindStringSubmatch(s)
			if len(matches) >= 3 {
				ip := matches[1]
				port, _ := strconv.Atoi(matches[2])
				return ip, port
			}
			// Если формат не соответствует, возвращаем пустой IP и порт 0
			return "", 0
		}
		ip1, port1 := getIPAndPort(openHosts[i])
		ip2, port2 := getIPAndPort(openHosts[j])

		// Сравниваем IP-адреса
		ip1Parts := strings.Split(ip1, ".")
		ip2Parts := strings.Split(ip2, ".")
		for k := 0; k < 4; k++ {
			num1, _ := strconv.Atoi(ip1Parts[k])
			num2, _ := strconv.Atoi(ip2Parts[k])
			if num1 != num2 {
				return num1 < num2
			}
		}
		// Если IP одинаковые, сравниваем порты
		return port1 < port2
	})

	switch key {
	case "-sl":
		fmt.Println("ICMP ping")
	case "-sn":
		fmt.Println("Name ping")
	case "-sh":
		fmt.Println("HTTP ping")
	case "-su":
		if len(ports) > 0 {
			fmt.Printf("UDP ping (порты: %v)\n", ports)
		} else {
			fmt.Println("UDP ping (ICMP)")
		}
	case "-sp":
		fmt.Printf("TCP ping (порты: %v)\n", ports)
	}

	// Вывод отсортированного списка доступных хостов
	for _, host := range listHost {
		fmt.Println(host)
	}
}