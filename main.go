// Программа ipscan выполняет пинг-сканирование или сканирование портов для диапазона IP-адресов.
// Использование: ipscan <тип_сканирования> <диапазон_IP_или_список>
//
// Типы сканирования:
//   -sn <диапазон_IP> Пинг-сканирование, например: -sn 192.168.0.1-100
//   -sn <список_IP> Пинг-сканирование, например: -sn 192.168.0.1,3,5,100
//   -sp <диапазон_IP> Сканирование портов, например: -sp 192.168.0.1-100
//   -sp <список_IP> Сканирование портов, например: -sp 192.168.0.1,3,5,100
// Дополнительно:
//   /help Показать справку

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
	fmt.Println("Использование: ipscan <тип_сканирования> <диапазон_IP_или_список>")
	fmt.Println("Типы сканирования:")
	fmt.Println("  -sn <диапазон_IP> Пинг-сканирование, например: -sn 192.168.0.1-100")
	fmt.Println("  -sn <список_IP> Пинг-сканирование, например: -sn 192.168.0.1,3,5,100")
	fmt.Println("  -sp <диапазон_IP> Сканирование портов, например: -sp 192.168.0.1-100")
	fmt.Println("  -sp <список_IP> Сканирование портов, например: -sp 192.168.0.1,3,5,100")
	fmt.Println("Дополнительно:")
	fmt.Println("  /help Показать это сообщение")
}

// ParseArgs парсит аргументы командной строки и возвращает список IP-адресов.
func ParseArgs(args []string) ([]string, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("недостаточно аргументов: ожидается <программа> <тип_сканирования> <диапазон_или_список>")
	}
	if args[1] != "-sn" && args[1] != "-sp" {
		return nil, fmt.Errorf("неподдерживаемый тип сканирования: %s, ожидается -sn или -sp", args[1])
	}
	if args[2] == "" {
		return nil, fmt.Errorf("диапазон или список IP не указан")
	}
	cleanedArg := strings.ReplaceAll(args[2], " ", "")
	var result []string
	if strings.Contains(cleanedArg, "-") {
		rangeParts := strings.Split(cleanedArg, "-")
		if len(rangeParts) != 2 {
			return nil, fmt.Errorf("неверный формат диапазона: %s", cleanedArg)
		}
		startParts := strings.Split(rangeParts[0], ".")
		if len(startParts) != 4 {
			return nil, fmt.Errorf("неверный формат начального IP: %s", rangeParts[0])
		}
		startOctet, err := strconv.Atoi(startParts[3])
		if err != nil {
			return nil, fmt.Errorf("неверный октет в начальном IP: %v", err)
		}
		endOctet, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return nil, fmt.Errorf("неверный конечный октет: %v", err)
		}
		if startOctet > endOctet || startOctet < 0 || endOctet > 255 {
			return nil, fmt.Errorf("недопустимый диапазон октетов: %d-%d", startOctet, endOctet)
		}
		baseIP := strings.Join(startParts[:3], ".")
		for i := startOctet; i <= endOctet; i++ {
			result = append(result, fmt.Sprintf("%s.%d", baseIP, i))
		}
	} else {
		parts := strings.Split(cleanedArg, ",")
		if len(parts) < 1 {
			return nil, fmt.Errorf("неверный формат списка IP: %s", cleanedArg)
		}
		firstParts := strings.Split(parts[0], ".")
		if len(firstParts) != 4 {
			return nil, fmt.Errorf("неверный формат первого IP: %s", parts[0])
		}
		baseIP := strings.Join(firstParts[:3], ".")
		for _, part := range parts {
			var fullIP string
			if strings.Contains(part, ".") {
				fullIP = part
			} else {
				octet, err := strconv.Atoi(part)
				if err != nil {
					return nil, fmt.Errorf("неверный октет в списке: %s", part)
				}
				fullIP = fmt.Sprintf("%s.%d", baseIP, octet)
			}
			if !isValidIP(fullIP) {
				return nil, fmt.Errorf("недопустимый IP-адрес: %s", fullIP)
			}
			result = append(result, fullIP)
		}
	}
	return result, nil
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
func pingHost(ip string) (unreachable bool, receivedHost string, err error) {
	pinger := fastping.NewPinger()
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
		fmt.Printf("Получен ответ от %s: время=%v\n", addr.String(), rtt)
	}
	pinger.OnIdle = func() {}
	pinger.MaxRTT = 5 * time.Second
	pinger.Size = 64
	if err := pinger.Run(); err != nil {
		fmt.Printf("Ошибка при выполнении пинга для %s: %v\n", ip, err)
		return true, "", err
	}
	if received {
		return false, ip, nil
	}
	return true, "", nil
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
	ips, err := ParseArgs(os.Args)
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
			unreachable, receivedHost, err := pingHost(ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// Ошибка уже выведена в pingHost
				return
			}
			if !unreachable {
				listHost = append(listHost, receivedHost)
			}
		}(ip)
	}
	wg.Wait()

	// Сортировка доступных хостов по числовым октетам
	sort.Slice(listHost, func(i, j int) bool {
		ip1Parts := strings.Split(listHost[i], ".")
		ip2Parts := strings.Split(listHost[j], ".")
		for k := 0; k < 4; k++ {
			num1, _ := strconv.Atoi(ip1Parts[k])
			num2, _ := strconv.Atoi(ip2Parts[k])
			if num1 != num2 {
				return num1 < num2
			}
		}
		return false
	})

	// Вывод отсортированного списка доступных хостов
	for _, host := range listHost {
		fmt.Printf("%s: хост доступен\n", host)
	}
}