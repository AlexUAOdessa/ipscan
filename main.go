package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tatsushid/go-fastping"
)

func printHelp() {
	fmt.Println("Использование: ipscan <тип_сканирования> <диапазон_IP_или_список>")
	fmt.Println("Типы сканирования:")
	fmt.Println("  -sn <диапазон_IP> Пинг-сканирование, например:   -sn 192.168.0.1-100")
	fmt.Println("  -sn <список_IP>   Пинг-сканирование, например:   -sn 192.168.0.1,3,5,100")
	fmt.Println("  -sp <диапазон_IP> Сканирование портов, например: -sp 192.168.0.1-100")
	fmt.Println("  -sp <список_IP>   Сканирование портов, например: -sp 192.168.0.1,3,5,100")
	fmt.Println("Дополнительно:")
	fmt.Println("  /help Показать это сообщение")
}

func ParseArgs(arg []string) ([]string, error) {
	var result []string

	// Проверяем минимальное количество аргументов
	if len(arg) < 3 {
		return nil, fmt.Errorf("недостаточно аргументов: ожидается <программа> <тип_сканирования> <диапазон_или_список>")
	}

	// Проверяем тип сканирования
	if arg[1] != "-sn" && arg[1] != "-sp" {
		return nil, fmt.Errorf("неподдерживаемый тип сканирования: %s, ожидается -sn или -sp", arg[1])
	}

	// Проверяем, что аргумент для диапазона/списка не пустой
	if arg[2] == "" {
		return nil, fmt.Errorf("диапазон или список IP не указан")
	}

	// Удаляем пробелы из arg[2]
	cleanedArg := strings.ReplaceAll(arg[2], " ", "")

	// Проверяем, является ли аргумент диапазоном (содержит "-")
	if strings.Contains(cleanedArg, "-") {
		// Разделяем по "-"
		rangeParts := strings.Split(cleanedArg, "-")
		if len(rangeParts) != 2 {
			return nil, fmt.Errorf("неверный формат диапазона: %s", cleanedArg)
		}

		// Извлекаем базовый IP и конечный октет
		startParts := strings.Split(rangeParts[0], ".")
		if len(startParts) != 4 {
			return nil, fmt.Errorf("неверный формат начального IP: %s", rangeParts[0])
		}

		startOctet, err := strconv.Atoi(startParts[3])
		if err != nil {
			return nil, fmt.Errorf("неверный формат октета в начальном IP: %v", err)
		}

		endOctet, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return nil, fmt.Errorf("неверный формат конечного октета: %v", err)
		}

		if startOctet > endOctet || startOctet < 0 || endOctet > 255 {
			return nil, fmt.Errorf("недопустимый диапазон октетов: %d-%d", startOctet, endOctet)
		}

		// Генерируем IP-адреса
		baseIP := strings.Join(startParts[:3], ".") // Например, "192.168.0"
		for i := startOctet; i <= endOctet; i++ {
			result = append(result, fmt.Sprintf("%s.%d", baseIP, i))
		}
	} else {
		// Обрабатываем список IP (например, "192.168.0.1,3,5,100")
		parts := strings.Split(cleanedArg, ",")
		if len(parts) < 1 {
			return nil, fmt.Errorf("неверный формат списка IP: %s", cleanedArg)
		}

		// Проверяем, является ли первый элемент полным IP
		firstParts := strings.Split(parts[0], ".")
		if len(firstParts) != 4 {
			return nil, fmt.Errorf("неверный формат первого IP в списке: %s", parts[0])
		}

		baseIP := strings.Join(firstParts[:3], ".") // Например, "192.168.0"
		for _, part := range parts {
			var octet int
			var fullIP string
			if strings.Contains(part, ".") {
				// Полный IP-адрес
				fullIP = part
			} else {
				// Только октет
				var err error
				octet, err = strconv.Atoi(part)
				if err != nil {
					return nil, fmt.Errorf("неверный формат октета в списке: %s", part)
				}
				fullIP = fmt.Sprintf("%s.%d", baseIP, octet)
			}

			// Проверяем валидность IP
			if !isValidIP(fullIP) {
				return nil, fmt.Errorf("недопустимый IP-адрес: %s", fullIP)
			}
			result = append(result, fullIP)
		}
	}

	return result, nil
}

// isValidIP проверяет, является ли строка валидным IPv4-адресом
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

func pingHost(ip string) (unreachable bool, err error) {
	pinger := fastping.NewPinger()
	ra, err := net.ResolveIPAddr("ip4:icmp", ip)
	if err != nil {
		fmt.Printf("Ошибка разрешения адреса для %s: %v\n", ip, err)
		return true, err
	}

	pinger.AddIPAddr(ra)
	received := false
	pinger.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		received = true
		fmt.Printf("Получен ответ от %s: время=%v\n", addr.String(), rtt)
	}
	pinger.OnIdle = func() {
		// Пинг завершён
	}

	// Настройки пинга
	pinger.MaxRTT = time.Second * 5 // Таймаут
	pinger.Size = 64                // Размер пакета
	// pinger.Count = 4                // Количество пакетов

	// fmt.Printf("PING %s:\n", ip)
	err = pinger.Run()
	if err != nil {
		fmt.Printf("Ошибка при выполнении пинга для %s: %v\n", ip, err)
		return true, err
	}

	if !received {
		return true, nil // Хост недоступен
	}
	return false, nil
}

func main() {
	// Проверяем минимальное количество аргументов
	if len(os.Args) < 2 {
		fmt.Println("Ошибка: укажите тип сканирования и диапазон IP или список адресов")
		printHelp()
		os.Exit(1)
	}

	// Проверяем, запрошена ли справка
	if os.Args[1] == "/help" {
		printHelp()
		os.Exit(0)
	}

	// Парсим аргументы
	ips, err := ParseArgs(os.Args)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		printHelp()
		os.Exit(1)
	}

	// Выводим результат для демонстрации
	// fmt.Println("Список IP-адресов для сканирования:")
	// for _, ip := range ips {
	// 	fmt.Println(ip)
	// }

	for _, ip := range ips {
		unreachable, err := pingHost(ip)
		if err != nil {
			fmt.Printf("Ошибка пинга %s: %v\n", ip, err)
			continue
		}
		if unreachable {
			fmt.Printf("%s: хост недоступен\n", ip)
		} else {
			fmt.Printf("%s: хост доступен\n", ip)
		}
	}
}