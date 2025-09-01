# XILLEN Network Attack Tool

## Описание
Мощный C++ инструмент для тестирования сетевой безопасности и проведения атак типа DoS/DDoS. Инструмент предоставляет комплексный набор функций для тестирования устойчивости сетевой инфраструктуры к различным типам атак.

## Возможности
- **Port Scanning**: Быстрое сканирование портов с многопоточностью
- **SYN Flood**: SYN flood атаки для тестирования TCP стеков
- **UDP Flood**: UDP flood атаки для тестирования пропускной способности
- **ICMP Flood**: ICMP flood атаки для тестирования сетевых устройств
- **ARP Spoofing**: ARP spoofing атаки для тестирования локальных сетей
- **DNS Amplification**: DNS amplification атаки для тестирования DNS серверов
- **Multi-threading**: Высокопроизводительные многопоточные атаки
- **Cross-platform**: Поддержка Windows, Linux и macOS

## Установка

### Требования
- C++17 совместимый компилятор (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.10+ (опционально)
- Права администратора/root для raw sockets

### Linux/macOS
```bash
git clone https://github.com/BengaminButton/xillen-network-attack
cd xillen-network-attack
make
```

### Windows
```bash
git clone https://github.com/BengaminButton/xillen-network-attack
cd xillen-network-attack
# Используйте Visual Studio или MinGW
g++ -std=c++17 -o xillen_network_attack.exe network_attack.cpp -lws2_32 -liphlpapi
```

## Использование

### Базовое использование
```bash
# Полный набор атак
./xillen_network_attack 192.168.1.100 80 --full-suite

# Только сканирование портов
./xillen_network_attack 10.0.0.1 443 --port-scan --verbose

# Конкретная атака
./xillen_network_attack 172.16.0.1 22 --syn-flood --timeout 10000
```

### Параметры командной строки
- `target_ip`: IP адрес цели (обязательный)
- `target_port`: Порт цели (обязательный)
- `--verbose`: Включить подробный вывод
- `--timeout N`: Установить таймаут в миллисекундах (по умолчанию: 5000)
- `--full-suite`: Запустить полный набор атак
- `--port-scan`: Только сканирование портов
- `--syn-flood`: Только SYN flood атака
- `--udp-flood`: Только UDP flood атака
- `--icmp-flood`: Только ICMP flood атака

## Функции

### 1. Port Scanning
Многопоточное сканирование портов с настраиваемым таймаутом:
```cpp
void port_scan_range(int start_port, int end_port);
```
- Поддержка диапазонов портов
- Многопоточность для высокой производительности
- Настраиваемые таймауты
- Детальная отчетность

### 2. SYN Flood Attack
SYN flood атаки для тестирования TCP стеков:
```cpp
void syn_flood_attack(int duration_seconds, int packets_per_second);
```
- Создание raw TCP пакетов
- Случайные source порты и sequence numbers
- Настраиваемая интенсивность
- Подробная статистика

### 3. UDP Flood Attack
UDP flood атаки для тестирования пропускной способности:
```cpp
void udp_flood_attack(int duration_seconds, int packets_per_second);
```
- Случайные размеры пакетов (64-1024 байт)
- Случайное содержимое пакетов
- Настраиваемая интенсивность
- Статистика отправленных пакетов

### 4. ICMP Flood Attack
ICMP flood атаки для тестирования сетевых устройств:
```cpp
void icmp_flood_attack(int duration_seconds, int packets_per_second);
```
- Создание raw ICMP пакетов
- Случайные ID и sequence numbers
- Правильный расчет checksum
- Настраиваемые размеры пакетов

### 5. ARP Spoofing
ARP spoofing атаки для тестирования локальных сетей:
```cpp
void arp_spoof_attack(const std::string& gateway_ip, int duration_seconds);
```
- Создание spoofed ARP пакетов
- Тестирование ARP таблиц
- Настраиваемая длительность
- Статистика отправленных пакетов

### 6. DNS Amplification
DNS amplification атаки для тестирования DNS серверов:
```cpp
void dns_amplification_attack(const std::vector<std::string>& dns_servers, int duration_seconds);
```
- Поддержка различных типов DNS запросов
- Использование публичных DNS серверов
- Настраиваемая длительность
- Статистика отправленных запросов

## Сборка

### Makefile команды
```bash
make              # Сборка release версии
make debug        # Сборка с debug символами
make release      # Сборка оптимизированной версии
make clean        # Очистка build файлов
make install      # Установка в систему (Unix-like)
make uninstall    # Удаление из системы
make test         # Тестирование сборки
make help         # Показать справку
```

### CMake (опционально)
```bash
mkdir build && cd build
cmake ..
make
```

## Примеры вывода
```
██╗  ██╗██╗██╗     ██╗     ██╗  ██╗███████╗███╗   ██╗
╚██╗██╔╝██║██║     ██║     ██║ ██╔╝██╔════╝████╗  ██║
 ╚███╔╝ ██║██║     ██║     █████╔╝ █████╗  ██╔██╗ ██║
 ██╔██╗ ██║██║     ██║     ██╔═██╗ ██╔══╝  ██║╚██╗██║
██╔╝ ██╗██║███████╗███████╗██║  ██╗███████╗██║ ╚████║
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
                                                        
    Network Attack & Penetration Testing Tool
    Version 1.0 - @Bengamin_Button

[+] Starting XILLEN Network Attack Suite
[+] Target: 192.168.1.100:80
[+] Starting port scan from 1 to 1024
[+] Port 22 is OPEN
[+] Port 80 is OPEN
[+] Port 443 is OPEN
[+] Port scan completed. Found 3 open ports
[+] Starting SYN flood attack for 10 seconds
[+] Sending 1000 packets per second
[+] SYN flood attack completed. Sent 10000 packets
[+] Network attack suite completed
[+] Results saved to: network_attack_results.txt
```

## Выходные файлы
- **network_attack_results.txt**: Детальные результаты всех атак
- **Консольный вывод**: Реальное время выполнения атак

## Обнаруживаемые уязвимости

### Сетевые уязвимости
1. **Open Ports**: Неиспользуемые открытые порты
2. **TCP Stack Vulnerabilities**: Уязвимости TCP стеков
3. **Network Capacity Issues**: Проблемы с пропускной способностью
4. **ARP Table Vulnerabilities**: Уязвимости ARP таблиц
5. **DNS Server Issues**: Проблемы DNS серверов

### Метрики производительности
1. **Response Time**: Время отклика на атаки
2. **Packet Loss**: Потеря пакетов
3. **Connection Stability**: Стабильность соединений
4. **Resource Usage**: Использование ресурсов

## Безопасность
⚠️ **ВНИМАНИЕ**: Используйте только для тестирования собственных систем или с явного разрешения владельцев. Несанкционированные атаки могут быть незаконными и привести к серьезным последствиям.

## Требования
- C++17 совместимый компилятор
- Права администратора/root для raw sockets
- Сетевая карта с поддержкой raw packets
- Знание сетевых протоколов и безопасности

## Авторы
- **@Bengamin_Button** - Основной разработчик
- **@XillenAdapter** - Технический консультант

## Ссылки
- 🌐 **Website**: https://benjaminbutton.ru/
- 🔗 **Organization**: https://xillenkillers.ru/
- 📱 **Telegram**: t.me/XillenAdapter

## Лицензия
MIT License - свободное использование и модификация

## Поддержка
Для вопросов и предложений обращайтесь через Telegram или создавайте Issues на GitHub.

---
*XILLEN Network Attack Tool - профессиональный инструмент для тестирования сетевой безопасности*
