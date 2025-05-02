// Пакет fastping предоставляет библиотеку для ICMP и TCP-пинга.
// Пример использования ICMP-пинга:
//
//	p := fastping.NewPinger()
//	ra, err := net.ResolveIPAddr("ip4:icmp", "8.8.8.8")
//	if err != nil {
//		fmt.Println(err)
//		os.Exit(1)
//	}
//	p.AddIPAddr(ra)
//	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
//		fmt.Printf("IP-адрес: %s, RTT: %v\n", addr.String(), rtt)
//	}
//	p.OnIdle = func() {
//		fmt.Println("Пинг завершён")
//	}
//	if err := p.Run(); err != nil {
//		fmt.Println(err)
//	}
//
// Пример использования TCP-пинга:
//
//	p := fastping.NewPinger()
//	if err := p.TCPPing("8.8.8.8:80", time.Second); err != nil {
//		fmt.Println("TCP-пинг не удался:", err)
//	} else {
//		fmt.Println("TCP-пинг успешен")
//	}
//
// ICMP-пинг отправляет пакет и ожидает ответа, вызывая обработчик OnRecv.
// После истечения MaxRTT вызывается OnIdle. Для примеров смотрите "cmd/ping/ping.go".
//
// Требуются права суперпользователя для ICMP-пакетов с сырыми сокетами.
// Для тестов используйте: sudo go test

package fastping

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	TimeSliceLength  = 8
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// Pinger управляет отправкой/получением ICMP и TCP-пакетов.
type Pinger struct {
	id      int
	seq     int
	addrs   map[string]*net.IPAddr
	network string
	source  string
	source6 string
	hasIPv4 bool
	hasIPv6 bool
	ctx     *context
	mu      sync.Mutex
	Size    int
	MaxRTT  time.Duration
	OnRecv  func(*net.IPAddr, time.Duration)
	OnIdle  func()
	Debug   bool
}

// packet содержит данные пакета и адрес.
type packet struct {
	bytes []byte
	addr  net.Addr
}

// context управляет состоянием выполнения.
type context struct {
	stop chan bool
	done chan bool
	err  error
}

// newContext создаёт новый контекст.
func newContext() *context {
	return &context{
		stop: make(chan bool),
		done: make(chan bool),
	}
}

// NewPinger создаёт новый экземпляр Pinger.
func NewPinger() *Pinger {
	rand.Seed(time.Now().UnixNano())
	return &Pinger{
		id:      rand.Intn(0xffff),
		seq:     rand.Intn(0xffff),
		addrs:   make(map[string]*net.IPAddr),
		network: "ip",
		source:  "",
		source6: "",
		Size:    TimeSliceLength,
		MaxRTT:  time.Second,
	}
}

// TCPPing выполняет TCP-пинг к указанному адресу с таймаутом.
func (p *Pinger) TCPPing(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("TCP-пинг к %s не удался: %v", addr, err)
	}
	conn.Close()
	return nil
}

// Network задаёт сетевую конечную точку для ICMP-пинга.
func (p *Pinger) Network(network string) (string, error) {
	origNet := p.network
	switch network {
	case "ip", "udp":
		p.network = network
	default:
		return origNet, fmt.Errorf("%s не является допустимой конечной точкой ICMP", network)
	}
	return origNet, nil
}

// Source задаёт источник IPv4/IPv6 для ICMP-пакетов.
func (p *Pinger) Source(source string) (string, error) {
	origSource := p.source
	if source == "" {
		p.mu.Lock()
		p.source = ""
		p.source6 = ""
		p.mu.Unlock()
		return origSource, nil
	}
	addr := net.ParseIP(source)
	if addr == nil {
		return origSource, fmt.Errorf("%s не является допустимым IPv4/IPv6-адресом", source)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if isIPv4(addr) {
		p.source = source
	} else if isIPv6(addr) {
		origSource = p.source6
		p.source6 = source
	} else {
		return origSource, fmt.Errorf("%s не является допустимым IPv4/IPv6-адресом", source)
	}
	return origSource, nil
}

// AddIP добавляет IP-адрес для пинга.
func (p *Pinger) AddIP(ipaddr string) error {
	addr := net.ParseIP(ipaddr)
	if addr == nil {
		return fmt.Errorf("%s не является допустимым IP-адресом", ipaddr)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addrs[addr.String()] = &net.IPAddr{IP: addr}
	if isIPv4(addr) {
		p.hasIPv4 = true
	} else if isIPv6(addr) {
		p.hasIPv6 = true
	}
	return nil
}

// AddIPAddr добавляет IP-адрес для пинга.
func (p *Pinger) AddIPAddr(ip *net.IPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addrs[ip.String()] = ip
	if isIPv4(ip.IP) {
		p.hasIPv4 = true
	} else if isIPv6(ip.IP) {
		p.hasIPv6 = true
	}
}

// RemoveIP удаляет IP-адрес из списка пинга.
func (p *Pinger) RemoveIP(ipaddr string) error {
	addr := net.ParseIP(ipaddr)
	if addr == nil {
		return fmt.Errorf("%s не является допустимым IP-адресом", ipaddr)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.addrs, addr.String())
	return nil
}

// RemoveIPAddr удаляет IP-адрес из списка пинга.
func (p *Pinger) RemoveIPAddr(ip *net.IPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.addrs, ip.String())
}

// AddHandler добавляет обработчик событий (устарело).
func (p *Pinger) AddHandler(event string, handler interface{}) error {
	switch event {
	case "receive":
		if hdl, ok := handler.(func(*net.IPAddr, time.Duration)); ok {
			p.mu.Lock()
			p.OnRecv = hdl
			p.mu.Unlock()
			return nil
		}
		return errors.New("обработчик receive должен быть `func(*net.IPAddr, time.Duration)`")
	case "idle":
		if hdl, ok := handler.(func()); ok {
			p.mu.Lock()
			p.OnIdle = hdl
			p.mu.Unlock()
			return nil
		}
		return errors.New("обработчик idle должен быть `func()`")
	default:
		return fmt.Errorf("событие %s не поддерживается", event)
	}
}

// Run выполняет единичный ICMP-пинг.
func (p *Pinger) Run() error {
	p.mu.Lock()
	p.ctx = newContext()
	p.mu.Unlock()
	p.run(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx.err
}

// RunLoop выполняет многократный ICMP-пинг.
func (p *Pinger) RunLoop() {
	p.mu.Lock()
	p.ctx = newContext()
	p.mu.Unlock()
	go p.run(false)
}

// Done возвращает канал, закрывающийся при остановке RunLoop.
func (p *Pinger) Done() <-chan bool {
	return p.ctx.done
}

// Stop останавливает RunLoop.
func (p *Pinger) Stop() {
	p.debugln("Stop: закрытие p.ctx.stop")
	close(p.ctx.stop)
	p.debugln("Stop: ожидание <-p.ctx.done")
	<-p.ctx.done
}

// Err возвращает ошибку RunLoop.
func (p *Pinger) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx.err
}

// listen слушает ICMP-пакеты на указанной конечной точке.
func (p *Pinger) listen(netProto, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		p.mu.Lock()
		p.ctx.err = err
		p.mu.Unlock()
		p.debugln("Run: закрытие p.ctx.done")
		close(p.ctx.done)
		return nil
	}
	return conn
}

// run выполняет логику ICMP-пинга.
func (p *Pinger) run(once bool) {
	p.debugln("Run: Начало")
	var conn, conn6 *icmp.PacketConn
	if p.hasIPv4 {
		if conn = p.listen(ipv4Proto[p.network], p.source); conn == nil {
			return
		}
		defer conn.Close()
	}
	if p.hasIPv6 {
		if conn6 = p.listen(ipv6Proto[p.network], p.source6); conn6 == nil {
			return
		}
		defer conn6.Close()
	}
	recv := make(chan *packet, 1)
	recvCtx := newContext()
	wg := new(sync.WaitGroup)
	if conn != nil {
		wg.Add(1)
		go p.recvICMP(conn, recv, recvCtx, wg)
	}
	if conn6 != nil {
		wg.Add(1)
		go p.recvICMP(conn6, recv, recvCtx, wg)
	}
	queue, err := p.sendICMP(conn, conn6)
	ticker := time.NewTicker(p.MaxRTT)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.stop:
			p.debugln("Run: <-p.ctx.stop")
			return
		case <-recvCtx.done:
			p.debugln("Run: <-recvCtx.done")
			p.mu.Lock()
			err = recvCtx.err
			p.mu.Unlock()
			return
		case <-ticker.C:
			p.mu.Lock()
			handler := p.OnIdle
			p.mu.Unlock()
			if handler != nil {
				handler()
			}
			if once || err != nil {
				return
			}
			p.debugln("Run: вызов sendICMP")
			queue, err = p.sendICMP(conn, conn6)
		case r := <-recv:
			p.debugln("Run: <-recv")
			p.procRecv(r, queue)
		}
	}
}

// sendICMP отправляет ICMP-пакеты.
func (p *Pinger) sendICMP(conn, conn6 *icmp.PacketConn) (map[string]*net.IPAddr, error) {
	p.debugln("sendICMP: Начало")
	p.mu.Lock()
	p.id = rand.Intn(0xffff)
	p.seq = rand.Intn(0xffff)
	p.mu.Unlock()
	queue := make(map[string]*net.IPAddr)
	wg := new(sync.WaitGroup)
	for key, addr := range p.addrs {
		var typ icmp.Type
		var cn *icmp.PacketConn
		if isIPv4(addr.IP) {
			typ = ipv4.ICMPTypeEcho
			cn = conn
		} else if isIPv6(addr.IP) {
			typ = ipv6.ICMPTypeEchoRequest
			cn = conn6
		} else {
			continue
		}
		if cn == nil {
			continue
		}
		t := timeToBytes(time.Now())
		if p.Size-TimeSliceLength > 0 {
			t = append(t, byteSliceOfSize(p.Size-TimeSliceLength)...)
		}
		p.mu.Lock()
		bytes, err := (&icmp.Message{
			Type: typ,
			Code: 0,
			Body: &icmp.Echo{
				ID:   p.id,
				Seq:  p.seq,
				Data: t,
			},
		}).Marshal(nil)
		p.mu.Unlock()
		if err != nil {
			wg.Wait()
			return queue, err
		}
		queue[key] = addr
		var dst net.Addr = addr
		if p.network == "udp" {
			dst = &net.UDPAddr{IP: addr.IP, Zone: addr.Zone}
		}
		wg.Add(1)
		go func(conn *icmp.PacketConn, ra net.Addr, b []byte) {
			defer wg.Done()
			for {
				if _, err := conn.WriteTo(b, ra); err != nil {
					if neterr, ok := err.(*net.OpError); ok && neterr.Err == syscall.ENOBUFS {
						continue
					}
				}
				break
			}
			p.debugln("sendICMP: WriteTo Завершено")
		}(cn, dst, bytes)
	}
	wg.Wait()
	p.debugln("sendICMP: Завершено")
	return queue, nil
}

// recvICMP получает ICMP-пакеты.
func (p *Pinger) recvICMP(conn *icmp.PacketConn, recv chan<- *packet, ctx *context, wg *sync.WaitGroup) {
	defer wg.Done()
	p.debugln("recvICMP: Начало")
	for {
		select {
		case <-ctx.stop:
			p.debugln("recvICMP: <-ctx.stop")
			return
		default:
		}
		bytes := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, ra, err := conn.ReadFrom(bytes)
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok && neterr.Timeout() {
				p.debugln("recvICMP: Тайм-аут чтения")
				continue
			}
			p.debugln("recvICMP: Ошибка OpError", err)
			p.mu.Lock()
			ctx.err = err
			p.mu.Unlock()
			close(ctx.done)
			return
		}
		select {
		case recv <- &packet{bytes: bytes, addr: ra}:
		case <-ctx.stop:
			p.debugln("recvICMP: <-ctx.stop")
			return
		}
	}
}

// procRecv обрабатывает полученные ICMP-пакеты.
func (p *Pinger) procRecv(recv *packet, queue map[string]*net.IPAddr) {
	var ipaddr *net.IPAddr
	switch adr := recv.addr.(type) {
	case *net.IPAddr:
		ipaddr = adr
	case *net.UDPAddr:
		ipaddr = &net.IPAddr{IP: adr.IP, Zone: adr.Zone}
	default:
		return
	}
	addr := ipaddr.String()
	p.mu.Lock()
	if _, ok := p.addrs[addr]; !ok {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	var bytes []byte
	var proto int
	if isIPv4(ipaddr.IP) {
		if p.network == "ip" {
			bytes = ipv4Payload(recv.bytes)
		} else {
			bytes = recv.bytes
		}
		proto = ProtocolICMP
	} else if isIPv6(ipaddr.IP) {
		bytes = recv.bytes
		proto = ProtocolIPv6ICMP
	} else {
		return
	}
	m, err := icmp.ParseMessage(proto, bytes)
	if err != nil || (m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply) {
		return
	}
	var rtt time.Duration
	if pkt, ok := m.Body.(*icmp.Echo); ok {
		p.mu.Lock()
		if pkt.ID == p.id && pkt.Seq == p.seq {
			rtt = time.Since(bytesToTime(pkt.Data[:TimeSliceLength]))
		}
		p.mu.Unlock()
	} else {
		return
	}
	if _, ok := queue[addr]; ok {
		delete(queue, addr)
		p.mu.Lock()
		handler := p.OnRecv
		p.mu.Unlock()
		if handler != nil {
			handler(ipaddr, rtt)
		}
	}
}

// debugln выводит отладочные сообщения, если Debug=true.
func (p *Pinger) debugln(args ...interface{}) {
	if p.Debug {
		log.Println(args...)
	}
}

// debugf форматирует отладочные сообщения, если Debug=true.
func (p *Pinger) debugf(format string, args ...interface{}) {
	if p.Debug {
		log.Printf(format, args...)
	}
}

// byteSliceOfSize создаёт срез байтов заданного размера.
func byteSliceOfSize(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 1
	}
	return b
}

// timeToBytes преобразует время в срез байтов.
func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

// bytesToTime преобразует срез байтов во время.
func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1e9, nsec%1e9)
}

// isIPv4 проверяет, является ли IP-адрес IPv4.
func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

// isIPv6 проверяет, является ли IP-адрес IPv6.
func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

// ipv4Payload извлекает полезную нагрузку из IPv4-пакета.
func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	return b[int(b[0]&0x0f)<<2:]
}