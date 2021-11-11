package controllers

import (
	"net"

	"github.com/cloudnativelabs/kube-router/pkg/utils"

	"github.com/coreos/go-iptables/iptables"
	v1core "k8s.io/api/core/v1"
)

type IPFamilyHandler struct {
	Family             v1core.IPFamily
	IptablesCmdHandler *iptables.IPTables
	IPSetHandler       *utils.IPSet
	NodeIP             net.IP
	PodCidr            string
	BridgeIfName       string
}

// func NewIPFamilyHandler(family v1core.IPFamily, nodeIP string,
// 	podCidr string) (*IPFamilyHandler, error) {
// 	var (
// 		iptablesCmdHandler *iptables.IPTables
// 		err                error
// 	)
//
// 	switch family {
// 	case v1core.IPv4Protocol:
// 		iptablesCmdHandler, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
// 	case v1core.IPv6Protocol:
// 		iptablesCmdHandler, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
// 	}
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to initialize ip6tables executor: %v", err)
// 	}
//
// 	return &IPFamilyHandler{
// 		Family:             family,
// 		IptablesCmdHandler: iptablesCmdHandler,
// 		NodeIP:             nodeIP,
// 		PodCidr:            podCidr,
// 	}, nil
// }
