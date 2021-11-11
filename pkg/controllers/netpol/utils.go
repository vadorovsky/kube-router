package netpol

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	api "k8s.io/api/core/v1"
	utilsnet "k8s.io/utils/net"
)

const (
	PodCompleted api.PodPhase = "Completed"
)

// isPodUpdateNetPolRelevant checks the attributes that we care about for building NetworkPolicies on the host and if it
// finds a relevant change, it returns true otherwise it returns false. The things we care about for NetworkPolicies:
// 1) Is the phase of the pod changing? (matters for catching completed, succeeded, or failed jobs)
// 2) Is the pod IP changing? (changes how the network policy is applied to the host)
// 3) Is the pod's host IP changing? (should be caught in the above, with the CNI kube-router runs with but we check
//     this as well for sanity)
// 4) Is a pod's label changing? (potentially changes which NetworkPolicies select this pod)
func isPodUpdateNetPolRelevant(oldPod, newPod *api.Pod) bool {
	return newPod.Status.Phase != oldPod.Status.Phase ||
		newPod.Status.PodIP != oldPod.Status.PodIP ||
		!reflect.DeepEqual(newPod.Status.PodIPs, oldPod.Status.PodIPs) ||
		newPod.Status.HostIP != oldPod.Status.HostIP ||
		!reflect.DeepEqual(newPod.Labels, oldPod.Labels)
}

func isNetPolActionable(pod *api.Pod) bool {
	return !isFinished(pod) && pod.Status.PodIP != "" && !pod.Spec.HostNetwork
}

func isFinished(pod *api.Pod) bool {
	// nolint:exhaustive // We don't care about PodPending, PodRunning, PodUnknown here as we want those to fall
	// into the false case
	switch pod.Status.Phase {
	case api.PodFailed, api.PodSucceeded, PodCompleted:
		return true
	}
	return false
}

func validateNodePortRange(nodePortOption string) (string, error) {
	const portBitSize = 16

	nodePortValidator := regexp.MustCompile(`^([0-9]+)[:-]([0-9]+)$`)
	if matched := nodePortValidator.MatchString(nodePortOption); !matched {
		return "", fmt.Errorf(
			"failed to parse node port range given: '%s' please see specification in help text", nodePortOption)
	}
	matches := nodePortValidator.FindStringSubmatch(nodePortOption)
	if len(matches) != 3 {
		return "", fmt.Errorf("could not parse port number from range given: '%s'", nodePortOption)
	}
	port1, err := strconv.ParseUint(matches[1], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse first port number from range given: '%s'", nodePortOption)
	}
	port2, err := strconv.ParseUint(matches[2], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse second port number from range given: '%s'", nodePortOption)
	}
	if port1 >= port2 {
		return "", fmt.Errorf("port 1 is greater than or equal to port 2 in range given: '%s'", nodePortOption)
	}
	return fmt.Sprintf("%d:%d", port1, port2), nil
}

func getIPsFromPods(pods []podInfo, family api.IPFamily) []string {
	var ips []string
	for _, pod := range pods {
		switch family {
		case api.IPv4Protocol:
			ip, _ := getPodIPv4Address(pod)
			ips = append(ips, ip)
		case api.IPv6Protocol:
			ip, _ := getPodIPv6Address(pod)
			ips = append(ips, ip)
		}
	}
	return ips
}

func (npc *NetworkPolicyController) createGenericHashIPSet(ipsetName, hashType string, ips []string,
	ipFamilyHandler *ipFamilyHandler) {
	setEntries := make([][]string, 0)
	switch ipFamilyHandler.Family {
	case api.IPv4Protocol:
		for _, ip := range ips {
			if !utilsnet.IsIPv4String(ip) {
				fmt.Printf("MANU - Something is wrong at createGenericHashIPSet. ip: %#v is not IPV4", ip)
			}
			setEntries = append(setEntries, []string{ip, utils.OptionTimeout, "0"})
		}
		ipFamilyHandler.IPSetHandler.RefreshSet(ipsetName, setEntries, hashType)
	case api.IPv6Protocol:
		for _, ip := range ips {
			if !utilsnet.IsIPv6String(ip) {
				fmt.Printf("MANU - Something is wrong at createGenericHashIPSet. ip: %#v is not IPV6", ip)
			}
			setEntries = append(setEntries, []string{ip, utils.OptionTimeout, "0"})
		}
		fmt.Printf("MANUEL - createGenericHashIPSet. Before RefreshSet. These are the ipset.Sets: %#v, "+
			"the setEntries: %#v and the hashType: %#v\n", ipFamilyHandler.IPSetHandler.Sets, setEntries, hashType)
		ipFamilyHandler.IPSetHandler.RefreshSet(ipsetName, setEntries, hashType)
	}
}

// createPolicyIndexedIPSet creates a policy based ipset and indexes it as an active ipset
func (npc *NetworkPolicyController) createPolicyIndexedIPSet(
	activePolicyIPSets map[string]bool, ipsetName, hashType string, ips []string, ipFamilyHandler *ipFamilyHandler) {
	activePolicyIPSets[ipsetName] = true
	npc.createGenericHashIPSet(ipsetName, hashType, ips, ipFamilyHandler)
}

// createPodWithPortPolicyRule handles the case where port details are provided by the ingress/egress rule and creates
// an iptables rule that matches on both the source/dest IPs and the port
func (npc *NetworkPolicyController) createPodWithPortPolicyRule(
	ports []protocolAndPort, policy networkPolicyInfo, policyName string, srcSetName string, dstSetName string,
	ipFamilyHandler *ipFamilyHandler) error {
	for _, portProtocol := range ports {
		comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
			policy.name + " namespace " + policy.namespace
		if err := npc.appendRuleToPolicyChain(policyName, comment, srcSetName, dstSetName, portProtocol.protocol,
			portProtocol.port, portProtocol.endport, ipFamilyHandler); err != nil {
			return err
		}
	}
	return nil
}

func getPodIPv6Address(pod podInfo) (string, error) {
	fmt.Printf("MANU - Inside getPodIPv6Address. These are the pod.ips: %#v\n", pod.ips)
	for _, ip := range pod.ips {
		fmt.Printf("MANU - This is the IP: %#v\n", ip.IP)
		if utilsnet.IsIPv6String(ip.IP) {
			return ip.IP, nil
		}
	}
	return "", fmt.Errorf("the pod has no IPv6Address")
}

func getPodIPv4Address(pod podInfo) (string, error) {
	for _, ip := range pod.ips {
		if utilsnet.IsIPv4String(ip.IP) {
			return ip.IP, nil
		}
	}
	return "", fmt.Errorf("the pod has no IPv4Address")
}
