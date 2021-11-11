package netpol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"

	v1core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	kubePodFirewallChainPrefix   = "KUBE-POD-FW-"
	kubeNetworkPolicyChainPrefix = "KUBE-NWPLCY-"
	kubeSourceIPSetPrefix        = "KUBE-SRC-"
	kubeDestinationIPSetPrefix   = "KUBE-DST-"
	kubeInputChainName           = "KUBE-ROUTER-INPUT"
	kubeForwardChainName         = "KUBE-ROUTER-FORWARD"
	kubeOutputChainName          = "KUBE-ROUTER-OUTPUT"
	kubeDefaultNetpolChain       = "KUBE-NWPLCY-DEFAULT"

	kubeIngressPolicyType = "ingress"
	kubeEgressPolicyType  = "egress"
	kubeBothPolicyType    = "both"

	syncVersionBase = 10
)

var (
	defaultChains = map[string]string{
		"INPUT":   kubeInputChainName,
		"FORWARD": kubeForwardChainName,
		"OUTPUT":  kubeOutputChainName,
	}
)

type ipFamilyHandler struct {
	iptablesSaveRestore *utils.IPTablesSaveRestore
	filterTableRules    bytes.Buffer

	*controllers.IPFamilyHandler
}

func newIPFamilyHandler(family v1core.IPFamily, nodeIP net.IP) (*ipFamilyHandler, error) {
	var (
		iptablesCmdHandler *iptables.IPTables
		err                error
	)

	iptablesSaveRestore := utils.NewIPTablesSaveRestore(family)

	switch family {
	case v1core.IPv4Protocol:
		iptablesCmdHandler, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return nil, err
		}
	case v1core.IPv6Protocol:
		iptablesCmdHandler, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
	}
	return &ipFamilyHandler{
		iptablesSaveRestore: iptablesSaveRestore,
		IPFamilyHandler: &controllers.IPFamilyHandler{
			Family:             family,
			IptablesCmdHandler: iptablesCmdHandler,
			NodeIP:             nodeIP,
		},
	}, nil
}

// Network policy controller provides both ingress and egress filtering for the pods as per the defined network
// policies. Two different types of iptables chains are used. Each pod running on the node which either
// requires ingress or egress filtering gets a pod specific chains. Each network policy has a iptables chain, which
// has rules expressed through ipsets matching source and destination pod ip's. In the FORWARD chain of the
// filter table a rule is added to jump the traffic originating (in case of egress network policy) from the pod
// or destined (in case of ingress network policy) to the pod specific iptables chain. Each
// pod specific iptables chain has rules to jump to the network polices chains, that pod matches. So packet
// originating/destined from/to pod goes through filter table's, FORWARD chain, followed by pod specific chain,
// followed by one or more network policy chains, till there is a match which will accept the packet, or gets
// dropped by the rule in the pod chain, if there is no match.

// NetworkPolicyController struct to hold information required by NetworkPolicyController
type NetworkPolicyController struct {
	nodeHostName                   string
	primaryServiceClusterIPRange   net.IPNet
	secondaryServiceClusterIPRange net.IPNet
	serviceExternalIPRanges        []net.IPNet
	serviceNodePortRange           string
	mu                             sync.Mutex
	syncPeriod                     time.Duration
	MetricsEnabled                 bool
	healthChan                     chan<- *healthcheck.ControllerHeartbeat
	fullSyncRequestChan            chan struct{}
	ipsetMutex                     *sync.Mutex
	enableIPv4                     bool
	enableIPv6                     bool

	ipFamilyHandlers map[uint16]*ipFamilyHandler

	ipSetHandler *utils.IPSet

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	NamespaceEventHandler     cache.ResourceEventHandler
	NetworkPolicyEventHandler cache.ResourceEventHandler
}

// internal structure to represent a network policy
type networkPolicyInfo struct {
	name        string
	namespace   string
	podSelector labels.Selector

	// set of pods matching network policy spec podselector label selector
	targetPods map[string]podInfo

	// whitelist ingress rules from the network policy spec
	ingressRules []ingressRule

	// whitelist egress rules from the network policy spec
	egressRules []egressRule

	// policy type "ingress" or "egress" or "both" as defined by PolicyType in the spec
	policyType string
}

// internal structure to represent Pod
type podInfo struct {
	ips       []v1core.PodIP
	name      string
	namespace string
	labels    map[string]string
}

// internal structure to represent NetworkPolicyIngressRule in the spec
type ingressRule struct {
	matchAllPorts  bool
	ports          []protocolAndPort
	namedPorts     []endPoints
	matchAllSource bool
	srcPods        []podInfo
	srcIPBlocks    [][]string
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type egressRule struct {
	matchAllPorts        bool
	ports                []protocolAndPort
	namedPorts           []endPoints
	matchAllDestinations bool
	dstPods              []podInfo
	dstIPBlocks          [][]string
}

type protocolAndPort struct {
	protocol string
	port     string
	endport  string
}

type endPoints struct {
	ips []string
	protocolAndPort
}

type numericPort2eps map[string]*endPoints
type protocol2eps map[string]numericPort2eps
type namedPort2eps map[string]protocol2eps

// Run runs forever till we receive notification on stopCh
func (npc *NetworkPolicyController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{},
	wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Info("Starting network policy controller")
	npc.healthChan = healthChan

	// setup kube-router specific top level custom chains (KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT)
	npc.ensureTopLevelChains()

	// setup default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// Full syncs of the network policy controller take a lot of time and can only be processed one at a time,
	// therefore, we start it in it's own goroutine and request a sync through a single item channel
	klog.Info("Starting network policy controller full sync goroutine")
	wg.Add(1)
	go func(fullSyncRequest <-chan struct{}, stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			// Add an additional non-blocking select to ensure that if the stopCh channel is closed it is handled first
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			default:
			}
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			case <-fullSyncRequest:
				klog.V(3).Info("Received request for a full sync, processing")
				npc.fullPolicySync() // fullPolicySync() is a blocking request here
			}
		}
	}(npc.fullSyncRequestChan, stopCh, wg)

	// loop forever till notified to stop on stopCh
	for {
		klog.V(1).Info("Requesting periodic sync of iptables to reflect network policies")
		npc.RequestFullSync()
		select {
		case <-stopCh:
			klog.Infof("Shutting down network policies controller")
			return
		case <-t.C:
		}
	}
}

// RequestFullSync allows the request of a full network policy sync without blocking the callee
func (npc *NetworkPolicyController) RequestFullSync() {
	select {
	case npc.fullSyncRequestChan <- struct{}{}:
		klog.V(3).Info("Full sync request queue was empty so a full sync request was successfully sent")
	default: // Don't block if the buffered channel is full, return quickly so that we don't block callee execution
		klog.V(1).Info("Full sync request queue was full, skipping...")
	}
}

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyController) fullPolicySync() {

	var err error
	var networkPoliciesInfo []networkPolicyInfo
	npc.mu.Lock()
	defer npc.mu.Unlock()

	healthcheck.SendHeartBeat(npc.healthChan, "NPC")
	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), syncVersionBase)
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
			metrics.ControllerIptablesSyncTotalTime.Add(endTime.Seconds())
			metrics.ControllerIptablesSyncTotalCount.Add(1)
		}
		klog.V(1).Infof("sync iptables took %v", endTime)
	}()

	klog.V(1).Infof("Starting sync of iptables with version: %s", syncVersion)

	// ensure kube-router specific top level chains and corresponding rules exist
	npc.ensureTopLevelChains()

	// ensure default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	networkPoliciesInfo, err = npc.buildNetworkPoliciesInfo()
	if err != nil {
		klog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
		return
	}

	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		ipFamilyHandler.filterTableRules.Reset()
		if err := ipFamilyHandler.iptablesSaveRestore.SaveInto("filter", &ipFamilyHandler.filterTableRules); err != nil {
			klog.Errorf("Aborting sync. Failed to run iptables-save: %v", err.Error())
			return
		}
	}

	activePolicyChains, activePolicyIPSets, err := npc.syncNetworkPolicyChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to sync network policy chains: %v", err.Error())
		return
	}

	activePodFwChains := npc.syncPodFirewallChains(networkPoliciesInfo, syncVersion)

	// Makes sure that the ACCEPT rules for packets marked with "0x20000" are added to the end of each of kube-router's
	// top level chains
	npc.ensureExplicitAccept()

	err = npc.cleanupStaleRules(activePolicyChains, activePodFwChains, false)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to cleanup stale iptables rules: %v", err.Error())
		return
	}

	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		if err := ipFamilyHandler.iptablesSaveRestore.Restore("filter",
			ipFamilyHandler.filterTableRules.Bytes()); err != nil {
			klog.Errorf("Aborting sync. Failed to run iptables-restore: %v\n%s",
				err.Error(), ipFamilyHandler.filterTableRules.String())
			return
		}
	}

	err = npc.cleanupStaleIPSets(activePolicyIPSets)
	if err != nil {
		klog.Errorf("Failed to cleanup stale ipsets: %v", err.Error())
		return
	}
}

// Creates custom chains KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT
// and following rules in the filter table to jump from builtin chain to custom chain
// -A INPUT   -m comment --comment "kube-router netpol" -j KUBE-ROUTER-INPUT
// -A FORWARD -m comment --comment "kube-router netpol" -j KUBE-ROUTER-FORWARD
// -A OUTPUT  -m comment --comment "kube-router netpol" -j KUBE-ROUTER-OUTPUT
func (npc *NetworkPolicyController) ensureTopLevelChains() {
	const serviceVIPPosition = 1
	const whitelistTCPNodePortsPosition = 2
	const whitelistUDPNodePortsPosition = 3
	const externalIPPositionAdditive = 4

	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		addUUIDForRuleSpec := func(chain string, ruleSpec *[]string) (string, error) {
			hash := sha256.Sum256([]byte(chain + strings.Join(*ruleSpec, "")))
			encoded := base32.StdEncoding.EncodeToString(hash[:])[:16]
			for idx, part := range *ruleSpec {
				if part == "--comment" {
					(*ruleSpec)[idx+1] = (*ruleSpec)[idx+1] + " - " + encoded
					return encoded, nil
				}
			}
			return "", fmt.Errorf("could not find a comment in the ruleSpec string given: %s",
				strings.Join(*ruleSpec, " "))
		}

		ensureRuleAtPosition := func(chain string, ruleSpec []string, uuid string, position int) {
			exists, err := ipFamilyHandler.IptablesCmdHandler.Exists("filter", chain, ruleSpec...)
			if err != nil {
				klog.Fatalf("Failed to verify rule exists in %s chain due to %s", chain, err.Error())
			}
			if !exists {
				err := ipFamilyHandler.IptablesCmdHandler.Insert("filter", chain, position, ruleSpec...)
				if err != nil {
					klog.Fatalf("Failed to run iptables command to insert in %s chain %s", chain, err.Error())
				}
				return
			}
			rules, err := ipFamilyHandler.IptablesCmdHandler.List("filter", chain)
			if err != nil {
				klog.Fatalf("failed to list rules in filter table %s chain due to %s", chain, err.Error())
			}

			var ruleNo, ruleIndexOffset int
			for i, rule := range rules {
				rule = strings.Replace(rule, "\"", "", 2) // removes quote from comment string
				if strings.HasPrefix(rule, "-P") || strings.HasPrefix(rule, "-N") {
					// if this chain has a default policy, then it will show as rule #1 from iptablesCmdHandler.List so we
					// need to account for this offset
					ruleIndexOffset++
					continue
				}
				if strings.Contains(rule, uuid) {
					// range uses a 0 index, but iptables uses a 1 index so we need to increase ruleNo by 1
					ruleNo = i + 1 - ruleIndexOffset
					break
				}
			}
			if ruleNo != position {
				err = ipFamilyHandler.IptablesCmdHandler.Insert("filter", chain, position, ruleSpec...)
				if err != nil {
					klog.Fatalf("Failed to run iptables command to insert in %s chain %s", chain, err.Error())
				}
				err = ipFamilyHandler.IptablesCmdHandler.Delete("filter", chain, strconv.Itoa(ruleNo+1))
				if err != nil {
					klog.Fatalf("Failed to delete incorrect rule in %s chain due to %s", chain, err.Error())
				}
			}
		}

		for builtinChain, customChain := range defaultChains {
			exists, err := ipFamilyHandler.IptablesCmdHandler.ChainExists("filter", customChain)
			if err != nil {
				klog.Fatalf("failed to check for the existence of chain %s, error: %v", customChain, err)
			}
			if !exists {
				err = ipFamilyHandler.IptablesCmdHandler.NewChain("filter", customChain)
				if err != nil {
					klog.Fatalf("failed to run iptables command to create %s chain due to %s", customChain,
						err.Error())
				}
			}
			args := []string{"-m", "comment", "--comment", "kube-router netpol", "-j", customChain}
			uuid, err := addUUIDForRuleSpec(builtinChain, &args)
			if err != nil {
				klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
			}
			ensureRuleAtPosition(builtinChain, args, uuid, 1)
		}

		whitelistPrimaryServiceVips := []string{"-m", "comment", "--comment", "allow traffic to primary cluster IP range",
			"-d", npc.primaryServiceClusterIPRange.String(), "-j", "RETURN"}
		uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistPrimaryServiceVips)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		ensureRuleAtPosition(kubeInputChainName, whitelistPrimaryServiceVips, uuid, serviceVIPPosition)

		whitelistSecondaryServiceVips := []string{"-m", "comment", "--comment", "allow traffic to primary cluster IP range",
			"-d", npc.secondaryServiceClusterIPRange.String(), "-j", "RETURN"}
		uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistSecondaryServiceVips)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		ensureRuleAtPosition(kubeInputChainName, whitelistSecondaryServiceVips, uuid, serviceVIPPosition)

		whitelistTCPNodeports := []string{"-p", "tcp", "-m", "comment", "--comment",
			"allow LOCAL TCP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
			"-m", "multiport", "--dports", npc.serviceNodePortRange, "-j", "RETURN"}
		uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistTCPNodeports)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		ensureRuleAtPosition(kubeInputChainName, whitelistTCPNodeports, uuid, whitelistTCPNodePortsPosition)

		whitelistUDPNodeports := []string{"-p", "udp", "-m", "comment", "--comment",
			"allow LOCAL UDP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
			"-m", "multiport", "--dports", npc.serviceNodePortRange, "-j", "RETURN"}
		uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistUDPNodeports)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		ensureRuleAtPosition(kubeInputChainName, whitelistUDPNodeports, uuid, whitelistUDPNodePortsPosition)

		for externalIPIndex, externalIPRange := range npc.serviceExternalIPRanges {
			whitelistServiceVips := []string{"-m", "comment", "--comment",
				"allow traffic to external IP range: " + externalIPRange.String(), "-d", externalIPRange.String(),
				"-j", "RETURN"}
			uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
			if err != nil {
				klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
			}
			ensureRuleAtPosition(kubeInputChainName, whitelistServiceVips, uuid, externalIPIndex+externalIPPositionAdditive)
		}
	}
}

func (npc *NetworkPolicyController) ensureExplicitAccept() {
	// for the traffic to/from the local pod's let network policy controller be
	// authoritative entity to ACCEPT the traffic if it complies to network policies
	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		for _, chain := range defaultChains {
			comment := "\"rule to explicitly ACCEPT traffic that comply to network policies\""
			args := []string{"-m", "comment", "--comment", comment, "-m", "mark", "--mark", "0x20000/0x20000",
				"-j", "ACCEPT"}
			ipFamilyHandler.filterTableRules = utils.AppendUnique(ipFamilyHandler.filterTableRules, chain, args)
		}
	}
}

// Creates custom chains KUBE-NWPLCY-DEFAULT
func (npc *NetworkPolicyController) ensureDefaultNetworkPolicyChain() {
	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		markArgs := make([]string, 0)
		markComment := "rule to mark traffic matching a network policy"
		markArgs = append(markArgs, "-j", "MARK", "-m", "comment", "--comment", markComment,
			"--set-xmark", "0x10000/0x10000")

		exists, err := ipFamilyHandler.IptablesCmdHandler.ChainExists("filter", kubeDefaultNetpolChain)
		if err != nil {
			klog.Fatalf("failed to check for the existence of chain %s, error: %v", kubeDefaultNetpolChain, err)
		}
		if !exists {
			err = ipFamilyHandler.IptablesCmdHandler.NewChain("filter", kubeDefaultNetpolChain)
			if err != nil {
				klog.Fatalf("failed to run iptables command to create %s chain due to %s",
					kubeDefaultNetpolChain, err.Error())
			}
		}
		err = ipFamilyHandler.IptablesCmdHandler.AppendUnique("filter", kubeDefaultNetpolChain, markArgs...)
		if err != nil {
			klog.Fatalf("Failed to run iptables command: %s", err.Error())
		}
	}
}

func (npc *NetworkPolicyController) cleanupStaleRules(activePolicyChains, activePodFwChains map[string]bool,
	deleteDefaultChains bool) error {

	cleanupPodFwChains := make([]string, 0)
	cleanupPolicyChains := make([]string, 0)

	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		// find iptables chains and ipsets that are no longer used by comparing current to the active maps we were passed
		chains, err := ipFamilyHandler.IptablesCmdHandler.ListChains("filter")
		if err != nil {
			return fmt.Errorf("unable to list chains: %w", err)
		}
		for _, chain := range chains {
			if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) {
				if chain == kubeDefaultNetpolChain {
					continue
				}
				if _, ok := activePolicyChains[chain]; !ok {
					cleanupPolicyChains = append(cleanupPolicyChains, chain)
					continue
				}
			}
			if strings.HasPrefix(chain, kubePodFirewallChainPrefix) {
				if _, ok := activePodFwChains[chain]; !ok {
					cleanupPodFwChains = append(cleanupPodFwChains, chain)
					continue
				}
			}
		}

		var newChains, newRules, desiredFilterTable bytes.Buffer
		rules := strings.Split(ipFamilyHandler.filterTableRules.String(), "\n")
		if len(rules) > 0 && rules[len(rules)-1] == "" {
			rules = rules[:len(rules)-1]
		}
		for _, rule := range rules {
			skipRule := false
			for _, podFWChainName := range cleanupPodFwChains {
				if strings.Contains(rule, podFWChainName) {
					skipRule = true
					break
				}
			}
			for _, policyChainName := range cleanupPolicyChains {
				if strings.Contains(rule, policyChainName) {
					skipRule = true
					break
				}
			}
			if deleteDefaultChains {
				for _, chain := range []string{kubeInputChainName, kubeForwardChainName, kubeOutputChainName,
					kubeDefaultNetpolChain} {
					if strings.Contains(rule, chain) {
						skipRule = true
						break
					}
				}
			}
			if strings.Contains(rule, "COMMIT") || strings.HasPrefix(rule, "# ") {
				skipRule = true
			}
			if skipRule {
				continue
			}
			if strings.HasPrefix(rule, ":") {
				newChains.WriteString(rule + " - [0:0]\n")
			}
			if strings.HasPrefix(rule, "-") {
				newRules.WriteString(rule + "\n")
			}
		}
		desiredFilterTable.WriteString("*filter" + "\n")
		desiredFilterTable.Write(newChains.Bytes())
		desiredFilterTable.Write(newRules.Bytes())
		desiredFilterTable.WriteString("COMMIT" + "\n")
		ipFamilyHandler.filterTableRules = desiredFilterTable
	}

	return nil
}

func (npc *NetworkPolicyController) cleanupStaleIPSets(activePolicyIPSets map[string]bool) error {
	// There are certain actions like Cleanup() actions that aren't working with full instantiations of the controller
	// and in these instances the mutex may not be present and may not need to be present as they are operating out of a
	// single goroutine where there is no need for locking
	if nil != npc.ipsetMutex {
		klog.V(1).Infof("Attempting to attain ipset mutex lock")
		npc.ipsetMutex.Lock()
		klog.V(1).Infof("Attained ipset mutex lock, continuing...")
		defer func() {
			npc.ipsetMutex.Unlock()
			klog.V(1).Infof("Returned ipset mutex lock")
		}()
	}

	for ipFamily := range npc.ipFamilyHandlers {
		cleanupPolicyIPSets := make([]*utils.Set, 0)

		ipsets, err := utils.NewIPSet(ipFamily)
		if err != nil {
			return fmt.Errorf("failed to create ipsets command executor due to %w", err)
		}
		err = ipsets.Save()
		if err != nil {
			klog.Fatalf("failed to initialize ipsets command executor due to %s", err.Error())
		}
		for _, set := range ipsets.Sets {
			if strings.HasPrefix(set.Name, kubeSourceIPSetPrefix) ||
				strings.HasPrefix(set.Name, kubeDestinationIPSetPrefix) {
				if _, ok := activePolicyIPSets[set.Name]; !ok {
					cleanupPolicyIPSets = append(cleanupPolicyIPSets, set)
				}
			}
		}
		// cleanup network policy ipsets
		for _, set := range cleanupPolicyIPSets {
			err = set.Destroy()
			if err != nil {
				return fmt.Errorf("failed to delete ipset %s due to %s", set.Name, err)
			}
		}
	}
	return nil
}

// Cleanup cleanup configurations done
func (npc *NetworkPolicyController) Cleanup() {
	klog.Info("Cleaning up NetworkPolicyController configurations...")

	var emptySet map[string]bool
	// Take a dump (iptables-save) of the current filter table for cleanupStaleRules() to work on
	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		if err := ipFamilyHandler.iptablesSaveRestore.SaveInto("filter", &ipFamilyHandler.filterTableRules); err != nil {
			klog.Errorf("error encountered attempting to list iptables rules for cleanup: %v", err)
			return
		}
	}
	// Run cleanupStaleRules() to get rid of most of the kube-router rules (this is the same logic that runs as
	// part NPC's runtime loop). Setting the last parameter to true causes even the default chains are removed.
	err := npc.cleanupStaleRules(emptySet, emptySet, true)
	if err != nil {
		klog.Errorf("error encountered attempting to cleanup iptables rules: %v", err)
		return
	}
	// Restore (iptables-restore) npc's cleaned up version of the iptables filter chain
	for _, ipFamilyHandler := range npc.ipFamilyHandlers {
		if err = ipFamilyHandler.iptablesSaveRestore.Restore("filter", ipFamilyHandler.filterTableRules.Bytes()); err != nil {
			klog.Errorf(
				"error encountered while loading running iptables-restore: %v\n%s", err,
				ipFamilyHandler.filterTableRules.String())
		}
	}

	// Cleanup ipsets
	err = npc.cleanupStaleIPSets(emptySet)
	if err != nil {
		klog.Errorf("error encountered while cleaning ipsets: %v", err)
		return
	}

	klog.Infof("Successfully cleaned the NetworkPolicyController configurations done by kube-router")
}

// NewNetworkPolicyController returns new NetworkPolicyController object
func NewNetworkPolicyController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	ipsetMutex *sync.Mutex) (*NetworkPolicyController, error) {
	npc := NetworkPolicyController{ipsetMutex: ipsetMutex}

	// Creating a single-item buffered channel to ensure that we only keep a single full sync request at a time,
	// additional requests would be pointless to queue since after the first one was processed the system would already
	// be up to date with all of the policy changes from any enqueued request after that
	npc.fullSyncRequestChan = make(chan struct{}, 1)

	// Validate and parse ClusterIP service range
	if config.ClusterIPCIDR == "" {
		return nil, fmt.Errorf("parameter --service-cluster-ip is empty")
	}
	clusterIPCIDRList := strings.Split(config.ClusterIPCIDR, ",")

	if len(clusterIPCIDRList) == 0 {
		return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter, the list is empty")
	}

	_, primaryIpnet, err := net.ParseCIDR(clusterIPCIDRList[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: %w", err)
	}
	npc.primaryServiceClusterIPRange = *primaryIpnet

	if len(clusterIPCIDRList) > 1 {
		_, secondaryIpnet, err := net.ParseCIDR(clusterIPCIDRList[1])
		if err != nil {
			return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: %v", err)
		}
		npc.secondaryServiceClusterIPRange = *secondaryIpnet
	}
	if len(clusterIPCIDRList) > 2 {
		return nil, fmt.Errorf("too many CIDRs provided in --service-cluster-ip-range parameter, only two " +
			"addresses are allowed at once for dual-stack")
	}

	// Validate and parse NodePort range
	if npc.serviceNodePortRange, err = validateNodePortRange(config.NodePortRange); err != nil {
		return nil, err
	}

	// Validate and parse ExternalIP service range
	for _, externalIPRange := range config.ExternalIPCIDRs {
		_, ipnet, err := net.ParseCIDR(externalIPRange)
		if err != nil {
			return nil, fmt.Errorf("failed to get parse --service-external-ip-range parameter: '%s'. Error: %s",
				externalIPRange, err.Error())
		}
		npc.serviceExternalIPRanges = append(npc.serviceExternalIPRanges, *ipnet)
	}

	if config.MetricsEnabled {
		// Register the metrics for this controller
		prometheus.MustRegister(metrics.ControllerIptablesSyncTime)
		prometheus.MustRegister(metrics.ControllerPolicyChainsSyncTime)
		prometheus.MustRegister(metrics.ControllerIptablesSyncTotalTime)
		prometheus.MustRegister(metrics.ControllerIptablesSyncTotalCount)
		npc.MetricsEnabled = true
	}

	npc.syncPeriod = config.IPTablesSyncPeriod

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	npc.nodeHostName = node.Name

	npc.enableIPv4 = config.EnableIPv4
	npc.enableIPv6 = config.EnableIPv6

	nodeIPv4, nodeIPv6, err := utils.GetNodeIP(node, npc.enableIPv4, npc.enableIPv6)
	if err != nil {
		return nil, err
	}
	// npc.nodeIPv4 = nodeIPv4
	// npc.nodeIPv6 = nodeIPv6
	npc.ipFamilyHandlers = make(map[uint16]*ipFamilyHandler)
	if npc.enableIPv4 {
		ipv4Handler, err := newIPFamilyHandler(v1core.IPv4Protocol, nodeIPv4)
		if err != nil {
			return nil, err
		}
		npc.ipFamilyHandlers[syscall.AF_INET] = ipv4Handler
	}
	if npc.enableIPv6 {
		ipv6Handler, err := newIPFamilyHandler(v1core.IPv6Protocol, nodeIPv6)
		if err != nil {
			return nil, err
		}
		npc.ipFamilyHandlers[syscall.AF_INET6] = ipv6Handler
	}

	npc.podLister = podInformer.GetIndexer()
	npc.PodEventHandler = npc.newPodEventHandler()

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()

	return &npc, nil
}
