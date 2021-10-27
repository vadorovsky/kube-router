package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/cri"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/moby/ipvs"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

// sync the ipvs service and server details configured to reflect the desired state of Kubernetes services
// and endpoints as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointsInfoMap) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsServicesSyncTime.Observe(endTime.Seconds())
		}
		klog.V(1).Infof("sync ipvs services took %v", endTime)
	}()

	var err error
	var syncErrors bool

	// map to track all active IPVS services and servers that are setup during sync of
	// cluster IP, nodeport and external IP services
	activeServiceEndpointMap := make(map[string][]string)

	err = nsc.setupClusterIPServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up IPVS services for service cluster IP's: %s", err.Error())
	}
	err = nsc.setupNodePortServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up IPVS services for service nodeport's: %s", err.Error())
	}
	err = nsc.setupExternalIPServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up IPVS services for service external IP's and load balancer IP's: %s",
			err.Error())
	}
	err = nsc.cleanupStaleVIPs(activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error cleaning up stale VIP's configured on the dummy interface: %s", err.Error())
	}
	err = nsc.cleanupStaleIPVSConfig(activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error cleaning up stale IPVS services and servers: %s", err.Error())
	}

	nsc.cleanupStaleMetrics(activeServiceEndpointMap)

	err = nsc.syncIpvsFirewall()
	if err != nil {
		syncErrors = true
		klog.Errorf("Error syncing ipvs svc iptables rules to permit traffic to service VIP's: %s", err.Error())
	}
	err = nsc.setupForDSR(serviceInfoMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up necessary policy based routing configuration needed for "+
			"direct server return: %s", err.Error())
	}

	if syncErrors {
		klog.V(1).Info("One or more errors encountered during sync of IPVS services and servers " +
			"to desired state")
	} else {
		klog.V(1).Info("IPVS servers and services are synced to desired state")
	}

	return nil
}

// func (nsc *NetworkServicesController) setupClusterIPService(ipvsSvcs []*ipvs.Service, protocol uint16,
// 	dummyVipInterface netlink.Link, svc *serviceInfo, endpoints []endpointsInfo,
// 	activeServiceEndpointMap map[string][]string, clusterIP net.IP) error {
// 	for _, ipvsSvc := range ipvsSvcs {
// 		ln := nsc.lnHandlers[ipvsSvc.AddressFamily]
// 		// assign cluster IP of the service to the dummy interface so that its routable from the pod's on the node
// 		err := ln.ipAddrAdd(dummyVipInterface, clusterIP.String(), true)
// 		if err != nil {
// 			return err
// 		}
//
// 		// create IPVS service for the service to be exposed through the cluster ip
// 		ipvsClusterVipSvc, err := ln.ipvsAddService(ipvsSvc, clusterIP, protocol, uint16(svc.port),
// 			svc.sessionAffinity, svc.sessionAffinityTimeoutSeconds, svc.scheduler, svc.flags)
// 		if err != nil {
// 			klog.Errorf("Failed to create ipvs service for cluster ip: %s", err.Error())
// 			return err
// 		}
// 		var clusterServiceID = generateIPPortID(clusterIP.String(), svc.protocol, strconv.Itoa(svc.port))
// 		activeServiceEndpointMap[clusterServiceID] = make([]string, 0)
//
// 		// add IPVS remote server to the IPVS service
// 		for _, endpoint := range endpoints {
// 			dst := ipvs.Destination{
// 				Address:       net.ParseIP(endpoint.ip),
// 				AddressFamily: ipvsSvc.AddressFamily,
// 				Port:          uint16(endpoint.port),
// 				Weight:        1,
// 			}
// 			// Conditions on which to add an endpoint on this node:
// 			// 1) Service is not a local service
// 			// 2) Service is a local service, but has no active endpoints on this node
// 			// 3) Service is a local service, has active endpoints on this node, and this endpoint is one of them
// 			if svc.local {
// 				if hasActiveEndpoints(endpoints) && !endpoint.isLocal {
// 					// This error is not logged, it's just supposed to trigger
// 					// the loop continuation.
// 					return errors.New("endpoint is not local")
// 				}
// 			}
//
// 			err := ln.ipvsAddServer(ipvsClusterVipSvc, &dst)
// 			if err != nil {
// 				klog.Errorf(err.Error())
// 			} else {
// 				activeServiceEndpointMap[clusterServiceID] = append(activeServiceEndpointMap[clusterServiceID],
// 					generateEndpointID(endpoint.ip, strconv.Itoa(endpoint.port)))
// 			}
// 		}
// 	}
//
// 	return nil
// }

func (nsc *NetworkServicesController) setupClusterIPServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointsInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return fmt.Errorf("failed get list of IPVS services due to: %w", err)
	}
	for k, svc := range serviceInfoMap {
		var protocol uint16

		switch svc.protocol {
		case tcpProtocol:
			protocol = syscall.IPPROTO_TCP
		case udpProtocol:
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}

		endpoints := endpointsInfoMap[k]
		dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
		if err != nil {
			return fmt.Errorf("failed creating dummy interface: %w", err)
		}
		// assign cluster IP of the service to the dummy interface so that its routable from the pod's on the node
		for clusterIPFamily, clusterIP := range svc.clusterIPs {
			err = nsc.ln.ipAddrAdd(dummyVipInterface, clusterIP, clusterIPFamily, true)
			if err != nil {
				continue
			}
		}

		// create IPVS services for the service to be exposed through the cluster ip
		for ipFamily, clusterIP := range svc.clusterIPs {
			ipvsClusterVipSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, clusterIP, ipFamily, protocol, uint16(svc.port),
				svc.sessionAffinity, svc.sessionAffinityTimeoutSeconds, svc.scheduler, svc.flags)
			if err != nil {
				klog.Errorf("Failed to create ipvs service for cluster ip: %s", err.Error())
				continue
			}
			var clusterServiceID = generateIPPortID(clusterIP.String(), svc.protocol, strconv.Itoa(svc.port))
			activeServiceEndpointMap[clusterServiceID] = make([]string, 0)

			// add IPVS remote server to the IPVS service
			for _, endpoint := range endpoints {
				dst := ipvs.Destination{
					Address:       net.ParseIP(endpoint.ip),
					AddressFamily: endpoint.ipFamily,
					Port:          uint16(endpoint.port),
					Weight:        1,
				}
				// Conditions on which to add an endpoint on this node:
				// 1) Service is not a local service
				// 2) Service is a local service, but has no active endpoints on this node
				// 3) Service is a local service, has active endpoints on this node, and this endpoint is one of them
				if svc.local {
					if hasActiveEndpoints(endpoints) && !endpoint.isLocal {
						continue
					}
				}

				err := nsc.ln.ipvsAddServer(ipvsClusterVipSvc, &dst)
				if err != nil {
					klog.Errorf(err.Error())
				} else {
					activeServiceEndpointMap[clusterServiceID] = append(activeServiceEndpointMap[clusterServiceID],
						generateEndpointID(endpoint.ip, strconv.Itoa(endpoint.port)))
				}
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) setupNodePortServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointsInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}
	for k, svc := range serviceInfoMap {
		var protocol uint16

		switch svc.protocol {
		case tcpProtocol:
			protocol = syscall.IPPROTO_TCP
		case udpProtocol:
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}

		if svc.nodePort == 0 {
			// service is not NodePort type
			continue
		}
		endpoints := endpointsInfoMap[k]
		if svc.local && !hasActiveEndpoints(endpoints) {
			klog.V(1).Infof("Skipping setting up NodePort service %s/%s as it does not have active endpoints",
				svc.namespace, svc.name)
			continue
		}

		// create IPVS service for the service to be exposed through the nodeport
		var ipvsNodeportSvcs []*ipvs.Service

		var nodeServiceIds []string

		if nsc.nodeportBindOnAllIP {
			// bind on all interfaces instead
			addrs, err := getAllLocalIPs()

			if err != nil {
				klog.Errorf("Could not get list of system addresses for ipvs services: %s", err.Error())
				continue
			}

			if len(addrs) == 0 {
				klog.Errorf("No IP addresses returned for nodeport service creation!")
				continue
			}

			ipvsNodeportSvcs = make([]*ipvs.Service, len(addrs))
			nodeServiceIds = make([]string, len(addrs))

			for ipFamily, addrs := range addrs {
				for _, addr := range addrs {
					ipvsNodeportSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, addr.IP, ipFamily, protocol, uint16(svc.nodePort),
						svc.sessionAffinity, svc.sessionAffinityTimeoutSeconds, svc.scheduler, svc.flags)
					if err != nil {
						klog.Errorf("Failed to create ipvs service for node port due to: %s", err.Error())
						continue
					}
					ipvsNodeportSvcs = append(ipvsNodeportSvcs, ipvsNodeportSvc)

					nodeServiceID := generateIPPortID(addr.IP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
					nodeServiceIds = append(nodeServiceIds, nodeServiceID)
					activeServiceEndpointMap[nodeServiceID] = make([]string, 0)
				}
			}
		} else {
			ipvsNodeportSvcs = make([]*ipvs.Service, 0, 2)
			nodeServiceIds = make([]string, 0, 2)

			for ipFamily, ipFamilyHandler := range nsc.ipFamilyHandlers {
				ipvsSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, ipFamilyHandler.NodeIP, ipFamily, protocol, uint16(svc.nodePort),
					svc.sessionAffinity, svc.sessionAffinityTimeoutSeconds, svc.scheduler, svc.flags)
				if err != nil {
					klog.Errorf("Failed to create ipvs service for node port due to: %s", err.Error())
					continue
				}
				ipvsNodeportSvcs = append(ipvsNodeportSvcs, ipvsSvc)

				id := generateIPPortID(ipFamilyHandler.NodeIP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
				nodeServiceIds = append(nodeServiceIds, id)

				activeServiceEndpointMap[id] = make([]string, 0)
			}
		}

		for _, endpoint := range endpoints {
			dst := ipvs.Destination{
				Address:       net.ParseIP(endpoint.ip),
				AddressFamily: syscall.AF_INET,
				Port:          uint16(endpoint.port),
				Weight:        1,
			}
			for i := 0; i < len(ipvsNodeportSvcs); i++ {
				if !svc.local || (svc.local && endpoint.isLocal) {
					err := nsc.ln.ipvsAddServer(ipvsNodeportSvcs[i], &dst)
					if err != nil {
						klog.Errorf(err.Error())
					} else {
						activeServiceEndpointMap[nodeServiceIds[i]] =
							append(activeServiceEndpointMap[nodeServiceIds[i]],
								generateEndpointID(endpoint.ip, strconv.Itoa(endpoint.port)))
					}
				}
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) setupExternalIPServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointsInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}
	for k, svc := range serviceInfoMap {
		var protocol uint16

		switch svc.protocol {
		case tcpProtocol:
			protocol = syscall.IPPROTO_TCP
		case udpProtocol:
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}

		endpoints := endpointsInfoMap[k]

		dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
		if err != nil {
			return errors.New("Failed creating dummy interface: " + err.Error())
		}

		externalIPServices := make([]externalIPService, 0)
		// create IPVS service for the service to be exposed through the external IP's
		// For external IP (which are meant for ingress traffic) Kube-router setsup IPVS services
		// based on FWMARK to enable Direct server return functionality. DSR requires a director
		// without a VIP http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
		// to avoid martian packets
		// extIPSet := sets.NewString(svc.externalIPs...)
		// if !svc.skipLbIps {
		// 	extIPSet = extIPSet.Union(sets.NewString(svc.loadBalancerIPs...))
		// }

		// if extIPSet.Len() == 0 {
		// 	// service is not LoadBalancer type and no external IP's are configured
		// 	continue
		// }

		if svc.local && !hasActiveEndpoints(endpoints) {
			klog.V(1).Infof("Skipping setting up IPVS service for external IP and LoadBalancer IP "+
				"for the service %s/%s as it does not have active endpoints\n", svc.namespace, svc.name)
			continue
		}
		mangleTableRulesDump := bytes.Buffer{}
		var mangleTableRules []string
		for _, ipFamilyHandler := range nsc.ipFamilyHandlers {
			if err := ipFamilyHandler.iptablesSaveRestore.SaveInto("mangle", &mangleTableRulesDump); err != nil {
				klog.Errorf("Failed to run iptables-save: %s" + err.Error())
			} else {
				mangleTableRules = strings.Split(mangleTableRulesDump.String(), "\n")
			}
		}
		for ipFamily, externalIPs := range svc.externalIPs {
			loadBalancerIPs := svc.loadBalancerIPs[ipFamily]
			// extIPSet := sets.NewString(externalIPs...)
			// extIPSet := sets.NewString()
			// for _, externalIP := range externalIPs {
			// 	extIPSet.Insert(externalIP.String())
			// }
			if !svc.skipLbIps {
				// extIPSet = extIPSet.Union(sets.NewString(loadBalancerIPs...))
				externalIPs = append(externalIPs, loadBalancerIPs...)
			}
			// if extIPSet.Len() == 0 {
			if len(externalIPs) == 0 {
				// service is not LoadBalancer type and no external IP's are configured
				continue
			}
			for _, externalIP := range externalIPs {
				var externalIPServiceID string
				if svc.directServerReturn && svc.directServerReturnMethod == tunnelInterfaceType {
					ipvsExternalIPSvc, err := nsc.ln.ipvsAddFWMarkService(externalIP, ipFamily, protocol,
						uint16(svc.port), svc.sessionAffinity, svc.sessionAffinityTimeoutSeconds, svc.scheduler, svc.flags)
					if err != nil {
						klog.Errorf("Failed to create ipvs service for External IP: %s due to: %s",
							externalIP, err.Error())
						continue
					}
					externalIPServices = append(externalIPServices, externalIPService{ipvsSvc: ipvsExternalIPSvc,
						externalIP: externalIP})
					fwMark, err := generateFwmark(externalIP.String(), svc.protocol, strconv.Itoa(svc.port))
					if err != nil {
						klog.Errorf("Failed to generate Fwmark")
						continue
					}
					externalIPServiceID = fmt.Sprint(fwMark)

					// ensure there is iptables mangle table rule to FWMARK the packet
					err = nsc.setupMangleTableRule(externalIP.String(), svc.protocol, strconv.Itoa(svc.port), externalIPServiceID,
						nsc.dsrTCPMSS)
					if err != nil {
						klog.Errorf("Failed to setup mangle table rule to FMWARD the traffic to external IP")
						continue
					}

					// ensure VIP less director. we dont assign VIP to any interface
					err = nsc.ln.ipAddrDel(dummyVipInterface, externalIP, ipFamily)
					if err != nil && err.Error() != IfaceHasNoAddr {
						klog.Errorf("Failed to delete external ip address from dummyVipInterface due to %s", err)
						continue
					}
					// do policy routing to deliver the packet locally so that IPVS can pick the packet
					err = routeVIPTrafficToDirector("0x" + fmt.Sprintf("%x", fwMark))
					if err != nil {
						klog.Errorf("Failed to setup ip rule to lookup traffic to external IP: %s through custom "+
							"route table due to %s", externalIP, err.Error())
						continue
					}
				} else {
					// ensure director with vip assigned
					err := nsc.ln.ipAddrAdd(dummyVipInterface, externalIP, ipFamily, true)
					if err != nil && err.Error() != IfaceHasAddr {
						klog.Errorf("Failed to assign external ip %s to dummy interface %s due to %s",
							externalIP, KubeDummyIf, err.Error())
					}

					// create IPVS service for the service to be exposed through the external ip
					ipvsExternalIPSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, externalIP, ipFamily, protocol,
						uint16(svc.port), svc.sessionAffinity, svc.sessionAffinityTimeoutSeconds, svc.scheduler, svc.flags)
					if err != nil {
						klog.Errorf("Failed to create ipvs service for external ip: %s due to %s",
							externalIP, err.Error())
						continue
					}
					externalIPServices = append(externalIPServices, externalIPService{
						ipvsSvc: ipvsExternalIPSvc, externalIP: externalIP})
					externalIPServiceID = generateIPPortID(externalIP.String(), svc.protocol, strconv.Itoa(svc.port))

					// ensure there is NO iptables mangle table rule to FWMARK the packet
					fwmark, err := generateFwmark(externalIP.String(), svc.protocol, strconv.Itoa(svc.port))
					if err != nil {
						klog.Errorf("Failed to generate a fwmark due to " + err.Error())
						continue
					}
					fwMark := fmt.Sprint(fwmark)
					for _, mangleTableRule := range mangleTableRules {
						if strings.Contains(mangleTableRule, externalIP.String()) && strings.Contains(mangleTableRule, fwMark) {
							err = nsc.ln.cleanupMangleTableRule(externalIP.String(), svc.protocol, strconv.Itoa(svc.port), fwMark,
								nsc.dsrTCPMSS)
							if err != nil {
								klog.Errorf("Failed to verify and cleanup any mangle table rule to FMWARD the traffic " +
									"to external IP due to " + err.Error())
								continue
							}
						}
					}
				}

				activeServiceEndpointMap[externalIPServiceID] = make([]string, 0)
				for _, endpoint := range endpoints {
					if !svc.local || (svc.local && endpoint.isLocal) {
						activeServiceEndpointMap[externalIPServiceID] =
							append(activeServiceEndpointMap[externalIPServiceID],
								generateEndpointID(endpoint.ip, strconv.Itoa(endpoint.port)))
					}
				}
			}
		}

		// add IPVS remote server to the IPVS service
		for _, endpoint := range endpoints {
			dst := ipvs.Destination{
				Address:       net.ParseIP(endpoint.ip),
				AddressFamily: syscall.AF_INET,
				Port:          uint16(endpoint.port),
				Weight:        1,
			}

			for _, externalIPService := range externalIPServices {
				if svc.local && !endpoint.isLocal {
					continue
				}

				if svc.directServerReturn && svc.directServerReturnMethod == tunnelInterfaceType {
					dst.ConnectionFlags = ipvs.ConnectionFlagTunnel
				}

				// add server to IPVS service
				err := nsc.ln.ipvsAddServer(externalIPService.ipvsSvc, &dst)
				if err != nil {
					klog.Errorf(err.Error())
				}

				// For now just support IPVS tunnel mode, we can add other ways of DSR in future
				if svc.directServerReturn && svc.directServerReturnMethod == tunnelInterfaceType {

					podObj, err := nsc.getPodObjectForEndpoint(endpoint.ip)
					if err != nil {
						klog.Errorf("Failed to find endpoint with ip: " + endpoint.ip + ". so skipping " +
							"preparing endpoint for DSR")
						continue
					}

					// we are only concerned with endpoint pod running on current node
					hostIP := net.ParseIP(podObj.Status.HostIP)
					if hostIP == nil {
						klog.Errorf("Failed to find host IP of pod %s associated with the endpoint %s",
							podObj.ObjectMeta.Name, endpoint.ip)
						continue
					}
					if netutils.IsIPv4(hostIP) && strings.Compare(
						podObj.Status.HostIP, nsc.ipFamilyHandlers[syscall.AF_INET].NodeIP.String()) != 0 {
						continue
					}
					if netutils.IsIPv6(hostIP) && strings.Compare(
						podObj.Status.HostIP, nsc.ipFamilyHandlers[syscall.AF_INET6].NodeIP.String()) != 0 {
						continue
					}

					containerURL := podObj.Status.ContainerStatuses[0].ContainerID
					runtime, containerID, err := cri.EndpointParser(containerURL)
					if err != nil {
						klog.Errorf("couldn't get containerID (container=%s, pod=%s). Skipping DSR endpoint "+
							"set up", podObj.Spec.Containers[0].Name, podObj.Name)
						continue
					}

					if containerID == "" {
						klog.Errorf("Failed to find container id for the endpoint with ip: %s so skipping "+
							"preparing endpoint for DSR", endpoint.ip)
						continue
					}

					if runtime == "docker" {
						// WARN: This method is deprecated and will be removed once docker-shim is removed from kubelet.
						err = nsc.ln.prepareEndpointForDsrWithDocker(containerID, endpoint.ip,
							externalIPService.externalIP.String(), endpoint.ipFamily)
						if err != nil {
							klog.Errorf("Failed to prepare endpoint %s to do direct server return due to %s",
								endpoint.ip, err.Error())
						}
					} else {
						// We expect CRI compliant runtimes here
						// ugly workaround, refactoring of pkg/Proxy is required
						err = nsc.ln.(*linuxNetworking).prepareEndpointForDsrWithCRI(nsc.dsr.runtimeEndpoint,
							containerID, endpoint.ip, externalIPService.externalIP.String(), endpoint.ipFamily)
						if err != nil {
							klog.Errorf("Failed to prepare endpoint %s to do DSR due to: %s",
								endpoint.ip, err.Error())
						}
					}
				}
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) setupForDSR(serviceInfoMap serviceInfoMap) error {
	klog.V(1).Infof("Setting up policy routing required for Direct Server Return functionality.")
	err := nsc.ln.setupPolicyRoutingForDSR()
	if err != nil {
		return errors.New("Failed setup PBR for DSR due to: " + err.Error())
	}
	klog.V(1).Infof("Custom routing table %s required for Direct Server Return is setup as expected.",
		customDSRRouteTableName)

	klog.V(1).Infof("Setting up custom route table required to add routes for external IP's.")
	err = nsc.ln.setupRoutesForExternalIPForDSR(serviceInfoMap)
	if err != nil {
		klog.Errorf("failed setup custom routing table required to add routes for external IP's due to: %v",
			err)
		return fmt.Errorf("failed setup custom routing table required to add routes for external IP's due to: %v",
			err)
	}
	klog.V(1).Infof("Custom routing table required for Direct Server Return is setup as expected.",
		externalIPRouteTableName)
	return nil
}

func (nsc *NetworkServicesController) cleanupStaleVIPs(activeServiceEndpointMap map[string][]string) error {
	// cleanup stale IPs on dummy interface
	klog.V(1).Info("Cleaning up if any, old service IPs on dummy interface")
	// This represents "ip - protocol - port" that is created as the key to activeServiceEndpointMap in
	// generateIPPortID()
	const expectedServiceIDParts = 3
	addrActive := make(map[string]bool)
	for k := range activeServiceEndpointMap {
		// verify active and its a generateIPPortID() type service
		if strings.Contains(k, "-") {
			parts := strings.SplitN(k, "-", expectedServiceIDParts)
			addrActive[parts[0]] = true
		}
	}

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
	if err != nil {
		return errors.New("Failed creating dummy interface: " + err.Error())
	}
	for ipFamily := range nsc.ipFamilyHandlers {
		var addrs []netlink.Addr
		addrs, err = netlink.AddrList(dummyVipInterface, int(ipFamily))
		if err != nil {
			return fmt.Errorf("failed to list dummy interface IPs: %w", err)
		}
		for _, addr := range addrs {
			isActive := addrActive[addr.IP.String()]
			if !isActive {
				klog.V(1).Infof("Found an IP %s which is no longer needed so cleaning up", addr.IP.String())
				err := nsc.ln.ipAddrDel(dummyVipInterface, addr.IP, ipFamily)
				if err != nil {
					klog.Errorf("Failed to delete stale IP %s due to: %s",
						addr.IP.String(), err.Error())
					continue
				}
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) cleanupStaleIPVSConfig(activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("failed get list of IPVS services due to: " + err.Error())
	}

	// cleanup stale ipvs service and servers
	klog.V(1).Info("Cleaning up if any, old ipvs service and servers which are no longer needed")

	var protocol string
	for _, ipvsSvc := range ipvsSvcs {
		if ipvsSvc.Protocol == syscall.IPPROTO_TCP {
			protocol = tcpProtocol
		} else {
			protocol = udpProtocol
		}
		var key string
		switch {
		case ipvsSvc.Address != nil:
			key = generateIPPortID(ipvsSvc.Address.String(), protocol, strconv.Itoa(int(ipvsSvc.Port)))
		case ipvsSvc.FWMark != 0:
			key = fmt.Sprint(ipvsSvc.FWMark)
		default:
			continue
		}

		endpointIDs, ok := activeServiceEndpointMap[key]
		// Only delete the service if it's not there anymore to prevent flapping
		// old: if !ok || len(endpointIDs) == 0 {
		if !ok {
			excluded := false
			for _, excludedCidr := range nsc.excludedCidrs {
				if excludedCidr.Contains(ipvsSvc.Address) {
					excluded = true
					break
				}
			}

			if excluded {
				klog.V(1).Infof("Ignoring deletion of an IPVS service %s in an excluded cidr",
					ipvsServiceString(ipvsSvc))
				continue
			}

			klog.V(1).Infof("Found a IPVS service %s which is no longer needed so cleaning up",
				ipvsServiceString(ipvsSvc))
			err := nsc.ln.ipvsDelService(ipvsSvc)
			if err != nil {
				klog.Errorf("Failed to delete stale IPVS service %s due to: %s",
					ipvsServiceString(ipvsSvc), err.Error())
				continue
			}
		} else {
			dsts, err := nsc.ln.ipvsGetDestinations(ipvsSvc)
			if err != nil {
				klog.Errorf("Failed to get list of servers from ipvs service")
			}
			for _, dst := range dsts {
				validEp := false
				for _, epID := range endpointIDs {
					if epID == generateEndpointID(dst.Address.String(), strconv.Itoa(int(dst.Port))) {
						validEp = true
						break
					}
				}
				if !validEp {
					klog.V(1).Infof("Found a destination %s in service %s which is no longer needed so "+
						"cleaning up", ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					err = nsc.ipvsDeleteDestination(ipvsSvc, dst)
					if err != nil {
						klog.Errorf("Failed to delete destination %s from ipvs service %s",
							ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					}
				}
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) cleanupStaleMetrics(activeServiceEndpointMap map[string][]string) {
	for k, v := range nsc.metricsMap {
		if _, ok := activeServiceEndpointMap[k]; ok {
			continue
		}

		metrics.ServiceBpsIn.DeleteLabelValues(v...)
		metrics.ServiceBpsOut.DeleteLabelValues(v...)
		metrics.ServiceBytesIn.DeleteLabelValues(v...)
		metrics.ServiceBytesOut.DeleteLabelValues(v...)
		metrics.ServiceCPS.DeleteLabelValues(v...)
		metrics.ServicePacketsIn.DeleteLabelValues(v...)
		metrics.ServicePacketsOut.DeleteLabelValues(v...)
		metrics.ServicePpsIn.DeleteLabelValues(v...)
		metrics.ServicePpsOut.DeleteLabelValues(v...)
		metrics.ServiceTotalConn.DeleteLabelValues(v...)
		metrics.ControllerIpvsServices.Dec()
		delete(nsc.metricsMap, k)
	}
}
