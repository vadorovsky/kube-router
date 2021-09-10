package routing

import (
	"errors"
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog/v2"
)

// set up MASQUERADE rule so that egress traffic from the pods gets masqueraded to node's IP

var (
	podEgressArgs4 = []string{"-m", "set", "--match-set", podSubnetsIPSetNameIPv4, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetNameIPv4, "dst",
		"-m", "set", "!", "--match-set", nodeAddrsIPSetNameIPv4, "dst",
		"-j", "MASQUERADE"}
	podEgressArgs6 = []string{"-m", "set", "--match-set", "inet6:" + podSubnetsIPSetNameIPv6, "src",
		"-m", "set", "!", "--match-set", "inet6:" + podSubnetsIPSetNameIPv6, "dst",
		"-m", "set", "!", "--match-set", "inet6:" + nodeAddrsIPSetNameIPv6, "dst",
		"-j", "MASQUERADE"}
	podEgressArgsBad4 = [][]string{{"-m", "set", "--match-set", podSubnetsIPSetNameIPv4, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetNameIPv4, "dst",
		"-j", "MASQUERADE"}}
	podEgressArgsBad6 = [][]string{{"-m", "set", "--match-set", "inet6:" + podSubnetsIPSetNameIPv6, "src",
		"-m", "set", "!", "--match-set", "inet6:" + podSubnetsIPSetNameIPv6, "dst",
		"-j", "MASQUERADE"}}
)

func (nrc *NetworkRoutingController) createPodEgressRule() error {
	if nrc.enableIPv4 {
		iptablesCmdHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return fmt.Errorf("failed create iptables handler: %w", err)
		}

		podEgressArgs := make([]string, len(podEgressArgs4))
		copy(podEgressArgs, podEgressArgs4)
		if iptablesCmdHandler.HasRandomFully() {
			podEgressArgs = append(podEgressArgs, "--random-fully")
		}

		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", podEgressArgs...)
		if err != nil {
			return errors.New("Failed to add iptables rule to masquerade outbound traffic from pods: " +
				err.Error() + "External connectivity will not work.")

		}
	}
	if nrc.enableIPv6 {
		iptablesCmdHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed create iptables handler: %w", err)
		}

		podEgressArgs := make([]string, len(podEgressArgs6))
		copy(podEgressArgs, podEgressArgs6)
		if iptablesCmdHandler.HasRandomFully() {
			podEgressArgs = append(podEgressArgs, "--random-fully")
		}

		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", podEgressArgs...)
		if err != nil {
			return errors.New("Failed to add iptables rule to masquerade outbound traffic from pods: " +
				err.Error() + "External connectivity will not work.")

		}
	}

	klog.V(1).Infof("Added iptables rule(s) to masquerade outbound traffic from pods.")
	return nil
}

func (nrc *NetworkRoutingController) deletePodEgressRule() error {
	if nrc.enableIPv4 {
		iptablesCmdHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return fmt.Errorf("failed create iptables handler: %w", err)
		}

		podEgressArgs := podEgressArgs4
		if iptablesCmdHandler.HasRandomFully() {
			podEgressArgs = append(podEgressArgs, "--random-fully")
		}

		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", podEgressArgs...)
		if err != nil {
			return errors.New("Failed to lookup iptables rule to masquerade outbound traffic from pods: " + err.Error())
		}

		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", podEgressArgs...)
			if err != nil {
				return errors.New("Failed to delete iptables rule to masquerade outbound traffic from pods: " +
					err.Error() + ". Pod egress might still work...")
			}
			klog.Infof("Deleted iptables rule to masquerade outbound traffic from pods.")
		}
	}
	if nrc.enableIPv6 {
		iptablesCmdHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("Failed create iptables handler:" + err.Error())
		}

		podEgressArgs := podEgressArgs4
		if iptablesCmdHandler.HasRandomFully() {
			podEgressArgs = append(podEgressArgs, "--random-fully")
		}

		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", podEgressArgs...)
		if err != nil {
			return errors.New("Failed to lookup iptables rule to masquerade outbound traffic from pods: " + err.Error())
		}

		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", podEgressArgs...)
			if err != nil {
				return errors.New("Failed to delete iptables rule to masquerade outbound traffic from pods: " +
					err.Error() + ". Pod egress might still work...")
			}
			klog.Infof("Deleted iptables rule to masquerade outbound traffic from pods.")
		}

	}

	return nil
}

func (nrc *NetworkRoutingController) deleteBadPodEgressRules() error {
	if nrc.enableIPv4 {
		iptablesCmdHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return fmt.Errorf("failed create iptables handler: %w", err)
		}
		podEgressArgsBad := podEgressArgsBad4

		// If random fully is supported remove the original rule as well
		if iptablesCmdHandler.HasRandomFully() {
			podEgressArgsBad = append(podEgressArgsBad, podEgressArgs4)
		}

		for _, args := range podEgressArgsBad {
			exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to lookup iptables rule: %w", err)
			}

			if exists {
				err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
				if err != nil {
					return fmt.Errorf("failed to delete old/bad iptables rule to masquerade outbound traffic "+
						"from pods: %w. Pod egress might still work, or bugs may persist after upgrade", err)
				}
				klog.Infof("Deleted old/bad iptables rule to masquerade outbound traffic from pods.")
			}
		}
	}
	if nrc.enableIPv6 {
		iptablesCmdHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed create iptables handler: %w", err)
		}
		podEgressArgsBad := podEgressArgsBad6

		// If random fully is supported remove the original rule as well
		if iptablesCmdHandler.HasRandomFully() {
			podEgressArgsBad = append(podEgressArgsBad, podEgressArgs6)
		}

		for _, args := range podEgressArgsBad {
			exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to lookup iptables rule: %w", err)
			}

			if exists {
				err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
				if err != nil {
					return fmt.Errorf("failed to delete old/bad iptables rule to masquerade outbound traffic "+
						"from pods: %w. Pod egress might still work, or bugs may persist after upgrade", err)
				}
				klog.Infof("Deleted old/bad iptables rule to masquerade outbound traffic from pods.")
			}
		}
	}

	return nil
}
