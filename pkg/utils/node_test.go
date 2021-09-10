package utils

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_GetNodeObject(t *testing.T) {
	curHostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("failed to get local hostname: %v", err)
	}

	testcases := []struct {
		name             string
		envNodeName      string
		hostnameOverride string
		existingNode     *apiv1.Node
		err              error
	}{
		{
			"node with NODE_NAME exists",
			"test-node",
			"",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
			},
			nil,
		},
		{
			"node with hostname overrie exists",
			"something-else",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
			},
			nil,
		},
		{
			"node with current hostname exists",
			"something-else",
			"something-else",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: curHostname,
				},
			},
			nil,
		},
		{
			"node with NODE_NAME, hostname override or current hostname does not exists",
			"test-node",
			"",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-node",
				},
			},
			errors.New("failed to identify the node by NODE_NAME, hostname or --hostname-override"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			_, err := clientset.CoreV1().Nodes().Create(context.Background(), testcase.existingNode, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing nodes for test: %v", err)
			}

			os.Setenv("NODE_NAME", testcase.envNodeName)
			defer os.Unsetenv("NODE_NAME")

			_, err = GetNodeObject(clientset, testcase.hostnameOverride)
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", testcase.err)
				t.Error("did not get expected error")
			}
		})
	}
}

func Test_GetNodeIP(t *testing.T) {
	testcases := []struct {
		name       string
		node       *apiv1.Node
		enableIPv4 bool
		enableIPv6 bool
		ipv4       net.IP
		ipv6       net.IP
		err        error
	}{
		{
			"has external and internal IPs (IPv4)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "10.0.0.1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "1.1.1.1",
						},
					},
				},
			},
			true,
			false,
			net.ParseIP("10.0.0.1"),
			nil,
			nil,
		},
		{
			"has only internal IP (IPv4)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "10.0.0.1",
						},
					},
				},
			},
			true,
			false,
			net.ParseIP("10.0.0.1"),
			nil,
			nil,
		},
		{
			"has only external IP (IPv4)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "1.1.1.1",
						},
					},
				},
			},
			true,
			false,
			net.ParseIP("1.1.1.1"),
			nil,
			nil,
		},
		{
			"has external and internal IPs (IPv6)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8:42:1::1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "a00:100::1",
						},
					},
				},
			},
			false,
			true,
			nil,
			net.ParseIP("2001:db8:42:1::1"),
			nil,
		},
		{
			"has only internal IP (IPv6)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8:42:1::1",
						},
					},
				},
			},
			false,
			true,
			nil,
			net.ParseIP("2001:db8:42:1::1"),
			nil,
		},
		{
			"has only external IP (IPv6)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "a00:100::1",
						},
					},
				},
			},
			false,
			true,
			nil,
			net.ParseIP("a00:100::1"),
			nil,
		},
		{
			"has external and internal IPs (dual-stack)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "10.0.0.1",
						},
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8:42:1::1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "a00:100::1",
						},
					},
				},
			},
			true,
			true,
			net.ParseIP("10.0.0.1"),
			net.ParseIP("2001:db8:42:1::1"),
			nil,
		},
		{
			"has only internal IP (dual-stack)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "10.0.0.1",
						},
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8:42:1::1",
						},
					},
				},
			},
			true,
			true,
			net.ParseIP("10.0.0.1"),
			net.ParseIP("2001:db8:42:1::1"),
			nil,
		},
		{
			"has only external IP (dual-stack)",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "a00:100::1",
						},
					},
				},
			},
			true,
			false,
			net.ParseIP("1.1.1.1"),
			net.ParseIP("a00:100::1"),
			nil,
		},
		{
			"has no addresses",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{},
				},
			},
			true,
			true,
			nil,
			nil,
			errors.New("host IP unknown"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			ipv4, ipv6, err := GetNodeIP(testcase.node, testcase.enableIPv4, testcase.enableIPv6)
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", testcase.err)
				t.Error("did not get expected error")
			}

			if !reflect.DeepEqual(ipv4, testcase.ipv4) {
				t.Logf("actual ip: %v", ipv4)
				t.Logf("expected ip: %v", testcase.ipv4)
				t.Error("did not get expected node ip")
			}

			if !reflect.DeepEqual(ipv4, testcase.ipv6) {
				t.Logf("actual ip: %v", ipv6)
				t.Logf("expected ip: %v", testcase.ipv6)
				t.Error("did not get expected node ip")
			}
		})
	}
}
