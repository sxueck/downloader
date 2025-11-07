package server

import (
	"fmt"
	"net"
)

// Whitelist 白名单管理器
type Whitelist struct {
	cidrs []*net.IPNet
}

// NewWhitelist 创建新的白名单管理器
func NewWhitelist() *Whitelist {
	return &Whitelist{
		cidrs: make([]*net.IPNet, 0),
	}
}

// AddCIDR 添加CIDR网段到白名单
func (w *Whitelist) AddCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}
	w.cidrs = append(w.cidrs, ipnet)
	return nil
}

// IsAllowed 检查IP地址是否在白名单内
func (w *Whitelist) IsAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range w.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs 批量解析CIDR网段
func (w *Whitelist) ParseCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		if err := w.AddCIDR(cidr); err != nil {
			return err
		}
	}
	return nil
}

// IsEmpty 检查白名单是否为空
func (w *Whitelist) IsEmpty() bool {
	return len(w.cidrs) == 0
}
