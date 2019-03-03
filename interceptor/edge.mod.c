#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xbf464da9, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x7840247b, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x1fdc7df2, __VMLINUX_SYMBOL_STR(_mcount) },
	{ 0xced6941f, __VMLINUX_SYMBOL_STR(__pskb_pull_tail) },
	{ 0xdcb764ad, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xe14e2d71, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x5a921311, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x9aaf7b11, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0x251bab4d, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x907787af, __VMLINUX_SYMBOL_STR(nf_register_net_hook) },
	{ 0xce743e2f, __VMLINUX_SYMBOL_STR(nf_unregister_net_hook) },
	{ 0x80d0e220, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x4e9dffb5, __VMLINUX_SYMBOL_STR(ip_fast_csum) },
	{ 0xd25bc5d4, __VMLINUX_SYMBOL_STR(csum_tcpudp_nofold) },
	{ 0x7232c3e5, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x4f68e5c9, __VMLINUX_SYMBOL_STR(do_gettimeofday) },
	{ 0x5ac0d098, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x4829a47e, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xe113bbbc, __VMLINUX_SYMBOL_STR(csum_partial) },
	{ 0x62786da1, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "5FF4693CEC75140B0E6F0E5");
