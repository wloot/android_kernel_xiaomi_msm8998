obj-$(CONFIG_MSM_MDSS_PLL) += mdss-pll-util.o
obj-$(CONFIG_MSM_MDSS_PLL) += mdss-pll.o
ifeq ($(CONFIG_ARCH_MSM8996), y)
	obj-$(CONFIG_MSM_MDSS_PLL) += mdss-dsi-pll-8996.o
	obj-$(CONFIG_MSM_MDSS_PLL) += mdss-dsi-pll-8996-util.o
	obj-$(CONFIG_MSM_MDSS_PLL) += mdss-hdmi-pll-8996.o
else
	obj-$(CONFIG_MSM_MDSS_PLL) += mdss-dsi-pll-8998.o
	obj-$(CONFIG_MSM_MDSS_PLL) += mdss-dp-pll-8998.o
	obj-$(CONFIG_MSM_MDSS_PLL) += mdss-dp-pll-8998-util.o
	obj-$(CONFIG_MSM_MDSS_PLL) += mdss-hdmi-pll-8998.o
endif
