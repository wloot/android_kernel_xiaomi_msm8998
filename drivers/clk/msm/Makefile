obj-$(CONFIG_COMMON_CLK_MSM)	+= clock.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-dummy.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-generic.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-local2.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-pll.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-alpha-pll.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-rpm.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-voter.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= reset.o

obj-$(CONFIG_MSM_CLK_CONTROLLER_V2)	+= msm-clock-controller.o

obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-debug.o

ifeq ($(CONFIG_ARCH_MSM8996), y)
	obj-$(CONFIG_COMMON_CLK_MSM) += clock-gcc-8996.o
	obj-$(CONFIG_COMMON_CLK_MSM) += clock-mmss-8996.o
	obj-$(CONFIG_COMMON_CLK_MSM) += clock-cpu-8996.o
else
	obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-gcc-8998.o
	obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-gpu-8998.o
	obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-mmss-8998.o
	obj-$(CONFIG_COMMON_CLK_MSM)	+= clock-osm.o
endif

obj-$(CONFIG_COMMON_CLK_MSM)	+= gdsc.o
obj-$(CONFIG_COMMON_CLK_MSM)	+= mdss/

obj-$(CONFIG_MSM_VIRTCLK_FRONTEND)	+= virtclk-front.o
obj-$(CONFIG_MSM_VIRTCLK_FRONTEND)	+= virt-reset-front.o
obj-$(CONFIG_MSM_VIRTCLK_FRONTEND_8996)	+= virtclk-front-8996.o

# TODO: remove me b/62058353
subdir-ccflags-y += \
	-Wno-literal-conversion
