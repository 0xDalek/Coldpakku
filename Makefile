#---------------------------------------------------------------------------------
# GBA Signer — Ethereum hardware wallet for the Game Boy Advance
#
# Based on the devkitARM + libgba template. Requires:
#   - DEVKITARM and DEVKITPRO in the environment (pacman package gba-dev)
#   - mGBA for emulation
#---------------------------------------------------------------------------------
ifeq ($(strip $(DEVKITARM)),)
$(error "DEVKITARM not set. Install devkitPro / package gba-dev and export DEVKITARM")
endif

include $(DEVKITARM)/gba_rules

#---------------------------------------------------------------------------------
TARGET   := gba-signer
BUILD    := build
SOURCES  := src \
            src/ui \
            src/crypto \
            src/storage \
            src/link \
            third_party/micro-ecc \
            third_party/crypto-algorithms
INCLUDES := src \
            src/ui \
            src/crypto \
            src/storage \
            src/link \
            third_party/micro-ecc \
            third_party/crypto-algorithms

#---------------------------------------------------------------------------------
# ROM header + flags
#---------------------------------------------------------------------------------
ROM_TITLE := GBA SIGNER
ROM_CODE  := GSIE
GAME_TITLE := -DGAME_TITLE='"$(ROM_TITLE)"'

ARCH    := -mthumb -mthumb-interwork

CFLAGS  := -g -Wall -Wextra -O2 \
           -mcpu=arm7tdmi -mtune=arm7tdmi \
           -fomit-frame-pointer \
           -ffast-math \
           $(ARCH) \
           $(INCLUDE) \
           -DuECC_PLATFORM=uECC_arm_thumb \
           -DuECC_OPTIMIZATION_LEVEL=2 \
           -DuECC_SUPPORTS_secp160r1=0 \
           -DuECC_SUPPORTS_secp192r1=0 \
           -DuECC_SUPPORTS_secp224r1=0 \
           -DuECC_SUPPORTS_secp256r1=0 \
           -DuECC_SUPPORTS_secp256k1=1 \
           -DuECC_SUPPORT_COMPRESSED_POINT=1 \
           -DuECC_VLI_NATIVE_LITTLE_ENDIAN=0

CXXFLAGS := $(CFLAGS) -fno-rtti -fno-exceptions

ASFLAGS := -g $(ARCH)
LDFLAGS  = -g $(ARCH) -Wl,-Map,$(notdir $*).map -specs=gba.specs

LIBS    := -lgba
LIBDIRS := $(LIBGBA)

#---------------------------------------------------------------------------------
# Build rules — adapted from the libgba template
#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT := $(CURDIR)/$(TARGET)
export VPATH  := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)

CFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))

ifeq ($(strip $(CPPFILES)),)
    export LD := $(CC)
else
    export LD := $(CXX)
endif

export OFILES := $(addsuffix .o,$(BINFILES)) \
                 $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)

export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
                  $(foreach dir,$(LIBDIRS),-I$(dir)/include) \
                  -I$(CURDIR)/$(BUILD)

export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

.PHONY: $(BUILD) clean run socket wordlist splash

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@echo "cleaning..."
	@rm -rf $(BUILD) $(TARGET).elf $(TARGET).gba

run: $(BUILD)
	@mgba-qt $(TARGET).gba &

socket: $(BUILD)
	@echo "launching mGBA with TCP socket on :12345..."
	@mgba -l 0.0.0.0:12345 $(TARGET).gba &

wordlist:
	@python3 tools/gen_wordlist.py third_party/bip39-wordlist.txt src/bip39_wordlist.h
	@echo "wordlist regenerated"

splash:
	@python3 tools/png_to_mode4.py assets/splash_coldpakku.png src/ui/splash_image.h --name SPLASH
	@echo "splash_image.h regenerated"

else

DEPENDS := $(OFILES:.o=.d)

$(OUTPUT).gba: $(OUTPUT).elf
$(OUTPUT).elf: $(OFILES)

-include $(DEPENDS)

endif
