TARGET := screenshot
BUILD_DIR := build
SOURCES := screenshot.m $(wildcard clearsword/*.c)
OBJECTS := $(patsubst %.m,$(BUILD_DIR)/%.o,$(filter %.m,$(SOURCES))) $(patsubst %.c,$(BUILD_DIR)/%.o,$(filter %.c,$(SOURCES)))
DEPFILES := $(OBJECTS:.o=.d)
ENTITLEMENTS := screenshot-entitlements.plist

SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG := $(shell xcrun --find clang)
ARCH_FLAGS := -arch arm64 -isysroot $(SDK) -miphoneos-version-min=18.0
CPPFLAGS := -Ishim -Iclearsword
CFLAGS := -O2 -Wall -Wextra -MMD -MP
FRAMEWORKS := -framework Foundation -framework UIKit -framework IOSurface -framework CoreGraphics -framework ImageIO -framework CoreFoundation -framework IOKit

.PHONY: all clean
all: $(TARGET)

$(TARGET): $(OBJECTS) $(ENTITLEMENTS)
	$(CLANG) $(ARCH_FLAGS) $(OBJECTS) $(FRAMEWORKS) -o $@.tmp
	ldid -S$(ENTITLEMENTS) $@.tmp
	mv $@.tmp $@

$(BUILD_DIR)/%.o: %.m
	@mkdir -p $(dir $@)
	$(CLANG) $(ARCH_FLAGS) $(CPPFLAGS) $(CFLAGS) -fobjc-arc -c $< -o $@

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CLANG) $(ARCH_FLAGS) $(CPPFLAGS) $(CFLAGS) -fblocks -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET).tmp

-include $(DEPFILES)
