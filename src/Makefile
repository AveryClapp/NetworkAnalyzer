CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I../NetworkInterfaceManager
LDFLAGS = -lpcap

BUILD_DIR = ../build
NIM_DIR = ../NetworkInterfaceManager

SRCS = main.cpp $(NIM_DIR)/NetworkInterfaceManager.cpp
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

TARGET = ../network_analyzer

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/$(NIM_DIR)/%.o: $(NIM_DIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: clean